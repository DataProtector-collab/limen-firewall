import type { KernelSnapshot, KernelSocket } from "./kernel-types";
import type { DriftGuard, GuardResult, TelemetryEventKind, TelemetryProgram, TelemetryState } from "./telemetry-types";

export const TELEMETRY_LIMITS = Object.freeze({ samples: 600, programs: 256, peers: 256, events: 256, patterns: 256, sockets: 4096, guards: 32, windowMs: 600_000, gapMs: 15_000, warmup: 12 });
const FANOUT_WINDOW_MS = 60_000;
const COOLDOWN_MS = 120_000;
const finitePositive = (value: number) => Number.isFinite(value) && value >= 0;
const canonical = (value: string) => value.replaceAll("/", "\\").toLowerCase();
const hasExecutable = (exe: string) => /^[a-z]:\\/i.test(canonical(exe)) || /^\\\\[^\\]+\\[^\\]+/.test(exe);
const median = (values: number[]) => {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
};
const stateName = (socket: KernelSocket) => socket.state.toLowerCase().replaceAll(/[_ -]/g, "");
const isListener = (socket: KernelSocket) => socket.proto === "TCP" && ["listen", "listening"].includes(stateName(socket));
const isSyn = (socket: KernelSocket) => socket.proto === "TCP" && ["synsent", "synreceived", "synrecv"].includes(stateName(socket));
function endpoint(socket: KernelSocket): string | null {
  if (socket.proto !== "TCP" || !["established", "synsent", "synreceived", "synrecv"].includes(stateName(socket))) return null;
  if (!socket.remoteIp || ["0.0.0.0", "::", "*", "::0"].includes(socket.remoteIp) || socket.remotePort <= 0 || socket.remotePort > 65535) return null;
  return `${socket.remoteIp.toLowerCase().includes(":") ? `[${socket.remoteIp.toLowerCase()}]` : socket.remoteIp}:${socket.remotePort}`;
}
function identity(socket: KernelSocket): { key: string; programKey: string; mode: TelemetryProgram["identityMode"] } {
  const programKey = socket.exe ? canonical(socket.exe) : `unresolved:${socket.pid ?? "unknown"}:${socket.comm}`;
  const started = socket.processStartedAt;
  if (socket.exe && socket.pid !== null && Number.isInteger(socket.pid) && socket.pid > 0 && typeof started === "number" && Number.isFinite(started) && started > 0) {
    return { key: `${programKey}|pid:${socket.pid}|start:${started}`, programKey, mode: "pid-start" };
  }
  return { key: programKey, programKey, mode: socket.exe ? "executable-group" : "unresolved" };
}
function tuple(socket: KernelSocket): string {
  const owner = identity(socket);
  // With no process start time, this is only an executable-level observation.
  return `${owner.key}|${socket.proto}|${socket.localIp}:${socket.localPort}|${socket.remoteIp}:${socket.remotePort}`;
}

export function createTelemetryState(): TelemetryState {
  return {
    sessionStartedAt: null, samples: [], programs: [], events: [], guards: [], peers: [], patterns: [], previousSockets: [],
    listenerStreaks: {}, knownListeners: [], rateBaseline: [], synBaseline: [], cooldowns: {}, counterSource: null, counters: null, nextEventId: 1,
    quality: { status: "not-native", reason: "Windows capture required", lastSnapshotAt: null, trafficReady: false, warmupSamples: 0, samplingGapMs: null, retentionLimited: false },
  };
}

export function unavailableTelemetry(previous: TelemetryState, reason: string, status: "not-native" | "unavailable" = "unavailable"): TelemetryState {
  return {
    ...previous, previousSockets: [], patterns: [], listenerStreaks: {}, knownListeners: [], rateBaseline: [], synBaseline: [], counters: null,
    quality: { ...previous.quality, status, reason, trafficReady: false, warmupSamples: 0 },
  };
}

/** Consume actual Windows socket observations. No payload, per-process byte, or direction inference is performed. */
export function ingestTelemetryState(previous: TelemetryState, snapshot: KernelSnapshot, rates: { rx: number; tx: number } | null): TelemetryState {
  if (snapshot.capture !== "windows" || snapshot.platform !== "win32") return unavailableTelemetry(previous, "Windows capture required", "not-native");
  if (!snapshot.available || !Number.isFinite(snapshot.at) || snapshot.at <= 0 || !Array.isArray(snapshot.sockets)) return unavailableTelemetry(previous, snapshot.error || "Capture unavailable");
  const at = snapshot.at;
  const lastAt = previous.quality.lastSnapshotAt;
  if (lastAt !== null && at <= lastAt) return unavailableTelemetry(previous, "Non-increasing capture timestamp");
  const durationMs = lastAt === null ? null : at - lastAt;
  const gap = previous.counters === null || durationMs === null || durationMs > TELEMETRY_LIMITS.gapMs;
  const counterSource = snapshot.counterSource ?? null;
  const counterReset = previous.counters !== null && (previous.counterSource !== counterSource || snapshot.rxBytes < previous.counters.rxBytes || snapshot.txBytes < previous.counters.txBytes);
  const comparable = !gap;
  const validRates = rates !== null && finitePositive(rates.rx) && finitePositive(rates.tx) && snapshot.trafficAvailable !== false && finitePositive(snapshot.rxBytes) && finitePositive(snapshot.txBytes) && !gap && !counterReset;
  const state: TelemetryState = {
    ...previous, sessionStartedAt: previous.sessionStartedAt ?? at,
    samples: previous.samples.filter(sample => sample.at >= at - TELEMETRY_LIMITS.windowMs),
    programs: [], peers: gap ? [] : previous.peers.filter(peer => peer.lastSeenAt >= at - TELEMETRY_LIMITS.windowMs).map(peer => ({ ...peer })),
    events: [...previous.events], guards: previous.guards, patterns: gap ? [] : previous.patterns.filter(pattern => pattern.lastSeenAt >= at - TELEMETRY_LIMITS.windowMs).map(pattern => ({ ...pattern, appearances: [...pattern.appearances] })),
    previousSockets: [], listenerStreaks: {}, knownListeners: gap ? [] : [...previous.knownListeners],
    rateBaseline: validRates ? previous.rateBaseline.filter(sample => sample.at >= at - TELEMETRY_LIMITS.windowMs).slice(-60) : [],
    synBaseline: gap ? [] : [...previous.synBaseline],
    cooldowns: Object.fromEntries(Object.entries(previous.cooldowns).filter(([, time]) => at - time < COOLDOWN_MS)),
    counterSource, counters: { rxBytes: snapshot.rxBytes, txBytes: snapshot.txBytes },
    quality: { status: "warming", reason: gap && lastAt !== null ? "Observation continuity reset after a capture gap" : counterReset ? "Counter source or counters changed" : null, lastSnapshotAt: at, trafficReady: validRates, warmupSamples: 0, samplingGapMs: durationMs, retentionLimited: previous.quality.retentionLimited },
  };
  const emit = (kind: TelemetryEventKind, evidence: Record<string, number | string>, programKey?: string, suffix = "") => {
    const key = `${kind}|${programKey ?? "host"}|${suffix}`;
    if (state.cooldowns[key] !== undefined && at - state.cooldowns[key] < COOLDOWN_MS) return;
    state.cooldowns[key] = at;
    if (Object.keys(state.cooldowns).length > TELEMETRY_LIMITS.events) {
      const oldest = Object.entries(state.cooldowns).sort((a, b) => a[1] - b[1])[0][0];
      delete state.cooldowns[oldest];
    }
    state.events.push({ id: `${state.sessionStartedAt}-${state.nextEventId++}`, at, kind, severity: ["guard-drift", "syn-pressure"].includes(kind) ? "warning" : "notice", programKey, evidence, acknowledgedAt: null });
  };
  if (validRates) {
    if (state.rateBaseline.length >= TELEMETRY_LIMITS.warmup) {
      for (const direction of ["rx", "tx"] as const) {
        const values = state.rateBaseline.map(sample => sample[direction]);
        const baseline = median(values);
        const mad = median(values.map(value => Math.abs(value - baseline)));
        const floor = direction === "tx" ? 256 * 1024 : 1024 * 1024;
        const threshold = Math.max(floor, baseline * 4, baseline + 6 * mad);
        if (rates[direction] > threshold) emit(`${direction}-burst`, { bytesPerSecond: Math.round(rates[direction]), baselineBytesPerSecond: Math.round(baseline), thresholdBytesPerSecond: Math.round(threshold), baselineSamples: state.rateBaseline.length, scope: "host-interfaces" });
      }
    }
    state.rateBaseline.push({ at, ...rates });
    state.rateBaseline = state.rateBaseline.slice(-60);
  }
  const previousSockets = new Set(comparable ? previous.previousSockets : []);
  const oldPrograms = new Map(previous.programs.map(program => [program.key, program]));
  const programs = new Map<string, TelemetryProgram>();
  const peers = new Map(state.peers.map(peer => [peer.key, peer]));
  const patterns = new Map(state.patterns.map(pattern => [pattern.key, pattern]));
  const seenTuples = new Set<string>();
  const newEndpoints = new Map<string, { programKey: string; endpoint: string }>();
  const listeners = new Map<string, { programKey: string; endpoint: string }>();
  const knownListeners = new Set(state.knownListeners);
  let newSockets = 0;
  let listenerCount = 0;
  let synCount = 0;
  if (snapshot.sockets.length > TELEMETRY_LIMITS.sockets) state.quality.retentionLimited = true;
  for (const socket of snapshot.sockets.slice(0, TELEMETRY_LIMITS.sockets)) {
    if (isListener(socket)) ++listenerCount;
    if (isSyn(socket)) ++synCount;
    const owner = identity(socket);
    let program = programs.get(owner.programKey);
    if (!program) {
      if (programs.size >= TELEMETRY_LIMITS.programs) { state.quality.retentionLimited = true; continue; }
      const old = oldPrograms.get(owner.programKey);
      program = {
        key: owner.programKey, exe: socket.exe, name: socket.comm || socket.exe.split(/[\\/]/).pop() || "Unknown",
        firstSeenAt: !gap && old && old.sampleCount > 0 ? old.firstSeenAt : at, lastSeenAt: at, sampleCount: !gap && old ? old.sampleCount + 1 : 1,
        currentSockets: 0, tcpPeers: [], listenerCount: 0, synCount: 0, identities: [], identityMode: owner.mode,
      };
      programs.set(program.key, program);
    }
    ++program.currentSockets;
    if (program.identities.length < 32 && !program.identities.includes(owner.key)) program.identities.push(owner.key);
    if (owner.mode !== "pid-start") program.identityMode = owner.mode;
    const socketTuple = tuple(socket);
    seenTuples.add(socketTuple);
    if (comparable && !previousSockets.has(socketTuple)) ++newSockets;
    if (isSyn(socket)) ++program.synCount;
    if (isListener(socket)) {
      ++program.listenerCount;
      const listenerEndpoint = `${socket.localIp}:${socket.localPort}`;
      const listenerKey = `${owner.key}|${listenerEndpoint}`;
      listeners.set(listenerKey, { programKey: program.key, endpoint: listenerEndpoint });
      if (!comparable) knownListeners.add(listenerKey);
    }
    const peerEndpoint = endpoint(socket);
    if (peerEndpoint !== null) {
      const peerKey = `${program.key}|${peerEndpoint}`;
      const peer = peers.get(peerKey);
      if (peer) peer.lastSeenAt = at;
      else if (peers.size < TELEMETRY_LIMITS.peers) peers.set(peerKey, { key: peerKey, programKey: program.key, endpoint: peerEndpoint, firstSeenAt: at, lastSeenAt: at });
      else state.quality.retentionLimited = true;
      if (comparable && !previousSockets.has(socketTuple)) newEndpoints.set(`${owner.key}|${peerEndpoint}`, { programKey: program.key, endpoint: peerEndpoint });
      const guard = state.guards.find(item => item.programKey === program.key);
      if (guard && !guard.peers.includes(peerEndpoint)) emit("guard-drift", { endpoint: peerEndpoint, frozenAt: guard.frozenAt, baselinePeers: guard.peers.length, protocol: "TCP", scope: "observed-peer-baseline", action: "observation-only" }, program.key, peerEndpoint);
    }
  }
  // Losing or regaining process-start visibility changes identity keys without
  // proving a new connection. Discard that program's timing continuity.
  const identityChanges = new Set([...programs.values()].filter(program => {
    const old = oldPrograms.get(program.key);
    return comparable && old && old.identityMode !== program.identityMode;
  }).map(program => program.key));
  for (const [key, pattern] of patterns) if (identityChanges.has(pattern.programKey)) patterns.delete(key);
  for (const [key, appearance] of newEndpoints) if (identityChanges.has(appearance.programKey)) newEndpoints.delete(key);
  for (const [key, listener] of listeners) {
    if (identityChanges.has(listener.programKey)) { knownListeners.add(key); continue; }
    if (knownListeners.has(key)) continue;
    const old = comparable ? previous.listenerStreaks[key] : undefined;
    const count = old ? old.count + 1 : 1;
    if (count >= 2 && old && at - old.at >= 1000) {
      emit("new-listener", { endpoint: listener.endpoint, consecutiveObservations: count, observedForMs: at - old.at, protocol: "TCP", scope: "local-listener" }, listener.programKey, listener.endpoint);
      knownListeners.add(key);
    } else if (Object.keys(state.listenerStreaks).length < TELEMETRY_LIMITS.peers) {
      state.listenerStreaks[key] = { ...listener, at: old?.at ?? at, count };
    } else state.quality.retentionLimited = true;
  }
  for (const [key, data] of newEndpoints) {
    let pattern = patterns.get(key);
    if (!pattern) {
      if (patterns.size >= TELEMETRY_LIMITS.patterns) { state.quality.retentionLimited = true; continue; }
      pattern = { key, ...data, lastSeenAt: at, appearances: [] };
      patterns.set(key, pattern);
    }
    pattern.lastSeenAt = at;
    pattern.appearances = [...pattern.appearances.filter(time => time >= at - TELEMETRY_LIMITS.windowMs), at].slice(-12);
    if (pattern.appearances.length >= 6) {
      const times = pattern.appearances.slice(-6);
      const intervals = times.slice(1).map((time, index) => time - times[index]);
      const typical = median(intervals);
      // Periods must exceed sampling resolution; repeated snapshots of a persistent socket never enter this path.
      const sampling = median(state.samples.slice(-12).map(sample => sample.durationMs ?? 0).filter(ms => ms > 0));
      const tolerance = Math.max(typical * 0.2, Number.isFinite(sampling) ? sampling : 0);
      if (Number.isFinite(sampling) && typical >= sampling * 3 && Math.max(...intervals) - Math.min(...intervals) <= tolerance) {
        emit("regular-reconnect", { endpoint: data.endpoint, intervals: intervals.length, typicalIntervalMs: typical, intervalSpreadMs: Math.max(...intervals) - Math.min(...intervals), sampleIntervalMs: sampling, scope: "new-socket-appearances", identityMode: programs.get(data.programKey)?.identityMode ?? "unresolved" }, data.programKey, data.endpoint);
      }
    }
  }
  state.peers = [...peers.values()].slice(-TELEMETRY_LIMITS.peers);
  state.patterns = [...patterns.values()].slice(-TELEMETRY_LIMITS.patterns);
  for (const program of programs.values()) {
    const programPeers = state.peers.filter(peer => peer.programKey === program.key);
    program.tcpPeers = programPeers.map(peer => peer.endpoint);
    const fanout = programPeers.filter(peer => peer.firstSeenAt > at - FANOUT_WINDOW_MS && peer.firstSeenAt > program.firstSeenAt);
    if (comparable && program.sampleCount >= 3 && at - program.firstSeenAt >= 10_000 && fanout.length >= 12) {
      emit("peer-fanout", { distinctNewPeers: fanout.length, windowMs: FANOUT_WINDOW_MS, scope: "tcp-endpoints", observationSamples: program.sampleCount }, program.key);
    }
  }
  // SYN states alone are not proof of a scan or failed packets. Require sustained growth against a warmed baseline.
  if (state.synBaseline.length >= 3) {
    const baseline = median(state.synBaseline);
    const prior = state.synBaseline.at(-1) ?? 0;
    if (synCount >= 8 && synCount > Math.max(4, baseline * 3) && prior >= 8) emit("syn-pressure", { currentSynSockets: synCount, previousSynSockets: prior, baselineSynSockets: baseline, baselineSamples: state.synBaseline.length, scope: "host-socket-states" });
  }
  state.synBaseline = [...state.synBaseline, synCount].slice(-30);
  state.programs = [...programs.values(), ...previous.programs.filter(program => !programs.has(program.key) && program.lastSeenAt >= at - TELEMETRY_LIMITS.windowMs).map(program => ({ ...program, ...(gap ? { sampleCount: 0, tcpPeers: [] } : {}), currentSockets: 0, listenerCount: 0, synCount: 0 }))].slice(0, TELEMETRY_LIMITS.programs);
  state.previousSockets = [...seenTuples].slice(0, TELEMETRY_LIMITS.sockets);
  if (knownListeners.size > TELEMETRY_LIMITS.sockets) state.quality.retentionLimited = true;
  state.knownListeners = [...knownListeners].slice(-TELEMETRY_LIMITS.sockets);
  state.samples.push({ at, durationMs: comparable ? durationMs : null, captureDurationMs: Number.isFinite(snapshot.captureDurationMs) ? snapshot.captureDurationMs! : null, rx: validRates ? rates.rx : null, tx: validRates ? rates.tx : null, sockets: snapshot.sockets.length, tcp: snapshot.tcpInuse, udp: snapshot.udpInuse, listeners: listenerCount, syn: synCount, newSockets: comparable && identityChanges.size === 0 ? newSockets : null });
  state.samples = state.samples.slice(-TELEMETRY_LIMITS.samples);
  state.events = state.events.slice(-TELEMETRY_LIMITS.events);
  state.quality.warmupSamples = state.rateBaseline.length;
  state.quality.status = state.rateBaseline.length >= TELEMETRY_LIMITS.warmup ? "ready" : "warming";
  if (!validRates && !state.quality.reason) state.quality.reason = snapshot.trafficError || "Waiting for comparable interface counter samples";
  return state;
}

export function guardEligibility(state: TelemetryState, programKey: string): GuardResult {
  const program = state.programs.find(item => item.key === programKey);
  if (!program || !hasExecutable(program.exe)) return { ok: false, error: "resolved-executable-required" };
  const now = state.quality.lastSnapshotAt;
  if (now === null || state.quality.status === "unavailable" || state.quality.status === "not-native" || !program.currentSockets || now - program.lastSeenAt > TELEMETRY_LIMITS.gapMs) return { ok: false, error: "current-observation-required" };
  if (program.sampleCount < 3 || program.lastSeenAt - program.firstSeenAt < 10_000) return { ok: false, error: "need-three-observations-over-ten-seconds" };
  if (!program.tcpPeers.length) return { ok: false, error: "tcp-peer-required" };
  if (state.quality.retentionLimited) return { ok: false, error: "observation-capacity-reached-reset-session" };
  if (!state.guards.some(guard => guard.programKey === programKey) && state.guards.length >= TELEMETRY_LIMITS.guards) return { ok: false, error: "guard-capacity-reached" };
  return { ok: true };
}

export function freezeTelemetryGuard(state: TelemetryState, programKey: string): { state: TelemetryState; result: GuardResult } {
  const result = guardEligibility(state, programKey);
  if (!result.ok) return { state, result };
  const program = state.programs.find(item => item.key === programKey)!;
  const guard: DriftGuard = { programKey, exe: program.exe, frozenAt: state.quality.lastSnapshotAt!, peers: [...program.tcpPeers], observationCount: program.sampleCount, observedSince: program.firstSeenAt };
  return { state: { ...state, guards: [...state.guards.filter(item => item.programKey !== programKey), guard] }, result };
}

export function acknowledgeTelemetryEvent(state: TelemetryState, id: string, at = Date.now()): TelemetryState {
  return { ...state, events: state.events.map(event => event.id === id && event.acknowledgedAt === null ? { ...event, acknowledgedAt: at } : event) };
}
