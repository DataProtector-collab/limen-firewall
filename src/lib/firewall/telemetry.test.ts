import assert from "node:assert/strict";
import test from "node:test";
import type { KernelSnapshot, KernelSocket } from "./kernel-types";
import { acknowledgeTelemetryEvent, createTelemetryState, freezeTelemetryGuard, guardEligibility, ingestTelemetryState, TELEMETRY_LIMITS, unavailableTelemetry } from "./telemetry";
import type { TelemetryState } from "./telemetry-types";

const socket: KernelSocket = {
  id: "native-tcp", proto: "TCP", family: 4, localIp: "192.0.2.10", localPort: 52000,
  remoteIp: "198.51.100.4", remotePort: 443, state: "ESTABLISHED", inode: "", pid: 42,
  comm: "example.exe", exe: "C:\\Apps\\Example.exe", uid: 0,
};
const rates = { rx: 1000, tx: 1000 };
function snapshot(at: number, sockets: KernelSocket[] = [socket], overrides: Partial<KernelSnapshot> = {}): KernelSnapshot {
  return { at, sockets, capture: "windows", platform: "win32", available: true, rxBytes: at * 100, txBytes: at * 100, tcpInuse: sockets.filter(item => item.proto === "TCP").length, udpInuse: sockets.filter(item => item.proto === "UDP").length, trafficAvailable: true, counterSource: "dotnet:adapter-a", captureDurationMs: 100, ...overrides };
}
function step(state: TelemetryState, at: number, sockets: KernelSocket[] = [socket], nextRates = rates): TelemetryState {
  return ingestTelemetryState(state, snapshot(at, sockets), nextRates);
}
function warm(): TelemetryState {
  let state = createTelemetryState();
  for (let i = 0; i < 13; i++) state = step(state, 1000 + i * 2000);
  return state;
}

test("native recorder excludes lab and never fabricates the first rate or direction", () => {
  const initial = createTelemetryState();
  assert.equal(ingestTelemetryState(initial, snapshot(1000, [socket], { capture: "linux", platform: "linux" }), rates).samples.length, 0);
  const first = step(initial, 1000);
  assert.equal(first.samples[0].rx, null);
  assert.equal(first.samples[0].newSockets, null);
  assert.equal(first.programs[0].identityMode, "executable-group");
  assert.equal("bytesIn" in first.programs[0], false);
  assert.equal("direction" in first.programs[0], false);
  assert.equal(first.events.length, 0);
});

test("host bursts need a warmed robust baseline and an absolute floor", () => {
  let state = createTelemetryState();
  for (let i = 0; i < 12; i++) state = step(state, 1000 + i * 2000, [], { rx: 0, tx: 0 });
  assert.equal(state.quality.warmupSamples, 11);
  state = step(state, 25000, [], { rx: 900_000, tx: 200_000 });
  assert.equal(state.events.length, 0);
  state = step(state, 27000, [], { rx: 2_000_000, tx: 800_000 });
  assert.deepEqual(state.events.map(event => event.kind), ["rx-burst", "tx-burst"]);
  assert.equal(state.events[0].evidence.scope, "host-interfaces");
  assert.equal(state.events[0].programKey, undefined);
  const acknowledged = acknowledgeTelemetryEvent(state, state.events[0].id, 28000);
  assert.equal(acknowledged.events[0].acknowledgedAt, 28000);
  assert.equal(state.events[0].acknowledgedAt, null, "pure transition does not mutate preceding state");
});

test("provider switches, counter resets, unavailable readings and gaps restart host warmup", () => {
  const initial = warm();
  for (const changed of [
    snapshot(27000, [], { counterSource: "dotnet:adapter-b" }),
    snapshot(27000, [], { rxBytes: 1, txBytes: 1 }),
    snapshot(27000, [], { trafficAvailable: false }),
    snapshot(45000, []),
  ]) {
    const next = ingestTelemetryState(initial, changed, { rx: 9_000_000, tx: 9_000_000 });
    assert.equal(next.quality.warmupSamples, 0);
    assert.equal(next.samples.at(-1)?.rx, null);
    assert.equal(next.events.length, 0);
  }
  const unavailable = unavailableTelemetry(initial, "paused");
  assert.equal(unavailable.quality.status, "unavailable");
  assert.equal(step(unavailable, 27000).quality.warmupSamples, 0);
  assert.equal(ingestTelemetryState(initial, snapshot(24000), rates).quality.status, "unavailable");
});

test("persistent TCP sockets and state changes are not periodic reconnects", () => {
  let state = createTelemetryState();
  for (let i = 0; i < 80; i++) state = step(state, 1000 + i * 2000, [{ ...socket, state: i % 2 ? "ESTABLISHED" : "SYN_SENT", id: `volatile-native-id-${i}` }]);
  assert.equal(state.patterns.length, 0);
  assert.equal(state.events.some(event => event.kind === "regular-reconnect"), false);
  assert.equal(state.samples.slice(1).every(sample => sample.newSockets === 0), true);
});

test("regular reconnect detection requires six observed appearances beyond sampling resolution", () => {
  let state = createTelemetryState();
  for (let i = 0; i <= 20; i++) {
    const current = i % 3 === 1 ? [{ ...socket, localPort: 52000 + i }] : [];
    state = step(state, 1000 + i * 2000, current);
  }
  const alert = state.events.find(event => event.kind === "regular-reconnect");
  assert.ok(alert);
  assert.equal(alert.evidence.intervals, 5);
  assert.equal(alert.evidence.typicalIntervalMs, 6000);
  assert.equal(alert.evidence.identityMode, "executable-group");
  const resumed = step(state, 100000, [{ ...socket, localPort: 60000 }]);
  assert.equal(resumed.patterns.length, 0, "capture gap discards timing continuity");
});

test("process start identity prevents PID reuse from forming one reconnect sequence", () => {
  let state = createTelemetryState();
  for (let i = 0; i <= 20; i++) {
    const current = i % 3 === 1 ? [{ ...socket, localPort: 52000 + i, processStartedAt: 100000 + i * 1000 }] : [];
    state = step(state, 1000 + i * 2000, current);
  }
  assert.equal(state.events.some(event => event.kind === "regular-reconnect"), false);
  assert.ok(state.patterns.length >= 6);
});

test("intermittent process-start visibility cannot turn a persistent connection into a timing pattern", () => {
  let state = createTelemetryState();
  for (let i = 0; i < 30; i++) state = step(state, 1000 + i * 2000, [{ ...socket, processStartedAt: i % 3 === 0 ? undefined : 100 }]);
  assert.equal(state.events.some(event => event.kind === "regular-reconnect"), false);
  assert.equal(state.patterns.length, 0);
  assert.ok(state.samples.some(sample => sample.newSockets === null));
});

test("a program absent during the first resumed capture must earn fresh guard observations", () => {
  let state = step(createTelemetryState(), 1000);
  state = step(state, 6000);
  state = step(state, 11000);
  const key = state.programs[0].key;
  assert.equal(guardEligibility(state, key).ok, true);
  state = unavailableTelemetry(state, "paused");
  state = step(state, 16000, []);
  state = step(state, 21000);
  assert.equal(state.programs[0].sampleCount, 1);
  assert.equal(state.programs[0].firstSeenAt, 21000);
  assert.equal(guardEligibility(state, key).ok, false);
  state = step(state, 26000);
  assert.equal(guardEligibility(state, key).ok, false);
  state = step(state, 31000);
  assert.equal(guardEligibility(state, key).ok, true);
});

test("Drift Guard freezes explicit TCP evidence and flags new peers without learning or blocking", () => {
  let state = step(createTelemetryState(), 1000);
  const key = state.programs[0].key;
  assert.equal(guardEligibility(state, key).ok, false);
  state = step(state, 6000);
  assert.equal(guardEligibility(state, key).ok, false);
  state = step(state, 11000);
  const frozen = freezeTelemetryGuard(state, key);
  assert.equal(frozen.result.ok, true);
  assert.deepEqual(frozen.state.guards[0].peers, ["198.51.100.4:443"]);
  state = step(frozen.state, 16000, [socket, { ...socket, localPort: 53000, remoteIp: "10.0.2.3", remotePort: 80 }]);
  const alert = state.events.find(event => event.kind === "guard-drift");
  assert.ok(alert);
  assert.equal(alert.evidence.endpoint, "10.0.2.3:80");
  assert.equal(alert.evidence.action, "observation-only");
  assert.deepEqual(state.guards[0].peers, ["198.51.100.4:443"], "frozen baseline never silently learns a drift");
  assert.equal(state.programs[0].currentSockets, 2, "observation does not edit or block sockets");
  const paused = unavailableTelemetry(state, "paused");
  assert.equal(guardEligibility(paused, key).ok, false);
  assert.equal(paused.guards.length, 1);
});

test("guards exclude UDP, wildcard listeners and TIME_WAIT; unknown executables cannot freeze", () => {
  for (const candidate of [
    { ...socket, proto: "UDP" as const },
    { ...socket, state: "LISTEN", remoteIp: "0.0.0.0", remotePort: 0 },
    { ...socket, state: "TIME_WAIT" },
    { ...socket, exe: "" },
  ]) {
    let state = createTelemetryState();
    for (const at of [1000, 6000, 11000]) state = step(state, at, [candidate]);
    assert.equal(freezeTelemetryGuard(state, state.programs[0].key).result.ok, false);
  }
});

test("new listener requires two observations; initial listeners and transient SYNs are not alerts", () => {
  const listener = { ...socket, state: "LISTEN", remoteIp: "0.0.0.0", remotePort: 0, localPort: 8000 };
  let state = step(createTelemetryState(), 1000, [listener]);
  state = step(state, 3000, [listener]);
  assert.equal(state.events.length, 0);
  const second = { ...listener, localPort: 9000 };
  state = step(state, 5000, [listener, second]);
  assert.equal(state.events.length, 0);
  state = step(state, 7000, [listener, second]);
  assert.equal(state.events.filter(event => event.kind === "new-listener").length, 1);
  const syns = Array.from({ length: 10 }, (_, i) => ({ ...socket, state: "SYN_SENT", localPort: 55000 + i }));
  state = step(state, 9000, syns);
  assert.equal(state.events.some(event => event.kind === "syn-pressure"), false);
  state = step(state, 11000, syns);
  assert.equal(state.events.some(event => event.kind === "syn-pressure"), true);
});

test("peer fanout excludes an already-present first snapshot and needs later observations", () => {
  const peers = Array.from({ length: 15 }, (_, i) => ({ ...socket, remoteIp: `198.51.100.${i + 10}`, localPort: 54000 + i }));
  let state = step(createTelemetryState(), 1000, peers);
  state = step(state, 6000, peers);
  state = step(state, 11000, peers);
  assert.equal(state.events.some(event => event.kind === "peer-fanout"), false);
  state = step(state, 16000, [...peers, ...peers.map((item, i) => ({ ...item, remoteIp: `203.0.113.${i + 10}`, localPort: item.localPort + 200 }))]);
  assert.equal(state.events.some(event => event.kind === "peer-fanout"), true);
});

test("recorder, programs, peers, patterns, cooldowns and events have hard bounds", () => {
  const many = Array.from({ length: 300 }, (_, i) => ({ ...socket, exe: `C:\\Apps\\Example-${i}.exe`, localPort: 52000 + i, remoteIp: `198.51.${Math.floor(i / 250)}.${i % 250 + 1}` }));
  let state = createTelemetryState();
  for (let i = 0; i < 650; i++) state = step(state, 1000 + i * 1000, many);
  assert.ok(state.samples.length <= TELEMETRY_LIMITS.samples);
  assert.ok(state.samples.every(sample => sample.at >= state.quality.lastSnapshotAt! - TELEMETRY_LIMITS.windowMs));
  assert.ok(state.programs.length <= TELEMETRY_LIMITS.programs);
  assert.ok(state.peers.length <= TELEMETRY_LIMITS.peers);
  assert.ok(state.patterns.length <= TELEMETRY_LIMITS.patterns);
  assert.ok(state.events.length <= TELEMETRY_LIMITS.events);
  assert.ok(Object.keys(state.cooldowns).length <= TELEMETRY_LIMITS.events);
  assert.equal(state.quality.retentionLimited, true);
  assert.equal(guardEligibility(state, state.programs[0].key).error, "observation-capacity-reached-reset-session");
});

test("a flood of distinct observed peers cannot grow guard events or timing patterns without bound", () => {
  let state = step(createTelemetryState(), 1000);
  state = step(state, 6000);
  state = step(state, 11000);
  state = freezeTelemetryGuard(state, state.programs[0].key).state;
  const flood = Array.from({ length: 400 }, (_, i) => ({ ...socket, localPort: 53000 + i, remoteIp: `203.0.${Math.floor(i / 250)}.${i % 250 + 1}` }));
  state = step(state, 16000, flood);
  assert.equal(state.events.length, TELEMETRY_LIMITS.events);
  assert.equal(state.events.every(event => event.kind === "guard-drift" || event.kind === "peer-fanout"), true);
  assert.equal(state.patterns.length, TELEMETRY_LIMITS.patterns);
  assert.equal(Object.keys(state.cooldowns).length, TELEMETRY_LIMITS.events);
  assert.equal(state.guards[0].peers.length, 1, "even a peer flood cannot change the explicitly frozen baseline");
});
