import { APP_BY_ID, APPS, SYSTEM_APP_IDS, destinationsFor, randomOf } from "./catalog";
import { getKernelSnapshot, type KernelSnapshot } from "./kernel";
import { getNativeBridge } from "./native-types";
import { hasInterfaceCounters, interfaceRates, kernelApp, sockToConn } from "./snapshot";
import { useFirewall } from "./store";
import type { AppInfo, Connection, Protocol } from "./types";

let session = 0;
let started = false;
let pollTimer: ReturnType<typeof setTimeout> | undefined;
let labTimer: ReturnType<typeof setInterval> | undefined;
let freshnessTimer: ReturnType<typeof setTimeout> | undefined;
let nativeTimer: ReturnType<typeof setInterval> | undefined;
let unsubscribeCapture: (() => void) | undefined;
let captureRevision = 0;
let pollInFlight = false;
let previousSnapshot: KernelSnapshot | undefined;
const CAPTURE_STALE_MS = 15000;

function watchCaptureFreshness() {
  clearTimeout(freshnessTimer);
  const currentSession = session;
  freshnessTimer = setTimeout(() => {
    freshnessTimer = undefined;
    const state = useFirewall.getState();
    if (!started || session !== currentSession || !state.settings.kernelCapture || state.settings.labTraffic) return;
    previousSnapshot = undefined;
    // Retain the last observed rows and timestamp, but never label old data live.
    useFirewall.setState({ kernelLive: false, kernelTrafficReady: false, captureStale: true,
      kernelRx: 0, kernelTx: 0, samples: [] });
  }, CAPTURE_STALE_MS);
}

function captureUnavailable(error: string) {
  clearTimeout(freshnessTimer);
  freshnessTimer = undefined;
  previousSnapshot = undefined;
  const state = useFirewall.getState();
  state.mergeKernelConnections([]);
  state.setKernelStats({ rx: 0, tx: 0, tcp: 0, udp: 0, apps: [], live: false });
  useFirewall.setState({ captureError: error, kernelTrafficReady: false, captureStale: false, trafficError: null, samples: [] });
}

function buildConnection(appId: string, inbound: boolean): Connection {
  const dest = randomOf(destinationsFor(appId));
  const ephemeral = 49152 + Math.floor(Math.random() * 16000);
  return {
    id: `lab-${crypto.randomUUID()}`, appId, protocol: dest.protocol,
    direction: inbound ? "in" : "out", localIp: "192.0.2.10",
    localPort: inbound ? dest.port : ephemeral, remoteHost: dest.host,
    remoteIp: dest.ip, remotePort: inbound ? ephemeral : dest.port,
    country: dest.country, state: "syn", bytesIn: 0, bytesOut: 0,
    rateIn: 0, rateOut: 0, startedAt: Date.now(), source: "lab", trafficMeasured: false,
  };
}

function applyLabConnection(conn: Connection) {
  const state = useFirewall.getState();
  if (!state.settings.labTraffic || conn.source !== "lab") return;
  const action = state.matchAction(conn);
  if (action === null) { state.enqueuePending(conn); return; }
  state.upsertConnection({ ...conn, state: action === "block" ? "blocked" : "established" });
  state.pushLog({ appId: conn.appId, protocol: conn.protocol, host: conn.remoteHost, ip: conn.remoteIp, port: conn.remotePort, direction: conn.direction, action, reason: "lab · rule" });
  useFirewall.setState((current) => ({ blockedCount: current.blockedCount + Number(action === "block"), allowedCount: current.allowedCount + Number(action === "allow") }));
}

export function applySnapshot(snapshot: KernelSnapshot): void {
  const state = useFirewall.getState();
  if (!snapshot.available || snapshot.capture === "unavailable") {
    captureUnavailable(snapshot.error ?? "Live capture is unavailable.");
    return;
  }
  if (!Number.isFinite(snapshot.at) || snapshot.at < 0) {
    captureUnavailable("Windows capture returned an invalid measurement time.");
    return;
  }
  if (state.kernelLastSnapshotAt !== null && snapshot.at <= state.kernelLastSnapshotAt) return;
  const countersAvailable = hasInterfaceCounters(snapshot);
  const rates = interfaceRates(snapshot, state.kernelLastSnapshotAt === null ? undefined : previousSnapshot);
  previousSnapshot = countersAvailable ? snapshot : undefined;
  const previous = new Map(state.connections.filter((c) => c.source === "kernel").map((c) => [c.id, c]));
  const apps = new Map<string, AppInfo>();
  const connections = snapshot.sockets.map((sock) => {
    const app = kernelApp(sock);
    apps.set(app.id, app);
    return sockToConn(sock, previous.get(sock.id));
  });
  // Observing a socket does not authorize, pause, or block it. Only Windows
  // Firewall applies native rules; the socket state remains exactly observed.
  state.mergeKernelConnections(connections);
  state.setKernelStats({ ...(rates ?? { rx: 0, tx: 0 }), tcp: snapshot.tcpInuse, udp: snapshot.udpInuse, apps: [...apps.values()], live: true });
  useFirewall.setState({ captureError: null, kernelLastSnapshotAt: snapshot.at, kernelTrafficReady: rates !== null,
    captureStale: false, trafficError: countersAvailable ? null : (snapshot.trafficError ?? "Windows adapter traffic counters are unavailable."),
    ...(rates ? {} : { samples: [] }) });
  if (rates) state.pushSample({ t: snapshot.at, in: rates.rx, out: rates.tx, blocked: 0 });
  if (started) watchCaptureFreshness();
}

async function pollKernel(currentSession: number): Promise<void> {
  if (!started || currentSession !== session || pollInFlight) return;
  const settings = useFirewall.getState().settings;
  const currentCapture = captureRevision;
  if (!settings.kernelCapture || settings.labTraffic || !getNativeBridge()) {
    previousSnapshot = undefined;
    if (useFirewall.getState().kernelLive) {
      useFirewall.getState().mergeKernelConnections([]);
      useFirewall.getState().setKernelStats({ rx: 0, tx: 0, tcp: 0, udp: 0, apps: [], live: false });
    }
  } else {
    pollInFlight = true;
    useFirewall.setState({ capturePending: true });
    if (!freshnessTimer) watchCaptureFreshness();
    try {
      const snapshot = await getKernelSnapshot();
      if (!started || currentSession !== session) return;
      if (captureRevision !== currentCapture) previousSnapshot = undefined;
      else applySnapshot(snapshot);
    } catch (error) {
      if (!started || currentSession !== session) return;
      if (captureRevision === currentCapture) {
        captureUnavailable(error instanceof Error ? error.message : String(error));
      }
    } finally {
      if (started && currentSession === session) {
        pollInFlight = false;
        useFirewall.setState({ capturePending: false });
      }
    }
  }
  if (started && currentSession === session) {
    // Schedule after completion; expensive OS calls can never overlap.
    pollTimer = setTimeout(() => { void pollKernel(currentSession); }, 2000);
  }
}

function stopEngine() {
  session += 1;
  started = false;
  clearTimeout(pollTimer);
  clearInterval(labTimer);
  clearTimeout(freshnessTimer);
  clearInterval(nativeTimer);
  unsubscribeCapture?.();
  pollTimer = undefined;
  labTimer = undefined;
  freshnessTimer = undefined;
  nativeTimer = undefined;
  unsubscribeCapture = undefined;
  pollInFlight = false;
  previousSnapshot = undefined;
  useFirewall.setState({ capturePending: false, kernelLive: false, kernelTrafficReady: false, captureStale: false, samples: [] });
}

export function applyInitialSnapshot(snapshot: KernelSnapshot) {
  if (getNativeBridge() && useFirewall.getState().settings.kernelCapture) applySnapshot(snapshot);
}

export function startEngine(initial?: KernelSnapshot | null) {
  if (typeof window === "undefined") return () => {};
  if (started) return () => {};
  if (!useFirewall.getState().hydrated) useFirewall.getState().hydrate();
  started = true;
  const currentSession = ++session;
  previousSnapshot = undefined;
  unsubscribeCapture = useFirewall.subscribe((state, previous) => {
    if (state.settings.kernelCapture === previous.settings.kernelCapture && state.settings.labTraffic === previous.settings.labTraffic) return;
    captureRevision++;
    previousSnapshot = undefined;
    clearTimeout(freshnessTimer);
    freshnessTimer = undefined;
    if (state.settings.kernelCapture && !state.settings.labTraffic && getNativeBridge()) {
      if (pollInFlight) {
        useFirewall.setState({ capturePending: true });
        watchCaptureFreshness();
      } else {
        clearTimeout(pollTimer);
        void pollKernel(currentSession);
      }
    }
  });
  if (initial) applyInitialSnapshot(initial);
  // Rule/status reads must remain available even while socket capture is slow.
  void useFirewall.getState().refreshNative();
  nativeTimer = setInterval(() => { void useFirewall.getState().refreshNative(); }, 15000);
  void pollKernel(currentSession);
  let nextLabPrompt = Date.now() + 1500;
  labTimer = setInterval(() => {
    const state = useFirewall.getState();
    if (!state.settings.labTraffic) { nextLabPrompt = Date.now() + 1500; return; }
    state.tickConnections(Date.now());
    if (!state.pending.length && Date.now() >= nextLabPrompt) {
      simulateConnection();
      nextLabPrompt = Date.now() + 8000;
    }
    const live = useFirewall.getState().connections.filter((c) => c.source === "lab" && c.state === "established");
    state.pushSample({ t: Date.now(), in: live.reduce((sum, c) => sum + c.rateIn, 0), out: live.reduce((sum, c) => sum + c.rateOut, 0), blocked: state.blockedCount });
  }, 500);
  return () => { if (currentSession === session) stopEngine(); };
}

export function simulateConnection(appId?: string, inbound = false) {
  const state = useFirewall.getState();
  if (!state.settings.labTraffic) return;
  if (appId && !APP_BY_ID[appId]) return;
  const candidates = APPS.filter((app) => !SYSTEM_APP_IDS.has(app.id));
  const undecided = candidates.filter((app) => !state.rules.some((r) => r.appId === app.id && r.scope === "app" && r.enabled));
  const selected = appId ?? randomOf(undecided.length ? undecided : candidates).id;
  applyLabConnection(buildConnection(selected, inbound));
}

export function appById(id: string) {
  return useFirewall.getState().kernelApps.find((app) => app.id === id) ?? APP_BY_ID[id];
}

export function protocolColor(protocol: Protocol): string {
  switch (protocol) {
    case "HTTPS": case "TLS": return "text-allow";
    case "HTTP": case "FTP": case "ICMP": return "text-warn";
    case "DNS": case "NTP": case "MDNS": return "text-info";
    case "UDP": case "QUIC": case "SSDP": return "text-accent";
    case "RDP": case "SMB": return "text-block";
    default: return "text-muted";
  }
}

if (import.meta.hot) import.meta.hot.dispose(stopEngine);
