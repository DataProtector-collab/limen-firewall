import { APP_BY_ID, APPS, SYSTEM_APP_IDS, destinationsFor, randomOf } from "./catalog";
import { getKernelSnapshot, type KernelSnapshot } from "./kernel";
import { getNativeBridge } from "./native-types";
import { interfaceRates, kernelApp, sockToConn } from "./snapshot";
import { useFirewall } from "./store";
import type { AppInfo, Connection, Protocol } from "./types";

let session = 0;
let started = false;
let pollTimer: ReturnType<typeof setTimeout> | undefined;
let labTimer: ReturnType<typeof setInterval> | undefined;
let previousSnapshot: KernelSnapshot | undefined;
let lastNativeRefresh = 0;

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
    previousSnapshot = undefined;
    state.mergeKernelConnections([]);
    state.setKernelStats({ rx: 0, tx: 0, tcp: 0, udp: 0, apps: [], live: false });
    useFirewall.setState({ captureError: snapshot.error ?? "Live capture is unavailable." });
    return;
  }
  if (previousSnapshot && snapshot.at <= previousSnapshot.at) return;
  const rates = interfaceRates(snapshot, previousSnapshot);
  previousSnapshot = snapshot;
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
  state.setKernelStats({ ...rates, tcp: snapshot.tcpInuse, udp: snapshot.udpInuse, apps: [...apps.values()], live: true });
  useFirewall.setState({ captureError: null });
  state.pushSample({ t: snapshot.at, in: rates.rx, out: rates.tx, blocked: 0 });
}

async function pollKernel(currentSession: number): Promise<void> {
  if (!started || currentSession !== session) return;
  const settings = useFirewall.getState().settings;
  if (!settings.kernelCapture || settings.labTraffic || !getNativeBridge()) {
    previousSnapshot = undefined;
    if (useFirewall.getState().kernelLive) {
      useFirewall.getState().mergeKernelConnections([]);
      useFirewall.getState().setKernelStats({ rx: 0, tx: 0, tcp: 0, udp: 0, apps: [], live: false });
    }
  } else {
    try {
      const snapshot = await getKernelSnapshot();
      if (!started || currentSession !== session) return;
      if (useFirewall.getState().settings !== settings) previousSnapshot = undefined;
      else applySnapshot(snapshot);
    } catch (error) {
      if (!started || currentSession !== session) return;
      previousSnapshot = undefined;
      if (useFirewall.getState().settings === settings) {
        const state = useFirewall.getState();
        state.mergeKernelConnections([]);
        state.setKernelStats({ rx: 0, tx: 0, tcp: 0, udp: 0, apps: [], live: false });
        useFirewall.setState({ captureError: error instanceof Error ? error.message : String(error) });
      }
    }
  }
  if (started && currentSession === session) {
    if (Date.now() - lastNativeRefresh > 15000) {
      lastNativeRefresh = Date.now();
      void useFirewall.getState().refreshNative();
    }
    // Schedule after completion; expensive OS calls can never overlap.
    pollTimer = setTimeout(() => { void pollKernel(currentSession); }, 2000);
  }
}

function stopEngine() {
  session += 1;
  started = false;
  clearTimeout(pollTimer);
  clearInterval(labTimer);
  pollTimer = undefined;
  labTimer = undefined;
  previousSnapshot = undefined;
  lastNativeRefresh = 0;
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
  lastNativeRefresh = 0;
  if (initial) applyInitialSnapshot(initial);
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
