import {
  APP_BY_ID,
  APPS,
  DESTINATIONS,
  INBOUND_APPS,
  PROMPT_APPS,
  SYSTEM_APP_IDS,
  destinationsFor,
  randomOf,
} from "./catalog";
import { getKernelSnapshot, type KernelSnapshot, type KernelSocket } from "./kernel";
import { useFirewall } from "./store";
import type { AppInfo, ConnState, Connection, Protocol } from "./types";

function uid(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}

function localPort(): number {
  return 49152 + Math.floor(Math.random() * 15000);
}

function inferProtocol(sock: KernelSocket): Protocol {
  const p = sock.remotePort || sock.localPort;
  if (sock.proto === "UDP") {
    if (p === 53 || p === 5353) return p === 5353 ? "MDNS" : "DNS";
    if (p === 123) return "NTP";
    if (p === 443) return "QUIC";
    if (p === 1900) return "SSDP";
    return "UDP";
  }
  if (p === 443) return "HTTPS";
  if (p === 80) return "HTTP";
  if (p === 53) return "DNS";
  if (p === 22 || p === 3389) return "RDP";
  if (p === 445) return "SMB";
  if (p === 21) return "FTP";
  return "TCP";
}

function appIdForKernel(sock: KernelSocket): string {
  const exe = sock.exe || sock.comm || "unknown";
  const base = exe.split("/").pop() || sock.comm || "proc";
  return `k-${base.replace(/[^a-zA-Z0-9._-]+/g, "-")}-${sock.pid ?? "x"}`;
}

function kernelApp(sock: KernelSocket): AppInfo {
  const exe = sock.exe || sock.comm;
  const name = (exe.split("/").pop() || sock.comm || "process").replace(/\.exe$/i, "");
  return {
    id: appIdForKernel(sock),
    name,
    exe: name,
    publisher: exe.startsWith("/") ? "local" : "unknown",
    signed: true,
    pid: sock.pid ?? 0,
    category: isTrustedExe(exe) ? "system" : "util",
    path: exe,
  };
}

export function isTrustedExe(exe: string): boolean {
  const s = exe.toLowerCase();
  return (
    s.includes("preview-proxy") ||
    s.includes("workspace-server") ||
    s.endsWith("/node") ||
    s.includes("/usr/bin/node") ||
    s.includes("vite") ||
    s === "kernel" ||
    s.endsWith("/limen") ||
    s.endsWith("/aegis")
  );
}

function isUnspecified(ip: string): boolean {
  return (
    ip === "0.0.0.0" ||
    ip === "::" ||
    ip === "::0" ||
    ip === "https://example.net/id/garnet"
  );
}

function isLoopback(ip: string): boolean {
  const s = ip.toLowerCase();
  return (
    s === "127.0.0.1" ||
    s === "::1" ||
    s.startsWith("127.") ||
    s === "localhost" ||
    s === "https://example.net/id/garnet"
  );
}

function buildConnection(
  appId: string,
  opts?: { inbound?: boolean; destIndex?: number; host?: string },
): Connection {
  const dests = destinationsFor(appId);
  let dest = dests[0]!;
  if (opts?.host) {
    dest = dests.find((d) => d.host === opts.host) ?? dest;
  } else if (opts?.destIndex != null) {
    dest = dests[opts.destIndex % dests.length] ?? dest;
  } else {
    dest = randomOf(dests);
  }
  const inbound = Boolean(opts?.inbound);
  return {
    id: uid("c"),
    appId,
    protocol: dest.protocol,
    direction: inbound ? "in" : "out",
    localPort: inbound ? dest.port : localPort(),
    remoteHost: dest.host,
    remoteIp: dest.ip,
    remotePort: inbound ? localPort() : dest.port,
    country: dest.country,
    state: "syn",
    bytesIn: 0,
    bytesOut: 0,
    rateIn: 0,
    rateOut: 0,
    startedAt: Date.now(),
    source: "lab",
  };
}

function applyNewConnection(conn: Connection) {
  const store = useFirewall.getState();
  const action = store.matchAction(conn);
  if (action === null) {
    store.enqueuePending(conn);
    return;
  }
  if (action === "block") {
    store.pushLog({
      appId: conn.appId,
      protocol: conn.protocol,
      host: conn.remoteHost,
      ip: conn.remoteIp,
      port: conn.remotePort,
      direction: conn.direction,
      action: "block",
      reason: "rule",
    });
    store.upsertConnection({ ...conn, state: "blocked" });
    useFirewall.setState((s) => ({ blockedCount: s.blockedCount + 1 }));
    return;
  }
  store.upsertConnection({ ...conn, state: conn.state === "listen" ? "listen" : "established" });
  useFirewall.setState((s) => ({ allowedCount: s.allowedCount + 1 }));
}

function seedBaseline() {
  const store = useFirewall.getState();
  if (store.connections.some((c) => c.source !== "kernel")) return;
  if (store.settings.kernelCapture && !store.settings.labTraffic) return;
  const seeds: Connection[] = [];
  const systemIds = ["svchost", "system", "defender", "onedrive", "search"];
  for (const id of systemIds) {
    const dests = DESTINATIONS[id] ?? [];
    const n = Math.min(dests.length, id === "svchost" ? 4 : 2);
    for (let i = 0; i < n; i++) {
      const c = buildConnection(id, { destIndex: i });
      c.state = "established";
      c.bytesIn = Math.round(8000 + Math.random() * 400000);
      c.bytesOut = Math.round(1200 + Math.random() * 80000);
      c.rateIn = Math.round(400 + Math.random() * 12000);
      c.rateOut = Math.round(80 + Math.random() * 2500);
      c.startedAt = Date.now() - Math.round(Math.random() * 120000);
      seeds.push(c);
    }
  }
  for (const c of seeds) store.upsertConnection(c);
}

let started = false;
let intervalId: number | null = null;
let kernelId: number | null = null;
let firstPromptAt = 0;
let secondPromptAt = 0;
let inboundAt = 0;
let lastUnknownAt = 0;
let ticks = 0;
let kernelPrimed = false;
let lastRx = 0;
let lastTx = 0;
let lastNicAt = 0;
const seenKernel = new Set<string>();

function sockToConn(sock: KernelSocket, prev?: Connection): Connection {
  const app = kernelApp(sock);
  const remoteUnspec = isUnspecified(sock.remoteIp);
  const listen = sock.state === "listen" || remoteUnspec;
  const inbound = listen ? "in" : sock.localPort < 49152 && sock.remotePort > 49152 ? "in" : "out";
  const state = (sock.state as ConnState) || "established";
  return {
    id: sock.id,
    appId: app.id,
    protocol: inferProtocol(sock),
    direction: inbound,
    localPort: sock.localPort,
    remoteHost: remoteUnspec ? "*" : sock.remoteIp,
    remoteIp: sock.remoteIp,
    remotePort: sock.remotePort,
    country: sock.family === 6 ? "v6" : "v4",
    state: state === "listen" ? "listen" : state,
    bytesIn: prev?.bytesIn ?? 0,
    bytesOut: prev?.bytesOut ?? 0,
    rateIn: prev?.rateIn ?? 0,
    rateOut: prev?.rateOut ?? 0,
    startedAt: prev?.startedAt ?? Date.now(),
    source: "kernel",
    inode: sock.inode,
    pid: sock.pid ?? undefined,
  };
}

function applySnapshot(snap: KernelSnapshot) {
  const store = useFirewall.getState();
  const now = Date.now();
  const dt = lastNicAt ? Math.max(0.5, (now - lastNicAt) / 1000) : 1;
  const rxRate = lastNicAt ? Math.max(0, (snap.rxBytes - lastRx) / dt) : 0;
  const txRate = lastNicAt ? Math.max(0, (snap.txBytes - lastTx) / dt) : 0;
  lastRx = snap.rxBytes;
  lastTx = snap.txBytes;
  lastNicAt = now;

  const prevById = new Map(
    store.connections.filter((c) => c.source === "kernel").map((c) => [c.id, c]),
  );
  const apps = new Map<string, AppInfo>();
  const conns: Connection[] = [];

  for (const sock of snap.sockets) {
    const app = kernelApp(sock);
    apps.set(app.id, app);
    const prev = prevById.get(sock.id);
    const conn = sockToConn(sock, prev);
    if (rxRate || txRate) {
      const share = Math.max(1, snap.sockets.length);
      conn.rateIn = rxRate / share;
      conn.rateOut = txRate / share;
      conn.bytesIn = (prev?.bytesIn ?? 0) + conn.rateIn * dt;
      conn.bytesOut = (prev?.bytesOut ?? 0) + conn.rateOut * dt;
    }
    conns.push(conn);

    const isNew = !seenKernel.has(sock.id);
    seenKernel.add(sock.id);
    if (!kernelPrimed) continue;
    if (!isNew) continue;
    if (conn.state === "listen") continue;
    if (isUnspecified(sock.remoteIp)) continue;
    if (isLoopback(sock.remoteIp)) continue;
    if (store.settings.autoAllowSystem && isTrustedExe(sock.exe)) continue;
    if (!store.settings.enabled) continue;
    applyNewConnection(conn);
  }

  kernelPrimed = true;
  store.mergeKernelConnections(conns);
  store.setKernelStats({
    rx: rxRate,
    tx: txRate,
    tcp: snap.tcpInuse,
    udp: snap.udpInuse,
    apps: [...apps.values()],
    live: true,
  });
  store.pushSample({
    t: now,
    in: rxRate,
    out: txRate,
    blocked: store.blockedCount,
  });
}

async function pollKernel() {
  const store = useFirewall.getState();
  if (!store.settings.kernelCapture) {
    store.setKernelStats({
      rx: 0,
      tx: 0,
      tcp: 0,
      udp: 0,
      apps: [],
      live: false,
    });
    return;
  }
  try {
    const snap = await getKernelSnapshot();
    applySnapshot(snap);
  } catch {
    useFirewall.getState().setKernelStats({
      rx: store.kernelRx,
      tx: store.kernelTx,
      tcp: store.kernelTcp,
      udp: store.kernelUdp,
      apps: store.kernelApps,
      live: false,
    });
  }
}

function stopEngine() {
  if (intervalId != null) window.clearInterval(intervalId);
  if (kernelId != null) window.clearInterval(kernelId);
  intervalId = null;
  kernelId = null;
  started = false;
  kernelPrimed = false;
  seenKernel.clear();
}

export function applyInitialSnapshot(snap: KernelSnapshot) {
  const store = useFirewall.getState();
  if (store.kernelLive && store.connections.some((c) => c.source === "kernel")) return;
  applySnapshot(snap);
}

export function startEngine(initial?: KernelSnapshot | null) {
  if (typeof window === "undefined") return () => {};
  const store = useFirewall.getState();
  if (!store.hydrated) store.hydrate();

  if (initial && store.settings.kernelCapture) {
    applySnapshot(initial);
  }

  if (started) return stopEngine;
  started = true;
  seedBaseline();

  firstPromptAt = Date.now() + 1400;
  secondPromptAt = Date.now() + 9000;
  inboundAt = Date.now() + 22000;
  lastUnknownAt = Date.now();

  if (!initial) void pollKernel();
  kernelId = window.setInterval(() => {
    void pollKernel();
  }, 1000);

  const tick = () => {
    ticks += 1;
    const now = Date.now();
    const s = useFirewall.getState();
    s.tickConnections(now);

    if (!s.settings.labTraffic) return;
    if (!s.settings.enabled) return;

    const pendingEmpty = s.pending.length === 0;
    const appWideAllow = s.rules.filter(
      (r) => r.enabled && r.action === "allow" && r.scope === "app",
    );
    const hostAllow = s.rules.filter(
      (r) => r.enabled && r.action === "allow" && r.scope === "app-host" && r.host,
    );

    if (now >= firstPromptAt && pendingEmpty && ticks > 1) {
      firstPromptAt = Infinity;
      const hasChrome = s.rules.some((r) => r.appId === "chrome" && r.scope === "app");
      applyNewConnection(buildConnection(hasChrome ? "discord" : "chrome", { destIndex: 0 }));
    }

    if (now >= secondPromptAt && s.pending.length === 0) {
      secondPromptAt = Infinity;
      if (!s.rules.some((r) => r.appId === "discord" && r.scope === "app")) {
        applyNewConnection(buildConnection("discord", { destIndex: 1 }));
      }
    }

    if (now >= inboundAt && s.pending.length === 0) {
      inboundAt = Infinity;
      applyNewConnection(buildConnection("rdp", { inbound: true, destIndex: 0 }));
    }

    const liveCount = s.connections.filter((c) => c.state === "established").length;
    if (liveCount < 42 && Math.random() < 0.5) {
      if (appWideAllow.length > 0 && (hostAllow.length === 0 || Math.random() < 0.75)) {
        applyNewConnection(buildConnection(randomOf(appWideAllow).appId));
      } else if (hostAllow.length > 0) {
        const rule = randomOf(hostAllow);
        applyNewConnection(buildConnection(rule.appId, { host: rule.host }));
      }
    }

    if (pendingEmpty && Math.random() < 0.012 && ticks > 30 && now - lastUnknownAt > 12000) {
      const undecided = PROMPT_APPS.filter(
        (id) => !s.rules.some((r) => r.appId === id && r.scope === "app"),
      );
      if (undecided.length > 0) {
        lastUnknownAt = now;
        applyNewConnection(buildConnection(randomOf([...undecided])));
      }
    }

    if (pendingEmpty && Math.random() < 0.01 && ticks > 50 && now - lastUnknownAt > 20000) {
      lastUnknownAt = now;
      applyNewConnection(
        buildConnection(randomOf([...INBOUND_APPS]), { inbound: true }),
      );
    }
  };

  intervalId = window.setInterval(tick, 500);
  window.setTimeout(tick, 200);

  if (import.meta.hot) {
    import.meta.hot.dispose(() => stopEngine());
  }

  return stopEngine;
}

export function simulateConnection(appId?: string, inbound = false) {
  const state = useFirewall.getState();
  const undecided = APPS.filter(
    (a) =>
      !SYSTEM_APP_IDS.has(a.id) &&
      !state.rules.some((r) => r.appId === a.id && r.scope === "app" && r.enabled),
  );
  const pool =
    undecided.length > 0
      ? undecided.map((a) => a.id)
      : APPS.filter((a) => !SYSTEM_APP_IDS.has(a.id)).map((a) => a.id);
  const id = appId ?? randomOf(pool);
  applyNewConnection(buildConnection(id, { inbound }));
}

export function appById(id: string) {
  const extra = useFirewall.getState().kernelApps.find((a) => a.id === id);
  return extra ?? APP_BY_ID[id];
}

export function protocolColor(p: Protocol): string {
  switch (p) {
    case "HTTPS":
    case "TLS":
      return "text-allow";
    case "HTTP":
    case "FTP":
      return "text-warn";
    case "DNS":
    case "NTP":
    case "MDNS":
      return "text-info";
    case "UDP":
    case "QUIC":
    case "SSDP":
      return "text-accent";
    case "RDP":
    case "SMB":
      return "text-block";
    case "ICMP":
      return "text-warn";
    default:
      return "text-muted";
  }
}
