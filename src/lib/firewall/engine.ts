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
import { useFirewall } from "./store";
import type { Connection, Protocol } from "./types";

function uid(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 10)}`;
}

function localPort(): number {
  return 49152 + Math.floor(Math.random() * 15000);
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
      reason: "Regel",
    });
    store.upsertConnection({ ...conn, state: "blocked" });
    useFirewall.setState((s) => ({ blockedCount: s.blockedCount + 1 }));
    return;
  }
  store.upsertConnection({ ...conn, state: "established" });
  useFirewall.setState((s) => ({ allowedCount: s.allowedCount + 1 }));
}

function seedBaseline() {
  const store = useFirewall.getState();
  if (store.connections.length > 0) return;
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
let firstPromptAt = 0;
let secondPromptAt = 0;
let inboundAt = 0;
let lastUnknownAt = 0;
let ticks = 0;

export function startEngine() {
  if (typeof window === "undefined" || started) return () => {};
  started = true;
  const store = useFirewall.getState();
  if (!store.hydrated) store.hydrate();
  seedBaseline();

  firstPromptAt = Date.now() + 1400;
  secondPromptAt = Date.now() + 9000;
  inboundAt = Date.now() + 22000;
  lastUnknownAt = Date.now();

  const tick = () => {
    ticks += 1;
    const now = Date.now();
    const s = useFirewall.getState();
    s.tickConnections(now);

    const live = useFirewall.getState().connections.filter((c) => c.state === "established");
    const rateIn = live.reduce((a, c) => a + c.rateIn, 0);
    const rateOut = live.reduce((a, c) => a + c.rateOut, 0);
    s.pushSample({
      t: now,
      in: rateIn,
      out: rateOut,
      blocked: useFirewall.getState().blockedCount,
    });

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

  return () => {
    if (intervalId != null) window.clearInterval(intervalId);
    intervalId = null;
    started = false;
  };
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
  return APP_BY_ID[id];
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
