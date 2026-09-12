import { create } from "zustand";
import { APP_BY_ID, SYSTEM_APP_IDS } from "./catalog";
import { defaultSettings, isLabRule, matchRule, validateSettings } from "./policy";
import { getNativeBridge, type NativeRule, type NativeRuleInput, type NativeStatus } from "./native-types";
import type { Action, AppInfo, Connection, DecisionScope, LogEntry, PendingRequest, Protocol, Rule, Settings, TrafficSample, ViewId } from "./types";

const STORAGE_KEY = "limen-lab-v2";
const uid = (prefix: string) => `${prefix}-${globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`}`;
let nativeRevision = 0;

export interface FirewallState {
  hydrated: boolean; view: ViewId; query: string; protoFilter: Protocol | "ALL";
  settings: Settings; rules: Rule[]; connections: Connection[];
  pending: PendingRequest[]; log: LogEntry[]; samples: TrafficSample[];
  kernelApps: AppInfo[]; kernelRx: number; kernelTx: number;
  kernelTcp: number; kernelUdp: number; kernelLive: boolean;
  captureError: string | null; blockedCount: number; allowedCount: number;
  nativeStatus: NativeStatus | null; nativeRules: NativeRule[];
  nativeBusy: boolean; nativeError: string | null;
  refreshNative: () => Promise<void>;
  applyNativeRule: (input: NativeRuleInput) => Promise<boolean>;
  removeNativeRule: (id: string) => Promise<boolean>;
  setNativeRuleEnabled: (id: string, enabled: boolean) => Promise<boolean>;
  clearNativeError: () => void;
  setView: (view: ViewId) => void; setQuery: (query: string) => void;
  setProtoFilter: (protocol: Protocol | "ALL") => void;
  patchSettings: (patch: Partial<Settings>) => void;
  matchAction: (conn: Connection) => Action | null;
  enqueuePending: (conn: Connection) => void;
  upsertConnection: (conn: Connection) => void;
  tickConnections: (now: number) => void;
  decide: (id: string, action: Action, scope: DecisionScope) => void;
  addRule: (rule: Omit<Rule, "id" | "createdAt" | "hits">) => void;
  removeRule: (id: string) => void; toggleRule: (id: string) => void;
  setAppAction: (appId: string, action: Action) => void;
  pushLog: (entry: Omit<LogEntry, "id" | "at">) => void;
  pushSample: (sample: TrafficSample) => void;
  setKernelStats: (stats: { rx: number; tx: number; tcp: number; udp: number; apps: AppInfo[]; live?: boolean }) => void;
  mergeKernelConnections: (conns: Connection[]) => void;
  hydrate: () => void; persist: () => void; reset: () => void;
}

const errorMessage = (error: unknown) => error instanceof Error ? error.message : String(error);
const appendError = (existing: string | null, message: string) => !existing ? message : existing.includes(message) ? existing : `${existing} · ${message}`;
function canonicalAddress(address?: string): string | undefined {
  if (!address?.includes(":")) return address;
  try { return new URL(`http://[${address}]/`).hostname; } catch { return address.toLowerCase(); }
}

async function readRulesAfterFailure(read: () => Promise<NativeRule[]>): Promise<NativeRule[]> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      read(),
      new Promise<NativeRule[]>((_, reject) => {
        timer = setTimeout(() => reject(new Error("Rule refresh timed out; inspect Windows Firewall before retrying.")), 10000);
      }),
    ]);
  } finally { clearTimeout(timer); }
}

export const useFirewall = create<FirewallState>((set, get) => {
  async function mutateNative(operation: () => Promise<(rules: NativeRule[]) => boolean>): Promise<boolean> {
    if (get().nativeBusy) return false;
    const bridge = getNativeBridge();
    if (!bridge) {
      set({ nativeError: "Windows desktop application required." });
      return false;
    }
    ++nativeRevision;
    set({ nativeBusy: true, nativeError: null });
    let mutationAttempted = false;
    try {
      const status = await bridge.getStatus();
      set({ nativeStatus: status });
      if (!status.available || !status.elevated || status.backend !== "windows-firewall") {
        throw new Error(status.reason || "Administrator privileges and Windows Firewall are required.");
      }
      mutationAttempted = true;
      const verify = await operation();
      const rules = await bridge.listRules();
      set({ nativeRules: rules });
      if (!verify(rules)) throw new Error("Windows did not confirm the requested rule change. Refresh the rule list before retrying.");
      return true;
    } catch (error) {
      let message = errorMessage(error);
      if (mutationAttempted) {
        // A native timeout or failed verification can follow an OS write.
        // Show the current authoritative state without disguising that failure.
        try { set({ nativeRules: await readRulesAfterFailure(() => bridge.listRules()) }); }
        catch (refreshError) { message += ` · ${errorMessage(refreshError)}`; }
      }
      set({ nativeError: message });
      return false;
    } finally {
      set({ nativeBusy: false });
    }
  }

  function reevaluateLabConnections() {
    set((state) => ({ connections: state.connections.map((conn) => {
      if (conn.source !== "lab") return conn;
      const rule = matchRule(state.rules, conn);
      if (!rule) return conn;
      return { ...conn, state: rule.action === "block" ? "blocked" : "established" };
    }) }));
  }

  return {
    hydrated: false, view: "monitor", query: "", protoFilter: "ALL",
    settings: { ...defaultSettings }, rules: [], connections: [], pending: [], log: [], samples: [],
    kernelApps: [], kernelRx: 0, kernelTx: 0, kernelTcp: 0, kernelUdp: 0, kernelLive: false,
    captureError: null, blockedCount: 0, allowedCount: 0,
    nativeStatus: null, nativeRules: [], nativeBusy: false, nativeError: null,

    refreshNative: async () => {
      const bridge = getNativeBridge();
      if (!bridge || get().nativeBusy) return;
      const revision = ++nativeRevision;
      try {
        const [status, rules] = await Promise.allSettled([bridge.getStatus(), bridge.listRules()]);
        if (revision === nativeRevision && !get().nativeBusy) {
          const errors = [status, rules].filter((result) => result.status === "rejected").map((result) => errorMessage((result as PromiseRejectedResult).reason));
          set({
            ...(status.status === "fulfilled" ? { nativeStatus: status.value } : {}),
            ...(rules.status === "fulfilled" ? { nativeRules: rules.value } : {}),
            nativeError: errors.reduce<string | null>((existing, message) => appendError(existing, message), get().nativeError),
          });
        }
      } catch (error) {
        if (revision === nativeRevision) set({ nativeError: appendError(get().nativeError, errorMessage(error)) });
      }
    },
    applyNativeRule: (input) => mutateNative(async () => {
      const rule = await getNativeBridge()!.applyRule(input);
      return (rules) => rules.some((r) => r.id === rule.id && r.enabled &&
        r.program.toLowerCase() === input.program.toLowerCase() && r.action === input.action &&
        r.direction === input.direction && r.protocol === input.protocol &&
        canonicalAddress(r.remoteAddress) === canonicalAddress(input.remoteAddress) && r.remotePort === input.remotePort && r.localPort === input.localPort);
    }),
    removeNativeRule: (id) => mutateNative(async () => {
      await getNativeBridge()!.removeRule(id);
      return (rules) => !rules.some((rule) => rule.id === id);
    }),
    setNativeRuleEnabled: (id, enabled) => mutateNative(async () => {
      await getNativeBridge()!.setRuleEnabled(id, enabled);
      return (rules) => rules.some((rule) => rule.id === id && rule.enabled === enabled);
    }),
    clearNativeError: () => set({ nativeError: null }),
    setView: (view) => set({ view }), setQuery: (query) => set({ query }),
    setProtoFilter: (protoFilter) => set({ protoFilter }),

    patchSettings: (patch) => {
      set((state) => {
        const settings = validateSettings({ ...state.settings, ...patch });
        // Sources are exclusive: switching modes cannot mix lab data with real sockets.
        if (patch.labTraffic === true) settings.kernelCapture = false;
        if (patch.kernelCapture === true) settings.labTraffic = false;
        const modeChanged = settings.labTraffic !== state.settings.labTraffic || settings.kernelCapture !== state.settings.kernelCapture;
        return {
          settings,
          connections: state.connections.filter((c) => c.source === "lab" ? settings.labTraffic : settings.kernelCapture),
          pending: settings.labTraffic ? state.pending : [],
          ...(modeChanged ? { samples: [], kernelApps: [], kernelRx: 0, kernelTx: 0, kernelTcp: 0, kernelUdp: 0, kernelLive: false, captureError: null } : {}),
        };
      });
      get().persist();
    },
    matchAction: (conn) => {
      if (conn.source !== "lab") return null;
      const { settings, rules } = get();
      if (!settings.enabled) return "allow";
      const hit = matchRule(rules, conn);
      if (hit) {
        set({ rules: rules.map((rule) => rule.id === hit.id ? { ...rule, hits: rule.hits + 1 } : rule) });
        return hit.action;
      }
      if (settings.autoAllowSystem && SYSTEM_APP_IDS.has(conn.appId)) return "allow";
      const policy = conn.direction === "in" ? settings.inboundPolicy : settings.defaultPolicy;
      return policy === "ask" ? null : policy;
    },
    enqueuePending: (conn) => {
      if (conn.source !== "lab" || !get().settings.labTraffic) return;
      set((state) => state.pending.some((item) => item.connection.id === conn.id) ? {} : {
        pending: [...state.pending, { id: uid("pending"), connection: { ...conn, state: "pending" as const }, stacked: 1 }].slice(-60),
      });
    },
    upsertConnection: (conn) => set((state) => ({ connections: [conn, ...state.connections.filter((c) => c.id !== conn.id)].slice(0, 1000) })),
    tickConnections: (now) => {
      if (!get().settings.labTraffic) return;
      set((state) => ({ connections: state.connections.flatMap((conn): Connection[] => {
        if (conn.source !== "lab") return [conn];
        if (conn.state === "blocked") return [];
        const age = now - conn.startedAt;
        if (age > 25000 && Math.random() < 0.08) return [];
        if (conn.state !== "established") return [conn];
        const incoming = Math.round(200 + Math.random() * 14000);
        const outgoing = Math.round(40 + Math.random() * 2800);
        return [{ ...conn, bytesIn: conn.bytesIn + incoming, bytesOut: conn.bytesOut + outgoing, rateIn: incoming * 2, rateOut: outgoing * 2 }];
      }) }));
    },
    decide: (pendingId, action, scope) => {
      const item = get().pending.find((pending) => pending.id === pendingId);
      if (!item || item.connection.source !== "lab") return;
      const conn = item.connection;
      if (scope !== "once") {
        const rule: Rule = {
          id: uid("rule"), appId: conn.appId, action, scope,
          host: scope === "app-host" ? conn.remoteHost : undefined,
          protocol: "ANY", port: "ANY", direction: "any", createdAt: Date.now(), enabled: true, hits: 0,
        };
        set((state) => ({ rules: [...state.rules.filter((r) => !(r.appId === rule.appId && r.scope === rule.scope && r.host === rule.host && (r.direction ?? "any") === "any" && (r.protocol ?? "ANY") === "ANY" && (r.port ?? "ANY") === "ANY")), rule] }));
      }
      const selected = get().pending.filter((pending) => scope === "once" ? pending.id === pendingId :
        pending.connection.appId === conn.appId && (scope === "app" || pending.connection.remoteHost === conn.remoteHost));
      const ids = new Set(selected.map((pending) => pending.id));
      for (const pending of selected) {
        const c = pending.connection;
        const effective = scope === "once" ? action : (get().matchAction(c) ?? action);
        get().upsertConnection({ ...c, state: effective === "allow" ? "established" : "blocked" });
        get().pushLog({ appId: c.appId, protocol: c.protocol, host: c.remoteHost, ip: c.remoteIp, port: c.remotePort, direction: c.direction, action: effective, reason: `lab · ${scope}` });
        set((state) => ({ blockedCount: state.blockedCount + Number(effective === "block"), allowedCount: state.allowedCount + Number(effective === "allow") }));
      }
      set((state) => ({ pending: state.pending.filter((pending) => !ids.has(pending.id)) }));
      reevaluateLabConnections();
      get().persist();
    },
    addRule: (input) => {
      const rule = { ...input, id: uid("rule"), createdAt: Date.now(), hits: 0 };
      if (!APP_BY_ID[rule.appId] || !isLabRule(rule)) return;
      set((state) => ({ rules: [...state.rules, rule] }));
      reevaluateLabConnections(); get().persist();
    },
    removeRule: (id) => { set((state) => ({ rules: state.rules.filter((rule) => rule.id !== id) })); get().persist(); },
    toggleRule: (id) => {
      set((state) => ({ rules: state.rules.map((rule) => rule.id === id ? { ...rule, enabled: !rule.enabled } : rule) }));
      reevaluateLabConnections(); get().persist();
    },
    setAppAction: (appId, action) => {
      if (!APP_BY_ID[appId]) return;
      const pending = get().pending.find((item) => item.connection.appId === appId);
      if (pending) { get().decide(pending.id, action, "app"); return; }
      set((state) => ({ rules: [...state.rules.filter((rule) => !(rule.appId === appId && rule.scope === "app")), {
        id: uid("rule"), appId, action, scope: "app", protocol: "ANY", port: "ANY", direction: "any", createdAt: Date.now(), enabled: true, hits: 0,
      }] }));
      reevaluateLabConnections(); get().persist();
    },
    pushLog: (entry) => set((state) => ({ log: [{ ...entry, id: uid("log"), at: Date.now() }, ...state.log].slice(0, 250) })),
    pushSample: (sample) => set((state) => ({ samples: [...state.samples, sample].slice(-48) })),
    setKernelStats: (stats) => set({ kernelRx: stats.rx, kernelTx: stats.tx, kernelTcp: stats.tcp, kernelUdp: stats.udp, kernelApps: stats.apps, kernelLive: stats.live ?? true }),
    mergeKernelConnections: (conns) => set((state) => ({ connections: [...conns, ...state.connections.filter((c) => c.source === "lab" && state.settings.labTraffic)] })),
    hydrate: () => {
      if (typeof window === "undefined") return;
      try {
        const raw = localStorage.getItem(STORAGE_KEY) ?? localStorage.getItem("limen-firewall-v1");
        if (raw) {
          const data = JSON.parse(raw) as { rules?: unknown[]; settings?: unknown };
          const settings = validateSettings(data.settings);
          if (settings.labTraffic) settings.kernelCapture = false;
          set({ settings, rules: Array.isArray(data.rules) ? data.rules.filter(isLabRule).filter((rule) => Boolean(APP_BY_ID[rule.appId])) : [] });
        }
      } catch { /* Invalid or unavailable browser storage cannot enable native rules. */ }
      set({ hydrated: true });
    },
    persist: () => {
      if (typeof window === "undefined") return;
      try {
        const { settings, rules } = get();
        localStorage.setItem(STORAGE_KEY, JSON.stringify({ settings, rules }));
      } catch { /* Storage can be disabled in a browser; native rules remain in Windows. */ }
    },
    reset: () => {
      set({ settings: { ...defaultSettings }, rules: [], connections: [], pending: [], log: [], samples: [], kernelApps: [], kernelRx: 0, kernelTx: 0, kernelTcp: 0, kernelUdp: 0, kernelLive: false, captureError: null, blockedCount: 0, allowedCount: 0 });
      // Reset affects the demonstration and display only. OS rules require explicit deletion.
      get().persist();
    },
  };
});
