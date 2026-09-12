import { create } from "zustand";
import { APP_BY_ID, APPS, SYSTEM_APP_IDS } from "./catalog";
import type {
  Action,
  Connection,
  DecisionScope,
  DefaultPolicy,
  LogEntry,
  PendingRequest,
  Protocol,
  Rule,
  Settings,
  TrafficSample,
  ViewId,
} from "./types";

const STORAGE_KEY = "aegis-firewall-v1";

function uid(prefix: string): string {
  return `${prefix}-${Math.random().toString(36).slice(2, 9)}-${Date.now().toString(36)}`;
}

function defaultSystemRules(): Rule[] {
  const now = Date.now();
  return APPS.filter((a) => SYSTEM_APP_IDS.has(a.id)).map((a) => ({
    id: `sys-${a.id}`,
    appId: a.id,
    action: "allow" as const,
    scope: "app" as const,
    protocol: "ANY" as const,
    port: "ANY" as const,
    createdAt: now,
    enabled: true,
    hits: 0,
  }));
}

const defaultSettings: Settings = {
  enabled: true,
  defaultPolicy: "ask",
  inboundPolicy: "ask",
  autoAllowSystem: true,
  promptSound: false,
};

export interface FirewallState {
  hydrated: boolean;
  view: ViewId;
  query: string;
  protoFilter: Protocol | "ALL";
  settings: Settings;
  rules: Rule[];
  connections: Connection[];
  pending: PendingRequest[];
  log: LogEntry[];
  samples: TrafficSample[];
  blockedCount: number;
  allowedCount: number;
  setView: (view: ViewId) => void;
  setQuery: (q: string) => void;
  setProtoFilter: (p: Protocol | "ALL") => void;
  patchSettings: (p: Partial<Settings>) => void;
  matchAction: (conn: Connection) => Action | null;
  enqueuePending: (conn: Connection) => void;
  upsertConnection: (conn: Connection) => void;
  tickConnections: (now: number) => void;
  decide: (pendingId: string, action: Action, scope: DecisionScope) => void;
  addRule: (rule: Omit<Rule, "id" | "createdAt" | "hits">) => void;
  removeRule: (id: string) => void;
  toggleRule: (id: string) => void;
  setAppAction: (appId: string, action: Action) => void;
  pushLog: (entry: Omit<LogEntry, "id" | "at">) => void;
  pushSample: (sample: TrafficSample) => void;
  hydrate: () => void;
  persist: () => void;
  reset: () => void;
}

function matchRule(rules: Rule[], conn: Connection): Rule | null {
  const ranked = rules
    .filter((r) => r.enabled && r.appId === conn.appId)
    .sort((a, b) => {
      const score = (r: Rule) =>
        (r.scope === "app-host" ? 4 : 0) +
        (r.host ? 2 : 0) +
        (r.protocol && r.protocol !== "ANY" ? 1 : 0);
      return score(b) - score(a);
    });

  for (const r of ranked) {
    if (r.scope === "app-host" && r.host && r.host !== conn.remoteHost) continue;
    if (r.protocol && r.protocol !== "ANY" && r.protocol !== conn.protocol) continue;
    if (r.port && r.port !== "ANY" && r.port !== conn.remotePort) continue;
    return r;
  }
  return null;
}

export const useFirewall = create<FirewallState>((set, get) => ({
  hydrated: false,
  view: "monitor",
  query: "",
  protoFilter: "ALL",
  settings: defaultSettings,
  rules: defaultSystemRules(),
  connections: [],
  pending: [],
  log: [],
  samples: [],
  blockedCount: 0,
  allowedCount: 0,

  setView: (view) => set({ view }),
  setQuery: (query) => set({ query }),
  setProtoFilter: (protoFilter) => set({ protoFilter }),

  patchSettings: (p) => {
    set((s) => ({ settings: { ...s.settings, ...p } }));
    get().persist();
  },

  matchAction: (conn) => {
    const { settings, rules } = get();
    if (!settings.enabled) return "allow";
    const hit = matchRule(rules, conn);
    if (hit) {
      set({
        rules: rules.map((r) =>
          r.id === hit.id ? { ...r, hits: r.hits + 1 } : r,
        ),
      });
      return hit.action;
    }
    if (settings.autoAllowSystem && SYSTEM_APP_IDS.has(conn.appId)) return "allow";
    const policy =
      conn.direction === "in" ? settings.inboundPolicy : settings.defaultPolicy;
    if (policy === "ask") return null;
    return policy;
  },

  enqueuePending: (conn) => {
    set((s) => {
      const existing = s.pending.find(
        (p) =>
          p.connection.appId === conn.appId &&
          p.connection.remoteHost === conn.remoteHost &&
          p.connection.protocol === conn.protocol,
      );
      if (existing) {
        return {
          pending: s.pending.map((p) =>
            p.id === existing.id ? { ...p, stacked: p.stacked + 1 } : p,
          ),
        };
      }
      return {
        pending: [
          ...s.pending,
          { id: uid("pend"), connection: { ...conn, state: "pending" }, stacked: 1 },
        ],
      };
    });
  },

  upsertConnection: (conn) => {
    set((s) => {
      const idx = s.connections.findIndex((c) => c.id === conn.id);
      if (idx === -1) {
        const next = [conn, ...s.connections].slice(0, 90);
        return { connections: next };
      }
      const copy = s.connections.slice();
      copy[idx] = conn;
      return { connections: copy };
    });
  },

  tickConnections: (now) => {
    set((s) => {
      const next: Connection[] = [];
      for (const c of s.connections) {
        if (c.state === "blocked") continue;
        const age = now - c.startedAt;
        if (c.state === "syn" && age > 900) {
          next.push({ ...c, state: "established" });
          continue;
        }
        if (c.state === "established") {
          const closeChance = age > 25000 ? 0.08 : 0.015;
          if (Math.random() < closeChance) continue;
          const burst = c.protocol === "HTTPS" || c.protocol === "QUIC" ? 1 : 0.35;
          const din = Math.round((200 + Math.random() * 14000) * burst);
          const dout = Math.round((40 + Math.random() * 2800) * burst);
          next.push({
            ...c,
            bytesIn: c.bytesIn + din,
            bytesOut: c.bytesOut + dout,
            rateIn: din * 2,
            rateOut: dout * 2,
          });
          continue;
        }
        next.push(c);
      }
      return { connections: next };
    });
  },

  decide: (pendingId, action, scope) => {
    const { pending, rules } = get();
    const item = pending.find((p) => p.id === pendingId);
    if (!item) return;
    const conn = item.connection;
    const app = APP_BY_ID[conn.appId];

    let nextRules = rules;
    if (scope === "app" || scope === "app-host") {
      const rule: Rule = {
        id: uid("rule"),
        appId: conn.appId,
        action,
        scope: scope === "app" ? "app" : "app-host",
        host: scope === "app-host" ? conn.remoteHost : undefined,
        protocol: "ANY",
        port: "ANY",
        createdAt: Date.now(),
        enabled: true,
        hits: 1,
      };
      nextRules = [
        ...rules.filter(
          (r) =>
            !(
              r.appId === rule.appId &&
              r.scope === rule.scope &&
              r.host === rule.host &&
              r.action !== rule.action
            ),
        ),
        rule,
      ];
    }

    const live: Connection = {
      ...conn,
      state: action === "allow" ? "established" : "blocked",
      startedAt: Date.now(),
    };

    get().pushLog({
      appId: conn.appId,
      protocol: conn.protocol,
      host: conn.remoteHost,
      ip: conn.remoteIp,
      port: conn.remotePort,
      direction: conn.direction,
      action,
      reason:
        scope === "once"
          ? `${app?.name ?? conn.appId} · einmal`
          : scope === "app-host"
            ? `${app?.name ?? conn.appId} → ${conn.remoteHost}`
            : `${app?.name ?? conn.appId} · gesamte App`,
    });

    set((s) => ({
      rules: nextRules,
      pending: s.pending.filter((p) => p.id !== pendingId),
      connections:
        action === "allow"
          ? [live, ...s.connections.filter((c) => c.id !== live.id)].slice(0, 90)
          : s.connections,
      blockedCount: s.blockedCount + (action === "block" ? 1 : 0),
      allowedCount: s.allowedCount + (action === "allow" ? 1 : 0),
    }));
    get().persist();
  },

  addRule: (rule) => {
    set((s) => ({
      rules: [
        ...s.rules,
        { ...rule, id: uid("rule"), createdAt: Date.now(), hits: 0 },
      ],
    }));
    get().persist();
  },

  removeRule: (id) => {
    set((s) => ({ rules: s.rules.filter((r) => r.id !== id) }));
    get().persist();
  },

  toggleRule: (id) => {
    set((s) => ({
      rules: s.rules.map((r) =>
        r.id === id ? { ...r, enabled: !r.enabled } : r,
      ),
    }));
    get().persist();
  },

  setAppAction: (appId, action) => {
    set((s) => {
      const without = s.rules.filter(
        (r) => !(r.appId === appId && r.scope === "app"),
      );
      return {
        rules: [
          ...without,
          {
            id: uid("rule"),
            appId,
            action,
            scope: "app",
            protocol: "ANY",
            port: "ANY",
            createdAt: Date.now(),
            enabled: true,
            hits: 0,
          },
        ],
      };
    });
    get().persist();
  },

  pushLog: (entry) => {
    set((s) => ({
      log: [{ ...entry, id: uid("log"), at: Date.now() }, ...s.log].slice(0, 250),
    }));
  },

  pushSample: (sample) => {
    set((s) => ({ samples: [...s.samples, sample].slice(-48) }));
  },

  hydrate: () => {
    if (typeof window === "undefined") return;
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const data = JSON.parse(raw) as {
          rules?: Rule[];
          settings?: Partial<Settings>;
        };
        set({
          rules:
            Array.isArray(data.rules) && data.rules.length > 0
              ? data.rules
              : defaultSystemRules(),
          settings: { ...defaultSettings, ...data.settings },
        });
      }
    } catch {
      /* ignore */
    }
    set({ hydrated: true });
  },

  persist: () => {
    if (typeof window === "undefined") return;
    const { rules, settings } = get();
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify({ rules, settings }));
    } catch {
      /* ignore */
    }
  },

  reset: () => {
    set({
      rules: defaultSystemRules(),
      settings: defaultSettings,
      connections: [],
      pending: [],
      log: [],
      samples: [],
      blockedCount: 0,
      allowedCount: 0,
    });
    get().persist();
  },
}));
