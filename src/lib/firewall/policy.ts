import { PROTOCOLS, type Connection, type Rule, type Settings } from "./types";
import { isLocale } from "../i18n/index";

export const defaultSettings: Settings = {
  enabled: true, defaultPolicy: "ask", inboundPolicy: "ask",
  autoAllowSystem: false, promptSound: false, language: "de",
  kernelCapture: true, labTraffic: false,
};

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function validateSettings(value: unknown): Settings {
  const next = { ...defaultSettings };
  if (!object(value)) return next;
  for (const key of ["enabled", "autoAllowSystem", "promptSound", "kernelCapture", "labTraffic"] as const) {
    if (typeof value[key] === "boolean") next[key] = value[key];
  }
  for (const key of ["defaultPolicy", "inboundPolicy"] as const) {
    if (value[key] === "ask" || value[key] === "allow" || value[key] === "block") next[key] = value[key];
  }
  if (typeof value.language === "string" && isLocale(value.language)) next.language = value.language;
  return next;
}

export function isLabRule(value: unknown): value is Rule {
  if (!object(value)) return false;
  return typeof value.id === "string" && value.id.length > 0 &&
    typeof value.appId === "string" && value.appId.length > 0 &&
    (value.action === "allow" || value.action === "block") &&
    (value.scope === "app" || (value.scope === "app-host" && typeof value.host === "string" && value.host.trim().length > 0)) &&
    (value.protocol === undefined || value.protocol === "ANY" || PROTOCOLS.includes(value.protocol as never)) &&
    (value.port === undefined || value.port === "ANY" || (typeof value.port === "number" && Number.isInteger(value.port) && value.port >= 1 && value.port <= 65535)) &&
    (value.direction === undefined || ["in", "out", "any"].includes(String(value.direction))) &&
    typeof value.enabled === "boolean" &&
    typeof value.createdAt === "number" && Number.isFinite(value.createdAt) &&
    typeof value.hits === "number" && Number.isFinite(value.hits) && value.hits >= 0;
}

export function matchRule(rules: Rule[], conn: Connection): Rule | null {
  // Local policies are simulations; observing a real connection never enforces them.
  if (conn.source !== "lab") return null;
  const matching = rules.filter((r) => {
    if (!r.enabled || r.appId !== conn.appId) return false;
    if (r.direction && r.direction !== "any" && r.direction !== conn.direction) return false;
    if (r.scope === "app-host" && (!r.host || r.host.toLowerCase() !== conn.remoteHost.toLowerCase())) return false;
    if (r.protocol && r.protocol !== "ANY" && r.protocol !== conn.protocol) return false;
    const port = conn.direction === "in" ? conn.localPort : conn.remotePort;
    return !r.port || r.port === "ANY" || r.port === port;
  });
  return matching.sort((a, b) => {
    // A matching deny wins, including when a broader allow was created first.
    if (a.action !== b.action) return a.action === "block" ? -1 : 1;
    const specificity = (r: Rule) => Number(r.scope === "app-host") * 4 + Number(r.protocol !== undefined && r.protocol !== "ANY") + Number(r.port !== undefined && r.port !== "ANY") + Number(r.direction !== undefined && r.direction !== "any");
    return specificity(b) - specificity(a) || b.createdAt - a.createdAt;
  })[0] ?? null;
}
