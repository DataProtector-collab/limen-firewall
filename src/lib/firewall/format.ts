import type { Action, AppCategory, Direction, Protocol } from "./types";

export function fmtBytes(n: number): string {
  const v = Math.max(0, n);
  if (v < 1024) return `${Math.round(v)} B`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB`;
  if (v < 1024 * 1024 * 1024) return `${(v / (1024 * 1024)).toFixed(1)} MB`;
  return `${(v / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function fmtRate(n: number): string {
  const v = Math.max(0, n);
  if (v < 1024) return `${Math.round(v)} B/s`;
  if (v < 1024 * 1024) return `${(v / 1024).toFixed(1)} KB/s`;
  return `${(v / (1024 * 1024)).toFixed(2)} MB/s`;
}

export function fmtTime(ts: number): string {
  return new Date(ts).toLocaleTimeString("de-DE", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function protoLabel(p: Protocol): string {
  if (p === "MDNS") return "mDNS";
  if (p === "WSS") return "WebSocket";
  return p;
}

export function directionLabel(d: Direction): string {
  return d === "in" ? "Eingehend" : "Ausgehend";
}

export function actionLabel(a: Action): string {
  return a === "allow" ? "Zugelassen" : "Blockiert";
}

export function categoryLabel(c: AppCategory): string {
  const map: Record<AppCategory, string> = {
    system: "Windows",
    browser: "Browser",
    chat: "Kommunikation",
    game: "Spiel",
    media: "Medien",
    office: "Büro",
    util: "Dienst",
    unknown: "Unbekannt",
  };
  return map[c];
}

export function initials(name: string): string {
  const parts = name.replace(/\.exe$/i, "").split(/[\s._-]+/).filter(Boolean);
  if (parts.length === 1) return parts[0]!.slice(0, 2).toUpperCase();
  return (parts[0]![0]! + parts[1]![0]!).toUpperCase();
}
