import type { Locale } from "@/lib/i18n";

export const PROTOCOLS = [
  "TCP",
  "UDP",
  "HTTP",
  "HTTPS",
  "TLS",
  "QUIC",
  "DNS",
  "ICMP",
  "WSS",
  "NTP",
  "SMB",
  "RDP",
  "FTP",
  "SSDP",
  "MDNS",
] as const;

export type Protocol = (typeof PROTOCOLS)[number];

export type Direction = "out" | "in" | "unknown";

export type ConnState =
  | "listen"
  | "syn"
  | "established"
  | "timewait"
  | "bound"
  | "closed"
  | "closing"
  | "closewait"
  | "finwait1"
  | "finwait2"
  | "lastack"
  | "unknown"
  | "blocked"
  | "pending";

export type Action = "allow" | "block";

export type DecisionScope = "once" | "app-host" | "app";

export type AppCategory =
  "system" | "browser" | "chat" | "game" | "media" | "office" | "util" | "unknown";

export type ViewId = "monitor" | "map" | "approval" | "war" | "blackbox" | "apps" | "rules" | "log" | "settings";

export type DefaultPolicy = "ask" | "allow" | "block";

export interface AppInfo {
  id: string;
  name: string;
  exe: string;
  publisher: string;
  signed: boolean | null;
  pid: number;
  category: AppCategory;
  path: string;
}

export interface Destination {
  host: string;
  ip: string;
  port: number;
  protocol: Protocol;
  country: string;
}

export interface Rule {
  id: string;
  appId: string;
  action: Action;
  scope: "app" | "app-host";
  host?: string;
  protocol?: Protocol | "ANY";
  port?: number | "ANY";
  createdAt: number;
  enabled: boolean;
  hits: number;
  direction?: "in" | "out" | "any";
}

export interface Connection {
  id: string;
  appId: string;
  protocol: Protocol;
  direction: Direction;
  localPort: number;
  localIp?: string;
  remoteHost: string;
  remoteIp: string;
  remotePort: number;
  country: string;
  state: ConnState;
  bytesIn: number;
  bytesOut: number;
  rateIn: number;
  rateOut: number;
  startedAt: number;
  source?: "kernel" | "lab";
  inode?: string;
  pid?: number;
  trafficMeasured?: boolean;
}

export interface LogEntry {
  id: string;
  at: number;
  appId: string;
  protocol: Protocol;
  host: string;
  ip: string;
  port: number;
  direction: Direction;
  action: Action;
  reason: string;
}

export interface PendingRequest {
  id: string;
  connection: Connection;
  stacked: number;
}

export interface Settings {
  enabled: boolean;
  defaultPolicy: DefaultPolicy;
  inboundPolicy: DefaultPolicy;
  autoAllowSystem: boolean;
  promptSound: boolean;
  language: Locale;
  kernelCapture: boolean;
  labTraffic: boolean;
}

export interface TrafficSample {
  t: number;
  in: number;
  out: number;
  blocked: number;
}
