import type { KernelSnapshot } from "./kernel-types";

export type TelemetryEventKind = "tx-burst" | "rx-burst" | "peer-fanout" | "regular-reconnect" | "new-listener" | "syn-pressure" | "guard-drift";
export interface TelemetryEvent {
  id: string;
  at: number;
  kind: TelemetryEventKind;
  severity: "notice" | "warning";
  programKey?: string;
  /** Observations, never a malware verdict or a claim that packets were dropped. */
  evidence: Record<string, number | string>;
  acknowledgedAt: number | null;
}
export interface TelemetrySample {
  at: number;
  durationMs: number | null;
  captureDurationMs: number | null;
  rx: number | null;
  tx: number | null;
  sockets: number;
  tcp: number;
  udp: number;
  listeners: number;
  syn: number;
  /** Newly observed socket tuples between comparable samples, not packet counts. */
  newSockets: number | null;
}
export interface TelemetryProgram {
  key: string;
  exe: string;
  name: string;
  firstSeenAt: number;
  lastSeenAt: number;
  sampleCount: number;
  currentSockets: number;
  tcpPeers: string[];
  listenerCount: number;
  synCount: number;
  identities: string[];
  identityMode: "pid-start" | "executable-group" | "unresolved";
}
export interface DriftGuard {
  programKey: string;
  exe: string;
  frozenAt: number;
  peers: string[];
  observationCount: number;
  observedSince: number;
}
export interface TelemetryQuality {
  status: "not-native" | "unavailable" | "warming" | "ready";
  reason: string | null;
  lastSnapshotAt: number | null;
  trafficReady: boolean;
  warmupSamples: number;
  samplingGapMs: number | null;
  retentionLimited: boolean;
}
export interface TelemetryPeer {
  key: string;
  programKey: string;
  endpoint: string;
  firstSeenAt: number;
  lastSeenAt: number;
}
export interface TelemetryPattern {
  key: string;
  programKey: string;
  endpoint: string;
  lastSeenAt: number;
  appearances: number[];
}
/** Serializable session data. Internal fields are bounded along with the public recorder. */
export interface TelemetryState {
  sessionStartedAt: number | null;
  samples: TelemetrySample[];
  programs: TelemetryProgram[];
  events: TelemetryEvent[];
  guards: DriftGuard[];
  quality: TelemetryQuality;
  peers: TelemetryPeer[];
  patterns: TelemetryPattern[];
  previousSockets: string[];
  listenerStreaks: Record<string, { at: number; count: number; programKey: string; endpoint: string }>;
  knownListeners: string[];
  rateBaseline: { at: number; rx: number; tx: number }[];
  synBaseline: number[];
  cooldowns: Record<string, number>;
  counterSource: string | null;
  counters: { rxBytes: number; txBytes: number } | null;
  nextEventId: number;
}
export interface GuardResult { ok: boolean; error?: string }
export interface TelemetryActions {
  ingest: (snapshot: KernelSnapshot, rates: { rx: number; tx: number } | null) => void;
  acknowledge: (id: string) => void;
  resetSession: () => void;
  freezeGuard: (programKey: string) => GuardResult;
  removeGuard: (programKey: string) => void;
}
