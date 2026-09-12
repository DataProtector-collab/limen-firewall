/** Observations of a Windows process instance, never evidence of per-service traffic. */
export interface ProcessIdentity {
  pid: number;
  startedAt: number;
}

export interface HostedService {
  name: string;
  displayName: string;
  state: string;
  serviceDll?: string;
  errors?: string[];
}

export interface ProcessEntry {
  pid: number;
  name: string;
  exe: string;
  parentPid: number | null;
  startedAt: number | null;
  services: HostedService[];
  errors: string[];
}

export interface ProcessSnapshot {
  at: number;
  available: boolean;
  processes: ProcessEntry[];
  errors: string[];
  truncated: boolean;
  captureDurationMs: number;
}

export interface ProcessInspection {
  at: number;
  available: boolean;
  identity: ProcessIdentity;
  process?: ProcessEntry;
  parent?: ProcessEntry;
  children: ProcessEntry[];
  modules: Array<{ name: string; path: string }>;
  modulesTruncated: boolean;
  sha256?: string;
  signature: {
    status: "valid" | "unsigned" | "invalid" | "unknown";
    nativeStatus?: string;
    publisher?: string;
  };
  errors: string[];
  captureDurationMs: number;
}
