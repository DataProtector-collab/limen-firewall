import type { KernelSnapshot } from "./kernel-types";
import type { ProcessIdentity, ProcessInspection, ProcessSnapshot } from "./observation-types";
import type { ApprovalInput, ApprovalStatus } from "./approval-types";
import type { GeoSnapshot } from "./geo-types";

export interface NativeRuleInput {
  program: string;
  action: "allow" | "block";
  direction: "in" | "out";
  remoteAddress?: string;
  protocol: "TCP" | "UDP" | "ANY";
  remotePort?: number;
  localPort?: number;
}

export interface NativeRule extends NativeRuleInput {
  id: string;
  enabled: boolean;
  createdAt: number;
  primaryStatus?: string;
  enforcementStatus?: string[];
  // Apply responses only: the privileged backend binds the exact submitted path
  // to the canonical executable path verified with Windows.
  requestedProgram?: string;
}

export interface NativeStatus {
  platform: string;
  available: boolean;
  elevated: boolean;
  firewallEnabled: boolean;
  backend: "windows-firewall" | "none";
  reason?: string;
  externalFirewallProviders?: string[];
  profiles?: Array<{
    name: string;
    enabled: boolean;
    defaultInboundAction: string;
    defaultOutboundAction: string;
  }>;
}

export interface LimenNativeBridge {
  platform: "win32";
  getStatus(): Promise<NativeStatus>;
  getSnapshot(): Promise<KernelSnapshot>;
  getProcessSnapshot?(): Promise<ProcessSnapshot>;
  inspectProcess?(identity: ProcessIdentity): Promise<ProcessInspection>;
  listRules(): Promise<NativeRule[]>;
  applyRule(input: NativeRuleInput): Promise<NativeRule>;
  removeRule(id: string): Promise<unknown>;
  setRuleEnabled(id: string, enabled: boolean): Promise<NativeRule>;
  getApprovalStatus?(): Promise<ApprovalStatus>;
  startApproval?(): Promise<ApprovalStatus>;
  stopApproval?(): Promise<ApprovalStatus>;
  decideApproval?(input: ApprovalInput): Promise<ApprovalStatus>;
  quitApplication?(): Promise<void>;
  onApprovalAttention?(listener: () => void): () => void;
  getGeoLocations?(addresses: string[]): Promise<GeoSnapshot>;
}

declare global {
  interface Window {
    limen?: LimenNativeBridge;
  }
}

export function isNativeDesktop(): boolean {
  return typeof window !== "undefined" && window.limen?.platform === "win32";
}

export function getNativeBridge(): LimenNativeBridge | undefined {
  return isNativeDesktop() ? window.limen : undefined;
}
