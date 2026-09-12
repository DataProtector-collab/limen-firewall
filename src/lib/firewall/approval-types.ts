export type ApprovalDecision = "pending" | "allow-endpoint" | "allow-program" | "deny";

export interface ApprovalAttempt {
  id: string;
  program: string;
  remoteAddress: string;
  remotePort: number;
  protocol: "TCP" | "UDP";
  firstSeenAt: number;
  lastSeenAt: number;
  count: number;
  decision: ApprovalDecision;
  canApprove: boolean;
}

export interface ApprovalStatus {
  available: boolean;
  active: boolean;
  sessionId: string;
  startedAt: number;
  scope: "internet";
  attempts: ApprovalAttempt[];
  approvedCount: number;
  deniedCount: number;
  droppedEvents: number;
  reason?: string;
}

export interface ApprovalInput {
  id: string;
  decision: Exclude<ApprovalDecision, "pending">;
}
