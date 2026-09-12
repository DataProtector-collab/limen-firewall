import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import type { LimenNativeBridge } from "./native-types";
import type { ApprovalStatus } from "./approval-types";
import { useApproval } from "./approval-store";

const status = (active: boolean): ApprovalStatus => ({ available: true, active, sessionId: active ? "session" : "",
  startedAt: active ? 1 : 0, scope: "internet", attempts: [], approvedCount: 0, deniedCount: 0, droppedEvents: 0 });
function install(bridge: Partial<LimenNativeBridge>) {
  Object.defineProperty(globalThis, "window", { configurable: true, value: { limen: { platform: "win32", ...bridge } } });
}
beforeEach(() => useApproval.setState({ status: null, error: null, busy: false, refreshedAt: null }));

test("an older approval status read cannot overwrite a completed native start", async () => {
  let resolveRead!: (value: ApprovalStatus) => void;
  install({ getApprovalStatus: () => new Promise(resolve => { resolveRead = resolve; }), startApproval: async () => status(true) });
  const reading = useApproval.getState().refresh();
  assert.equal(await useApproval.getState().start(), true);
  resolveRead(status(false));
  await reading;
  assert.equal(useApproval.getState().status?.active, true);
});

test("an uncertain approval failure re-reads native state and keeps the error", async () => {
  install({ startApproval: async () => { throw new Error("Native host disconnected"); }, getApprovalStatus: async () => status(false) });
  assert.equal(await useApproval.getState().start(), false);
  assert.equal(useApproval.getState().status?.active, false);
  assert.match(useApproval.getState().error!, /disconnected/);
  assert.equal(useApproval.getState().busy, false);
});

test("a second decision cannot race a pending approval mutation", async () => {
  let complete!: (value: ApprovalStatus) => void;
  let calls = 0;
  install({ decideApproval: () => { calls += 1; return new Promise(resolve => { complete = resolve; }); } });
  const first = useApproval.getState().decide({ id: "one", decision: "allow-endpoint" });
  assert.equal(await useApproval.getState().decide({ id: "two", decision: "deny" }), false);
  assert.equal(calls, 1);
  complete(status(true));
  assert.equal(await first, true);
});
