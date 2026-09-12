import { create } from "zustand";
import { getNativeBridge } from "./native-types";
import type { ApprovalInput, ApprovalStatus } from "./approval-types";

interface ApprovalState {
  status: ApprovalStatus | null;
  error: string | null;
  busy: boolean;
  refreshedAt: number | null;
  refresh(): Promise<void>;
  start(): Promise<boolean>;
  stop(): Promise<boolean>;
  decide(input: ApprovalInput): Promise<boolean>;
}

let revision = 0;
const message = (error: unknown) => error instanceof Error ? error.message : String(error);

// Native session state is never persisted in browser storage. Windows is authoritative.
export const useApproval = create<ApprovalState>((set, get) => {
  async function change(operation: () => Promise<ApprovalStatus>): Promise<boolean> {
    if (get().busy) return false;
    ++revision;
    set({ busy: true, error: null });
    try {
      const status = await operation();
      set({ status, refreshedAt: Date.now() });
      return true;
    } catch (error) {
      let detail = message(error);
      try {
        const status = await getNativeBridge()?.getApprovalStatus?.();
        if (status) set({ status, refreshedAt: Date.now() });
      } catch (refreshError) { detail += ` · ${message(refreshError)}`; }
      set({ error: detail });
      return false;
    } finally { set({ busy: false }); }
  }

  return {
    status: null, busy: false, error: null, refreshedAt: null,
    async refresh() {
      const bridge = getNativeBridge();
      if (!bridge?.getApprovalStatus || get().busy) return;
      const current = revision;
      try {
        const status = await bridge.getApprovalStatus();
        if (current === revision && !get().busy) set({ status, error: null, refreshedAt: Date.now() });
      } catch (error) {
        if (current === revision && !get().busy) set({ error: message(error) });
      }
    },
    start: () => change(() => {
      const bridge = getNativeBridge();
      if (!bridge?.startApproval) throw new Error("The native connection guard is unavailable.");
      return bridge.startApproval();
    }),
    stop: () => change(() => {
      const bridge = getNativeBridge();
      if (!bridge?.stopApproval) throw new Error("The native connection guard is unavailable.");
      return bridge.stopApproval();
    }),
    decide: (input) => change(() => {
      const bridge = getNativeBridge();
      if (!bridge?.decideApproval) throw new Error("The native connection guard is unavailable.");
      return bridge.decideApproval(input);
    }),
  };
});

export function startApprovalObservation(): () => void {
  if (!getNativeBridge()?.getApprovalStatus) return () => {};
  let stopped = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const tick = async () => {
    if (stopped) return;
    await useApproval.getState().refresh();
    if (!stopped) timer = setTimeout(() => void tick(), 1500);
  };
  void tick();
  return () => { stopped = true; clearTimeout(timer); };
}
