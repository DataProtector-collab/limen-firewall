import { create } from "zustand";
import type { KernelSnapshot } from "./kernel-types";
import { acknowledgeTelemetryEvent, createTelemetryState, freezeTelemetryGuard, ingestTelemetryState, unavailableTelemetry } from "./telemetry";
import type { TelemetryActions, TelemetryState } from "./telemetry-types";

/** Session-only recorder. Nothing is persisted or sent to a remote service. */
export const useTelemetry = create<TelemetryState & TelemetryActions>((set, get) => ({
  ...createTelemetryState(),
  ingest: (snapshot, rates) => set(state => ingestTelemetryState(state, snapshot, rates)),
  acknowledge: id => set(state => acknowledgeTelemetryEvent(state, id)),
  resetSession: () => set(createTelemetryState()),
  freezeGuard: programKey => {
    const next = freezeTelemetryGuard(get(), programKey);
    if (next.result.ok) set(next.state);
    return next.result;
  },
  removeGuard: programKey => set(state => ({ guards: state.guards.filter(guard => guard.programKey !== programKey) })),
}));

export function ingestTelemetry(snapshot: KernelSnapshot, rates: { rx: number; tx: number } | null): void {
  useTelemetry.getState().ingest(snapshot, rates);
}

export function markTelemetryUnavailable(reason: string): void {
  useTelemetry.setState(state => unavailableTelemetry(state, reason));
}
