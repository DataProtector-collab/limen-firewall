import assert from "node:assert/strict";
import { beforeEach, test } from "node:test";
import { useFirewall } from "./store";
import type { LimenNativeBridge, NativeRule, NativeRuleInput } from "./native-types";
import type { Connection } from "./types";

const input: NativeRuleInput = { program: "C:\\Apps\\Example.exe", action: "block", direction: "out", protocol: "ANY" };
const rule: NativeRule = { ...input, id: "Limen-test", enabled: true, createdAt: 1 };
const status = { platform: "win32", available: true, elevated: true, firewallEnabled: true, backend: "windows-firewall" as const };
const conn: Connection = { id: "lab1", appId: "chrome", source: "lab", protocol: "HTTPS", direction: "out", localPort: 52000, remoteHost: "example.com", remoteIp: "192.0.2.20", remotePort: 443, country: "", state: "syn", bytesIn: 0, bytesOut: 0, rateIn: 0, rateOut: 0, startedAt: 1 };

function bridge(overrides: Partial<LimenNativeBridge> = {}): LimenNativeBridge {
  return {
    platform: "win32", getStatus: async () => status,
    getSnapshot: async () => { throw new Error("unused"); }, listRules: async () => [rule],
    applyRule: async () => rule, removeRule: async () => undefined,
    setRuleEnabled: async (_id, enabled) => ({ ...rule, enabled }), ...overrides,
  };
}

function install(value?: LimenNativeBridge, storage = new Map<string, string>()) {
  Object.defineProperty(globalThis, "window", { configurable: true, value: { limen: value } });
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: { getItem: (key: string) => storage.get(key) ?? null, setItem: (key: string, value: string) => storage.set(key, value) } });
  return storage;
}

beforeEach(() => {
  install();
  useFirewall.getState().reset();
  useFirewall.setState({ hydrated: false, nativeStatus: null, nativeRules: [], nativeBusy: false, nativeError: null });
});

test("native mutations only report success after Windows confirms the requested rule", async () => {
  install(bridge());
  assert.equal(await useFirewall.getState().applyNativeRule(input), true);
  assert.deepEqual(useFirewall.getState().nativeRules, [rule]);
  assert.equal(useFirewall.getState().blockedCount, 0);
  assert.deepEqual(useFirewall.getState().rules, []);
  install(bridge({ listRules: async () => [] }));
  assert.equal(await useFirewall.getState().applyNativeRule(input), false);
  assert.match(useFirewall.getState().nativeError!, /did not confirm/);
});

test("rejected or unavailable native actions never create optimistic rules", async () => {
  let invoked = 0;
  install(bridge({ getStatus: async () => ({ ...status, elevated: false, reason: "Administrator required" }), applyRule: async () => { invoked++; return rule; } }));
  assert.equal(await useFirewall.getState().applyNativeRule(input), false);
  assert.equal(invoked, 0);
  assert.deepEqual(useFirewall.getState().nativeRules, []);
  install(bridge({ applyRule: async () => { throw new Error("Access denied"); } }));
  assert.equal(await useFirewall.getState().applyNativeRule(input), false);
  assert.match(useFirewall.getState().nativeError!, /Access denied/);
  assert.equal(useFirewall.getState().nativeBusy, false);
});

test("a stale native refresh cannot overwrite a completed mutation", async () => {
  let resolveOld!: (rules: NativeRule[]) => void;
  let reads = 0;
  install(bridge({ listRules: () => ++reads === 1 ? new Promise((resolve) => { resolveOld = resolve; }) : Promise.resolve([rule]) }));
  const refresh = useFirewall.getState().refreshNative();
  await Promise.resolve();
  assert.equal(await useFirewall.getState().applyNativeRule(input), true);
  resolveOld([]);
  await refresh;
  assert.deepEqual(useFirewall.getState().nativeRules, [rule]);
});

test("removal and enable changes require an authoritative matching result", async () => {
  install(bridge());
  assert.equal(await useFirewall.getState().removeNativeRule(rule.id), false);
  assert.equal(await useFirewall.getState().setNativeRuleEnabled(rule.id, false), false);
  install(bridge({ listRules: async () => [] }));
  assert.equal(await useFirewall.getState().removeNativeRule(rule.id), true);
});

test("hydration respects empty rules, ignores malformed data and never applies native rules", () => {
  const storage = install();
  storage.set("limen-lab-v2", JSON.stringify({ rules: [], settings: {} }));
  useFirewall.getState().hydrate();
  assert.deepEqual(useFirewall.getState().rules, []);
  assert.equal(useFirewall.getState().settings.language, "de");
  storage.set("limen-lab-v2", JSON.stringify({ rules: [null, { action: "allow" }], nativeRules: [rule] }));
  useFirewall.getState().hydrate();
  assert.deepEqual(useFirewall.getState().rules, []);
  assert.deepEqual(useFirewall.getState().nativeRules, []);
});

test("demo/native sources stay isolated when switching modes or updating rules", () => {
  const state = useFirewall.getState();
  state.patchSettings({ labTraffic: true });
  assert.equal(useFirewall.getState().settings.kernelCapture, false);
  state.upsertConnection(conn);
  state.enqueuePending(conn);
  state.patchSettings({ kernelCapture: true });
  assert.equal(useFirewall.getState().settings.labTraffic, false);
  assert.deepEqual(useFirewall.getState().connections, []);
  assert.deepEqual(useFirewall.getState().pending, []);
  const observed = { ...conn, source: "kernel" as const, state: "established" as const };
  state.upsertConnection(observed);
  state.setAppAction(conn.appId, "block");
  assert.equal(useFirewall.getState().connections[0]?.state, "established");
  assert.equal(state.matchAction(observed), null);
});

test("an application demo decision resolves all matching pending requests without losing them", () => {
  const state = useFirewall.getState();
  state.patchSettings({ labTraffic: true });
  state.enqueuePending(conn);
  state.enqueuePending({ ...conn, id: "lab2", direction: "in", localPort: 443 });
  state.decide(useFirewall.getState().pending[0]!.id, "allow", "app");
  assert.equal(useFirewall.getState().pending.length, 0);
  assert.equal(useFirewall.getState().connections.length, 2);
  assert.equal(useFirewall.getState().allowedCount, 2);
});

test("non-admin rule access failure preserves successfully read platform status", async () => {
  install(bridge({ getStatus: async () => ({ ...status, elevated: false }), listRules: async () => { throw new Error("Access denied"); } }));
  await useFirewall.getState().refreshNative();
  assert.equal(useFirewall.getState().nativeStatus?.elevated, false);
  assert.equal(useFirewall.getState().nativeStatus?.available, true);
  assert.match(useFirewall.getState().nativeError!, /Access denied/);
});

test("native confirmation accepts equivalent Windows-normalized IPv6 addresses", async () => {
  const normalized = { ...rule, remoteAddress: "2001:db8::1" };
  install(bridge({ applyRule: async () => normalized, listRules: async () => [normalized] }));
  assert.equal(await useFirewall.getState().applyNativeRule({ ...input, remoteAddress: "2001:0DB8:0:0:0:0:0:1" }), true);
});

test("partial native failure refreshes OS truth while preserving its error across refresh", async () => {
  let changed = false;
  install(bridge({
    applyRule: async () => { changed = true; throw new Error("ActiveStore verification failed after write"); },
    listRules: async () => changed ? [rule] : [],
  }));
  assert.equal(await useFirewall.getState().applyNativeRule(input), false);
  assert.deepEqual(useFirewall.getState().nativeRules, [rule]);
  assert.match(useFirewall.getState().nativeError!, /verification failed after write/);
  await useFirewall.getState().refreshNative();
  assert.match(useFirewall.getState().nativeError!, /verification failed after write/);
  install(bridge({ listRules: async () => { throw new Error("Refresh rejected"); } }));
  await useFirewall.getState().refreshNative();
  assert.match(useFirewall.getState().nativeError!, /verification failed after write/);
  assert.match(useFirewall.getState().nativeError!, /Refresh rejected/);
  useFirewall.getState().clearNativeError();
  assert.equal(useFirewall.getState().nativeError, null);
});

test("recovery read failures preserve the original mutation failure", async () => {
  install(bridge({
    applyRule: async () => { throw new Error("Write outcome uncertain"); },
    listRules: async () => { throw new Error("Refresh access denied"); },
  }));
  assert.equal(await useFirewall.getState().applyNativeRule(input), false);
  assert.match(useFirewall.getState().nativeError!, /Write outcome uncertain/);
  assert.match(useFirewall.getState().nativeError!, /Refresh access denied/);
  assert.equal(useFirewall.getState().nativeBusy, false);
});

test("uncertain mutation recovery is bounded even if the bridge stops responding", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout"] });
  install(bridge({
    applyRule: async () => { throw new Error("Native request failed"); },
    listRules: () => new Promise(() => {}),
  }));
  const result = useFirewall.getState().applyNativeRule(input);
  await Promise.resolve(); await Promise.resolve(); await Promise.resolve();
  context.mock.timers.tick(10000);
  assert.equal(await result, false);
  assert.match(useFirewall.getState().nativeError!, /Native request failed/);
  assert.match(useFirewall.getState().nativeError!, /refresh timed out/);
  assert.equal(useFirewall.getState().nativeBusy, false);
});

test("native canonical executable paths require an apply response bound to the exact submitted alias", async () => {
  const alias = { ...input, program: "C:\\PROGRA~1\\Example\\app.exe" };
  const canonical = { ...rule, program: "C:\\Program Files\\Example\\app.exe" };
  install(bridge({ applyRule: async () => ({ ...canonical, requestedProgram: alias.program }), listRules: async () => [canonical] }));
  assert.equal(await useFirewall.getState().applyNativeRule(alias), true);

  install(bridge({ applyRule: async () => canonical, listRules: async () => [canonical] }));
  assert.equal(await useFirewall.getState().applyNativeRule(alias), false);

  install(bridge({ applyRule: async () => ({ ...canonical, requestedProgram: "C:\\Other\\app.exe" }), listRules: async () => [canonical] }));
  assert.equal(await useFirewall.getState().applyNativeRule(alias), false);

  install(bridge({ applyRule: async () => ({ ...canonical, requestedProgram: alias.program }), listRules: async () => [{ ...canonical, program: "C:\\Other\\app.exe" }] }));
  assert.equal(await useFirewall.getState().applyNativeRule(alias), false);
});
