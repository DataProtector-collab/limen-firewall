import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { applySnapshot, simulateConnection, startEngine } from "./engine";
import { getKernelSnapshot } from "./kernel";
import { useFirewall } from "./store";
import { useTelemetry } from "./telemetry-store";
import type { KernelSnapshot } from "./kernel-types";

const snapshot: KernelSnapshot = {
  at: 1000, available: true, capture: "windows", platform: "win32", rxBytes: 1000, txBytes: 2000,
  tcpInuse: 1, udpInuse: 0, sockets: [{ id: "observed1", proto: "TCP", family: 4,
    localIp: "192.0.2.10", localPort: 52000, remoteIp: "198.51.100.20", remotePort: 443,
    state: "ESTABLISHED", inode: "", pid: 42, comm: "Example", exe: "C:\\Apps\\Example.exe", uid: 0 }],
};
let stop: (() => void) | undefined;

beforeEach(() => {
  Object.defineProperty(globalThis, "window", { configurable: true, value: {} });
  applySnapshot({ ...snapshot, available: false, capture: "unavailable" });
  useFirewall.getState().reset();
  useTelemetry.getState().resetSession();
  useFirewall.setState({ hydrated: true });
});
afterEach(() => { stop?.(); stop = undefined; });
const flush = async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); };

test("the flight recorder receives native snapshots and withholds rates after capture fails", () => {
  applySnapshot(snapshot);
  applySnapshot({ ...snapshot, at: 3000, rxBytes: 5000, txBytes: 8000 });
  const observed = useTelemetry.getState();
  assert.equal(observed.samples.length, 2);
  assert.equal(observed.samples[0]!.rx, null);
  assert.equal(observed.samples[1]!.rx, 2000);
  assert.equal(observed.samples[1]!.tx, 3000);
  assert.equal(observed.programs[0]!.exe, "C:\\Apps\\Example.exe");
  applySnapshot({ ...snapshot, at: 5000, available: false, capture: "unavailable", error: "Capture lost" });
  assert.equal(useTelemetry.getState().quality.status, "unavailable");
  assert.equal(useTelemetry.getState().quality.trafficReady, false);
  assert.equal(useTelemetry.getState().samples.length, 2);
});

test("browser capture is explicitly unavailable and never reads a web server", async () => {
  const result = await getKernelSnapshot();
  assert.equal(result.available, false);
  assert.equal(result.capture, "unavailable");
  assert.deepEqual(result.sockets, []);
});

test("unavailable snapshots clear real rows and rates instead of claiming live data", () => {
  applySnapshot(snapshot);
  assert.equal(useFirewall.getState().kernelLive, true);
  applySnapshot({ ...snapshot, at: 2000, available: false, capture: "unavailable", error: "Access denied" });
  assert.equal(useFirewall.getState().kernelLive, false);
  assert.equal(useFirewall.getState().kernelRx, 0);
  assert.deepEqual(useFirewall.getState().connections, []);
  assert.equal(useFirewall.getState().captureError, "Access denied");
  assert.equal(useFirewall.getState().kernelTrafficReady, false);
  assert.deepEqual(useFirewall.getState().samples, []);
});

test("the initial counter baseline never claims a zero rate, while subsequent measured quiet traffic does", () => {
  applySnapshot(snapshot);
  assert.equal(useFirewall.getState().kernelLive, true);
  assert.equal(useFirewall.getState().kernelLastSnapshotAt, 1000);
  assert.equal(useFirewall.getState().kernelTrafficReady, false);
  assert.deepEqual(useFirewall.getState().samples, []);
  applySnapshot({ ...snapshot, at: 3000 });
  assert.equal(useFirewall.getState().kernelTrafficReady, true);
  assert.deepEqual(useFirewall.getState().samples, [{ t: 3000, in: 0, out: 0, blocked: 0 }]);
  applySnapshot({ ...snapshot, at: 5000, rxBytes: 7000, txBytes: 4000 });
  assert.equal(useFirewall.getState().kernelRx, 3000);
  assert.equal(useFirewall.getState().kernelTx, 1000);
});

test("counter failure leaves socket observations available and recovery requires two new counter reads", () => {
  applySnapshot(snapshot);
  applySnapshot({ ...snapshot, at: 2000, rxBytes: 5000 });
  assert.equal(useFirewall.getState().kernelTrafficReady, true);
  applySnapshot({ ...snapshot, at: 3000, rxBytes: 0, txBytes: 0, trafficAvailable: false, trafficError: "Adapter read failed" });
  assert.equal(useFirewall.getState().kernelLive, true);
  assert.equal(useFirewall.getState().connections.length, 1);
  assert.equal(useFirewall.getState().kernelTrafficReady, false);
  assert.equal(useFirewall.getState().trafficError, "Adapter read failed");
  assert.deepEqual(useFirewall.getState().samples, []);
  applySnapshot({ ...snapshot, at: 4000, rxBytes: 9000 });
  assert.equal(useFirewall.getState().kernelTrafficReady, false);
  assert.equal(useFirewall.getState().trafficError, null);
  applySnapshot({ ...snapshot, at: 5000, rxBytes: 10000 });
  assert.equal(useFirewall.getState().kernelTrafficReady, true);
  assert.equal(useFirewall.getState().kernelRx, 1000);
  assert.equal(useFirewall.getState().samples.length, 1);
});

test("new real sockets never trigger simulated prompts or fake decision counts", () => {
  useFirewall.getState().addRule({ appId: "chrome", action: "block", scope: "app", enabled: true });
  applySnapshot(snapshot);
  applySnapshot({ ...snapshot, at: 2000, sockets: [...snapshot.sockets, { ...snapshot.sockets[0]!, id: "observed2" }] });
  assert.equal(useFirewall.getState().connections[0]!.state, "established");
  assert.deepEqual(useFirewall.getState().pending, []);
  assert.equal(useFirewall.getState().blockedCount, 0);
  assert.equal(useFirewall.getState().allowedCount, 0);
});

test("polling never overlaps and stopped sessions ignore late OS replies", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout", "setInterval", "Date"] });
  let reads = 0;
  let resolve!: (value: KernelSnapshot) => void;
  window.limen = {
    platform: "win32", getSnapshot: () => { reads++; return new Promise((done) => { resolve = done; }); },
    getStatus: async () => ({ platform: "win32", available: true, elevated: false, firewallEnabled: true, backend: "windows-firewall" }),
    listRules: async () => [], applyRule: async () => { throw new Error("unused"); },
    removeRule: async () => undefined, setRuleEnabled: async () => { throw new Error("unused"); },
  };
  stop = startEngine();
  context.mock.timers.tick(10000);
  assert.equal(reads, 1);
  stop();
  resolve(snapshot);
  await flush();
  context.mock.timers.tick(10000);
  assert.equal(reads, 1);
  assert.equal(useFirewall.getState().kernelLive, false);
  assert.deepEqual(useFirewall.getState().connections, []);
});

test("turning capture off rejects an in-flight snapshot", async () => {
  let resolve!: (value: KernelSnapshot) => void;
  window.limen = {
    platform: "win32", getSnapshot: () => new Promise((done) => { resolve = done; }),
    getStatus: async () => ({ platform: "win32", available: true, elevated: false, firewallEnabled: true, backend: "windows-firewall" }),
    listRules: async () => [], applyRule: async () => { throw new Error("unused"); },
    removeRule: async () => undefined, setRuleEnabled: async () => { throw new Error("unused"); },
  };
  stop = startEngine();
  useFirewall.getState().patchSettings({ kernelCapture: false });
  resolve(snapshot);
  await flush();
  assert.equal(useFirewall.getState().kernelLive, false);
  assert.deepEqual(useFirewall.getState().connections, []);
});

test("a slow pending capture becomes stale without overlapping reads or inventing traffic", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout", "setInterval", "Date"] });
  let reads = 0;
  const pending: Array<(value: KernelSnapshot) => void> = [];
  window.limen = {
    platform: "win32", getSnapshot: () => { reads++; return new Promise((done) => { pending.push(done); }); },
    getStatus: async () => ({ platform: "win32", available: true, elevated: false, firewallEnabled: true, backend: "windows-firewall" }),
    listRules: async () => [], applyRule: async () => { throw new Error("unused"); },
    removeRule: async () => undefined, setRuleEnabled: async () => { throw new Error("unused"); },
  };
  stop = startEngine();
  assert.equal(useFirewall.getState().capturePending, true);
  pending.shift()!(snapshot);
  await flush();
  assert.equal(useFirewall.getState().capturePending, false);
  context.mock.timers.tick(2000);
  pending.shift()!({ ...snapshot, at: 3000, rxBytes: 7000 });
  await flush();
  assert.equal(useFirewall.getState().kernelTrafficReady, true);
  assert.equal(useFirewall.getState().kernelRx, 3000);
  context.mock.timers.tick(2000);
  assert.equal(useFirewall.getState().capturePending, true);
  context.mock.timers.tick(13000);
  assert.equal(reads, 3);
  assert.equal(useFirewall.getState().captureStale, true);
  assert.equal(useFirewall.getState().kernelLive, false);
  assert.equal(useFirewall.getState().kernelTrafficReady, false);
  assert.equal(useFirewall.getState().kernelLastSnapshotAt, 3000);
  assert.equal(useFirewall.getState().connections.length, 1); // Last observation, explicitly stale.
  assert.deepEqual(useFirewall.getState().samples, []);
  pending.shift()!({ ...snapshot, at: 18000, rxBytes: 9000 });
  await flush();
  assert.equal(useFirewall.getState().captureStale, false);
  assert.equal(useFirewall.getState().kernelLive, true);
  assert.equal(useFirewall.getState().kernelTrafficReady, false); // No rate across the capture gap.
  assert.equal(useFirewall.getState().capturePending, false);
});

test("unrelated settings do not discard a pending observation, but pausing and resuming capture does", async (context) => {
  context.mock.timers.enable({ apis: ["setTimeout", "setInterval", "Date"] });
  const pending: Array<(value: KernelSnapshot) => void> = [];
  window.limen = {
    platform: "win32", getSnapshot: () => new Promise((done) => { pending.push(done); }),
    getStatus: async () => ({ platform: "win32", available: true, elevated: false, firewallEnabled: true, backend: "windows-firewall" }),
    listRules: async () => [], applyRule: async () => { throw new Error("unused"); },
    removeRule: async () => undefined, setRuleEnabled: async () => { throw new Error("unused"); },
  };
  stop = startEngine();
  useFirewall.getState().patchSettings({ language: "en" });
  pending.shift()!(snapshot);
  await flush();
  assert.equal(useFirewall.getState().kernelLastSnapshotAt, 1000);
  context.mock.timers.tick(2000);
  useFirewall.getState().patchSettings({ kernelCapture: false });
  useFirewall.getState().patchSettings({ kernelCapture: true });
  pending.shift()!({ ...snapshot, at: 3000 });
  await flush();
  assert.equal(useFirewall.getState().kernelLastSnapshotAt, null);
  assert.equal(useFirewall.getState().kernelLive, false);
  context.mock.timers.tick(2000);
  pending.shift()!({ ...snapshot, at: 5000 });
  await flush();
  assert.equal(useFirewall.getState().kernelLastSnapshotAt, 5000);
  assert.equal(useFirewall.getState().kernelTrafficReady, false);
});

test("lab traffic requires explicit opt-in and cannot impersonate a native process", () => {
  simulateConnection("chrome");
  assert.deepEqual(useFirewall.getState().pending, []);
  useFirewall.getState().patchSettings({ labTraffic: true });
  simulateConnection("native-C%3A%2FApps%2FExample.exe");
  assert.deepEqual(useFirewall.getState().pending, []);
  simulateConnection("chrome");
  assert.equal(useFirewall.getState().pending.length, 1);
  assert.equal(useFirewall.getState().pending[0]?.connection.source, "lab");
});
