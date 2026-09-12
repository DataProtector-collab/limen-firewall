import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { applySnapshot, simulateConnection, startEngine } from "./engine";
import { getKernelSnapshot } from "./kernel";
import { useFirewall } from "./store";
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
  useFirewall.setState({ hydrated: true });
});
afterEach(() => { stop?.(); stop = undefined; });
const flush = async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); };

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
