import assert from "node:assert/strict";
import test from "node:test";
import { appIdForKernel, interfaceRates, kernelApp, sockToConn } from "./snapshot";
import type { KernelSocket } from "./kernel-types";

const socket: KernelSocket = {
  id: "socket-1", proto: "TCP", family: 4, localIp: "192.0.2.10", localPort: 52000,
  remoteIp: "198.51.100.4", remotePort: 443, state: "established", inode: "",
  pid: 42, comm: "example.exe", exe: "C:\\Apps\\Example.exe", uid: 0,
};

test("executable identity survives PID changes and Windows path casing", () => {
  assert.equal(appIdForKernel(socket), appIdForKernel({ ...socket, pid: 999, exe: "c:/apps/example.exe" }));
  assert.notEqual(appIdForKernel(socket), appIdForKernel({ ...socket, exe: "C:\\Other\\Example.exe" }));
  assert.notEqual(appIdForKernel({ ...socket, exe: "", pid: 1 }), appIdForKernel({ ...socket, exe: "", pid: 2 }));
});

test("process metadata never invents a verified signature or trusts a filename", () => {
  const app = kernelApp(socket);
  assert.equal(app.name, "Example");
  assert.equal(app.exe, "Example.exe");
  assert.equal(app.signed, null);
  assert.equal(kernelApp({ ...socket, exe: "C:\\Temp\\vite.exe" }).category, "unknown");
  assert.equal(kernelApp({ ...socket, signature: { status: "valid", publisher: "Example Ltd" } }).signed, true);
  assert.equal(kernelApp({ ...socket, signature: { status: "unsigned" } }).signed, false);
});

test("a real snapshot cannot retain simulated blocking or fabricate application traffic", () => {
  const old = { ...sockToConn(socket), state: "blocked" as const, bytesIn: 20000, rateIn: 1200 };
  const conn = sockToConn(socket, old);
  assert.equal(conn.state, "established");
  assert.equal(conn.protocol, "TCP"); // Port 443 alone does not establish HTTPS.
  assert.equal(conn.direction, "unknown");
  assert.equal(conn.bytesIn, 0);
  assert.equal(conn.rateIn, 0);
  assert.equal(conn.trafficMeasured, false);
  assert.equal(conn.localIp, socket.localIp);
});

test("interface rates distinguish a measured quiet interval from an absent baseline or counter reset", () => {
  const previous = { at: 1000, rxBytes: 5000, txBytes: 9000 };
  assert.deepEqual(interfaceRates({ at: 3000, rxBytes: 7000, txBytes: 10000 }, previous), { rx: 1000, tx: 500 });
  assert.deepEqual(interfaceRates({ ...previous, at: 2000 }, previous), { rx: 0, tx: 0 });
  assert.equal(interfaceRates(previous), null);
  assert.equal(interfaceRates({ at: 2000, rxBytes: 10, txBytes: 10 }, previous), null);
  assert.equal(interfaceRates({ ...previous, at: 500 }, previous), null);
  assert.equal(interfaceRates({ ...previous, at: 2000, rxBytes: NaN }, previous), null);
  assert.equal(interfaceRates({ ...previous, at: 2000, trafficAvailable: false }, previous), null);
  assert.equal(interfaceRates({ ...previous, at: 2000, counterSource: "different-adapter" }, previous), null);
});

test("native Windows states preserve established, bound and closing sockets accurately", () => {
  for (const [native, expected] of [
    ["ESTABLISHED", "established"], ["LISTEN", "listen"], ["BOUND", "bound"],
    ["SYNSENT", "syn"], ["SYN_RECEIVED", "syn"], ["TIMEWAIT", "timewait"],
    ["LASTACK", "lastack"], ["CLOSEWAIT", "closewait"], ["FINWAIT1", "finwait1"],
    ["FINWAIT2", "finwait2"], ["CLOSING", "closing"], ["DELETETCB", "closed"],
    ["unexpected", "unknown"],
  ]) assert.equal(sockToConn({ ...socket, state: native! }).state, expected);
});
