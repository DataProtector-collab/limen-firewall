import type { KernelSocket } from "./kernel-types";
import type { AppInfo, Connection, ConnState } from "./types";

export function appIdForKernel(sock: KernelSocket): string {
  const path = sock.exe.trim();
  // PID changes do not invalidate a program identity. Unknown paths are never
  // usable as native rules; scope those identities to the observed process.
  if (/^[a-z]:[\\/]/i.test(path)) return `native-${encodeURIComponent(path.replace(/\\/g, "/").toLowerCase())}`;
  if (path.startsWith("/")) return `native-${encodeURIComponent(path)}`;
  return `process-${sock.pid ?? "unknown"}-${encodeURIComponent(sock.comm || "unknown")}`;
}

export function kernelApp(sock: KernelSocket): AppInfo {
  const base = sock.exe.split(/[\\/]/).pop() || sock.comm || "Unknown process";
  return {
    id: appIdForKernel(sock), name: base.replace(/\.exe$/i, ""), exe: base,
    publisher: sock.signature?.publisher ?? "",
    signed: sock.signature?.status === "valid" ? true : sock.signature?.status === "unsigned" ? false : null,
    pid: sock.pid ?? 0, category: "unknown", path: sock.exe,
  };
}

export function sockToConn(sock: KernelSocket, prev?: Connection): Connection {
  const states: Record<string, ConnState> = {
    LISTEN: "listen", ESTABLISHED: "established", SYN: "syn", SYNSENT: "syn", SYNRECEIVED: "syn",
    TIMEWAIT: "timewait", BOUND: "bound", CLOSED: "closed", CLOSING: "closing", CLOSEWAIT: "closewait",
    FINWAIT1: "finwait1", FINWAIT2: "finwait2", LASTACK: "lastack", DELETETCB: "closed",
  };
  return {
    id: sock.id, appId: appIdForKernel(sock), protocol: sock.proto,
    direction: sock.direction ?? "unknown", localIp: sock.localIp, localPort: sock.localPort,
    remoteHost: sock.remoteIp || "—", remoteIp: sock.remoteIp, remotePort: sock.remotePort,
    country: sock.family === 6 ? "IPv6" : "IPv4",
    state: states[sock.state.toUpperCase().replace(/[^A-Z0-9]/g, "")] ?? "unknown",
    // Socket tables provide no per-process byte counts. Interface totals must
    // never be attributed to programs by inventing an equal share.
    bytesIn: 0, bytesOut: 0, rateIn: 0, rateOut: 0, trafficMeasured: false,
    startedAt: prev?.startedAt ?? Date.now(), source: "kernel", inode: sock.inode,
    pid: sock.pid ?? undefined,
  };
}

export function interfaceRates(current: { at: number; rxBytes: number; txBytes: number }, previous?: { at: number; rxBytes: number; txBytes: number }): { rx: number; tx: number } {
  if (!previous || current.at <= previous.at) return { rx: 0, tx: 0 };
  const seconds = (current.at - previous.at) / 1000;
  return {
    rx: Number.isFinite(current.rxBytes) ? Math.max(0, current.rxBytes - previous.rxBytes) / seconds : 0,
    tx: Number.isFinite(current.txBytes) ? Math.max(0, current.txBytes - previous.txBytes) / seconds : 0,
  };
}
