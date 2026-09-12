import type { KernelSnapshot, KernelSocket } from "./kernel-types";
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

type InterfaceCounters = Pick<KernelSnapshot, "at" | "rxBytes" | "txBytes" | "trafficAvailable" | "counterSource">;

export function hasInterfaceCounters(snapshot: InterfaceCounters): boolean {
  return snapshot.trafficAvailable !== false &&
    [snapshot.at, snapshot.rxBytes, snapshot.txBytes].every((value) => Number.isFinite(value) && value >= 0);
}

export function interfaceRates(current: InterfaceCounters, previous?: InterfaceCounters): { rx: number; tx: number } | null {
  // A rate needs two comparable measurements. Missing counters, adapter changes,
  // and counter resets require a new baseline; none establish zero traffic.
  if (!previous || !hasInterfaceCounters(current) || !hasInterfaceCounters(previous) ||
      current.at <= previous.at || current.counterSource !== previous.counterSource ||
      current.rxBytes < previous.rxBytes || current.txBytes < previous.txBytes) return null;
  const seconds = (current.at - previous.at) / 1000;
  return {
    rx: (current.rxBytes - previous.rxBytes) / seconds,
    tx: (current.txBytes - previous.txBytes) / seconds,
  };
}
