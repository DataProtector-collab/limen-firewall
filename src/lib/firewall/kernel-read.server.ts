import { readdirSync, readFileSync, readlinkSync } from "node:fs";
import type { KernelSnapshot, KernelSocket } from "./kernel-types";

const TCP_STATE: Record<string, string> = {
  "01": "established",
  "02": "syn",
  "03": "syn",
  "04": "timewait",
  "05": "timewait",
  "06": "timewait",
  "07": "timewait",
  "08": "timewait",
  "09": "listen",
  "0A": "listen",
  "0B": "syn",
};

function ipv4(hex: string): string {
  const n = Number.parseInt(hex, 16);
  if (!Number.isFinite(n)) return "0.0.0.0";
  return `${n & 255}.${(n >> 8) & 255}.${(n >> 16) & 255}.${(n >> 24) & 255}`;
}

function ipv6(hex: string): string {
  if (hex.length < 32) return "::";
  const bytes: number[] = [];
  for (let i = 0; i < 32; i += 8) {
    const word = Number.parseInt(hex.slice(i, i + 8), 16);
    if (!Number.isFinite(word)) return "::";
    bytes.push(word & 255, (word >> 8) & 255, (word >> 16) & 255, (word >> 24) & 255);
  }
  const mapped =
    bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
  if (mapped) {
    return `${bytes[12]}.${bytes[13]}.${bytes[14]}.${bytes[15]}`;
  }
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(((bytes[i]! << 8) | bytes[i + 1]!).toString(16));
  }
  let bestStart = -1;
  let bestLen = 0;
  let runStart = -1;
  for (let i = 0; i <= 8; i++) {
    if (i < 8 && groups[i] === "0") {
      if (runStart < 0) runStart = i;
    } else if (runStart >= 0) {
      const len = i - runStart;
      if (len > bestLen) {
        bestStart = runStart;
        bestLen = len;
      }
      runStart = -1;
    }
  }
  if (bestLen >= 2) {
    const head = groups.slice(0, bestStart).join(":");
    const tail = groups.slice(bestStart + bestLen).join(":");
    return `${head}::${tail}`.replace(/^::$/, "::");
  }
  return groups.join(":");
}

function parseTable(path: string, proto: "TCP" | "UDP", v6: boolean): Omit<KernelSocket, "pid" | "comm" | "exe">[] {
  let raw = "";
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    return [];
  }
  const lines = raw.split("\n").slice(1);
  const out: Omit<KernelSocket, "pid" | "comm" | "exe">[] = [];
  for (const line of lines) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 10) continue;
    const [lAddr, lPortHex] = cols[1]!.split(":");
    const [rAddr, rPortHex] = cols[2]!.split(":");
    if (!lAddr || !lPortHex || !rAddr || !rPortHex) continue;
    const localIp = v6 ? ipv6(lAddr) : ipv4(lAddr);
    const remoteIp = v6 ? ipv6(rAddr) : ipv4(rAddr);
    const localPort = Number.parseInt(lPortHex, 16);
    const remotePort = Number.parseInt(rPortHex, 16);
    const st = cols[3] ?? "01";
    const inode = cols[9] ?? "0";
    const uid = Number.parseInt(cols[7] ?? "0", 10);
    out.push({
      id: `k-${proto}-${v6 ? 6 : 4}-${inode}-${localPort}-${remotePort}`,
      proto,
      family: v6 ? 6 : 4,
      localIp,
      localPort,
      remoteIp,
      remotePort,
      state: proto === "UDP" ? (remotePort === 0 ? "listen" : "established") : (TCP_STATE[st] ?? "established"),
      inode,
      uid,
    });
  }
  return out;
}

function inodeToPid(): Map<string, { pid: number; comm: string; exe: string }> {
  const map = new Map<string, { pid: number; comm: string; exe: string }>();
  let pids: string[] = [];
  try {
    pids = readdirSync("/proc");
  } catch {
    return map;
  }
  for (const pidStr of pids) {
    if (!/^\d+$/.test(pidStr)) continue;
    const pid = Number(pidStr);
    let comm = "";
    let exe = "";
    try {
      comm = readFileSync(`/proc/${pid}/comm`, "utf8").trim();
    } catch {
      continue;
    }
    try {
      exe = readlinkSync(`/proc/${pid}/exe`);
    } catch {
      exe = comm;
    }
    let fds: string[] = [];
    try {
      fds = readdirSync(`/proc/${pid}/fd`);
    } catch {
      continue;
    }
    for (const fd of fds) {
      try {
        const target = readlinkSync(`/proc/${pid}/fd/${fd}`);
        if (target.startsWith("socket:[")) {
          const ino = target.slice(8, -1);
          if (!map.has(ino)) map.set(ino, { pid, comm, exe });
        }
      } catch {
        /* ignore */
      }
    }
  }
  return map;
}

function ifaceBytes(): { rx: number; tx: number } {
  let raw = "";
  try {
    raw = readFileSync("/proc/net/dev", "utf8");
  } catch {
    return { rx: 0, tx: 0 };
  }
  let rx = 0;
  let tx = 0;
  for (const line of raw.split("\n").slice(2)) {
    const idx = line.indexOf(":");
    if (idx < 0) continue;
    const name = line.slice(0, idx).trim();
    if (!name || name === "lo") continue;
    const cols = line.slice(idx + 1).trim().split(/\s+/);
    rx += Number(cols[0] ?? 0);
    tx += Number(cols[8] ?? 0);
  }
  return { rx, tx };
}

function sockCounts(): { tcp: number; udp: number } {
  let raw = "";
  try {
    raw = readFileSync("/proc/net/sockstat", "utf8");
  } catch {
    return { tcp: 0, udp: 0 };
  }
  let tcp = 0;
  let udp = 0;
  for (const line of raw.split("\n")) {
    if (line.startsWith("TCP:")) {
      const m = /inuse (\d+)/.exec(line);
      if (m) tcp = Number(m[1]);
    }
    if (line.startsWith("UDP:")) {
      const m = /inuse (\d+)/.exec(line);
      if (m) udp = Number(m[1]);
    }
  }
  return { tcp, udp };
}

export function readKernelSnapshot(): KernelSnapshot {
  const owners = inodeToPid();
  const rows = [
    ...parseTable("/proc/net/tcp", "TCP", false),
    ...parseTable("/proc/net/tcp6", "TCP", true),
    ...parseTable("/proc/net/udp", "UDP", false),
    ...parseTable("/proc/net/udp6", "UDP", true),
  ];
  const sockets: KernelSocket[] = rows.map((r) => {
    const owner = owners.get(r.inode);
    return {
      ...r,
      pid: owner?.pid ?? null,
      comm: owner?.comm ?? "kernel",
      exe: owner?.exe ?? "kernel",
    };
  });
  const nic = ifaceBytes();
  const counts = sockCounts();
  return {
    at: Date.now(),
    sockets,
    rxBytes: nic.rx,
    txBytes: nic.tx,
    tcpInuse: counts.tcp,
    udpInuse: counts.udp,
    capture: "kernel",
  };
}
