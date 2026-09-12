export interface KernelSocket {
  id: string;
  proto: "TCP" | "UDP";
  family: 4 | 6;
  localIp: string;
  localPort: number;
  remoteIp: string;
  remotePort: number;
  state: string;
  inode: string;
  pid: number | null;
  comm: string;
  exe: string;
  uid: number;
  direction?: "in" | "out" | "unknown";
  signature?: { status: "valid" | "unsigned" | "unknown"; publisher?: string };
}

export interface KernelSnapshot {
  at: number;
  sockets: KernelSocket[];
  rxBytes: number;
  txBytes: number;
  tcpInuse: number;
  udpInuse: number;
  capture: "windows" | "linux" | "unavailable";
  available: boolean;
  platform: string;
  error?: string;
}
