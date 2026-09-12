import { getNativeBridge } from "./native-types";
import type { KernelSnapshot } from "./kernel-types";

export type { KernelSnapshot, KernelSocket } from "./kernel-types";

// Browser demos never read sockets or process information from their server.
export async function getKernelSnapshot(): Promise<KernelSnapshot> {
  const bridge = getNativeBridge();
  if (bridge) return bridge.getSnapshot();
  return {
    at: Date.now(), sockets: [], rxBytes: 0, txBytes: 0,
    tcpInuse: 0, udpInuse: 0, capture: "unavailable",
    available: false, platform: "browser",
    error: "Live capture requires the Windows desktop application.",
  };
}
