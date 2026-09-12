import { createServerFn } from "@tanstack/react-start";
import type { KernelSnapshot } from "./kernel-types";

export type { KernelSnapshot, KernelSocket } from "./kernel-types";

export const getKernelSnapshot = createServerFn({ method: "POST" }).handler(
  async (): Promise<KernelSnapshot> => {
    const { readKernelSnapshot } = await import("./kernel-read.server.ts");
    return readKernelSnapshot();
  },
);
