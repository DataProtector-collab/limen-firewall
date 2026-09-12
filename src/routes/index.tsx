import { createFileRoute } from "@tanstack/react-router";
import { FirewallShell } from "@/components/firewall/shell";
import { getKernelSnapshot } from "@/lib/firewall/kernel";
import type { KernelSnapshot } from "@/lib/firewall/kernel-types";

export const Route = createFileRoute("/")({
  loader: async (): Promise<KernelSnapshot | null> => {
    try {
      return await getKernelSnapshot();
    } catch {
      return null;
    }
  },
  component: Home,
});

function Home() {
  const snap = Route.useLoaderData();
  return <FirewallShell initialSnap={snap} />;
}
