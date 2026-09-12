import { createFileRoute } from "@tanstack/react-router";
import { FirewallShell } from "@/components/firewall/shell";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  return <FirewallShell />;
}
