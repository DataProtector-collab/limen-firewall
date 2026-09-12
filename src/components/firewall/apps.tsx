import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { APPS } from "@/lib/firewall/catalog";
import { simulateConnection } from "@/lib/firewall/engine";
import { categoryLabel, fmtBytes, initials } from "@/lib/firewall/format";
import { useFirewall } from "@/lib/firewall/store";
import { cn } from "@/lib/utils";

export function AppsView() {
  const connections = useFirewall((s) => s.connections);
  const rules = useFirewall((s) => s.rules);
  const setAppAction = useFirewall((s) => s.setAppAction);

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted">
        Jede Anwendung mit eigener Richtlinie. Unbekannte Programme lösen den
        Verbindungsdialog aus.
      </p>
      <ul className="grid gap-2">
        {APPS.map((app) => {
          const traffic = connections
            .filter((c) => c.appId === app.id)
            .reduce((a, c) => a + c.bytesIn + c.bytesOut, 0);
          const live = connections.filter(
            (c) => c.appId === app.id && c.state === "established",
          ).length;
          const appRule = rules.find((r) => r.appId === app.id && r.scope === "app" && r.enabled);
          return (
            <li
              key={app.id}
              className="flex flex-col gap-3 rounded-lg border border-border bg-surface p-4 sm:flex-row sm:items-center"
            >
              <div
                className={cn(
                  "flex size-11 shrink-0 items-center justify-center rounded-md font-mono text-xs",
                  app.signed ? "bg-elevated text-accent" : "bg-block/15 text-block",
                )}
              >
                {initials(app.name)}
              </div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <h3 className="text-sm font-medium text-fg">{app.name}</h3>
                  <Badge>{categoryLabel(app.category)}</Badge>
                  {appRule ? (
                    <Badge variant={appRule.action === "allow" ? "allow" : "block"}>
                      {appRule.action === "allow" ? "Erlaubt" : "Gesperrt"}
                    </Badge>
                  ) : (
                    <Badge variant="warn">Nachfrage</Badge>
                  )}
                </div>
                <p className="mt-0.5 truncate font-mono text-xs text-subtle">
                  {app.exe} · PID {app.pid} · {app.publisher}
                </p>
                <p className="mt-1 text-xs text-muted">
                  {live} aktiv · {fmtBytes(traffic)}
                </p>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button size="sm" className="h-11" variant="ghost" onClick={() => simulateConnection(app.id)}>
                  Verbinden
                </Button>
                <Button
                  size="sm"
                  className="h-11"
                  variant={appRule?.action === "block" ? "block" : "outline"}
                  onClick={() => setAppAction(app.id, "block")}
                >
                  Blockieren
                </Button>
                <Button
                  size="sm"
                  className="h-11"
                  variant={appRule?.action === "allow" ? "allow" : "outline"}
                  onClick={() => setAppAction(app.id, "allow")}
                >
                  Zulassen
                </Button>
              </div>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
