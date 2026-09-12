import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { APPS } from "@/lib/firewall/catalog";
import { simulateConnection } from "@/lib/firewall/engine";
import { categoryLabel, fmtBytes, initials } from "@/lib/firewall/format";
import { useFirewall } from "@/lib/firewall/store";
import type { AppInfo } from "@/lib/firewall/types";
import { useT } from "@/lib/i18n/use-t";
import { cn } from "@/lib/utils";

export function AppsView() {
  const t = useT();
  const lang = useFirewall((s) => s.settings.language);
  const connections = useFirewall((s) => s.connections);
  const rules = useFirewall((s) => s.rules);
  const setAppAction = useFirewall((s) => s.setAppAction);
  const kernelApps = useFirewall((s) => s.kernelApps);
  const labTraffic = useFirewall((s) => s.settings.labTraffic);

  const seen = new Set<string>();
  const list: AppInfo[] = [];
  for (const a of kernelApps) {
    if (seen.has(a.id)) continue;
    seen.add(a.id);
    list.push(a);
  }
  if (labTraffic) {
    for (const a of APPS) {
      if (seen.has(a.id)) continue;
      seen.add(a.id);
      list.push(a);
    }
  }

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted">{t("apps.intro")}</p>
      {list.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border px-4 py-12 text-center text-sm text-muted">
          {t("empty.conns")}
        </div>
      ) : (
        <ul className="grid gap-2">
          {list.map((app) => {
            const traffic = connections
              .filter((c) => c.appId === app.id)
              .reduce((a, c) => a + c.bytesIn + c.bytesOut, 0);
            const live = connections.filter(
              (c) =>
                c.appId === app.id &&
                (c.state === "established" || c.state === "listen"),
            ).length;
            const appRule = rules.find(
              (r) => r.appId === app.id && r.scope === "app" && r.enabled,
            );
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
                    <Badge>{categoryLabel(app.category, lang)}</Badge>
                    {appRule ? (
                      <Badge variant={appRule.action === "allow" ? "allow" : "block"}>
                        {appRule.action === "allow" ? t("badge.allow") : t("badge.block")}
                      </Badge>
                    ) : (
                      <Badge variant="warn">{t("badge.ask")}</Badge>
                    )}
                  </div>
                  <p className="mt-0.5 truncate font-mono text-xs text-subtle">
                    {app.exe} · PID {app.pid} · {app.publisher}
                  </p>
                  <p className="mt-1 text-xs text-muted">
                    {t("apps.live", { n: live, bytes: fmtBytes(traffic) })}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  {labTraffic ? (
                    <Button
                      size="sm"
                      className="h-11"
                      variant="ghost"
                      onClick={() => simulateConnection(app.id)}
                    >
                      {t("btn.connect")}
                    </Button>
                  ) : null}
                  <Button
                    size="sm"
                    className="h-11"
                    variant={appRule?.action === "block" ? "block" : "outline"}
                    onClick={() => setAppAction(app.id, "block")}
                  >
                    {t("btn.block")}
                  </Button>
                  <Button
                    size="sm"
                    className="h-11"
                    variant={appRule?.action === "allow" ? "allow" : "outline"}
                    onClick={() => setAppAction(app.id, "allow")}
                  >
                    {t("btn.allow")}
                  </Button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
