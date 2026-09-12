import { Trash2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { appById } from "@/lib/firewall/engine";
import { protoLabel } from "@/lib/firewall/format";
import { useFirewall } from "@/lib/firewall/store";
import { useT } from "@/lib/i18n/use-t";

export function RulesView() {
  const t = useT();
  const rules = useFirewall((s) => s.rules);
  const toggleRule = useFirewall((s) => s.toggleRule);
  const removeRule = useFirewall((s) => s.removeRule);

  const sorted = [...rules].sort((a, b) => b.createdAt - a.createdAt);

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted">{t("rules.intro")}</p>
      {sorted.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border px-4 py-12 text-center text-sm text-muted">
          {t("empty.rules")}
        </div>
      ) : (
        <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-surface">
          {sorted.map((r) => {
            const app = appById(r.appId);
            return (
              <li key={r.id} className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm text-fg">{app?.name ?? r.appId}</span>
                    <Badge variant={r.action === "allow" ? "allow" : "block"}>
                      {r.action === "allow" ? t("btn.allow") : t("btn.block")}
                    </Badge>
                    <Badge>
                      {r.scope === "app" ? t("rules.appWide") : r.host ?? t("rules.target")}
                    </Badge>
                  </div>
                  <p className="mt-1 font-mono text-xs text-subtle">
                    {app?.exe} · {r.protocol && r.protocol !== "ANY" ? protoLabel(r.protocol) : "ANY"} ·{" "}
                    {r.port ?? "ANY"} · {t("rules.hits", { n: r.hits })}
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <Switch
                    checked={r.enabled}
                    onCheckedChange={() => toggleRule(r.id)}
                    aria-label={t("set.fw")}
                  />
                  <Button
                    size="icon"
                    variant="ghost"
                    aria-label={t("btn.reset")}
                    onClick={() => removeRule(r.id)}
                  >
                    <Trash2 className="size-4" />
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
