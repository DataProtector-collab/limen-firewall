import { Trash2 } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { APP_BY_ID } from "@/lib/firewall/catalog";
import { protoLabel } from "@/lib/firewall/format";
import { useFirewall } from "@/lib/firewall/store";

export function RulesView() {
  const rules = useFirewall((s) => s.rules);
  const toggleRule = useFirewall((s) => s.toggleRule);
  const removeRule = useFirewall((s) => s.removeRule);

  const sorted = [...rules].sort((a, b) => b.createdAt - a.createdAt);

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm text-muted">
        Persistente Regeln. Spezifische Ziele überschreiben App-weite Einträge.
      </p>
      {sorted.length === 0 ? (
        <div className="rounded-lg border border-dashed border-border px-4 py-12 text-center text-sm text-muted">
          Noch keine Regeln. Entscheide im Verbindungsdialog, dann erscheinen sie
          hier.
        </div>
      ) : (
        <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-surface">
          {sorted.map((r) => {
            const app = APP_BY_ID[r.appId];
            return (
              <li key={r.id} className="flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-center">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm text-fg">{app?.name ?? r.appId}</span>
                    <Badge variant={r.action === "allow" ? "allow" : "block"}>
                      {r.action === "allow" ? "Zulassen" : "Blockieren"}
                    </Badge>
                    <Badge>
                      {r.scope === "app" ? "Gesamte App" : r.host ?? "Ziel"}
                    </Badge>
                  </div>
                  <p className="mt-1 font-mono text-xs text-subtle">
                    {app?.exe} · {r.protocol && r.protocol !== "ANY" ? protoLabel(r.protocol) : "ANY"} ·{" "}
                    {r.port ?? "ANY"} · {r.hits} Treffer
                  </p>
                </div>
                <div className="flex items-center gap-3">
                  <Switch
                    checked={r.enabled}
                    onCheckedChange={() => toggleRule(r.id)}
                    aria-label="Regel aktiv"
                  />
                  <Button
                    size="icon"
                    variant="ghost"
                    aria-label="Regel löschen"
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
