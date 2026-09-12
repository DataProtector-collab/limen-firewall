import { Badge } from "@/components/ui/badge";
import { APPS } from "@/lib/firewall/catalog";
import { actionLabel, directionLabel, fmtTime } from "@/lib/firewall/format";
import { useFirewall } from "@/lib/firewall/store";
import { useT } from "@/lib/i18n/use-t";

export function LogView() {
  const t = useT();
  const lang = useFirewall((s) => s.settings.language);
  const log = useFirewall((s) => s.log);
  if (!log.length)
    return (
      <p className="rounded-lg border border-dashed border-border p-8 text-center text-sm text-muted">
        {t("empty.log")}
      </p>
    );
  return (
    <div className="space-y-3">
      <p className="text-sm text-muted">{t("sub.log")}</p>
      <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-surface">
        {log.map((e) => (
          <li key={e.id} className="flex flex-col gap-2 p-4 sm:flex-row sm:items-start">
            <time
              dateTime={new Date(e.at).toISOString()}
              className="shrink-0 font-mono text-xs text-muted"
            >
              {fmtTime(e.at, lang)}
            </time>
            <div className="min-w-0 flex-1">
              <p className="break-all text-sm">
                {APPS.find((app) => app.id === e.appId)?.name || e.appId} → {e.host}
              </p>
              <p className="mt-1 break-all font-mono text-xs text-muted">
                {e.ip}:{e.port} · {e.protocol} · {directionLabel(e.direction, lang)}
              </p>
              <p className="mt-1 break-words text-xs text-muted">{e.reason}</p>
            </div>
            <Badge className="w-fit shrink-0" variant={e.action === "allow" ? "allow" : "block"}>
              {actionLabel(e.action, lang)}
            </Badge>
          </li>
        ))}
      </ul>
    </div>
  );
}
