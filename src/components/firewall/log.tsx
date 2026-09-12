import { Badge } from "@/components/ui/badge";
import { appById, protocolColor } from "@/lib/firewall/engine";
import { actionLabel, fmtTime, protoLabel } from "@/lib/firewall/format";
import { useFirewall } from "@/lib/firewall/store";
import { useT } from "@/lib/i18n/use-t";
import { cn } from "@/lib/utils";

export function LogView() {
  const t = useT();
  const lang = useFirewall((s) => s.settings.language);
  const log = useFirewall((s) => s.log);

  if (log.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-border px-4 py-12 text-center text-sm text-muted">
        {t("empty.log")}
      </div>
    );
  }

  return (
    <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-surface">
      {log.map((e) => {
        const app = appById(e.appId);
        return (
          <li key={e.id} className="grid gap-1 px-4 py-3 md:grid-cols-[7rem_1fr_auto] md:items-center">
            <span className="font-mono text-xs tabular-nums text-subtle">
              {fmtTime(e.at, lang)}
            </span>
            <div className="min-w-0">
              <p className="truncate text-sm text-fg">
                {app?.name ?? e.appId}
                <span className="text-muted"> → {e.host}</span>
              </p>
              <p className="truncate font-mono text-xs text-subtle">
                {e.ip}:{e.port} ·{" "}
                <span className={protocolColor(e.protocol)}>{protoLabel(e.protocol)}</span>
                {" · "}
                {e.direction === "in" ? t("dir.in") : t("dir.out")} · {e.reason}
              </p>
            </div>
            <Badge variant={e.action === "allow" ? "allow" : "block"} className={cn("w-fit")}>
              {actionLabel(e.action, lang)}
            </Badge>
          </li>
        );
      })}
    </ul>
  );
}
