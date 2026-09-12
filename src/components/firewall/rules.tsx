import { useState } from "react";
import { Trash2, RefreshCw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { APPS } from "@/lib/firewall/catalog";
import { directionLabel } from "@/lib/firewall/format";
import { isNativeDesktop, type NativeRule } from "@/lib/firewall/native-types";
import { useFirewall } from "@/lib/firewall/store";
import { useT } from "@/lib/i18n/use-t";

export function RulesView() {
  const t = useT();
  const lang = useFirewall((s) => s.settings.language);
  const rules = useFirewall((s) => s.rules);
  const lab = useFirewall((s) => s.settings.labTraffic);
  const toggleRule = useFirewall((s) => s.toggleRule);
  const removeRule = useFirewall((s) => s.removeRule);
  const nativeRules = useFirewall((s) => s.nativeRules);
  const status = useFirewall((s) => s.nativeStatus);
  const busy = useFirewall((s) => s.nativeBusy);
  const refresh = useFirewall((s) => s.refreshNative);
  const [refreshing, setRefreshing] = useState(false);
  const removeNative = useFirewall((s) => s.removeNativeRule);
  const toggleNative = useFirewall((s) => s.setNativeRuleEnabled);
  const canWrite =
    status?.available && status.backend === "windows-firewall" && status.elevated && !busy;
  return (
    <div className="space-y-6">
      {isNativeDesktop() ? (
        <section className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-medium">{t("native.title")}</h2>
            <Button
              variant="outline"
              size="icon"
              disabled={busy || refreshing}
              onClick={async () => {
                setRefreshing(true);
                try {
                  await refresh();
                } finally {
                  setRefreshing(false);
                }
              }}
              aria-label={t("native.refresh")}
            >
              <RefreshCw className="size-4" />
            </Button>
          </div>
          <p className="text-sm text-muted">{t("native.rulesIntro")}</p>
          <p className="text-xs text-muted">{t("native.profileHint")}</p>
          <p className="text-xs text-muted">{t("native.enforcementHint")}</p>
          {!status?.elevated ? <p className="text-sm text-warn">{t("native.adminNo")}</p> : null}
          {nativeRules.length ? (
            <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-surface">
              {[...nativeRules]
                .sort((a, b) => b.createdAt - a.createdAt)
                .map((r) => (
                  <li key={r.id} className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap gap-2">
                        <Badge variant={r.action === "allow" ? "allow" : "block"}>
                          {t(r.action === "allow" ? "native.ruleAllow" : "native.ruleBlock")}
                        </Badge>
                        <Badge variant="info">{t("native.saved")}</Badge>
                        <Badge>{t(r.enabled ? "native.on" : "native.off")}</Badge>
                      </div>
                      <p dir="ltr" className="mt-2 break-all font-mono text-xs">
                        {r.program}
                      </p>
                      <p className="mt-1 break-all text-xs text-muted">
                        {r.remoteAddress || t("native.allHosts")} ·{" "}
                        {directionLabel(r.direction, lang)} · {r.protocol} · {t("field.local")}:{" "}
                        {r.localPort ?? "*"} · {t("field.target")}: {r.remotePort ?? "*"}
                      </p>
                      <RuleEnforcement rule={r} />
                    </div>
                    <div className="flex shrink-0 items-center gap-3">
                      <label className="flex min-h-11 items-center">
                        <Switch
                          checked={r.enabled}
                          disabled={!canWrite}
                          onCheckedChange={(enabled) => void toggleNative(r.id, enabled)}
                          aria-label={t("native.toggle", { app: r.program })}
                        />
                      </label>
                      <Button
                        variant="ghost"
                        size="icon"
                        disabled={!canWrite}
                        onClick={() => void removeNative(r.id)}
                        aria-label={t("native.remove", { app: r.program })}
                      >
                        <Trash2 className="size-4" />
                      </Button>
                    </div>
                  </li>
                ))}
            </ul>
          ) : (
            <p className="rounded-lg border border-dashed border-border p-8 text-center text-sm text-muted">
              {t("native.rulesEmpty")}
            </p>
          )}
        </section>
      ) : null}
      {lab ? (
        <section className="space-y-3">
          <h2 className="text-sm font-medium">{t("status.lab")}</h2>
          <p className="text-sm text-muted">{t("rules.labIntro")}</p>
          {rules.length ? (
            <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-surface">
              {[...rules]
                .sort((a, b) => b.createdAt - a.createdAt)
                .map((r) => {
                  const name = APPS.find((a) => a.id === r.appId)?.name || r.appId;
                  return (
                    <li key={r.id} className="flex flex-col gap-3 p-4 sm:flex-row sm:items-center">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <p className="text-sm font-medium">{name}</p>
                          <Badge variant={r.action === "allow" ? "allow" : "block"}>
                            {t(r.action === "allow" ? "badge.allow" : "badge.block")}
                          </Badge>
                        </div>
                        <p className="mt-1 break-all text-xs text-muted">
                          {r.scope === "app" ? t("rules.appWide") : r.host} · {r.protocol || "ANY"}{" "}
                          · {r.port ?? "ANY"} · {t("rules.hits", { n: r.hits })}
                        </p>
                      </div>
                      <div className="flex shrink-0 items-center gap-3">
                        <label className="flex min-h-11 items-center">
                          <Switch
                            checked={r.enabled}
                            onCheckedChange={() => toggleRule(r.id)}
                            aria-label={t("rules.toggle", { app: name })}
                          />
                        </label>
                        <Button
                          size="icon"
                          variant="ghost"
                          aria-label={t("rules.remove", { app: name })}
                          onClick={() => removeRule(r.id)}
                        >
                          <Trash2 className="size-4" />
                        </Button>
                      </div>
                    </li>
                  );
                })}
            </ul>
          ) : (
            <p className="rounded-lg border border-dashed border-border p-8 text-center text-sm text-muted">
              {t("empty.rules")}
            </p>
          )}
        </section>
      ) : null}
      {!isNativeDesktop() && !lab ? <p className="text-sm text-muted">{t("set.labHint")}</p> : null}
    </div>
  );
}

function RuleEnforcement({ rule }: { rule: NativeRule }) {
  const t = useT();
  const primary = rule.primaryStatus?.trim();
  const enforcement = rule.enforcementStatus?.filter(Boolean) ?? [];
  const complete = Boolean(primary && enforcement.length);
  const inactive = Boolean(
    (primary && primary !== "OK") || enforcement.some((status) => status !== "Full"),
  );
  const warning = inactive || !complete;
  return (
    <div
      className={
        warning
          ? "mt-3 rounded-md border border-warn/40 bg-warn/10 p-3 text-xs text-warn"
          : "mt-2 text-xs text-muted"
      }
    >
      <p className={warning ? "font-medium" : undefined}>
        {t(
          inactive
            ? "native.enforcementInactive"
            : !complete
              ? "native.enforcementUnknown"
              : "native.enforcementReported",
        )}
      </p>
      {primary || enforcement.length ? (
        <p className="mt-1 break-words">
          {t("native.enforcementReasons", {
            reasons: [primary, ...enforcement].filter(Boolean).join(" · "),
          })}
        </p>
      ) : null}
    </div>
  );
}
