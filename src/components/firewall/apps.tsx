import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { NativeRuleEditor } from "@/components/firewall/native-controls";
import { APPS } from "@/lib/firewall/catalog";
import { simulateConnection } from "@/lib/firewall/engine";
import { categoryLabel, initials } from "@/lib/firewall/format";
import { isNativeDesktop } from "@/lib/firewall/native-types";
import { useFirewall } from "@/lib/firewall/store";
import type { AppInfo } from "@/lib/firewall/types";
import { useT } from "@/lib/i18n/use-t";

export function AppsView() {
  const t = useT();
  const lang = useFirewall((s) => s.settings.language);
  const connections = useFirewall((s) => s.connections);
  const rules = useFirewall((s) => s.rules);
  const kernelApps = useFirewall((s) => s.kernelApps);
  const lab = useFirewall((s) => s.settings.labTraffic);
  const setAppAction = useFirewall((s) => s.setAppAction);
  const clearError = useFirewall((s) => s.clearNativeError);
  const [editor, setEditor] = useState<AppInfo | null>(null);
  return (
    <div className="space-y-6">
      {isNativeDesktop() ? (
        <section className="space-y-3">
          <h2 className="text-sm font-medium">{t("status.native")}</h2>
          <p className="text-sm text-muted">{t("apps.intro")}</p>
          {kernelApps.length ? (
            <ul className="space-y-2">
              {kernelApps.map((app) => (
                <li
                  key={app.id}
                  className="flex flex-col gap-3 rounded-lg border border-border bg-surface p-4 lg:flex-row lg:items-center"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="break-words text-sm font-medium">{app.name}</h3>
                      <Badge variant="info">{t("status.native")}</Badge>
                    </div>
                    <p dir="ltr" className="mt-1 break-all font-mono text-xs text-muted">
                      {app.path || app.exe} · PID {app.pid || "—"}
                    </p>
                    <p className="mt-2 text-xs text-muted">
                      {t("native.signature")} · {t("native.traffic")}
                    </p>
                    <p className="mt-1 text-xs text-muted">
                      {t("apps.live", {
                        n: connections.filter((c) => c.source === "kernel" && c.appId === app.id)
                          .length,
                      })}
                    </p>
                  </div>
                  <Button
                    variant="outline"
                    className="h-auto min-h-11 whitespace-normal py-2"
                    onClick={() => {
                      clearError();
                      setEditor(app);
                    }}
                  >
                    {t("native.rule")}
                  </Button>
                </li>
              ))}
            </ul>
          ) : (
            <p className="rounded-lg border border-dashed border-border p-8 text-center text-sm text-muted">
              {t("empty.apps")}
            </p>
          )}
        </section>
      ) : null}
      {lab ? (
        <section className="space-y-3">
          <h2 className="text-sm font-medium">{t("status.lab")}</h2>
          <p className="text-sm text-muted">{t("apps.labIntro")}</p>
          <ul className="space-y-2">
            {APPS.map((app) => {
              const appRule = rules.find(
                (r) => r.appId === app.id && r.scope === "app" && r.enabled,
              );
              return (
                <li
                  key={app.id}
                  className="flex flex-col gap-3 rounded-lg border border-border bg-surface p-4 lg:flex-row lg:items-center"
                >
                  <div className="flex min-w-0 flex-1 items-start gap-3">
                    <div className="flex size-11 shrink-0 items-center justify-center rounded-md bg-elevated font-mono text-xs text-accent">
                      {initials(app.name)}
                    </div>
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <h3 className="text-sm font-medium">{app.name}</h3>
                        <Badge variant="accent">{t("status.lab")}</Badge>
                        <Badge>{categoryLabel(app.category, lang)}</Badge>
                      </div>
                      <p className="mt-1 break-all font-mono text-xs text-muted">{app.exe}</p>
                      <Badge
                        className="mt-2"
                        variant={
                          appRule ? (appRule.action === "allow" ? "allow" : "block") : "default"
                        }
                      >
                        {t(
                          appRule
                            ? appRule.action === "allow"
                              ? "badge.allow"
                              : "badge.block"
                            : "badge.default",
                        )}
                      </Badge>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Button variant="ghost" onClick={() => simulateConnection(app.id)}>
                      {t("btn.connect")}
                    </Button>
                    <Button variant="outline" onClick={() => setAppAction(app.id, "block")}>
                      {t("btn.block")}
                    </Button>
                    <Button variant="outline" onClick={() => setAppAction(app.id, "allow")}>
                      {t("btn.allow")}
                    </Button>
                  </div>
                </li>
              );
            })}
          </ul>
        </section>
      ) : null}
      {!isNativeDesktop() && !lab ? <p className="text-sm text-muted">{t("set.labHint")}</p> : null}
      {editor ? <NativeRuleEditor app={editor} onClose={() => setEditor(null)} /> : null}
    </div>
  );
}
