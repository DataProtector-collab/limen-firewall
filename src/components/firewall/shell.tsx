import { useEffect } from "react";
import { Activity, AppWindow, FlaskConical, ListTree, Radio, Settings2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { AppsView } from "@/components/firewall/apps";
import { LogView } from "@/components/firewall/log";
import { MonitorView } from "@/components/firewall/monitor";
import { PromptOverlay } from "@/components/firewall/prompt-overlay";
import { RulesView } from "@/components/firewall/rules";
import { SettingsView } from "@/components/firewall/settings";
import { NativeError, NativeStatusPanel } from "@/components/firewall/native-controls";
import { simulateConnection, startEngine } from "@/lib/firewall/engine";
import type { KernelSnapshot } from "@/lib/firewall/kernel-types";
import { isNativeDesktop } from "@/lib/firewall/native-types";
import { useFirewall } from "@/lib/firewall/store";
import type { ViewId } from "@/lib/firewall/types";
import { useT } from "@/lib/i18n/use-t";
import { APP_NAME, APP_VERSION } from "@/lib/version";
import { cn } from "@/lib/utils";

const NAV: { id: ViewId; key: string; icon: typeof Activity }[] = [
  { id: "monitor", key: "nav.monitor", icon: Activity },
  { id: "apps", key: "nav.apps", icon: AppWindow },
  { id: "rules", key: "nav.rules", icon: ListTree },
  { id: "log", key: "nav.log", icon: Radio },
  { id: "settings", key: "nav.settings", icon: Settings2 },
];

export function FirewallShell({ initialSnap }: { initialSnap?: KernelSnapshot | null }) {
  const t = useT();
  const view = useFirewall((s) => s.view);
  const setView = useFirewall((s) => s.setView);
  const language = useFirewall((s) => s.settings.language);
  const capture = useFirewall((s) => s.settings.kernelCapture);
  const lab = useFirewall((s) => s.settings.labTraffic);
  const live = useFirewall((s) => s.kernelLive);
  const error = useFirewall((s) => s.captureError);
  const status = useFirewall((s) => s.nativeStatus);
  const native = isNativeDesktop();
  const statusNeedsAttention = Boolean(
    status &&
    (!status.available ||
      !status.elevated ||
      !status.firewallEnabled ||
      status.reason ||
      status.profiles?.some((profile) => !profile.enabled)),
  );
  useEffect(() => startEngine(initialSnap), [initialSnap]);
  useEffect(() => {
    document.documentElement.lang = language === "de" ? "de" : "en";
    document.documentElement.dir = "ltr";
  }, [language]);
  return (
    <div className="min-h-dvh bg-bg text-fg">
      <div className="mx-auto flex min-h-dvh max-w-7xl">
        <aside className="hidden w-56 shrink-0 flex-col border-e border-border bg-surface md:flex">
          <div className="flex items-center gap-3 px-4 py-5">
            <Activity className="size-7 shrink-0 text-accent" />
            <div className="min-w-0">
              <p className="font-medium">{APP_NAME}</p>
              <p className="text-xs text-muted">
                {t("app.subtitle")} · v{APP_VERSION}
              </p>
            </div>
          </div>
          <nav className="flex flex-1 flex-col gap-1 px-2" aria-label={APP_NAME}>
            {NAV.map(({ id, key, icon: Icon }) => (
              <button
                key={id}
                type="button"
                onClick={() => setView(id)}
                aria-current={view === id ? "page" : undefined}
                className={cn(
                  "flex min-h-11 items-center gap-2 rounded-sm px-3 text-sm",
                  view === id ? "bg-elevated text-fg" : "text-muted hover:bg-elevated",
                )}
              >
                <Icon className="size-4" />
                {t(key)}
              </button>
            ))}
          </nav>
          <div className="space-y-1 border-t border-border p-4 text-xs text-muted">
            <p>{t(native ? "status.native" : "status.lab")}</p>
            {native ? (
              <>
                <p>{t(capture ? "status.observing" : "status.paused")}</p>
                <p className={live ? "text-muted" : "text-warn"}>
                  {t(live ? "status.live" : "status.unavailable")}
                </p>
              </>
            ) : null}
          </div>
        </aside>
        <div className="min-w-0 flex-1">
          <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-border bg-bg/95 px-4 py-3">
            <div className="min-w-0 flex-1">
              <h1 className="text-base font-medium">{t("title." + view)}</h1>
              <p className="text-xs text-muted">{t("sub." + view)}</p>
            </div>
            {lab ? (
              <Button
                variant="outline"
                onClick={() => simulateConnection()}
                aria-label={t("btn.new")}
                className="shrink-0"
              >
                <FlaskConical className="size-4" />
                <span className="hidden lg:inline">{t("btn.new")}</span>
              </Button>
            ) : null}
          </header>
          <main className="space-y-4 p-4 pb-24 md:p-6 md:pb-8">
            {native && view !== "settings" ? (
              <details
                open={statusNeedsAttention}
                className="rounded-lg border border-border bg-surface"
              >
                <summary
                  className={cn(
                    "cursor-pointer px-3 py-2 text-xs",
                    statusNeedsAttention ? "text-warn" : "text-muted",
                  )}
                >
                  {t("native.title")} ·{" "}
                  {t(
                    !status
                      ? "status.loading"
                      : statusNeedsAttention
                        ? "native.statusAttention"
                        : "native.statusDetails",
                  )}
                </summary>
                <div className="border-t border-border [&>section]:rounded-none [&>section]:border-0">
                  <NativeStatusPanel />
                </div>
              </details>
            ) : (
              <NativeStatusPanel detailed={view === "settings"} />
            )}
            <div className="sticky top-24 z-40">
              <NativeError dismissible />
            </div>
            {native && error ? (
              <p
                role="alert"
                className="break-words rounded-md border border-warn/40 bg-warn/10 p-3 text-sm text-warn"
              >
                {t("status.unavailable")}: {error}
              </p>
            ) : null}
            {view === "monitor" ? (
              <MonitorView />
            ) : view === "apps" ? (
              <AppsView />
            ) : view === "rules" ? (
              <RulesView />
            ) : view === "log" ? (
              <LogView />
            ) : (
              <SettingsView />
            )}
          </main>
        </div>
      </div>
      <nav
        className="fixed inset-x-0 bottom-0 z-30 grid grid-cols-5 border-t border-border bg-surface md:hidden"
        aria-label={APP_NAME}
      >
        {NAV.map(({ id, key, icon: Icon }) => (
          <button
            key={id}
            type="button"
            onClick={() => setView(id)}
            aria-current={view === id ? "page" : undefined}
            aria-label={t(key)}
            className={cn(
              "flex h-16 min-w-0 flex-col items-center justify-center gap-1 px-1 text-xs",
              view === id ? "text-fg" : "text-muted",
            )}
          >
            <Icon className="size-4" />
            <span className="w-full truncate text-center">{t(key)}</span>
          </button>
        ))}
      </nav>
      {lab ? <PromptOverlay /> : null}
    </div>
  );
}
