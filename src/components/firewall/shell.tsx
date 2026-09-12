import { useEffect } from "react";
import {
  Activity,
  AppWindow,
  ListTree,
  Radio,
  Settings2,
  Shield,
  ShieldAlert,
  ShieldOff,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { AppsView } from "@/components/firewall/apps";
import { LogView } from "@/components/firewall/log";
import { MonitorView } from "@/components/firewall/monitor";
import { PromptOverlay } from "@/components/firewall/prompt-overlay";
import { RulesView } from "@/components/firewall/rules";
import { SettingsView } from "@/components/firewall/settings";
import { simulateConnection, startEngine } from "@/lib/firewall/engine";
import type { KernelSnapshot } from "@/lib/firewall/kernel-types";
import { useFirewall } from "@/lib/firewall/store";
import type { ViewId } from "@/lib/firewall/types";
import { LOCALE_META } from "@/lib/i18n";
import { useT } from "@/lib/i18n/use-t";
import { APP_VERSION } from "@/lib/version";
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
  const pending = useFirewall((s) => s.pending);
  const enabled = useFirewall((s) => s.settings.enabled);
  const language = useFirewall((s) => s.settings.language);
  const kernelCapture = useFirewall((s) => s.settings.kernelCapture);
  const kernelTcp = useFirewall((s) => s.kernelTcp);
  const kernelLive = useFirewall((s) => s.kernelLive);
  const live = useFirewall(
    (s) => s.connections.filter((c) => c.state === "established" || c.state === "listen").length,
  );

  useEffect(() => startEngine(initialSnap), [initialSnap]);

  useEffect(() => {
    const meta = LOCALE_META[language];
    document.documentElement.lang = language;
    document.documentElement.dir = meta.dir;
  }, [language]);

  const titles: Record<ViewId, { t: string; s: string }> = {
    monitor: { t: t("title.monitor"), s: t("sub.monitor") },
    apps: { t: t("title.apps"), s: t("sub.apps") },
    rules: { t: t("title.rules"), s: t("sub.rules") },
    log: { t: t("title.log"), s: t("sub.log") },
    settings: { t: t("title.settings"), s: t("sub.settings") },
  };

  return (
    <div className="min-h-dvh bg-bg text-fg">
      <div className="mx-auto flex min-h-dvh max-w-7xl">
        <aside className="hidden w-56 shrink-0 flex-col border-r border-border bg-surface md:flex">
          <div className="flex items-center gap-2 px-4 py-5">
            <ShieldMark active={enabled} alert={pending.length > 0} />
            <div>
              <p className="text-sm font-medium tracking-tight">Aegis</p>
              <p className="text-xs text-subtle">
                {t("app.subtitle")} · v{APP_VERSION}
              </p>
            </div>
          </div>
          <nav className="flex flex-1 flex-col gap-1 px-2">
            {NAV.map((item) => {
              const Icon = item.icon;
              const on = view === item.id;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => setView(item.id)}
                  className={cn(
                    "flex h-11 items-center gap-2 rounded-sm px-3 text-sm transition-colors",
                    on
                      ? "bg-elevated text-fg"
                      : "text-muted hover:bg-elevated/60 hover:text-fg",
                  )}
                >
                  <Icon className="size-4" />
                  {t(item.key)}
                  {item.id === "monitor" && pending.length > 0 ? (
                    <span className="ms-auto size-2 rounded-full bg-warn" />
                  ) : null}
                </button>
              );
            })}
          </nav>
          <div className="border-t border-border px-4 py-4 text-xs text-subtle">
            <p className="flex items-center gap-1.5">
              {enabled ? (
                <Shield className="size-3.5 text-allow" />
              ) : (
                <ShieldOff className="size-3.5 text-block" />
              )}
              {enabled ? t("status.protected") : t("status.inactive")}
            </p>
            <p className="mt-1 font-mono tabular-nums">{t("status.sockets", { n: live })}</p>
            {kernelCapture ? (
              <p className={kernelLive ? "mt-1 text-allow" : "mt-1 text-warn"}>
                {t("status.kernel")} · {kernelLive ? t("status.kernelLive") : t("status.kernelErr")}
                {kernelLive ? ` · TCP ${kernelTcp}` : ""}
              </p>
            ) : null}
          </div>
        </aside>

        <div className="flex min-w-0 flex-1 flex-col">
          <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-border bg-bg/90 px-4 py-3 backdrop-blur-sm">
            <div className="md:hidden">
              <ShieldMark active={enabled} alert={pending.length > 0} />
            </div>
            <div className="min-w-0 flex-1">
              <h1 className="truncate text-base font-medium leading-tight">
                {titles[view].t}
              </h1>
              <p className="truncate text-xs text-muted">{titles[view].s}</p>
            </div>
            <Button
              size="icon"
              variant="outline"
              onClick={() => simulateConnection()}
              className="sm:hidden"
              aria-label={t("btn.new")}
            >
              <ShieldAlert className="size-4" />
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => simulateConnection()}
              className="hidden sm:inline-flex"
            >
              <ShieldAlert className="size-4" />
              {t("btn.new")}
            </Button>
          </header>

          <main className="flex-1 px-4 py-4 pb-24 md:px-6 md:pb-8">
            {view === "monitor" ? <MonitorView /> : null}
            {view === "apps" ? <AppsView /> : null}
            {view === "rules" ? <RulesView /> : null}
            {view === "log" ? <LogView /> : null}
            {view === "settings" ? <SettingsView /> : null}
          </main>
        </div>
      </div>

      <nav className="fixed inset-x-0 bottom-0 z-30 border-t border-border bg-surface/95 backdrop-blur-sm md:hidden">
        <div className="grid grid-cols-5">
          {NAV.map((item) => {
            const Icon = item.icon;
            const on = view === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => setView(item.id)}
                className={cn(
                  "flex h-14 flex-col items-center justify-center gap-0.5 text-xs",
                  on ? "text-fg" : "text-muted",
                )}
              >
                <Icon className="size-4" />
                {t(item.key)}
              </button>
            );
          })}
        </div>
      </nav>

      <PromptOverlay />
    </div>
  );
}

function ShieldMark({ active, alert }: { active: boolean; alert: boolean }) {
  return (
    <div className="relative flex size-9 items-center justify-center rounded-md bg-elevated">
      {alert ? (
        <ShieldAlert className="size-5 text-warn" />
      ) : active ? (
        <Shield className="size-5 text-allow" />
      ) : (
        <ShieldOff className="size-5 text-block" />
      )}
      {alert ? (
        <span className="pulse-ring absolute inset-0 rounded-md border border-warn" />
      ) : null}
    </div>
  );
}
