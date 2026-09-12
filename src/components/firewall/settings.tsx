import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { useFirewall } from "@/lib/firewall/store";
import type { DefaultPolicy } from "@/lib/firewall/types";
import { LOCALES, LOCALE_META, type Locale } from "@/lib/i18n";
import { useT } from "@/lib/i18n/use-t";
import { APP_VERSION, RELEASES } from "@/lib/version";
import { cn } from "@/lib/utils";

export function SettingsView() {
  const t = useT();
  const settings = useFirewall((s) => s.settings);
  const patch = useFirewall((s) => s.patchSettings);
  const reset = useFirewall((s) => s.reset);

  return (
    <div className="mx-auto flex max-w-xl flex-col gap-6">
      <Row title={t("set.fw")} hint={t("set.fwHint")}>
        <Switch
          checked={settings.enabled}
          onCheckedChange={(v) => patch({ enabled: v })}
          aria-label={t("set.fw")}
        />
      </Row>

      <Row title={t("set.kernel")} hint={t("set.kernelHint")}>
        <Switch
          checked={settings.kernelCapture}
          onCheckedChange={(v) => patch({ kernelCapture: v })}
          aria-label={t("set.kernel")}
        />
      </Row>

      <Row title={t("set.lab")} hint={t("set.labHint")}>
        <Switch
          checked={settings.labTraffic}
          onCheckedChange={(v) => patch({ labTraffic: v })}
          aria-label={t("set.lab")}
        />
      </Row>

      <section className="rounded-lg border border-border bg-surface p-4">
        <h3 className="text-sm font-medium text-fg">{t("set.out")}</h3>
        <p className="mt-1 text-xs text-muted">{t("set.outHint")}</p>
        <PolicyPicker
          value={settings.defaultPolicy}
          onChange={(defaultPolicy) => patch({ defaultPolicy })}
        />
      </section>

      <section className="rounded-lg border border-border bg-surface p-4">
        <h3 className="text-sm font-medium text-fg">{t("set.in")}</h3>
        <p className="mt-1 text-xs text-muted">{t("set.inHint")}</p>
        <PolicyPicker
          value={settings.inboundPolicy}
          onChange={(inboundPolicy) => patch({ inboundPolicy })}
        />
      </section>

      <Row title={t("set.sys")} hint={t("set.sysHint")}>
        <Switch
          checked={settings.autoAllowSystem}
          onCheckedChange={(v) => patch({ autoAllowSystem: v })}
          aria-label={t("set.sys")}
        />
      </Row>

      <section className="rounded-lg border border-border bg-surface p-4">
        <h3 className="text-sm font-medium text-fg">{t("set.lang")}</h3>
        <p className="mt-1 text-xs text-muted">{t("set.langHint")}</p>
        <div className="mt-3 grid grid-cols-2 gap-1.5 sm:grid-cols-3">
          {LOCALES.map((loc) => (
            <button
              key={loc}
              type="button"
              onClick={() => patch({ language: loc as Locale })}
              className={cn(
                "rounded-sm border px-2 py-2 text-left text-xs transition-colors",
                settings.language === loc
                  ? "border-accent bg-accent/10 text-fg"
                  : "border-border text-muted hover:text-fg",
              )}
            >
              <span className="block font-medium">{LOCALE_META[loc].native}</span>
              <span className="text-subtle">{LOCALE_META[loc].english}</span>
            </button>
          ))}
        </div>
      </section>

      <section className="rounded-lg border border-border bg-surface p-4">
        <h3 className="text-sm font-medium text-fg">{t("ver.title")}</h3>
        <p className="mt-1 font-mono text-xs text-subtle">Aegis v{APP_VERSION}</p>
        <ol className="mt-3 space-y-4">
          {RELEASES.map((rel) => (
            <li key={rel.version} className="border-s border-border ps-3">
              <p className="text-sm text-fg">
                v{rel.version}
                <span className="ms-2 font-mono text-xs text-subtle">{rel.date}</span>
              </p>
              <p className="text-xs text-muted">{rel.title}</p>
              <ul className="mt-1 list-disc ps-4 text-xs text-subtle">
                {rel.items.map((item) => (
                  <li key={item}>{item}</li>
                ))}
              </ul>
            </li>
          ))}
        </ol>
      </section>

      <div className="rounded-lg border border-border bg-elevated p-4 text-xs leading-relaxed text-muted">
        {t("set.note", { version: APP_VERSION })}
      </div>

      <Button variant="outline" onClick={reset}>
        {t("btn.reset")}
      </Button>
    </div>
  );
}

function Row({
  title,
  hint,
  children,
}: {
  title: string;
  hint: string;
  children: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border border-border bg-surface px-4 py-3">
      <div>
        <p className="text-sm font-medium text-fg">{title}</p>
        <p className="text-xs text-muted">{hint}</p>
      </div>
      {children}
    </div>
  );
}

function PolicyPicker({
  value,
  onChange,
}: {
  value: DefaultPolicy;
  onChange: (v: DefaultPolicy) => void;
}) {
  const t = useT();
  const policies: { id: DefaultPolicy; label: string; hint: string }[] = [
    { id: "ask", label: t("policy.ask"), hint: t("policy.askHint") },
    { id: "block", label: t("policy.block"), hint: t("policy.blockHint") },
    { id: "allow", label: t("policy.allow"), hint: t("policy.allowHint") },
  ];
  return (
    <div className="mt-3 grid grid-cols-3 gap-1.5">
      {policies.map((p) => (
        <button
          key={p.id}
          type="button"
          onClick={() => onChange(p.id)}
          className={cn(
            "rounded-sm border px-2 py-2 text-left transition-colors",
            value === p.id
              ? "border-accent bg-accent/10 text-fg"
              : "border-border text-muted hover:text-fg",
          )}
        >
          <span className="block text-xs font-medium">{p.label}</span>
          <span className="mt-0.5 block text-xs text-subtle">{p.hint}</span>
        </button>
      ))}
    </div>
  );
}
