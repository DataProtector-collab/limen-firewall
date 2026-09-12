import { useState, type ReactNode } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { ModalContent } from "@/components/firewall/native-controls";
import { isNativeDesktop } from "@/lib/firewall/native-types";
import { useFirewall } from "@/lib/firewall/store";
import type { DefaultPolicy } from "@/lib/firewall/types";
import { LOCALES, LOCALE_META } from "@/lib/i18n";
import { useT } from "@/lib/i18n/use-t";
import { APP_NAME, APP_VERSION } from "@/lib/version";
import { cn } from "@/lib/utils";

export function SettingsView() {
  const t = useT();
  const settings = useFirewall((s) => s.settings);
  const patch = useFirewall((s) => s.patchSettings);
  const reset = useFirewall((s) => s.reset);
  const [confirmReset, setConfirmReset] = useState(false);
  return (
    <div className="mx-auto max-w-2xl space-y-4">
      {isNativeDesktop() ? (
        <Row title={t("set.observe")} hint={t("set.observeHint")}>
          <Switch
            checked={settings.kernelCapture}
            onCheckedChange={(kernelCapture) => patch({ kernelCapture })}
            aria-label={t("set.observe")}
          />
        </Row>
      ) : null}
      <Row title={t("set.lab")} hint={t("set.labHint")}>
        <Switch
          checked={settings.labTraffic}
          onCheckedChange={(labTraffic) => patch({ labTraffic })}
          aria-label={t("set.lab")}
        />
      </Row>
      {settings.labTraffic ? (
        <section className="space-y-3 rounded-lg border border-border bg-surface p-4">
          <h2 className="text-sm font-medium">{t("status.lab")}</h2>
          <p className="text-xs text-muted">{t("prompt.hint")}</p>
          <Row title={t("set.labEnabled")} hint={t("set.labEnabledHint")}>
            <Switch
              checked={settings.enabled}
              onCheckedChange={(enabled) => patch({ enabled })}
              aria-label={t("set.labEnabled")}
            />
          </Row>
          <PolicyPicker
            name="outbound-lab-policy"
            title={t("set.out")}
            value={settings.defaultPolicy}
            onChange={(defaultPolicy) => patch({ defaultPolicy })}
          />
          <PolicyPicker
            name="inbound-lab-policy"
            title={t("set.in")}
            value={settings.inboundPolicy}
            onChange={(inboundPolicy) => patch({ inboundPolicy })}
          />
          <Row title={t("set.sys")} hint={t("set.sysHint")}>
            <Switch
              checked={settings.autoAllowSystem}
              onCheckedChange={(autoAllowSystem) => patch({ autoAllowSystem })}
              aria-label={t("set.sys")}
            />
          </Row>
        </section>
      ) : null}
      <section className="rounded-lg border border-border bg-surface p-4">
        <h2 className="text-sm font-medium">{t("set.lang")}</h2>
        <p className="mt-1 text-xs text-muted">{t("set.langHint")}</p>
        <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3">
          {LOCALES.map((loc) => (
            <button
              key={loc}
              type="button"
              aria-pressed={settings.language === loc}
              onClick={() => patch({ language: loc })}
              className={cn(
                "min-h-11 rounded-sm border px-3 py-2 text-start text-xs",
                settings.language === loc
                  ? "border-accent bg-accent/10 text-fg"
                  : "border-border text-muted",
              )}
            >
              <span className="block font-medium" lang={loc}>
                {LOCALE_META[loc].native}
              </span>
              <span>
                {loc === "en" || loc === "de" ? LOCALE_META[loc].english : "English fallback"}
              </span>
            </button>
          ))}
        </div>
      </section>
      <section className="rounded-lg border border-border bg-surface p-4">
        <h2 className="text-sm font-medium">
          {t("ver.title")} · {APP_NAME} {APP_VERSION}
        </h2>
        <p className="mt-2 text-xs text-muted">{t("ver.note")}</p>
      </section>
      <Dialog.Root open={confirmReset} onOpenChange={setConfirmReset}>
        <Dialog.Trigger asChild>
          <Button variant="outline" className="h-auto min-h-11 whitespace-normal py-2">
            {t("btn.reset")}
          </Button>
        </Dialog.Trigger>
        <ModalContent title={t("reset.title")} description={t("reset.hint")}>
          <div className="flex flex-wrap justify-end gap-2">
            <Dialog.Close asChild>
              <Button variant="outline">{t("btn.cancel")}</Button>
            </Dialog.Close>
            <Button
              className="h-auto min-h-11 whitespace-normal py-2"
              onClick={() => {
                reset();
                setConfirmReset(false);
              }}
            >
              {t("btn.resetConfirm")}
            </Button>
          </div>
        </ModalContent>
      </Dialog.Root>
    </div>
  );
}
function Row({ title, hint, children }: { title: string; hint: string; children: ReactNode }) {
  return (
    <label className="flex min-h-11 items-center justify-between gap-4 rounded-lg border border-border bg-surface p-4">
      <span className="min-w-0">
        <span className="block text-sm font-medium">{title}</span>
        <span className="block text-xs text-muted">{hint}</span>
      </span>
      {children}
    </label>
  );
}
function PolicyPicker({
  name,
  title,
  value,
  onChange,
}: {
  name: string;
  title: string;
  value: DefaultPolicy;
  onChange: (value: DefaultPolicy) => void;
}) {
  const t = useT();
  return (
    <fieldset className="rounded-lg border border-border p-3">
      <legend className="px-1 text-sm font-medium">{title}</legend>
      <p className="text-xs text-muted">{t("set.policyHint")}</p>
      <div className="mt-2 grid gap-2 sm:grid-cols-3">
        {(["ask", "block", "allow"] as const).map((policy) => (
          <label
            key={policy}
            className="flex min-h-11 cursor-pointer items-center gap-2 rounded-sm border border-border p-2 text-xs"
          >
            <input
              type="radio"
              name={name}
              checked={value === policy}
              onChange={() => onChange(policy)}
            />
            {t("policy." + policy)}
          </label>
        ))}
      </div>
    </fieldset>
  );
}
