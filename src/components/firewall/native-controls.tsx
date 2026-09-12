import { useState, type ReactNode } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { AlertTriangle, RefreshCw, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { isNativeDesktop } from "@/lib/firewall/native-types";
import { useFirewall } from "@/lib/firewall/store";
import type { AppInfo } from "@/lib/firewall/types";
import { useT } from "@/lib/i18n/use-t";

export function NativeError({ dismissible = false }: { dismissible?: boolean }) {
  const t = useT();
  const error = useFirewall((s) => s.nativeError);
  const clear = useFirewall((s) => s.clearNativeError);
  if (!error) return null;
  return (
    <div
      role="alert"
      className="flex max-h-64 items-start gap-2 overflow-y-auto rounded-md border border-block/40 bg-surface p-3 text-sm text-block"
    >
      <AlertTriangle className="mt-0.5 size-4 shrink-0" />
      <div className="min-w-0 flex-1 break-words">
        <p className="font-medium">{t("native.error")}</p>
        <p>{error}</p>
      </div>
      {dismissible ? (
        <Button variant="ghost" size="icon" onClick={clear} aria-label={t("native.dismiss")}>
          <X />
        </Button>
      ) : null}
    </div>
  );
}

export function NativeStatusPanel({ detailed = false }: { detailed?: boolean }) {
  const t = useT();
  const status = useFirewall((s) => s.nativeStatus);
  const busy = useFirewall((s) => s.nativeBusy);
  const refresh = useFirewall((s) => s.refreshNative);
  const [refreshing, setRefreshing] = useState(false);
  const native = isNativeDesktop();
  return (
    <section className="space-y-2 rounded-lg border border-border bg-surface p-4 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="font-medium">{t(native ? "native.title" : "native.webTitle")}</h2>
        <Badge variant="info">{t(native ? "status.native" : "status.lab")}</Badge>
      </div>
      <p className="text-muted">{t(native ? "native.limit" : "native.webHint")}</p>
      {native ? (
        <>
          {!status ? (
            <p role="status" className="text-muted">
              {t("status.loading")}
            </p>
          ) : (
            <>
              {!status.available || status.backend !== "windows-firewall" ? (
                <p className="text-sm text-warn">{t("native.backendUnavailable")}</p>
              ) : null}
              <p className="text-xs text-muted">
                {t("native.admin")}:{" "}
                <span className={status.elevated ? "text-fg" : "text-warn"}>
                  {t(status.elevated ? "native.adminYes" : "native.adminNo")}
                </span>
              </p>
              {status.reason ? (
                <p className="break-words text-xs text-warn">{status.reason}</p>
              ) : null}
              <div className="flex flex-wrap gap-2" aria-label={t("native.profiles")}>
                {status.profiles?.length ? (
                  status.profiles.map((profile) => (
                    <Badge key={profile.name} variant={profile.enabled ? "default" : "warn"}>
                      {profile.name}: {t(profile.enabled ? "native.on" : "native.off")}
                    </Badge>
                  ))
                ) : (
                  <Badge variant="warn">
                    {t("native.profiles")}: {t("native.unknown")}
                  </Badge>
                )}
              </div>
              {detailed ? <p className="text-xs text-muted">{t("native.profileHint")}</p> : null}
            </>
          )}
          {detailed ? (
            <Button
              variant="outline"
              className="h-auto min-h-11 whitespace-normal py-2"
              disabled={busy || refreshing}
              onClick={async () => {
                setRefreshing(true);
                try {
                  await refresh();
                } finally {
                  setRefreshing(false);
                }
              }}
            >
              <RefreshCw className="size-4 shrink-0" />
              {t(busy || refreshing ? "native.refreshing" : "native.refresh")}
            </Button>
          ) : null}
        </>
      ) : null}
    </section>
  );
}

export function ModalContent({
  title,
  description,
  children,
  busy = false,
}: {
  title: string;
  description: string;
  children: ReactNode;
  busy?: boolean;
}) {
  const t = useT();
  return (
    <Dialog.Portal>
      <Dialog.Overlay className="fixed inset-0 z-50 bg-bg/85" />
      <div className="pointer-events-none fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6">
        <Dialog.Content
          className="pointer-events-auto flex max-h-full w-full max-w-lg flex-col overflow-hidden rounded-xl border border-border bg-surface shadow-xl"
          onInteractOutside={(e) => e.preventDefault()}
          onEscapeKeyDown={(e) => {
            if (busy) e.preventDefault();
          }}
        >
          <div className="flex items-start gap-3 border-b border-border p-4">
            <div className="min-w-0 flex-1">
              <Dialog.Title className="text-lg font-medium">{title}</Dialog.Title>
              <Dialog.Description className="mt-2 text-sm text-muted">
                {description}
              </Dialog.Description>
            </div>
            <Dialog.Close asChild>
              <Button variant="ghost" size="icon" disabled={busy} aria-label={t("btn.close")}>
                <X />
              </Button>
            </Dialog.Close>
          </div>
          <div className="min-h-0 overflow-y-auto overscroll-contain p-4">{children}</div>
        </Dialog.Content>
      </div>
    </Dialog.Portal>
  );
}

export function NativeRuleEditor({
  app,
  remoteIp,
  onClose,
}: {
  app: AppInfo;
  remoteIp?: string;
  onClose: () => void;
}) {
  const t = useT();
  const status = useFirewall((s) => s.nativeStatus);
  const busy = useFirewall((s) => s.nativeBusy);
  const apply = useFirewall((s) => s.applyNativeRule);
  const setView = useFirewall((s) => s.setView);
  const [action, setAction] = useState<"allow" | "block">("block");
  const [specific, setSpecific] = useState(false);
  const [address, setAddress] = useState(remoteIp ?? "");
  const [direction, setDirection] = useState<"in" | "out">("out");
  const [protocol, setProtocol] = useState<"TCP" | "UDP" | "ANY">("ANY");
  const [localPort, setLocalPort] = useState("");
  const [remotePort, setRemotePort] = useState("");
  const pathAvailable = /^[a-z]:\\.*\.exe$/i.test(app.path);
  const canWrite =
    status?.available && status.backend === "windows-firewall" && status.elevated && pathAvailable;
  return (
    <Dialog.Root
      open
      onOpenChange={(open) => {
        if (!open && !busy) onClose();
      }}
    >
      <ModalContent title={t("native.ruleTitle")} description={t("native.ruleHint")} busy={busy}>
        <form
          className="space-y-4"
          onSubmit={async (event) => {
            event.preventDefault();
            if (!canWrite || busy) return;
            const ok = await apply({
              program: app.path,
              action,
              direction,
              protocol,
              ...(specific ? { remoteAddress: address.trim() } : {}),
              ...(protocol !== "ANY" && localPort ? { localPort: Number(localPort) } : {}),
              ...(protocol !== "ANY" && remotePort ? { remotePort: Number(remotePort) } : {}),
            });
            if (ok) {
              onClose();
              // Storage can succeed while ActiveStore reports an inactive rule.
              // Show that result immediately instead of returning to the monitor.
              setView("rules");
            }
          }}
        >
          <div>
            <p className="text-xs text-muted">{t("native.program")}</p>
            <p className="font-medium">{app.name}</p>
            <p dir="ltr" className="mt-1 break-all font-mono text-xs text-muted">
              {app.path || t("native.programUnknown")}
            </p>
          </div>
          <fieldset disabled={busy} className="space-y-3">
            <legend className="mb-2 text-sm font-medium">{t("native.action")}</legend>
            <div className="flex flex-wrap gap-3">
              {(["block", "allow"] as const).map((value) => (
                <label
                  key={value}
                  className="flex min-h-11 cursor-pointer items-center gap-2 rounded-sm border border-border px-3 text-sm"
                >
                  <input
                    type="radio"
                    name="native-action"
                    value={value}
                    checked={action === value}
                    onChange={() => setAction(value)}
                  />
                  {t(`native.${value}`)}
                </label>
              ))}
            </div>
          </fieldset>
          <fieldset disabled={busy}>
            <legend className="mb-2 text-sm font-medium">{t("field.dir")}</legend>
            <div className="flex flex-wrap gap-3">
              {(["out", "in"] as const).map((value) => (
                <label
                  key={value}
                  className="flex min-h-11 cursor-pointer items-center gap-2 rounded-sm border border-border px-3 text-sm"
                >
                  <input
                    type="radio"
                    name="native-direction"
                    checked={direction === value}
                    onChange={() => setDirection(value)}
                  />
                  {t(`dir.${value}`)}
                </label>
              ))}
            </div>
            <p className="mt-2 text-xs text-muted">{t("native.directionHint")}</p>
          </fieldset>
          <fieldset disabled={busy} className="space-y-3">
            <legend className="mb-2 text-sm font-medium">{t("native.transport")}</legend>
            <select
              aria-label={t("native.transport")}
              value={protocol}
              onChange={(event) => {
                setProtocol(event.target.value as typeof protocol);
                if (event.target.value === "ANY") {
                  setLocalPort("");
                  setRemotePort("");
                }
              }}
              className="min-h-11 w-full rounded-sm border border-border bg-elevated px-3 text-sm text-fg"
            >
              <option value="ANY">{t("native.anyTransport")}</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
            </select>
            {protocol !== "ANY" ? (
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="space-y-1 text-xs text-muted">
                  <span>{t("native.localPort")}</span>
                  <Input
                    type="number"
                    min={1}
                    max={65535}
                    step={1}
                    value={localPort}
                    onChange={(e) => setLocalPort(e.target.value)}
                    inputMode="numeric"
                    placeholder={t("native.anyPort")}
                  />
                </label>
                <label className="space-y-1 text-xs text-muted">
                  <span>{t("native.remotePort")}</span>
                  <Input
                    type="number"
                    min={1}
                    max={65535}
                    step={1}
                    value={remotePort}
                    onChange={(e) => setRemotePort(e.target.value)}
                    inputMode="numeric"
                    placeholder={t("native.anyPort")}
                  />
                </label>
              </div>
            ) : null}
            <p className="text-xs text-muted">{t("native.portHint")}</p>
          </fieldset>
          <fieldset disabled={busy} className="space-y-2">
            <legend className="mb-2 text-sm font-medium">{t("native.scope")}</legend>
            <label className="flex min-h-11 cursor-pointer items-center gap-2 text-sm">
              <input
                type="radio"
                name="native-scope"
                checked={!specific}
                onChange={() => setSpecific(false)}
              />
              {t("native.allHosts")}
            </label>
            <label className="flex min-h-11 cursor-pointer items-center gap-2 text-sm">
              <input
                type="radio"
                name="native-scope"
                checked={specific}
                onChange={() => setSpecific(true)}
              />
              {t("native.oneIp")}
            </label>
            {specific ? (
              <label className="block space-y-1 text-xs text-muted">
                <span>{t("native.remoteIp")}</span>
                <Input
                  value={address}
                  onChange={(e) => setAddress(e.target.value)}
                  required
                  dir="ltr"
                  autoComplete="off"
                  spellCheck={false}
                />
              </label>
            ) : null}
            <p className="text-xs text-muted">{t("native.ipHint")}</p>
          </fieldset>
          <div className="flex flex-wrap gap-2" aria-label={t("native.profiles")}>
            {status?.profiles?.map((profile) => (
              <Badge key={profile.name} variant={profile.enabled ? "default" : "warn"}>
                {profile.name}: {t(profile.enabled ? "native.on" : "native.off")}
              </Badge>
            ))}
          </div>
          <p className="text-xs text-muted">{t("native.profileHint")}</p>
          {!pathAvailable ? (
            <p className="text-sm text-warn">{t("native.programUnknown")}</p>
          ) : !status?.elevated ? (
            <p className="text-sm text-warn">{t("native.adminNo")}</p>
          ) : null}
          <NativeError />
          <section
            aria-label={t("native.scopeSummary")}
            className="space-y-1 rounded-md border border-border bg-elevated p-3 text-sm"
          >
            <p className="font-medium">{t("native.scopeSummary")}</p>
            <p className="break-words">{app.name}</p>
            <p>
              {t(`native.${action}`)} · {t(`dir.${direction}`)} ·{" "}
              {protocol === "ANY" ? t("native.anyTransport") : protocol}
            </p>
            <p className="break-all text-xs text-muted">
              {specific ? `${t("native.oneIp")}: ${address.trim() || "—"}` : t("native.allHosts")}
            </p>
            {protocol !== "ANY" && (localPort || remotePort) ? (
              <p className="text-xs text-muted">
                {t("native.localPort")}: {localPort || t("native.anyPort")} ·{" "}
                {t("native.remotePort")}: {remotePort || t("native.anyPort")}
              </p>
            ) : null}
          </section>
          <div className="flex flex-wrap justify-end gap-2 border-t border-border pt-4">
            <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
              {t("btn.cancel")}
            </Button>
            <Button
              type="submit"
              variant={action === "block" ? "block" : "allow"}
              disabled={!canWrite || busy || (specific && !address.trim())}
              className="h-auto min-h-11 whitespace-normal py-2"
            >
              {t(busy ? "native.refreshing" : "native.apply")}
            </Button>
          </div>
        </form>
      </ModalContent>
    </Dialog.Root>
  );
}
