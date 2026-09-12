import { useState, type ReactNode } from "react";
import { Ban, Globe, Lock, ShieldAlert, ShieldOff } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { appById, protocolColor } from "@/lib/firewall/engine";
import { directionLabel, initials, protoLabel } from "@/lib/firewall/format";
import { useFirewall } from "@/lib/firewall/store";
import type { DecisionScope } from "@/lib/firewall/types";
import { useT } from "@/lib/i18n/use-t";
import { cn } from "@/lib/utils";

export function PromptOverlay() {
  const t = useT();
  const lang = useFirewall((s) => s.settings.language);
  const pending = useFirewall((s) => s.pending);
  const decide = useFirewall((s) => s.decide);
  const item = pending[0];
  const [scope, setScope] = useState<DecisionScope>("app-host");

  if (!item) return null;

  const conn = item.connection;
  const app = appById(conn.appId);
  const inbound = conn.direction === "in";
  const unsigned = app ? !app.signed : true;
  const rest = pending.length - 1;
  const kernel = conn.source === "kernel";

  const scopes: { id: DecisionScope; label: string; hint: string }[] = [
    { id: "once", label: t("prompt.once"), hint: t("prompt.onceHint") },
    { id: "app-host", label: t("prompt.appHost"), hint: t("prompt.appHostHint") },
    { id: "app", label: t("prompt.app"), hint: t("prompt.appHint") },
  ];

  return (
    <div
      className="backdrop-enter fixed inset-0 z-50 flex items-end justify-center bg-bg/80 p-3 sm:items-center sm:p-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby="prompt-title"
    >
      <div className="prompt-enter w-full max-w-lg overflow-hidden rounded-xl border border-border bg-surface shadow-[var(--shadow-panel)]">
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-wider text-warn">
            <ShieldAlert className="size-4" />
            {t("prompt.title")}
          </div>
          {rest > 0 ? (
            <Badge variant="warn">{t("prompt.queue", { n: rest })}</Badge>
          ) : (
            <span className="font-mono text-xs text-subtle">Aegis</span>
          )}
        </div>

        <div className="space-y-5 px-5 py-5">
          <div className="flex items-start gap-3">
            <div
              className={cn(
                "relative flex size-12 shrink-0 items-center justify-center rounded-md font-mono text-sm font-medium",
                unsigned
                  ? "bg-block/15 text-block"
                  : inbound
                    ? "bg-warn/15 text-warn"
                    : "bg-elevated text-accent",
              )}
            >
              {app ? initials(app.name) : "?"}
              <span className="pulse-ring absolute inset-0 rounded-md border border-current opacity-40" />
            </div>
            <div className="min-w-0 flex-1">
              <h2 id="prompt-title" className="text-lg font-medium leading-snug text-fg">
                {app?.name ?? t("prompt.unknownApp")}
              </h2>
              <p className="truncate font-mono text-xs text-muted">{app?.exe}</p>
              <p className="mt-1 truncate text-xs text-subtle">{app?.path}</p>
            </div>
          </div>

          <p className="text-sm leading-relaxed text-fg">
            {inbound ? t("prompt.bodyIn") : t("prompt.bodyOut")}
          </p>

          {kernel ? (
            <div className="text-xs text-info">
              {t("prompt.kernel", { inode: conn.inode ?? "—" })}
            </div>
          ) : null}

          {unsigned ? (
            <div className="flex items-start gap-2 rounded-md border border-block/30 bg-block/10 px-3 py-2 text-xs text-block">
              <ShieldOff className="mt-0.5 size-4 shrink-0" />
              {t("prompt.unsigned")}
            </div>
          ) : inbound ? (
            <div className="flex items-start gap-2 rounded-md border border-warn/30 bg-warn/10 px-3 py-2 text-xs text-warn">
              <Ban className="mt-0.5 size-4 shrink-0" />
              {t("prompt.inbound")}
            </div>
          ) : (
            <div className="flex items-center gap-2 text-xs text-muted">
              <Lock className="size-3.5" />
              {t("prompt.signed", { publisher: app?.publisher ?? "" })}
            </div>
          )}

          <div className="grid grid-cols-2 gap-2 rounded-md border border-border bg-elevated p-3 text-xs">
            <Field label={t("field.target")}>
              <span className="flex items-center gap-1.5 text-fg">
                <Globe className="size-3.5 text-muted" />
                <span className="truncate">{conn.remoteHost}</span>
              </span>
            </Field>
            <Field label={t("field.ip")}>
              <span className="font-mono text-fg">{conn.remoteIp}</span>
            </Field>
            <Field label={t("field.proto")}>
              <span className={cn("font-mono", protocolColor(conn.protocol))}>
                {protoLabel(conn.protocol)}
              </span>
            </Field>
            <Field label={t("field.port")}>
              <span className="font-mono text-fg">{conn.remotePort}</span>
            </Field>
            <Field label={t("field.dir")}>
              <span className="text-fg">{directionLabel(conn.direction, lang)}</span>
            </Field>
            <Field label={t("field.country")}>
              <span className="text-fg">{conn.country}</span>
            </Field>
          </div>

          {item.stacked > 1 ? (
            <p className="text-xs text-muted">{t("prompt.stacked", { n: item.stacked })}</p>
          ) : null}

          <div>
            <p className="mb-2 text-xs font-medium uppercase tracking-wider text-subtle">
              {t("prompt.scope")}
            </p>
            <div className="grid grid-cols-3 gap-1.5">
              {scopes.map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setScope(opt.id)}
                  className={cn(
                    "rounded-sm border px-2 py-2 text-left transition-colors duration-150",
                    scope === opt.id
                      ? "border-accent bg-accent/10 text-fg"
                      : "border-border bg-bg text-muted hover:text-fg",
                  )}
                >
                  <span className="block text-xs font-medium">{opt.label}</span>
                  <span className="mt-0.5 hidden text-xs leading-tight text-subtle sm:block">
                    {opt.hint}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 border-t border-border bg-elevated/60 p-4">
          <Button
            variant="block"
            onClick={() => {
              decide(item.id, "block", scope);
              setScope("app-host");
            }}
          >
            {t("btn.block")}
          </Button>
          <Button
            variant="allow"
            onClick={() => {
              decide(item.id, "allow", scope);
              setScope("app-host");
            }}
          >
            {t("btn.allow")}
          </Button>
        </div>
      </div>
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  return (
    <div className="min-w-0">
      <div className="text-subtle">{label}</div>
      <div className="mt-0.5 truncate">{children}</div>
    </div>
  );
}
