import { useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ModalContent } from "@/components/firewall/native-controls";
import { endpoint } from "@/components/firewall/endpoints";
import { APPS } from "@/lib/firewall/catalog";
import { directionLabel } from "@/lib/firewall/format";
import { useFirewall } from "@/lib/firewall/store";
import type { DecisionScope, PendingRequest } from "@/lib/firewall/types";
import { useT } from "@/lib/i18n/use-t";

export function PromptOverlay() {
  const t = useT();
  const pending = useFirewall((s) => s.pending);
  const labPending = pending.filter((p) => p.connection.source !== "kernel");
  const item = labPending[0];
  const [dismissed, setDismissed] = useState<string | null>(null);
  if (!item) return null;
  if (dismissed === item.id)
    return (
      <div className="fixed bottom-20 end-3 z-40 max-w-full px-3 md:bottom-4">
        <Button
          className="h-auto min-h-11 whitespace-normal py-2"
          onClick={() => setDismissed(null)}
        >
          {t("prompt.resume", { n: labPending.length })}
        </Button>
      </div>
    );
  return (
    <LabDecisionDialog
      key={item.id}
      item={item}
      rest={labPending.length - 1}
      onDefer={() => setDismissed(item.id)}
    />
  );
}
function LabDecisionDialog({
  item,
  rest,
  onDefer,
}: {
  item: PendingRequest;
  rest: number;
  onDefer: () => void;
}) {
  const t = useT();
  const lang = useFirewall((s) => s.settings.language);
  const decide = useFirewall((s) => s.decide);
  const [scope, setScope] = useState<DecisionScope>("once");
  const c = item.connection;
  const app = APPS.find((a) => a.id === c.appId);
  return (
    <Dialog.Root
      open
      onOpenChange={(open) => {
        if (!open) onDefer();
      }}
    >
      <ModalContent title={t("prompt.title")} description={t("prompt.hint")}>
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-base font-medium">{app?.name || t("prompt.unknownApp")}</h2>
            <Badge variant="accent">{t("status.lab")}</Badge>
            {rest ? <Badge>{t("prompt.queue", { n: rest })}</Badge> : null}
          </div>
          <p className="text-xs text-muted">{t("prompt.signature")}</p>
          <dl className="grid grid-cols-1 gap-3 rounded-md border border-border bg-elevated p-3 text-xs sm:grid-cols-2">
            <div className="min-w-0">
              <dt className="text-muted">{t("field.local")}</dt>
              <dd dir="ltr" className="break-all font-mono">
                {endpoint(c.localIp, c.localPort)}
              </dd>
            </div>
            <div className="min-w-0">
              <dt className="text-muted">{t("field.target")}</dt>
              <dd dir="ltr" className="break-all font-mono">
                {c.remoteHost}
                <br />
                {endpoint(c.remoteIp, c.remotePort)}
              </dd>
            </div>
            <div>
              <dt className="text-muted">{t("field.proto")}</dt>
              <dd>{c.protocol}</dd>
            </div>
            <div>
              <dt className="text-muted">{t("field.dir")}</dt>
              <dd>{directionLabel(c.direction, lang)}</dd>
            </div>
          </dl>
          {item.stacked > 1 ? (
            <p className="text-xs text-muted">{t("prompt.stacked", { n: item.stacked })}</p>
          ) : null}
          <fieldset>
            <legend className="mb-2 text-sm font-medium">{t("prompt.scope")}</legend>
            <div className="grid gap-2 sm:grid-cols-3">
              {(["once", "app-host", "app"] as const).map((value) => (
                <label
                  key={value}
                  className="flex min-h-11 cursor-pointer items-center gap-2 rounded-sm border border-border p-2 text-xs"
                >
                  <input
                    type="radio"
                    name="lab-decision-scope"
                    checked={value === scope}
                    onChange={() => setScope(value)}
                  />
                  {t(value === "app-host" ? "prompt.appHost" : "prompt." + value)}
                </label>
              ))}
            </div>
          </fieldset>
          <div className="flex flex-wrap justify-end gap-2 border-t border-border pt-4">
            <Button variant="outline" onClick={onDefer}>
              {t("prompt.defer")}
            </Button>
            <Button
              variant="block"
              className="h-auto min-h-11 whitespace-normal py-2"
              onClick={() => decide(item.id, "block", scope)}
            >
              {t("btn.block")}
            </Button>
            <Button
              variant="allow"
              className="h-auto min-h-11 whitespace-normal py-2"
              onClick={() => decide(item.id, "allow", scope)}
            >
              {t("btn.allow")}
            </Button>
          </div>
        </div>
      </ModalContent>
    </Dialog.Root>
  );
}
