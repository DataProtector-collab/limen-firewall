import type { ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { useFirewall } from "@/lib/firewall/store";
import type { DefaultPolicy } from "@/lib/firewall/types";
import { cn } from "@/lib/utils";

const POLICIES: { id: DefaultPolicy; label: string; hint: string }[] = [
  { id: "ask", label: "Nachfragen", hint: "Dialog bei unbekannter App" },
  { id: "block", label: "Sperren", hint: "Standardmäßig alles blockieren" },
  { id: "allow", label: "Zulassen", hint: "Nur explizite Block-Regeln greifen" },
];

export function SettingsView() {
  const settings = useFirewall((s) => s.settings);
  const patch = useFirewall((s) => s.patchSettings);
  const reset = useFirewall((s) => s.reset);

  return (
    <div className="mx-auto flex max-w-xl flex-col gap-6">
      <Row
        title="Firewall aktiv"
        hint="Wenn aus, laufen alle Verbindungen ungefiltert durch."
      >
        <Switch
          checked={settings.enabled}
          onCheckedChange={(v) => patch({ enabled: v })}
          aria-label="Firewall aktiv"
        />
      </Row>

      <section className="rounded-lg border border-border bg-surface p-4">
        <h3 className="text-sm font-medium text-fg">Ausgehende Standardrichtlinie</h3>
        <p className="mt-1 text-xs text-muted">
          Gilt, wenn keine Regel zur App passt.
        </p>
        <PolicyPicker
          value={settings.defaultPolicy}
          onChange={(defaultPolicy) => patch({ defaultPolicy })}
        />
      </section>

      <section className="rounded-lg border border-border bg-surface p-4">
        <h3 className="text-sm font-medium text-fg">Eingehende Verbindungen</h3>
        <p className="mt-1 text-xs text-muted">
          RDP, SMB und unerwartete Ports. Empfehlung: Nachfragen oder Sperren.
        </p>
        <PolicyPicker
          value={settings.inboundPolicy}
          onChange={(inboundPolicy) => patch({ inboundPolicy })}
        />
      </section>

      <Row
        title="Windows-Dienste automatisch zulassen"
        hint="System, svchost, Defender und Search ohne Dialog."
      >
        <Switch
          checked={settings.autoAllowSystem}
          onCheckedChange={(v) => patch({ autoAllowSystem: v })}
          aria-label="Windows-Dienste zulassen"
        />
      </Row>

      <div className="rounded-lg border border-border bg-elevated p-4 text-xs leading-relaxed text-muted">
        Aegis ist eine vollständige Firewall-Konsole: TCP, UDP, HTTP, HTTPS, QUIC,
        DNS, ICMP, WebSocket, RDP und weitere Protokolle werden erfasst. Neue
        Apps lösen den Zulassen/Blockieren-Dialog aus. Regeln bleiben auf diesem
        Gerät gespeichert.
      </div>

      <Button variant="outline" onClick={reset}>
        Regeln und Einstellungen zurücksetzen
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
  return (
    <div className="mt-3 grid grid-cols-3 gap-1.5">
      {POLICIES.map((p) => (
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
