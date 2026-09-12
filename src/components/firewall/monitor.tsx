import type { ReactNode } from "react";
import { Area, AreaChart, ResponsiveContainer, YAxis } from "recharts";
import { ArrowDown, ArrowUp, ShieldOff } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { APP_BY_ID } from "@/lib/firewall/catalog";
import { protocolColor } from "@/lib/firewall/engine";
import { fmtBytes, fmtRate, protoLabel } from "@/lib/firewall/format";
import { useFirewall } from "@/lib/firewall/store";
import { PROTOCOLS, type Protocol } from "@/lib/firewall/types";
import { cn } from "@/lib/utils";

const FILTERS: Array<Protocol | "ALL"> = [
  "ALL",
  "TCP",
  "UDP",
  "HTTP",
  "HTTPS",
  "QUIC",
  "DNS",
  "ICMP",
  "WSS",
  "RDP",
];

export function MonitorView() {
  const connections = useFirewall((s) => s.connections);
  const samples = useFirewall((s) => s.samples);
  const query = useFirewall((s) => s.query);
  const setQuery = useFirewall((s) => s.setQuery);
  const protoFilter = useFirewall((s) => s.protoFilter);
  const setProtoFilter = useFirewall((s) => s.setProtoFilter);
  const blockedCount = useFirewall((s) => s.blockedCount);
  const allowedCount = useFirewall((s) => s.allowedCount);

  const live = connections.filter((c) => c.state === "established");
  const rateIn = live.reduce((a, c) => a + c.rateIn, 0);
  const rateOut = live.reduce((a, c) => a + c.rateOut, 0);

  const q = query.trim().toLowerCase();
  const shown = connections.filter((c) => {
    if (c.state === "blocked") return false;
    if (protoFilter !== "ALL" && c.protocol !== protoFilter) return false;
    if (!q) return true;
    const app = APP_BY_ID[c.appId];
    return (
      app?.name.toLowerCase().includes(q) ||
      app?.exe.toLowerCase().includes(q) ||
      c.remoteHost.toLowerCase().includes(q) ||
      c.remoteIp.includes(q) ||
      c.protocol.toLowerCase().includes(q)
    );
  });

  const protoMix = PROTOCOLS.map((p) => ({
    p,
    n: live.filter((c) => c.protocol === p).length,
  })).filter((x) => x.n > 0);

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">
        <Stat
          label="Aktive Verbindungen"
          value={String(live.length)}
          hint={`${connections.length} erfasst`}
        />
        <Stat
          label="Empfangen"
          value={fmtRate(rateIn)}
          hint={`${fmtBytes(live.reduce((a, c) => a + c.bytesIn, 0))} gesamt`}
          icon={<ArrowDown className="size-3.5 text-allow" />}
        />
        <Stat
          label="Gesendet"
          value={fmtRate(rateOut)}
          hint={`${fmtBytes(live.reduce((a, c) => a + c.bytesOut, 0))} gesamt`}
          icon={<ArrowUp className="size-3.5 text-info" />}
        />
        <Stat
          label="Entscheidungen"
          value={`${allowedCount} / ${blockedCount}`}
          hint="Zugelassen / blockiert"
        />
      </div>

      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        <div className="flex items-center justify-between px-4 pt-3">
          <p className="text-xs font-medium uppercase tracking-wider text-subtle">
            Durchsatz
          </p>
          <p className="font-mono text-xs text-muted">
            ↓ {fmtRate(rateIn)} · ↑ {fmtRate(rateOut)}
          </p>
        </div>
        <div className="h-28 w-full px-1 pb-1">
          {samples.length > 2 ? (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={samples} margin={{ top: 8, right: 8, left: 8, bottom: 0 }}>
                <defs>
                  <linearGradient id="inFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--color-allow)" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="var(--color-allow)" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="outFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--color-info)" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="var(--color-info)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <YAxis hide domain={[0, "auto"]} />
                <Area
                  type="monotone"
                  dataKey="in"
                  stroke="var(--color-allow)"
                  fill="url(#inFill)"
                  strokeWidth={1.5}
                  isAnimationActive={false}
                />
                <Area
                  type="monotone"
                  dataKey="out"
                  stroke="var(--color-info)"
                  fill="url(#outFill)"
                  strokeWidth={1.5}
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-full items-center justify-center text-xs text-subtle">
              Warte auf Messwerte…
            </div>
          )}
        </div>
      </div>

      {protoMix.length > 0 ? (
        <div className="flex flex-wrap gap-1.5">
          {protoMix.map((x) => (
            <Badge key={x.p} variant="default" className="font-mono">
              <span className={protocolColor(x.p)}>{protoLabel(x.p)}</span>
              <span className="ml-1.5 tabular-nums text-subtle">{x.n}</span>
            </Badge>
          ))}
        </div>
      ) : null}

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Suche App, Host, IP…"
          className="sm:max-w-xs"
        />
        <div className="flex gap-1 overflow-x-auto pb-1">
          {FILTERS.map((p) => (
            <button
              key={p}
              type="button"
              onClick={() => setProtoFilter(p)}
              className={cn(
                "h-9 shrink-0 rounded-full border px-3 font-mono text-xs transition-colors",
                protoFilter === p
                  ? "border-accent bg-accent/15 text-fg"
                  : "border-border text-muted hover:text-fg",
              )}
            >
              {p === "ALL" ? "Alle" : protoLabel(p)}
            </button>
          ))}
        </div>
      </div>

      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        <div className="hidden grid-cols-[1.3fr_0.6fr_1.4fr_0.5fr_0.6fr_0.7fr] gap-2 border-b border-border px-4 py-2 text-xs uppercase tracking-wider text-subtle md:grid">
          <span>Anwendung</span>
          <span>Protokoll</span>
          <span>Ziel</span>
          <span>Port</span>
          <span>Richtung</span>
          <span className="text-right">Traffic</span>
        </div>
        {shown.length === 0 ? (
          <div className="flex flex-col items-center gap-2 px-4 py-12 text-center text-sm text-muted">
            <ShieldOff className="size-6 text-subtle" />
            Keine passenden Verbindungen.
          </div>
        ) : (
          <ul className="divide-y divide-border">
            {shown.slice(0, 60).map((c) => {
              const app = APP_BY_ID[c.appId];
              return (
                <li
                  key={c.id}
                  className="grid grid-cols-1 gap-1 px-4 py-3 md:grid-cols-[1.3fr_0.6fr_1.4fr_0.5fr_0.6fr_0.7fr] md:items-center md:gap-2"
                >
                  <div className="min-w-0">
                    <p className="truncate text-sm text-fg">{app?.name ?? c.appId}</p>
                    <p className="truncate font-mono text-xs text-subtle">
                      {app?.exe} · PID {app?.pid}
                    </p>
                  </div>
                  <div className={cn("font-mono text-xs", protocolColor(c.protocol))}>
                    {protoLabel(c.protocol)}
                  </div>
                  <div className="min-w-0">
                    <p className="truncate text-sm text-fg">{c.remoteHost}</p>
                    <p className="truncate font-mono text-xs text-subtle">
                      {c.remoteIp} · {c.country}
                    </p>
                  </div>
                  <div className="font-mono text-xs tabular-nums text-muted">
                    {c.remotePort}
                  </div>
                  <div className="text-xs text-muted">
                    {c.direction === "in" ? "Eingehend" : "Ausgehend"}
                  </div>
                  <div className="text-right font-mono text-xs tabular-nums text-muted">
                    {fmtRate(c.rateIn + c.rateOut)}
                    <span className="block text-subtle">{fmtBytes(c.bytesIn + c.bytesOut)}</span>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}

function Stat({
  label,
  value,
  hint,
  icon,
}: {
  label: string;
  value: string;
  hint: string;
  icon?: ReactNode;
}) {
  return (
    <div className="rounded-lg border border-border bg-surface px-4 py-3">
      <div className="flex items-center justify-between text-xs text-subtle">
        {label}
        {icon}
      </div>
      <p className="mt-1 font-mono text-xl tabular-nums tracking-tight text-fg">{value}</p>
      <p className="mt-0.5 text-xs text-muted">{hint}</p>
    </div>
  );
}
