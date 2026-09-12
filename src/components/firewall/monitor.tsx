import { useEffect, useState } from "react";
import { Area, AreaChart, ResponsiveContainer, YAxis } from "recharts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeRuleEditor } from "@/components/firewall/native-controls";
import { endpoint } from "@/components/firewall/endpoints";
import { APPS } from "@/lib/firewall/catalog";
import { directionLabel, fmtBytes, fmtRate } from "@/lib/firewall/format";
import { isNativeDesktop } from "@/lib/firewall/native-types";
import { useFirewall } from "@/lib/firewall/store";
import { PROTOCOLS, type AppInfo, type Connection } from "@/lib/firewall/types";
import { useT } from "@/lib/i18n/use-t";
import { cn } from "@/lib/utils";

export function MonitorView() {
  const t = useT();
  const lang = useFirewall((s) => s.settings.language);
  const conns = useFirewall((s) => s.connections);
  const apps = useFirewall((s) => s.kernelApps);
  const samples = useFirewall((s) => s.samples);
  const query = useFirewall((s) => s.query);
  const setQuery = useFirewall((s) => s.setQuery);
  const proto = useFirewall((s) => s.protoFilter);
  const setProto = useFirewall((s) => s.setProtoFilter);
  const settings = useFirewall((s) => s.settings);
  const rx = useFirewall((s) => s.kernelRx);
  const tx = useFirewall((s) => s.kernelTx);
  const live = useFirewall((s) => s.kernelLive);
  const trafficReady = useFirewall((s) => s.kernelTrafficReady);
  const lastSnapshotAt = useFirewall((s) => s.kernelLastSnapshotAt);
  const pending = useFirewall((s) => s.capturePending);
  const stale = useFirewall((s) => s.captureStale);
  const trafficError = useFirewall((s) => s.trafficError);
  const nativeRules = useFirewall((s) => s.nativeRules);
  const setView = useFirewall((s) => s.setView);
  const patchSettings = useFirewall((s) => s.patchSettings);
  const allowed = useFirewall((s) => s.allowedCount);
  const blocked = useFirewall((s) => s.blockedCount);
  const clearError = useFirewall((s) => s.clearNativeError);
  const [limit, setLimit] = useState(60);
  const [now, setNow] = useState(Date.now);
  const [editor, setEditor] = useState<{ app: AppInfo; remoteIp?: string } | null>(null);
  const native = isNativeDesktop();
  useEffect(() => {
    if (!native) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [native]);
  const appMap = new Map([...APPS, ...apps].map((app) => [app.id, app]));
  const visible = conns.filter((c) => (c.source === "kernel" ? native : settings.labTraffic));
  const q = query.trim().toLowerCase();
  const shown = visible.filter((c) => {
    if (proto !== "ALL" && c.protocol !== proto) return false;
    const app = appMap.get(c.appId);
    return (
      !q ||
      [
        app?.name,
        app?.exe,
        app?.path,
        c.remoteHost,
        c.remoteIp,
        c.localIp,
        String(c.localPort),
        String(c.remotePort),
        c.protocol,
      ].some((value) => value?.toLowerCase().includes(q))
    );
  });
  const measured = native && settings.kernelCapture && live && trafficReady;
  const snapshotAge = lastSnapshotAt
    ? Math.max(0, Math.floor((now - lastSnapshotAt) / 1000))
    : null;
  const snapshotTime = lastSnapshotAt
    ? new Date(lastSnapshotAt).toLocaleTimeString(lang === "de" ? "de-DE" : "en-GB")
    : null;
  const openEditor = (app: AppInfo, conn: Connection) => {
    clearError();
    const remoteIp =
      conn.remoteIp && conn.remoteIp !== "0.0.0.0" && conn.remoteIp !== "::"
        ? conn.remoteIp
        : undefined;
    setEditor({ app, remoteIp });
  };
  return (
    <div className="space-y-4">
      {native ? (
        <>
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 space-y-1">
              <p
                className={cn(
                  "flex items-center gap-2 text-sm",
                  stale || !settings.kernelCapture ? "text-warn" : "text-fg",
                )}
              >
                <span
                  aria-hidden="true"
                  className={cn(
                    "size-2 shrink-0 rounded-full",
                    live && settings.kernelCapture ? "bg-info" : "bg-warn",
                  )}
                />
                {t(
                  !settings.kernelCapture
                    ? "status.paused"
                    : stale
                      ? "monitor.stale"
                      : pending
                        ? "monitor.updating"
                        : live
                          ? "status.observing"
                          : "status.unavailable",
                )}
              </p>
              <p className="text-xs text-muted">
                {snapshotTime !== null && snapshotAge !== null
                  ? t("monitor.lastRead", { time: snapshotTime, seconds: snapshotAge })
                  : t("monitor.firstRead")}
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              {!settings.kernelCapture ? (
                <Button variant="outline" onClick={() => patchSettings({ kernelCapture: true })}>
                  {t("monitor.resume")}
                </Button>
              ) : null}
              <Button variant="outline" onClick={() => setView("rules")}>
                {t("monitor.manageRules", { n: nativeRules.length })}
              </Button>
            </div>
          </div>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
            <Stat
              label={t("stat.active")}
              value={String(visible.filter((c) => c.source === "kernel").length)}
              hint={t(stale ? "monitor.stale" : live ? "status.live" : "status.unavailable")}
            />
            <Stat
              label={t("stat.rx")}
              value={measured ? fmtRate(rx) : "—"}
              hint={t(measured ? "stat.hostHint" : !trafficError && live ? "stat.wait" : "stat.na")}
            />
            <Stat
              label={t("stat.tx")}
              value={measured ? fmtRate(tx) : "—"}
              hint={t(measured ? "stat.hostHint" : !trafficError && live ? "stat.wait" : "stat.na")}
            />
          </div>
          {trafficError ? (
            <p
              role="alert"
              className="break-words rounded-md border border-warn/40 bg-warn/10 p-3 text-sm text-warn"
            >
              {t("monitor.trafficUnavailable")}: {trafficError}
            </p>
          ) : null}
        </>
      ) : null}
      {settings.labTraffic ? (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-surface px-4 py-3 text-sm">
          <Badge variant="accent">{t("status.lab")}</Badge>
          <span>
            {t("stat.lab")}: {visible.filter((c) => c.source !== "kernel").length}
          </span>
          <span className="text-muted">
            {t("stat.decisions")}: {allowed} / {blocked}
          </span>
        </div>
      ) : null}
      <div className="space-y-2">
        {native ? (
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <h2 className="text-sm font-medium">{t("monitor.connections")}</h2>
            <p className="text-xs text-muted">{t("monitor.ruleHelp")}</p>
          </div>
        ) : null}
        <Input
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setLimit(60);
          }}
          placeholder={t("search.ph")}
          aria-label={t("search.ph")}
        />
        <div className="flex flex-wrap gap-2">
          <select
            aria-label={t("field.proto")}
            value={proto}
            onChange={(e) => {
              setProto(e.target.value as typeof proto);
              setLimit(60);
            }}
            className="min-h-11 max-w-full rounded-sm border border-border bg-elevated px-3 text-sm text-fg"
          >
            <option value="ALL">{t("filter.all")}</option>
            {PROTOCOLS.map((p) => (
              <option key={p}>{p}</option>
            ))}
          </select>
          <p role="status" className="flex items-center text-xs text-muted">
            {t("monitor.results", { n: shown.length })}
          </p>
        </div>
      </div>
      {shown.length ? (
        <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border bg-surface">
          {shown.slice(0, limit).map((c) => {
            const app = appMap.get(c.appId);
            const real = c.source === "kernel";
            return (
              <li
                key={c.id}
                className="grid gap-3 p-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] md:grid-cols-3"
              >
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="break-words text-sm font-medium">{app?.name || c.appId}</p>
                    <Badge variant={real ? "info" : "accent"}>
                      {t(real ? "status.native" : "status.lab")}
                    </Badge>
                  </div>
                  <p className="mt-1 break-all font-mono text-xs text-muted">
                    {app?.exe || "—"} · PID {c.pid ?? app?.pid ?? "—"}
                  </p>
                  <p className="mt-1 text-xs text-muted">
                    {t("field.state")}: {c.state} · {c.protocol}
                  </p>
                </div>
                <dl className="min-w-0 space-y-2 text-xs">
                  <div>
                    <dt className="text-muted">{t("field.local")}</dt>
                    <dd dir="ltr" className="break-all font-mono">
                      {endpoint(c.localIp, c.localPort)}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-muted">{t("field.target")}</dt>
                    <dd dir="ltr" className="break-all font-mono">
                      {c.remotePort ||
                      (c.remoteIp && c.remoteIp !== "0.0.0.0" && c.remoteIp !== "::")
                        ? endpoint(c.remoteIp, c.remotePort)
                        : t("monitor.noPeer")}
                    </dd>
                  </div>
                  <div className="text-muted">
                    {t("field.dir")}: {directionLabel(c.direction, lang)}
                  </div>
                </dl>
                <div className="flex min-w-0 flex-wrap items-center justify-between gap-2 sm:col-span-2 md:col-span-1 md:flex-col md:items-end">
                  <p className={cn("text-xs text-muted", real ? "" : "font-mono")}>
                    {real
                      ? t("native.traffic")
                      : t("monitor.labTraffic", { bytes: fmtBytes(c.bytesIn + c.bytesOut) })}
                  </p>
                  {real && app ? (
                    <Button
                      variant="outline"
                      className="h-auto min-h-11 max-w-full whitespace-normal py-2 text-xs"
                      onClick={() => openEditor(app, c)}
                    >
                      {t("native.rule")}
                    </Button>
                  ) : null}
                </div>
              </li>
            );
          })}
        </ul>
      ) : (
        <p className="rounded-lg border border-dashed border-border p-8 text-center text-sm text-muted">
          {t("empty.conns")}
        </p>
      )}
      {shown.length > limit ? (
        <Button
          variant="outline"
          onClick={() => setLimit((n) => n + 60)}
          className="h-auto min-h-11 whitespace-normal py-2"
        >
          {t("monitor.more", { n: shown.length - limit })}
        </Button>
      ) : null}
      {native ? (
        <>
          <details className="rounded-lg border border-border bg-surface p-3">
            <summary className="cursor-pointer text-sm font-medium">{t("stat.throughput")}</summary>
            <p className="mt-2 text-xs text-muted">{t("stat.hostHint")}</p>
            <div className="mt-3 h-28 w-full min-w-0" role="img" aria-label={t("stat.throughput")}>
              {measured && samples.length > 2 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={samples} margin={{ top: 8, right: 8, left: 8, bottom: 0 }}>
                    <YAxis hide domain={[0, "auto"]} />
                    <Area
                      type="linear"
                      dataKey="in"
                      stroke="var(--color-allow)"
                      fill="var(--color-allow)"
                      fillOpacity={0.12}
                      isAnimationActive={false}
                    />
                    <Area
                      type="linear"
                      dataKey="out"
                      stroke="var(--color-info)"
                      fill="var(--color-info)"
                      fillOpacity={0.08}
                      isAnimationActive={false}
                    />
                  </AreaChart>
                </ResponsiveContainer>
              ) : (
                <p className="flex h-full items-center justify-center text-xs text-muted">
                  {t(!trafficError && live ? "stat.wait" : "stat.na")}
                </p>
              )}
            </div>
          </details>
          <p className="text-xs text-muted">{t("monitor.windowsHint")}</p>
        </>
      ) : null}
      {editor ? (
        <NativeRuleEditor
          app={editor.app}
          remoteIp={editor.remoteIp}
          onClose={() => setEditor(null)}
        />
      ) : null}
    </div>
  );
}

function Stat({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <div className="rounded-lg border border-border bg-surface p-3">
      <p className="text-xs text-muted">{label}</p>
      <p className="mt-1 font-mono text-xl">{value}</p>
      <p className="mt-1 text-xs text-muted">{hint}</p>
    </div>
  );
}
