import { useEffect, useState } from "react";
import {
  Activity,
  ArrowDown,
  ArrowUp,
  Download,
  Fingerprint,
  Radar,
  Timer,
  TriangleAlert,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { NativeRuleEditor } from "@/components/firewall/native-controls";
import { fmtRate } from "@/lib/firewall/format";
import { isNativeDesktop } from "@/lib/firewall/native-types";
import { useFirewall } from "@/lib/firewall/store";
import { guardEligibility, TELEMETRY_LIMITS } from "@/lib/firewall/telemetry";
import { useTelemetry } from "@/lib/firewall/telemetry-store";
import type {
  TelemetryEvent,
  TelemetryEventKind,
  TelemetryProgram,
} from "@/lib/firewall/telemetry-types";
import type { AppInfo } from "@/lib/firewall/types";
import { cn } from "@/lib/utils";

type Copy = (en: string, de: string) => string;
const chartTooltip = {
  background: "var(--color-surface)",
  border: "1px solid var(--color-border)",
  borderRadius: 8,
  color: "var(--color-fg)",
  fontSize: 12,
};

export function WarMonitorView() {
  const language = useFirewall((state) => state.settings.language);
  const capture = useFirewall((state) => state.settings.kernelCapture);
  const pending = useFirewall((state) => state.capturePending);
  const captureStale = useFirewall((state) => state.captureStale);
  const live = useFirewall((state) => state.kernelLive);
  const clearError = useFirewall((state) => state.clearNativeError);
  const samples = useTelemetry((state) => state.samples);
  const programs = useTelemetry((state) => state.programs);
  const events = useTelemetry((state) => state.events);
  const guards = useTelemetry((state) => state.guards);
  const quality = useTelemetry((state) => state.quality);
  const acknowledge = useTelemetry((state) => state.acknowledge);
  const freezeGuard = useTelemetry((state) => state.freezeGuard);
  const removeGuard = useTelemetry((state) => state.removeGuard);
  const [now, setNow] = useState(Date.now);
  const [showAcknowledged, setShowAcknowledged] = useState(false);
  const [selectedKey, setSelectedKey] = useState("");
  const [guardError, setGuardError] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [editor, setEditor] = useState<AppInfo | null>(null);
  const text: Copy = (en, de) => (language === "de" ? de : en);
  const native = isNativeDesktop();
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  if (!native)
    return (
      <section className="rounded-lg border border-border bg-surface p-5">
        <Radar className="mb-3 size-7 text-info" />
        <h2 className="font-medium">War Monitor</h2>
        <p className="mt-2 text-sm text-muted">
          {text(
            "Live telemetry and anomaly detection require the Windows desktop application. Simulation traffic is excluded from this recorder.",
            "Live-Telemetrie und Mustererkennung benötigen die Windows-Desktop-Anwendung. Simulationsverkehr fließt nicht in diese Aufzeichnung ein.",
          )}
        </p>
      </section>
    );

  const latest = samples.at(-1);
  const ageMs = quality.lastSnapshotAt === null ? null : Math.max(0, now - quality.lastSnapshotAt);
  const stale = captureStale || (ageMs !== null && ageMs > TELEMETRY_LIMITS.gapMs);
  const fresh =
    capture &&
    live &&
    !stale &&
    quality.status !== "unavailable" &&
    quality.status !== "not-native";
  const measured = fresh && quality.trafficReady;
  const formatTime = (at: number) =>
    new Date(at).toLocaleTimeString(language === "de" ? "de-DE" : "en-GB");
  const chart = samples.slice(-180);
  const outstanding = events.filter((event) => event.acknowledgedAt === null);
  const shownEvents = [...events]
    .reverse()
    .filter((event) => showAcknowledged || event.acknowledgedAt === null);
  const selected = programs.find((program) => program.key === selectedKey);
  const selectedGuard = guards.find((guard) => guard.programKey === selectedKey);
  const eligible = selectedKey
    ? guardEligibility(useTelemetry.getState(), selectedKey)
    : { ok: false, error: "select-program" };
  const titles: Record<TelemetryEventKind, string> = {
    "tx-burst": text("Host transmit burst", "Sendespitze des Hosts"),
    "rx-burst": text("Host receive burst", "Empfangsspitze des Hosts"),
    "peer-fanout": text("Many new TCP peers", "Viele neue TCP-Gegenstellen"),
    "regular-reconnect": text(
      "Regular new socket appearances",
      "Regelmäßig neu beobachtete Sockets",
    ),
    "new-listener": text("New persistent TCP listener", "Neuer beständiger TCP-Listener"),
    "syn-pressure": text("Sustained SYN socket growth", "Anhaltender Anstieg von SYN-Sockets"),
    "guard-drift": text("DriftGuard: new peer", "DriftGuard: neue Gegenstelle"),
  };

  function openRule(program: TelemetryProgram) {
    if (!/^[a-z]:\\.*\.exe$/i.test(program.exe)) return;
    clearError();
    setEditor({
      id: program.key,
      name: program.name,
      path: program.exe,
      exe: program.exe.split("\\").pop() || program.name,
      pid: 0,
      category: "unknown",
      signed: null,
      publisher: "",
    });
  }

  function exportRecorder() {
    setExportError(null);
    try {
      const state = useTelemetry.getState();
      const record = {
        format: "limen-flight-recorder-v1",
        exportedAt: new Date().toISOString(),
        observationScope:
          "Windows socket snapshots and host interface counters; no packet payloads or per-process byte attribution",
        sessionStartedAt: state.sessionStartedAt,
        samples: state.samples,
        programs: state.programs,
        events: state.events,
        guards: state.guards,
        quality: state.quality,
      };
      const blob = new Blob([JSON.stringify(record, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `limen-flight-recorder-${new Date().toISOString().replaceAll(":", "-")}.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      setExportError(error instanceof Error ? error.message : String(error));
    }
  }

  return (
    <div className="space-y-4">
      <section className="overflow-hidden rounded-lg border border-info/30 bg-surface">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3">
          <div className="flex flex-wrap items-center gap-2">
            <Radar className="size-4 text-info" />
            <h2 className="text-sm font-medium">War Monitor</h2>
            <Badge variant={fresh ? "info" : "warn"}>
              {!capture
                ? text("Paused", "Pausiert")
                : stale
                  ? text("Stale data", "Veraltete Daten")
                  : pending
                    ? text("Reading", "Lesung läuft")
                    : fresh
                      ? text("Live observations", "Aktuelle Beobachtungen")
                      : text("Waiting for Windows", "Warte auf Windows")}
            </Badge>
          </div>
          <p className="font-mono text-xs text-muted">
            {quality.lastSnapshotAt ? formatTime(quality.lastSnapshotAt) : "—"} ·{" "}
            {ageMs === null ? "—" : `${Math.floor(ageMs / 1000)}s`} {text("old", "alt")}
          </p>
        </div>
        <div className="grid grid-cols-2 gap-px bg-border lg:grid-cols-4">
          <TelemetryMetric
            icon={ArrowDown}
            label={text("Host RX", "Host RX")}
            value={
              measured && latest?.rx !== null && latest?.rx !== undefined ? fmtRate(latest.rx) : "—"
            }
            detail={text(
              "Received · all measured interfaces",
              "Empfangen · gemessene Schnittstellen",
            )}
            tone="text-allow"
          />
          <TelemetryMetric
            icon={ArrowUp}
            label={text("Host TX", "Host TX")}
            value={
              measured && latest?.tx !== null && latest?.tx !== undefined ? fmtRate(latest.tx) : "—"
            }
            detail={text("Sent · all measured interfaces", "Gesendet · gemessene Schnittstellen")}
            tone="text-info"
          />
          <TelemetryMetric
            icon={Activity}
            label={text("Observed sockets", "Beobachtete Sockets")}
            value={fresh && latest ? String(latest.sockets) : "—"}
            detail={
              latest
                ? `${latest.tcp} TCP · ${latest.udp} UDP`
                : text("No snapshot", "Keine Momentaufnahme")
            }
          />
          <TelemetryMetric
            icon={Timer}
            label={text("Capture latency", "Latenz der Lesung")}
            value={
              fresh && latest?.captureDurationMs !== null && latest?.captureDurationMs !== undefined
                ? `${Math.round(latest.captureDurationMs)} ms`
                : "—"
            }
            detail={
              latest?.durationMs
                ? `${text("Sample interval", "Abstand der Messungen")}: ${(latest.durationMs / 1000).toFixed(1)}s`
                : text("Waiting for comparable reads", "Warte auf vergleichbare Lesungen")
            }
          />
        </div>
      </section>

      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
        <p className={quality.status === "ready" && fresh ? "text-muted" : "text-warn"}>
          {!capture
            ? text(
                "Observation is paused; saved Windows rules keep running.",
                "Die Beobachtung ist pausiert; gespeicherte Windows-Regeln laufen weiter.",
              )
            : stale
              ? text(
                  "The last observations are retained. Live values are withheld until a fresh capture arrives.",
                  "Letzte Beobachtungen bleiben erhalten. Live-Werte erscheinen erst wieder nach einer aktuellen Lesung.",
                )
              : `${text("Traffic baseline", "Datenverkehr-Basis")}: ${Math.min(quality.warmupSamples, TELEMETRY_LIMITS.warmup)}/${TELEMETRY_LIMITS.warmup} ${text("comparable samples", "vergleichbare Messungen")}`}
        </p>
        <p className="text-muted">
          {text("Snapshot analysis · no packet payloads", "Momentaufnahmen · keine Paketnutzdaten")}
        </p>
      </div>
      {quality.reason ? (
        <p className="break-words text-xs text-muted">{qualityReason(quality.reason, text)}</p>
      ) : null}
      {quality.retentionLimited ? (
        <p
          role="status"
          className="rounded-md border border-warn/40 bg-warn/10 p-3 text-xs text-warn"
        >
          {text(
            "The bounded recorder reached a capacity limit. Coverage is partial and new DriftGuard baselines are unavailable until the session is reset.",
            "Die begrenzte Aufzeichnung hat eine Kapazitätsgrenze erreicht. Die Abdeckung ist teilweise; neue DriftGuard-Basiswerte sind erst nach dem Zurücksetzen der Sitzung möglich.",
          )}
        </p>
      ) : null}

      <section className="rounded-lg border border-border bg-surface p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-medium">
            {text("Interface telemetry", "Schnittstellen-Telemetrie")}
          </h3>
          <div className="flex gap-3 font-mono text-xs">
            <span className="text-allow">RX</span>
            <span className="text-info">TX</span>
            <span className="text-muted">B/s</span>
          </div>
        </div>
        <div
          className="mt-3 h-40 w-full min-w-0 overflow-hidden"
          role="img"
          aria-label={text(
            "Measured host receive and transmit rates over time",
            "Gemessene Empfangs- und Senderaten des Hosts im Zeitverlauf",
          )}
        >
          {chart.some((sample) => sample.rx !== null || sample.tx !== null) ? (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chart} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid stroke="var(--color-border)" vertical={false} />
                <XAxis
                  dataKey="at"
                  tickFormatter={formatTime}
                  minTickGap={60}
                  tick={{ fill: "var(--color-muted)", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  width={60}
                  tickFormatter={fmtRate}
                  tick={{ fill: "var(--color-muted)", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={chartTooltip}
                  labelFormatter={(label) => formatTime(Number(label))}
                  formatter={(value, name) => [fmtRate(Number(value)), name]}
                />
                <Area
                  name="RX"
                  type="linear"
                  dataKey="rx"
                  stroke="var(--color-allow)"
                  fill="var(--color-allow)"
                  fillOpacity={0.1}
                  connectNulls={false}
                  isAnimationActive={false}
                />
                <Area
                  name="TX"
                  type="linear"
                  dataKey="tx"
                  stroke="var(--color-info)"
                  fill="var(--color-info)"
                  fillOpacity={0.12}
                  connectNulls={false}
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <EmptyChart
              text={text(
                "Waiting for two comparable interface counter readings. Missing measurements are not zero traffic.",
                "Warte auf zwei vergleichbare Schnittstellenzähler. Fehlende Messungen bedeuten keinen Datenverkehr von null.",
              )}
            />
          )}
        </div>
        <p className="mt-2 text-xs text-muted">
          {text(
            "Host totals. A spike cannot be assigned to a program from these counters.",
            "Host-Summen. Eine Spitze lässt sich aus diesen Zählern keinem Programm zuordnen.",
          )}
        </p>
      </section>

      <section className="rounded-lg border border-border bg-surface p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-medium">
            {text("Socket load & turnover", "Socketlast und Wechsel")}
          </h3>
          <p className="font-mono text-xs text-muted">
            {latest
              ? `${latest.listeners} ${text("listeners", "Listener")} · ${latest.syn} SYN`
              : "—"}
          </p>
        </div>
        <div
          className="mt-3 h-28 w-full min-w-0 overflow-hidden"
          role="img"
          aria-label={text(
            "Observed socket count and newly observed socket tuples",
            "Socketanzahl und neu beobachtete Socket-Kombinationen",
          )}
        >
          {chart.length ? (
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={chart} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
                <CartesianGrid stroke="var(--color-border)" vertical={false} />
                <XAxis
                  dataKey="at"
                  tickFormatter={formatTime}
                  minTickGap={60}
                  tick={{ fill: "var(--color-muted)", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  allowDecimals={false}
                  width={40}
                  tick={{ fill: "var(--color-muted)", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={chartTooltip}
                  labelFormatter={(label) => formatTime(Number(label))}
                />
                <Line
                  name={text("Observed sockets", "Beobachtete Sockets")}
                  dataKey="sockets"
                  type="linear"
                  stroke="var(--color-info)"
                  strokeWidth={2}
                  dot={false}
                  isAnimationActive={false}
                />
                <Line
                  name={text("New socket tuples", "Neue Socket-Kombinationen")}
                  dataKey="newSockets"
                  type="linear"
                  stroke="var(--color-accent)"
                  dot={false}
                  connectNulls={false}
                  isAnimationActive={false}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <EmptyChart
              text={text("No socket observations yet.", "Noch keine Socketbeobachtungen.")}
            />
          )}
        </div>
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs">
          <span className="text-info">{text("Observed sockets", "Beobachtete Sockets")}</span>
          <span className="text-accent">
            {text("New tuples per sample", "Neue Kombinationen pro Messung")}
          </span>
        </div>
        <p className="mt-2 text-xs text-muted">
          {text(
            "Turnover compares process, protocol and endpoints between snapshots. Short-lived sockets can be missed; this is not a packet or failed-connection count.",
            "Der Wechsel vergleicht Prozess, Protokoll und Endpunkte zwischen Momentaufnahmen. Kurzlebige Sockets können fehlen; dies zählt keine Pakete oder gescheiterten Verbindungen.",
          )}
        </p>
      </section>

      <section className="space-y-3 rounded-lg border border-border bg-surface p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3 className="flex items-center gap-2 text-sm font-medium">
            <TriangleAlert className="size-4 text-warn" />
            {text("Patterns to review", "Muster zur Prüfung")}
            <Badge variant={outstanding.length ? "warn" : "default"}>{outstanding.length}</Badge>
          </h3>
          <label className="flex min-h-11 cursor-pointer items-center gap-2 text-xs text-muted">
            <input
              type="checkbox"
              checked={showAcknowledged}
              onChange={(event) => setShowAcknowledged(event.target.checked)}
            />
            {text("Include reviewed", "Gesehene einblenden")}
          </label>
        </div>
        <p className="text-xs text-muted">
          {text(
            "Heuristics flag changes and recurring patterns. They do not classify malware or prove protection. Read the measured evidence before creating any rule.",
            "Heuristiken markieren Änderungen und wiederkehrende Muster. Sie erkennen keine Malware und belegen keinen Schutz. Prüfe die gemessenen Hinweise vor einer Regeländerung.",
          )}
        </p>
        {shownEvents.length ? (
          <ul className="max-h-[30rem] space-y-2 overflow-y-auto overscroll-contain">
            {shownEvents.map((event) => {
              const program = programs.find((item) => item.key === event.programKey);
              return (
                <li
                  key={event.id}
                  data-testid="telemetry-event"
                  data-event-kind={event.kind}
                  className={cn(
                    "space-y-2 rounded-md border p-3",
                    event.severity === "warning" && !event.acknowledgedAt
                      ? "border-warn/40 bg-warn/5"
                      : "border-border bg-elevated/40",
                  )}
                >
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div>
                      <p className="text-sm font-medium">{titles[event.kind]}</p>
                      <p className="mt-1 text-xs text-muted">
                        {formatTime(event.at)} ·{" "}
                        {program?.name ||
                          (event.programKey
                            ? event.programKey.split("\\").pop()
                            : text("Host-wide observation", "Hostweite Beobachtung"))}
                      </p>
                    </div>
                    <Badge
                      variant={
                        event.acknowledgedAt
                          ? "default"
                          : event.severity === "warning"
                            ? "warn"
                            : "info"
                      }
                    >
                      {event.acknowledgedAt
                        ? text("Reviewed", "Gesehen")
                        : event.severity === "warning"
                          ? text("Review", "Prüfen")
                          : text("Notice", "Hinweis")}
                    </Badge>
                  </div>
                  {program?.exe ? (
                    <p dir="ltr" className="break-all font-mono text-xs text-muted">
                      {program.exe}
                    </p>
                  ) : null}
                  <Evidence event={event} text={text} formatTime={formatTime} />
                  <div className="flex flex-wrap gap-2">
                    {!event.acknowledgedAt ? (
                      <Button
                        variant="outline"
                        className="min-h-11 text-xs"
                        onClick={() => acknowledge(event.id)}
                      >
                        {text("Mark reviewed", "Als gesehen markieren")}
                      </Button>
                    ) : null}
                    {program && /^[a-z]:\\.*\.exe$/i.test(program.exe) ? (
                      <Button
                        variant="outline"
                        className="min-h-11 text-xs"
                        onClick={() => openRule(program)}
                      >
                        {text("Review a program rule", "Programmregel prüfen")}
                      </Button>
                    ) : null}
                  </div>
                </li>
              );
            })}
          </ul>
        ) : (
          <p className="rounded-md border border-dashed border-border p-5 text-sm text-muted">
            {text(
              "No unreviewed patterns in the retained observations. This is not a security verdict.",
              "Keine ungesehenen Muster in den gespeicherten Beobachtungen. Das ist keine Sicherheitsbewertung.",
            )}
          </p>
        )}
      </section>

      <section className="space-y-3 rounded-lg border border-accent/40 bg-accent/5 p-4">
        <div className="flex flex-wrap items-center gap-2">
          <Fingerprint className="size-5 text-accent" />
          <h3 className="text-sm font-medium">DriftGuard</h3>
          <Badge variant="accent">
            {text("Experimental · this session", "Experimentell · diese Sitzung")}
          </Badge>
        </div>
        <p className="text-sm text-muted">
          {text(
            "Freeze the observed TCP peers of one executable as a reference. A later peer outside that reference creates a review event. It never blocks automatically.",
            "Halte die beobachteten TCP-Gegenstellen einer EXE als Vergleich fest. Eine spätere Gegenstelle außerhalb dieses Vergleichs erzeugt einen Prüfhinweis. Es wird nie automatisch blockiert.",
          )}
        </p>
        <label className="block space-y-1 text-xs text-muted">
          <span>{text("Executable to observe", "Zu beobachtende Programmdatei")}</span>
          <select
            aria-label={text("Executable to observe", "Zu beobachtende Programmdatei")}
            value={selectedKey}
            onChange={(event) => {
              setSelectedKey(event.target.value);
              setGuardError(null);
            }}
            className="min-h-11 w-full min-w-0 rounded-sm border border-border bg-surface px-3 text-sm text-fg"
          >
            <option value="">
              {text("Select an observed program…", "Beobachtetes Programm wählen…")}
            </option>
            {[...programs]
              .sort((a, b) => b.currentSockets - a.currentSockets || a.name.localeCompare(b.name))
              .map((program) => (
                <option key={program.key} value={program.key}>
                  {program.name} · {program.currentSockets} {text("sockets", "Sockets")} ·{" "}
                  {program.exe || text("path unavailable", "Pfad unbekannt")}
                </option>
              ))}
          </select>
        </label>
        {selected ? (
          <div
            data-testid="telemetry-program"
            data-program-key={selected.key}
            className="space-y-2 rounded-md border border-border bg-surface p-3"
          >
            <p dir="ltr" className="break-all font-mono text-xs">
              {selected.exe || text("Executable path unavailable", "Programmpfad nicht verfügbar")}
            </p>
            <p className="text-xs text-muted">
              {selected.sampleCount} {text("observations", "Beobachtungen")} ·{" "}
              {selected.tcpPeers.length} {text("TCP peers", "TCP-Gegenstellen")} ·{" "}
              {Math.max(0, Math.floor((selected.lastSeenAt - selected.firstSeenAt) / 1000))}s
            </p>
            <p className="text-xs text-muted">
              {selected.identityMode === "pid-start"
                ? text(
                    "Process instances identified by PID and start time; the guard applies to the executable path.",
                    "Prozessinstanzen über PID und Startzeit identifiziert; der Vergleich gilt für den EXE-Pfad.",
                  )
                : text(
                    "Observations are grouped by executable path; individual process instances are not verified here.",
                    "Beobachtungen sind nach EXE-Pfad gruppiert; einzelne Prozessinstanzen sind hier nicht verifiziert.",
                  )}
            </p>
            {selectedGuard ? (
              <Badge variant="accent">
                {text("Reference frozen", "Vergleich festgehalten")} ·{" "}
                {formatTime(selectedGuard.frozenAt)}
              </Badge>
            ) : null}
            <Button
              disabled={!fresh || !eligible.ok || Boolean(selectedGuard)}
              onClick={() => {
                const result = freezeGuard(selected.key);
                setGuardError(result.ok ? null : result.error || "unknown");
              }}
              className="h-auto min-h-11 whitespace-normal py-2"
            >
              {text("Freeze observed peer baseline", "Beobachtete Gegenstellen festhalten")}
            </Button>
            {!eligible.ok && !selectedGuard ? (
              <p className="text-xs text-muted">{guardReason(eligible.error || "unknown", text)}</p>
            ) : null}
          </div>
        ) : null}
        {guardError ? (
          <p role="alert" className="text-sm text-warn">
            {guardReason(guardError, text)}
          </p>
        ) : null}
        <p className="text-xs text-muted">
          {text(
            "Requires at least 3 observations over 10 seconds and a TCP peer. The reference includes IP and port; CDNs and legitimate service changes can trigger notices. UDP remote peers are unavailable. Shared executables such as svchost.exe can host several services.",
            "Benötigt mindestens 3 Beobachtungen über 10 Sekunden und eine TCP-Gegenstelle. Der Vergleich enthält IP und Port; CDNs und normale Dienständerungen können Hinweise auslösen. Entfernte UDP-Gegenstellen sind nicht verfügbar. Gemeinsame EXE-Dateien wie svchost.exe können mehrere Dienste beherbergen.",
          )}
        </p>
        {guards.length ? (
          <ul className="space-y-2">
            {guards.map((guard) => (
              <li key={guard.programKey} className="rounded-md border border-border bg-surface p-3">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <div className="min-w-0 flex-1">
                    <p dir="ltr" className="break-all font-mono text-xs">
                      {guard.exe}
                    </p>
                    <p className="mt-1 text-xs text-muted">
                      {guard.peers.length} {text("reference peers", "Vergleichsgegenstellen")} ·{" "}
                      {formatTime(guard.frozenAt)}
                    </p>
                  </div>
                  <Button
                    variant="ghost"
                    className="h-auto min-h-11 whitespace-normal text-xs"
                    onClick={() => removeGuard(guard.programKey)}
                  >
                    {text("Remove reference", "Vergleich entfernen")}
                  </Button>
                </div>
                <details className="mt-2 text-xs">
                  <summary className="cursor-pointer text-muted">
                    {text("Show reference IPs and ports", "Vergleichs-IPs und Ports zeigen")}
                  </summary>
                  <ul className="mt-2 max-h-40 overflow-y-auto font-mono">
                    {guard.peers.map((peer) => (
                      <li key={peer} className="break-all py-0.5">
                        {peer}
                      </li>
                    ))}
                  </ul>
                </details>
              </li>
            ))}
          </ul>
        ) : null}
      </section>

      <section className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-surface p-4">
        <div className="min-w-0 flex-1">
          <h3 className="text-sm font-medium">Flight Recorder</h3>
          <p className="mt-1 text-xs text-muted">
            {samples.length} {text("samples", "Messungen")} · {events.length}{" "}
            {text("events", "Hinweise")} ·{" "}
            {text("up to 10 minutes of telemetry", "bis zu 10 Minuten Telemetrie")}
          </p>
          <p className="mt-2 text-xs text-muted">
            {text(
              "JSON stays local and includes program paths, endpoints and review events. Recording and DriftGuard references are kept only for this app session.",
              "Die JSON-Datei bleibt lokal und enthält Programmpfade, Endpunkte und Prüfhinweise. Aufzeichnung und DriftGuard-Vergleiche bestehen nur in dieser App-Sitzung.",
            )}
          </p>
        </div>
        <Button variant="outline" disabled={!samples.length} onClick={exportRecorder}>
          <Download className="size-4" />
          {text("Export JSON", "JSON exportieren")}
        </Button>
        {exportError ? (
          <p role="alert" className="w-full break-words text-xs text-warn">
            {exportError}
          </p>
        ) : null}
        <details className="w-full border-t border-border pt-3 text-xs">
          <summary className="cursor-pointer text-muted">
            {text(
              "Recorder details and session reset",
              "Aufzeichnungsdetails und Sitzung zurücksetzen",
            )}
          </summary>
          <p className="mt-2 text-muted">
            {text(
              "The rolling memory has explicit limits: 600 samples, 256 program groups, 256 events and 32 DriftGuard references. Reset clears these observations and references; Windows rules remain stored.",
              "Der rollende Speicher ist begrenzt: 600 Messungen, 256 Programmgruppen, 256 Hinweise und 32 DriftGuard-Vergleiche. Zurücksetzen löscht Beobachtungen und Vergleiche; Windows-Regeln bleiben gespeichert.",
            )}
          </p>
          <Button
            variant="outline"
            className="mt-3 text-xs"
            onClick={() => {
              useTelemetry.getState().resetSession();
              setSelectedKey("");
              setGuardError(null);
            }}
          >
            {text("Reset recorder session", "Aufzeichnungssitzung zurücksetzen")}
          </Button>
        </details>
      </section>
      {editor ? <NativeRuleEditor app={editor} onClose={() => setEditor(null)} /> : null}
    </div>
  );
}

function TelemetryMetric({
  icon: Icon,
  label,
  value,
  detail,
  tone = "text-fg",
}: {
  icon: typeof Activity;
  label: string;
  value: string;
  detail: string;
  tone?: string;
}) {
  return (
    <div className="min-w-0 bg-surface p-3">
      <p className="flex items-center gap-1.5 text-xs text-muted">
        <Icon className="size-3.5 shrink-0" />
        {label}
      </p>
      <p className={cn("mt-2 break-words font-mono text-xl tabular-nums", tone)}>{value}</p>
      <p className="mt-1 text-[11px] leading-relaxed text-muted">{detail}</p>
    </div>
  );
}

function EmptyChart({ text }: { text: string }) {
  return (
    <p className="flex h-full items-center justify-center px-5 text-center text-xs text-muted">
      {text}
    </p>
  );
}

function guardReason(reason: string, text: Copy): string {
  const reasons: Record<string, string> = {
    "select-program": text(
      "Select an observed executable first.",
      "Wähle zuerst eine beobachtete Programmdatei.",
    ),
    "resolved-executable-required": text(
      "A resolved executable path is required.",
      "Ein ermittelter Programmpfad ist erforderlich.",
    ),
    "current-observation-required": text(
      "A current socket observation is required.",
      "Eine aktuelle Socketbeobachtung ist erforderlich.",
    ),
    "need-three-observations-over-ten-seconds": text(
      "Collect at least 3 observations over 10 seconds before freezing a reference.",
      "Sammle mindestens 3 Beobachtungen über 10 Sekunden, bevor du den Vergleich festhältst.",
    ),
    "tcp-peer-required": text(
      "No observable TCP peer yet. UDP endpoints do not supply remote peers.",
      "Noch keine beobachtbare TCP-Gegenstelle. UDP-Endpunkte liefern keine entfernten Gegenstellen.",
    ),
    "observation-capacity-reached-reset-session": text(
      "Recorder capacity reached. Export and reset the session before collecting a new baseline.",
      "Aufzeichnungskapazität erreicht. Exportiere und setze die Sitzung zurück, bevor du eine neue Basis sammelst.",
    ),
    "guard-capacity-reached": text(
      "The 32-reference limit is reached. Remove an existing reference first.",
      "Die Grenze von 32 Vergleichen ist erreicht. Entferne zuerst einen vorhandenen Vergleich.",
    ),
  };
  return reasons[reason] || reason;
}

function qualityReason(reason: string, text: Copy): string {
  const reasons: Record<string, string> = {
    "Windows capture required": text(
      "Windows capture is required.",
      "Windows-Beobachtung ist erforderlich.",
    ),
    "Observation continuity reset after a capture gap": text(
      "A gap in capture restarted the comparison baseline.",
      "Eine Lücke in der Beobachtung hat die Vergleichsbasis neu gestartet.",
    ),
    "Counter source or counters changed": text(
      "The counter source changed or counters reset; a new baseline is being collected.",
      "Die Zählerquelle hat gewechselt oder Zähler wurden zurückgesetzt; eine neue Basis wird gesammelt.",
    ),
    "Waiting for comparable interface counter samples": text(
      "Waiting for comparable interface counter readings.",
      "Warte auf vergleichbare Schnittstellenzähler.",
    ),
    "Non-increasing capture timestamp": text(
      "The Windows capture timestamp did not advance.",
      "Der Zeitstempel der Windows-Lesung ist nicht fortgeschritten.",
    ),
  };
  return reasons[reason] || reason;
}

function Evidence({
  event,
  text,
  formatTime,
}: {
  event: TelemetryEvent;
  text: Copy;
  formatTime: (at: number) => string;
}) {
  const labels: Record<string, string> = {
    bytesPerSecond: text("Measured rate", "Gemessene Rate"),
    baselineBytesPerSecond: text("Baseline median", "Median der Basis"),
    thresholdBytesPerSecond: text("Threshold", "Schwelle"),
    baselineSamples: text("Baseline samples", "Basismessungen"),
    endpoint: text("Endpoint", "Endpunkt"),
    frozenAt: text("Reference frozen at", "Vergleich festgehalten um"),
    baselinePeers: text("Reference peers", "Vergleichsgegenstellen"),
    protocol: text("Protocol", "Protokoll"),
    scope: text("Scope", "Umfang"),
    action: text("Action", "Aktion"),
    consecutiveObservations: text("Consecutive observations", "Aufeinanderfolgende Beobachtungen"),
    observedForMs: text("Observed duration", "Beobachtungsdauer"),
    intervals: text("Observed intervals", "Beobachtete Abstände"),
    typicalIntervalMs: text("Typical interval", "Typischer Abstand"),
    intervalSpreadMs: text("Interval spread", "Streuung der Abstände"),
    sampleIntervalMs: text("Sampling interval", "Messabstand"),
    identityMode: text("Identity scope", "Identitätsumfang"),
    distinctNewPeers: text("New distinct peers", "Neue unterschiedliche Gegenstellen"),
    windowMs: text("Time window", "Zeitfenster"),
    observationSamples: text("Observations", "Beobachtungen"),
    currentSynSockets: text("Current SYN sockets", "Aktuelle SYN-Sockets"),
    previousSynSockets: text("Previous SYN sockets", "Vorherige SYN-Sockets"),
    baselineSynSockets: text("Baseline SYN median", "SYN-Median der Basis"),
  };
  const values: Record<string, string> = {
    "host-interfaces": text("Host interfaces", "Host-Schnittstellen"),
    "observed-peer-baseline": text(
      "Observed TCP peer reference",
      "Beobachteter TCP-Gegenstellenvergleich",
    ),
    "observation-only": text("Review event only", "Nur Prüfhinweis"),
    "local-listener": text("Local TCP listener", "Lokaler TCP-Listener"),
    "new-socket-appearances": text(
      "Newly observed socket tuples",
      "Neu beobachtete Socket-Kombinationen",
    ),
    "pid-start": text("PID and start time", "PID und Startzeit"),
    "executable-group": text("Executable group", "EXE-Gruppe"),
    unresolved: text("Unresolved identity", "Ungeklärte Identität"),
    "tcp-endpoints": text("TCP endpoints", "TCP-Endpunkte"),
    "host-socket-states": text("Host socket states", "Socketzustände des Hosts"),
  };
  return (
    <dl className="grid gap-x-4 gap-y-1.5 text-xs sm:grid-cols-2">
      {Object.entries(event.evidence).map(([key, value]) => (
        <div key={key} className="min-w-0">
          <dt className="text-muted">{labels[key] || key}</dt>
          <dd className="break-all font-mono">
            {typeof value === "number" && key.toLowerCase().includes("bytespersecond")
              ? fmtRate(value)
              : typeof value === "number" && key === "frozenAt"
                ? formatTime(value)
                : typeof value === "number" && key.endsWith("Ms")
                  ? `${(value / 1000).toFixed(1)}s`
                  : values[String(value)] || String(value)}
          </dd>
        </div>
      ))}
    </dl>
  );
}
