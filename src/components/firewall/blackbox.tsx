import { useEffect, useRef, useState } from "react";
import { Box, ChevronRight, FileSearch, RefreshCw, ShieldCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { NativeRuleEditor } from "@/components/firewall/native-controls";
import { getNativeBridge } from "@/lib/firewall/native-types";
import type {
  ProcessEntry,
  ProcessInspection,
  ProcessSnapshot,
} from "@/lib/firewall/observation-types";
import { useFirewall } from "@/lib/firewall/store";
import type { AppInfo } from "@/lib/firewall/types";
import { useT } from "@/lib/i18n/use-t";
import { cn } from "@/lib/utils";

export function BlackboxView() {
  const language = useFirewall((state) => state.settings.language);
  const setView = useFirewall((state) => state.setView);
  const setQuery = useFirewall((state) => state.setQuery);
  const clearError = useFirewall((state) => state.clearNativeError);
  const t = useT();
  const text = (en: string, de: string) => (language === "de" ? de : en);
  const bridge = getNativeBridge();
  const supported = Boolean(bridge?.getProcessSnapshot && bridge?.inspectProcess);
  const [snapshot, setSnapshot] = useState<ProcessSnapshot | null>(null);
  const [pending, setPending] = useState(false);
  const [readError, setReadError] = useState<string | null>(null);
  const [query, setSearch] = useState("");
  const [limit, setLimit] = useState(60);
  const [inspection, setInspection] = useState<ProcessInspection | null>(null);
  const [selected, setSelected] = useState<ProcessEntry | null>(null);
  const [inspecting, setInspecting] = useState(false);
  const [inspectionError, setInspectionError] = useState<string | null>(null);
  const [editor, setEditor] = useState<AppInfo | null>(null);
  const [now, setNow] = useState(Date.now);
  const refresh = useRef<() => void>(() => {});
  const inspectionGeneration = useRef(0);

  useEffect(() => {
    if (!bridge?.getProcessSnapshot) return;
    let cancelled = false;
    let running = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const poll = async () => {
      if (cancelled || running) return;
      clearTimeout(timer);
      running = true;
      setPending(true);
      try {
        const result = await bridge.getProcessSnapshot!();
        if (cancelled) return;
        if (result.available) setSnapshot(result);
        setReadError(
          result.available ? null : result.errors.join(" · ") || "Process snapshot unavailable.",
        );
      } catch (error) {
        if (!cancelled) setReadError(error instanceof Error ? error.message : String(error));
      } finally {
        running = false;
        if (!cancelled) {
          setPending(false);
          timer = setTimeout(() => void poll(), 15000);
        }
      }
    };
    refresh.current = () => void poll();
    void poll();
    const clock = setInterval(() => setNow(Date.now()), 1000);
    return () => {
      cancelled = true;
      clearTimeout(timer);
      clearInterval(clock);
      refresh.current = () => {};
      inspectionGeneration.current += 1;
    };
  }, [bridge]);

  async function inspect(process: ProcessEntry) {
    if (!bridge?.inspectProcess || process.startedAt === null || inspecting) return;
    const generation = ++inspectionGeneration.current;
    setSelected(process);
    setInspection(null);
    setInspectionError(null);
    setInspecting(true);
    try {
      const result = await bridge.inspectProcess({
        pid: process.pid,
        startedAt: process.startedAt,
      });
      if (generation !== inspectionGeneration.current) return;
      setInspection(result);
    } catch (error) {
      if (generation === inspectionGeneration.current)
        setInspectionError(error instanceof Error ? error.message : String(error));
    } finally {
      if (generation === inspectionGeneration.current) setInspecting(false);
    }
  }

  if (!supported)
    return (
      <section className="rounded-lg border border-border bg-surface p-5">
        <Box className="mb-3 size-7 text-accent" />
        <h2 className="font-medium">Blackbox Breaker</h2>
        <p className="mt-2 text-sm text-muted">
          {text(
            "Process inspection requires the current Windows desktop application. The browser lab has no access to your processes, services or files.",
            "Die Prozessanalyse benötigt die aktuelle Windows-Desktop-Anwendung. Das Browserlabor hat keinen Zugriff auf deine Prozesse, Dienste oder Dateien.",
          )}
        </p>
      </section>
    );

  const search = query.trim().toLowerCase();
  const processes = (snapshot?.processes ?? []).filter(
    (process) =>
      !search ||
      [
        process.name,
        process.exe,
        String(process.pid),
        ...process.services.flatMap((service) => [service.name, service.displayName]),
      ].some((value) => value.toLowerCase().includes(search)),
  );
  const process = inspection?.available ? inspection.process : undefined;
  const age = snapshot ? Math.max(0, Math.floor((now - snapshot.at) / 1000)) : null;
  const stale = Boolean(readError || (age !== null && age > 45));
  const formatTime = (at: number) =>
    new Date(at).toLocaleTimeString(language === "de" ? "de-DE" : "en-GB");
  const dateTime = (at: number | null) =>
    at === null
      ? text("Unavailable", "Nicht verfügbar")
      : new Date(at).toLocaleString(language === "de" ? "de-DE" : "en-GB");
  const isCurrent =
    selected &&
    snapshot?.processes.some(
      (entry) => entry.pid === selected.pid && entry.startedAt === selected.startedAt,
    );
  const openRule = () => {
    if (!process?.exe) return;
    clearError();
    setEditor({
      id: `inspection-${process.pid}-${process.startedAt}`,
      name: process.name,
      exe: process.exe.split("\\").pop() || process.name,
      path: process.exe,
      pid: process.pid,
      category: "unknown",
      publisher: inspection?.signature.publisher || "",
      signed: inspection?.signature.status === "valid" ? true : null,
    });
  };

  return (
    <div className="space-y-4">
      <section className="overflow-hidden rounded-lg border border-border bg-surface">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-4 py-3">
          <div className="flex items-center gap-2 text-sm font-medium">
            <Box className="size-4 text-accent" /> Blackbox Breaker{" "}
            <Badge variant="info">{text("Read-only inspection", "Lesende Analyse")}</Badge>
          </div>
          <Button
            variant="outline"
            disabled={pending}
            onClick={() => refresh.current()}
            className="min-h-11"
          >
            <RefreshCw className={cn("size-4", pending && "animate-spin")} />
            {text(
              pending ? "Reading…" : "Refresh processes",
              pending ? "Wird gelesen…" : "Prozesse aktualisieren",
            )}
          </Button>
        </div>
        <div className="grid grid-cols-2 divide-x divide-border sm:grid-cols-4">
          <Metric
            label={text("Processes", "Prozesse")}
            value={snapshot ? String(snapshot.processes.length) : "—"}
          />
          <Metric
            label={text("Hosted services", "Gehostete Dienste")}
            value={
              snapshot
                ? String(snapshot.processes.reduce((sum, item) => sum + item.services.length, 0))
                : "—"
            }
          />
          <Metric
            label={text("Last read", "Letzte Lesung")}
            value={snapshot ? formatTime(snapshot.at) : "—"}
            hint={age !== null ? `${age}s ${text("ago", "alt")}` : undefined}
            warn={stale}
          />
          <Metric
            label={text("Read duration", "Lesedauer")}
            value={snapshot ? `${Math.round(snapshot.captureDurationMs)} ms` : "—"}
          />
        </div>
      </section>
      <p className="text-xs leading-relaxed text-muted">
        {text(
          "See which services and modules belong to a process. A hosted service or loaded DLL does not prove that it opened a socket. PID and start time identify the process instance; unavailable details stay unavailable.",
          "Sieh, welche Dienste und Module zu einem Prozess gehören. Ein gehosteter Dienst oder eine geladene DLL belegt nicht, wer einen Socket geöffnet hat. PID und Startzeit identifizieren die Prozessinstanz; fehlende Details bleiben als nicht verfügbar markiert.",
        )}
      </p>
      {readError || stale ? (
        <p
          role="alert"
          className="rounded-md border border-warn/40 bg-warn/10 p-3 text-sm text-warn"
        >
          {text(
            "The process list is not current. Last successful observations are retained.",
            "Die Prozessliste ist nicht aktuell. Die zuletzt erfolgreichen Beobachtungen bleiben sichtbar.",
          )}
          {readError ? ` ${readError}` : ""}
        </p>
      ) : null}
      {snapshot?.errors.length ? (
        <Issues title={text("Partial read", "Teilweise Lesung")} errors={snapshot.errors} />
      ) : null}
      {snapshot?.truncated ? (
        <p className="text-xs text-warn">
          {text(
            "The process list reached its safety limit; additional processes are not shown.",
            "Die Prozessliste hat ihre Begrenzung erreicht; weitere Prozesse werden nicht angezeigt.",
          )}
        </p>
      ) : null}
      <div className="grid items-start gap-4 md:grid-cols-[minmax(0,.85fr)_minmax(0,1.15fr)]">
        <section className="min-w-0 space-y-2">
          <Input
            value={query}
            onChange={(event) => {
              setSearch(event.target.value);
              setLimit(60);
            }}
            aria-label={text("Search processes, PID or service", "Prozess, PID oder Dienst suchen")}
            placeholder={text("Process, PID, service…", "Prozess, PID, Dienst…")}
          />
          <p role="status" className="text-xs text-muted">
            {processes.length} {text("matching processes", "passende Prozesse")}
          </p>
          <div className="max-h-[34rem] overflow-y-auto overscroll-contain rounded-lg border border-border bg-surface">
            {processes.length ? (
              <ul className="divide-y divide-border">
                {processes.slice(0, limit).map((entry) => {
                  const active =
                    selected?.pid === entry.pid && selected.startedAt === entry.startedAt;
                  return (
                    <li key={`${entry.pid}-${entry.startedAt}`}>
                      <button
                        data-testid="blackbox-process"
                        data-process-pid={entry.pid}
                        data-process-start={entry.startedAt ?? ""}
                        type="button"
                        disabled={inspecting || entry.startedAt === null}
                        onClick={() => void inspect(entry)}
                        aria-pressed={active}
                        className={cn(
                          "flex w-full items-start gap-2 p-3 text-left disabled:cursor-not-allowed disabled:opacity-60",
                          active
                            ? "bg-accent/10 ring-1 ring-inset ring-accent/40"
                            : "hover:bg-elevated",
                        )}
                      >
                        <div className="min-w-0 flex-1">
                          <p className="break-words text-sm font-medium">{entry.name}</p>
                          <p className="mt-1 font-mono text-xs text-muted">
                            PID {entry.pid} · {entry.services.length} {text("services", "Dienste")}
                          </p>
                          {entry.services.length ? (
                            <p className="mt-1 break-words text-xs text-muted">
                              {entry.services
                                .slice(0, 3)
                                .map((service) => service.name)
                                .join(" · ")}
                              {entry.services.length > 3 ? ` +${entry.services.length - 3}` : ""}
                            </p>
                          ) : null}
                          {entry.startedAt === null ? (
                            <p className="mt-1 text-xs text-warn">
                              {text(
                                "Start time unavailable; inspection disabled",
                                "Startzeit nicht verfügbar; Detailanalyse gesperrt",
                              )}
                            </p>
                          ) : null}
                        </div>
                        <ChevronRight
                          aria-hidden="true"
                          className="mt-1 size-4 shrink-0 text-muted"
                        />
                      </button>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="p-5 text-sm text-muted">
                {text(
                  pending ? "Reading Windows processes…" : "No matching process observations.",
                  pending
                    ? "Windows-Prozesse werden gelesen…"
                    : "Keine passenden Prozessbeobachtungen.",
                )}
              </p>
            )}
            {processes.length > limit ? (
              <Button
                variant="ghost"
                className="w-full"
                onClick={() => setLimit((value) => value + 60)}
              >
                {text("Show more", "Mehr anzeigen")} ({processes.length - limit})
              </Button>
            ) : null}
          </div>
        </section>
        <section
          aria-label={text("Process inspection", "Prozessdetails")}
          className="min-w-0 space-y-3 rounded-lg border border-border bg-surface p-4"
        >
          {!selected ? (
            <div className="py-10 text-center">
              <FileSearch className="mx-auto mb-3 size-8 text-accent" />
              <h2 className="text-sm font-medium">
                {text("Look inside a process", "Einen Prozess aufschlüsseln")}
              </h2>
              <p className="mt-2 text-xs leading-relaxed text-muted">
                {text(
                  "Select a process to read its hosted services, process relationships, modules, Authenticode signature and SHA-256 file hash.",
                  "Wähle einen Prozess für gehostete Dienste, Prozessbeziehungen, Module, Authenticode-Signatur und SHA-256-Dateihash.",
                )}
              </p>
            </div>
          ) : (
            <>
              <div>
                <h2 className="break-words font-medium">{selected.name}</h2>
                <p className="mt-1 font-mono text-xs text-muted">PID {selected.pid}</p>
                <p className="mt-1 text-xs text-muted">
                  {text("Started", "Gestartet")}: {dateTime(selected.startedAt)}
                </p>
              </div>
              {inspecting ? (
                <p role="status" className="flex items-center gap-2 text-sm text-info">
                  <RefreshCw className="size-4 animate-spin" />
                  {text("Inspecting this process instance…", "Diese Prozessinstanz wird geprüft…")}
                </p>
              ) : null}
              {inspectionError ? (
                <p role="alert" className="break-words text-sm text-warn">
                  {inspectionError}
                </p>
              ) : null}
              {selected && !isCurrent ? (
                <p className="text-xs text-warn">
                  {text(
                    "This process instance is absent from the latest process list. Inspection results below describe the recorded time.",
                    "Diese Prozessinstanz fehlt in der aktuellen Prozessliste. Detailergebnisse beziehen sich auf den angegebenen Prüfzeitpunkt.",
                  )}
                </p>
              ) : null}
              {inspection ? (
                <>
                  <p className="text-xs text-muted">
                    {text("Inspected", "Geprüft")}: {formatTime(inspection.at)} ·{" "}
                    {Math.round(inspection.captureDurationMs)} ms
                  </p>
                  {!inspection.available ? (
                    <p role="alert" className="text-sm text-warn">
                      {text(
                        "The selected process instance could not be inspected. Refresh the process list before retrying.",
                        "Die gewählte Prozessinstanz konnte nicht geprüft werden. Aktualisiere die Prozessliste vor einem erneuten Versuch.",
                      )}
                    </p>
                  ) : null}
                  {inspection.errors.length ? (
                    <Issues
                      title={text("Inspection details unavailable", "Fehlende Analysedetails")}
                      errors={inspection.errors}
                    />
                  ) : null}
                </>
              ) : null}
              {process && inspection ? (
                <>
                  <p dir="ltr" className="break-all font-mono text-xs">
                    {process.exe ||
                      text("Executable path unavailable", "Programmpfad nicht verfügbar")}
                  </p>
                  {process.errors.length ? (
                    <Issues
                      title={text("Process read notes", "Hinweise zur Prozesslesung")}
                      errors={process.errors}
                    />
                  ) : null}
                  <div className="flex flex-wrap gap-2">
                    <Button
                      variant="outline"
                      className="h-auto min-h-11 whitespace-normal py-2 text-xs"
                      onClick={() => {
                        setQuery(process.exe || process.name);
                        setView("monitor");
                      }}
                    >
                      {text("Find in monitor", "Im Monitor suchen")}
                    </Button>
                    {/^[a-z]:\\.*\.exe$/i.test(process.exe) ? (
                      <Button
                        variant="outline"
                        className="h-auto min-h-11 whitespace-normal py-2 text-xs"
                        onClick={openRule}
                      >
                        {t("native.rule")}
                      </Button>
                    ) : null}
                  </div>
                  {process.services.length ? (
                    <p className="text-xs text-warn">
                      {text(
                        "A program rule affects this executable and can affect all services it hosts. Service-level socket attribution is not available.",
                        "Eine Programmregel betrifft diese EXE und kann alle gehosteten Dienste betreffen. Die Zuordnung eines Sockets zu einem einzelnen Dienst ist nicht verfügbar.",
                      )}
                    </p>
                  ) : null}
                  <div className="space-y-2 border-t border-border pt-3">
                    <h3 className="flex items-center gap-2 text-sm font-medium">
                      <ShieldCheck className="size-4" />
                      {text("File identity", "Dateiidentität")}
                    </h3>
                    <Badge
                      variant={
                        inspection.signature.status === "valid"
                          ? "allow"
                          : inspection.signature.status === "invalid"
                            ? "block"
                            : "warn"
                      }
                    >
                      {text("Signature", "Signatur")}:{" "}
                      {
                        {
                          valid: text("Valid", "Gültig"),
                          invalid: text("Invalid", "Ungültig"),
                          unsigned: text("Unsigned", "Unsigniert"),
                          unknown: text("Unknown", "Unbekannt"),
                        }[inspection.signature.status]
                      }
                    </Badge>
                    {inspection.signature.publisher ? (
                      <p className="break-words text-xs">{inspection.signature.publisher}</p>
                    ) : null}
                    {inspection.signature.nativeStatus ? (
                      <p className="break-words text-xs text-muted">
                        {inspection.signature.nativeStatus}
                      </p>
                    ) : null}
                    <p className="text-xs text-muted">SHA-256</p>
                    <p dir="ltr" className="break-all font-mono text-xs">
                      {inspection.sha256 || text("Not available", "Nicht verfügbar")}
                    </p>
                    <p className="text-xs text-muted">
                      {text(
                        "Signature validity is not a verdict about a program's behavior.",
                        "Eine gültige Signatur bewertet nicht das Verhalten eines Programms.",
                      )}
                    </p>
                  </div>
                  <details open className="border-t border-border pt-3">
                    <summary className="cursor-pointer text-sm font-medium">
                      {text("Hosted services", "Gehostete Dienste")} ({process.services.length})
                    </summary>
                    {process.services.length ? (
                      <ul className="mt-2 space-y-3">
                        {process.services.map((service) => (
                          <li key={service.name} className="rounded-md bg-elevated p-2 text-xs">
                            <p className="break-words font-medium">
                              {service.displayName || service.name}
                            </p>
                            <p className="mt-1 break-words text-muted">
                              {service.name} · {service.state}
                            </p>
                            {service.serviceDll ? (
                              <p dir="ltr" className="mt-1 break-all font-mono text-muted">
                                {service.serviceDll}
                              </p>
                            ) : null}
                            {service.errors?.length ? (
                              <Issues
                                title={text("Details unavailable", "Details nicht verfügbar")}
                                errors={service.errors}
                              />
                            ) : null}
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="mt-2 text-xs text-muted">
                        {text(
                          "No hosted services were reported for this process.",
                          "Für diesen Prozess wurden keine gehosteten Dienste gemeldet.",
                        )}
                      </p>
                    )}
                  </details>
                  <details className="border-t border-border pt-3">
                    <summary className="cursor-pointer text-sm font-medium">
                      {text("Process relationships", "Prozessbeziehungen")}
                    </summary>
                    <div className="mt-2 space-y-2 text-xs">
                      <p className="text-muted">{text("Parent process", "Elternprozess")}</p>
                      {inspection.parent ? (
                        <ProcessLine process={inspection.parent} />
                      ) : (
                        <p>
                          {text(
                            "Not verified or unavailable",
                            "Nicht verifiziert oder nicht verfügbar",
                          )}
                        </p>
                      )}
                      <p className="pt-2 text-muted">
                        {text("Verified children", "Verifizierte Kindprozesse")} (
                        {inspection.children.length})
                      </p>
                      {inspection.children.map((child) => (
                        <ProcessLine key={`${child.pid}-${child.startedAt}`} process={child} />
                      ))}
                    </div>
                  </details>
                  <details className="border-t border-border pt-3">
                    <summary className="cursor-pointer text-sm font-medium">
                      {text("Loaded modules", "Geladene Module")} ({inspection.modules.length})
                    </summary>
                    {inspection.modulesTruncated ? (
                      <p className="mt-2 text-xs text-warn">
                        {text("The module list is truncated.", "Die Modulliste ist begrenzt.")}
                      </p>
                    ) : null}
                    {inspection.modules.length ? (
                      <ul className="mt-2 max-h-64 space-y-2 overflow-y-auto">
                        {inspection.modules.map((module, index) => (
                          <li key={`${module.path}-${index}`} className="text-xs">
                            <p className="break-words">{module.name}</p>
                            <p dir="ltr" className="break-all font-mono text-muted">
                              {module.path}
                            </p>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <p className="mt-2 text-xs text-muted">
                        {text(
                          "No module data returned; check the inspection notes.",
                          "Keine Moduldaten zurückgegeben; beachte die Analysehinweise.",
                        )}
                      </p>
                    )}
                  </details>
                </>
              ) : null}
            </>
          )}
        </section>
      </div>
      {editor ? <NativeRuleEditor app={editor} onClose={() => setEditor(null)} /> : null}
    </div>
  );
}

function Metric({
  label,
  value,
  hint,
  warn,
}: {
  label: string;
  value: string;
  hint?: string;
  warn?: boolean;
}) {
  return (
    <div className="min-w-0 p-3">
      <p className="text-xs text-muted">{label}</p>
      <p className={cn("mt-1 break-words font-mono text-lg", warn && "text-warn")}>{value}</p>
      {hint ? <p className="text-xs text-muted">{hint}</p> : null}
    </div>
  );
}

function Issues({ title, errors }: { title: string; errors: string[] }) {
  return (
    <details className="rounded-md border border-warn/30 bg-warn/5 p-2 text-xs text-warn">
      <summary className="cursor-pointer">
        {title} ({errors.length})
      </summary>
      <ul className="mt-2 list-inside list-disc space-y-1 break-words">
        {errors.map((error, index) => (
          <li key={index}>{error}</li>
        ))}
      </ul>
    </details>
  );
}

function ProcessLine({ process }: { process: ProcessEntry }) {
  return (
    <div className="rounded-md bg-elevated p-2">
      <p className="break-words">
        {process.name} · PID {process.pid}
      </p>
      <p dir="ltr" className="mt-1 break-all font-mono text-muted">
        {process.exe || "—"}
      </p>
    </div>
  );
}
