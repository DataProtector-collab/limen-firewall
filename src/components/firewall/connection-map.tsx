import { useEffect, useMemo, useState } from "react";
import { Globe2, MapPin, ShieldCheck, TriangleAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useFirewall } from "@/lib/firewall/store";
import { useApproval } from "@/lib/firewall/approval-store";
import { getNativeBridge, isNativeDesktop } from "@/lib/firewall/native-types";
import { GEO_ADDRESS_LIMIT, approvalMapPeers, groupMapConnections, mapAddresses, mapConnections, mapPoint } from "@/lib/firewall/geo";
import type { GeoCountry, GeoSnapshot } from "@/lib/firewall/geo-types";
import countriesData from "@/assets/geo-countries.json";
import worldMap from "@/assets/geo-world.svg";
import { cn } from "@/lib/utils";

const countries: Record<string, GeoCountry> = countriesData;

export function ConnectionMapView() {
  const language = useFirewall((state) => state.settings.language);
  const captureEnabled = useFirewall((state) => state.settings.kernelCapture);
  const connections = useFirewall((state) => state.connections);
  const apps = useFirewall((state) => state.kernelApps);
  const captureStale = useFirewall((state) => state.captureStale);
  const live = useFirewall((state) => state.kernelLive);
  const lastSnapshotAt = useFirewall((state) => state.kernelLastSnapshotAt);
  const approvalStatus = useApproval((state) => state.status);
  const approvalError = useApproval((state) => state.error);
  const [geo, setGeo] = useState<GeoSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [program, setProgram] = useState("");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [selection, setSelection] = useState("all");
  const [query, setQuery] = useState("");
  const [visibleCount, setVisibleCount] = useState(80);
  const text = (en: string, de: string) => language === "de" ? de : en;
  const allPeers = useMemo(() => mapConnections([...connections, ...approvalMapPeers(approvalStatus?.attempts ?? [])]), [connections, approvalStatus]);
  const addressKey = useMemo(() => JSON.stringify(mapAddresses(allPeers)), [allPeers]);
  useEffect(() => {
    const bridge = getNativeBridge();
    if (!bridge?.getGeoLocations) return;
    let cancelled = false;
    setLoading(true);
    bridge.getGeoLocations(JSON.parse(addressKey) as string[]).then((result) => {
      if (!cancelled) { setGeo(result); setError(null); }
    }).catch((reason: unknown) => {
      if (!cancelled) { setGeo(null); setError(reason instanceof Error ? reason.message : String(reason)); }
    }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [addressKey]);
  const peers = useMemo(() => allPeers.filter((connection) => (!program || connection.appId === program) && (sourceFilter === "all" || connection.source === sourceFilter)), [allPeers, program, sourceFilter]);
  const grouped = useMemo(() => groupMapConnections(peers, geo?.results ?? [], countries), [peers, geo]);
  const appNames = new Map(apps.map((app) => [app.id, app.exe || app.name]));
  for (const peer of allPeers) if (peer.program && !appNames.has(peer.appId)) appNames.set(peer.appId, peer.program.split(/[\\/]/).pop() || peer.program);
  const participatingApps = [...new Set(allPeers.map((peer) => peer.appId))].map((id) => ({ id, name: appNames.get(id) ?? text("Unknown program", "Programm unbekannt") }));
  const selected = selection === "non-public" ? grouped.nonPublic : selection === "unknown" ? grouped.unknown :
    selection === "all" ? peers : grouped.groups.find((group) => group.country.code === selection)?.connections ?? [];
  const filtered = selected.filter((connection) => !query || `${connection.remoteIp} ${appNames.get(connection.appId) ?? ""} ${connection.pid ?? ""}`.toLowerCase().includes(query.toLowerCase()));
  const locationByIp = new Map((geo?.results ?? []).map((location) => [location.ip, location]));
  const countryName = (country: GeoCountry) => language === "de" ? country.nameDe : country.name;
  const select = (value: string) => { setSelection(value); setVisibleCount(80); };

  if (!isNativeDesktop() || !getNativeBridge()?.getGeoLocations) return (
    <section className="rounded-lg border border-border bg-surface p-5">
      <Globe2 className="mb-3 size-7 text-info" />
      <h2 className="font-medium">{text("Connection map", "Verbindungskarte")}</h2>
      <p className="mt-2 text-sm text-muted">{text("The offline connection map requires the current Windows application. Simulation addresses are excluded.", "Die Offline-Verbindungskarte benötigt die aktuelle Windows-Anwendung. Simulationsadressen werden nicht verwendet.")}</p>
    </section>
  );

  return (
    <div className="min-w-0 space-y-4" data-testid="connection-map">
      <section className="rounded-lg border border-border bg-surface p-4 sm:p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h2 className="flex items-center gap-2 font-medium"><Globe2 className="size-5 text-info" />{text("Where your connections meet the world", "Wo deine Verbindungen auf die Welt treffen")}</h2>
            <p className="mt-2 max-w-3xl text-sm text-muted">{text("Dots represent approximate countries of TCP peers and blocked outbound attempts reported by the connection guard. They are placed at country labels, not server locations. Socket capture does not establish direction; guard events identify outgoing attempts.", "Punkte zeigen ungefähre Länder von TCP-Gegenstellen und blockierten ausgehenden Versuchen des Verbindungswächters. Sie stehen am Kartenlabel, nicht am Serverstandort. Die Socket-Erfassung belegt keine Richtung; Wächter-Ereignisse benennen ausgehende Versuche.")}</p>
          </div>
          <span className="flex items-center gap-1 rounded-full bg-info/10 px-2 py-1 text-xs text-info"><ShieldCheck className="size-3" />{text("Offline lookup", "Offline-Zuordnung")}</span>
        </div>
        {(!captureEnabled || !live || captureStale) && <p role="status" className="mt-3 flex items-start gap-2 rounded-md bg-warning/10 p-3 text-xs text-warning"><TriangleAlert className="size-4 shrink-0" />{text("Capture is paused, unavailable or stale. Retained observations are not current traffic.", "Erfassung pausiert, nicht verfügbar oder veraltet. Aufbewahrte Beobachtungen sind kein aktueller Verkehr.")}</p>}
        {error && <p role="alert" className="mt-3 break-words rounded-md bg-danger/10 p-3 text-sm text-danger">{text("Offline location lookup failed: ", "Offline-Länderzuordnung fehlgeschlagen: ")}{error}</p>}
        {approvalError && <p role="status" className="mt-3 break-words text-xs text-warning">{text("Guard event refresh failed; retained attempts may be stale: ", "Wächter-Ereignisse konnten nicht aktualisiert werden; aufbewahrte Versuche können veraltet sein: ")}{approvalError}</p>}
        {!approvalStatus?.active && (approvalStatus?.attempts.length ?? 0) > 0 && <p className="mt-3 text-xs text-muted">{text("Guard attempts shown here belong to the retained, stopped session.", "Angezeigte Wächter-Versuche stammen aus der aufbewahrten, beendeten Sitzung.")}</p>}
        <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:flex-wrap sm:items-end">
          <label className="w-full min-w-0 text-xs text-muted sm:w-auto sm:flex-1">{text("Program", "Programm")}
            <select aria-label={text("Program", "Programm")} value={program} onChange={(event) => { setProgram(event.target.value); select("all"); }} className="mt-1 block w-full min-w-0 rounded-md border border-border bg-bg px-3 py-2 text-sm text-fg">
              <option value="">{text("All observed programs", "Alle beobachteten Programme")}</option>
              {participatingApps.map((app) => <option key={app.id} value={app.id}>{app.name}</option>)}
            </select>
          </label>
          <label className="w-full min-w-0 text-xs text-muted sm:w-auto sm:flex-1">{text("Observation source", "Beobachtungsquelle")}<select aria-label={text("Observation source", "Beobachtungsquelle")} value={sourceFilter} onChange={(event) => { setSourceFilter(event.target.value); select("all"); }} className="mt-1 block w-full min-w-0 rounded-md border border-border bg-bg px-3 py-2 text-sm text-fg"><option value="all">{text("Sockets and guard attempts", "Sockets und Wächter-Versuche")}</option><option value="kernel">{text("Observed TCP sockets", "Beobachtete TCP-Sockets")}</option><option value="approval">{text("Blocked outbound attempts", "Blockierte ausgehende Versuche")}</option></select></label>
          <p role="status" className="pb-2 text-xs text-muted">{loading ? text("Resolving locally…", "Lokal zuordnen…") : `${grouped.groups.length} ${text("countries", "Länder")} · ${new Set(peers.map((peer) => peer.remoteIp)).size} ${text("peers", "Gegenstellen")}`}</p>
        </div>
        <div className="relative mt-4 overflow-hidden rounded-lg border border-border bg-[#091a21]" data-testid="world-map">
          <svg viewBox="0 0 1000 500" className="block h-auto w-full" role="group" aria-label={text("Approximate country map of observed peers", "Ungefähre Länderkarte beobachteter Gegenstellen")}>
            <defs><radialGradient id="geo-glow"><stop stopColor="#36c4b3" stopOpacity="0.11" /><stop offset="1" stopColor="#36c4b3" stopOpacity="0" /></radialGradient></defs>
            <ellipse cx="500" cy="250" rx="550" ry="280" fill="url(#geo-glow)" />
            {[125, 250, 375].map((y) => <line key={`lat${y}`} x1="0" y1={y} x2="1000" y2={y} stroke="#1a313b" strokeWidth="0.5" />)}
            {[125, 250, 375, 500, 625, 750, 875].map((x) => <line key={`lon${x}`} x1={x} y1="0" x2={x} y2="500" stroke="#1a313b" strokeWidth="0.5" />)}
            <image href={worldMap} x="0" y="0" width="1000" height="500" aria-hidden="true" />
            {grouped.groups.map((group) => {
              const point = mapPoint(group.country);
              const radius = Math.min(12, 4 + Math.log2(group.addresses.length + 1));
              const active = selection === group.country.code;
              const label = `${countryName(group.country)} · ${group.addresses.length} ${text("peers", "Gegenstellen")} · ${group.connections.length} ${text("observations", "Beobachtungen")}`;
              const onlyAttempts = group.connections.every((connection) => connection.source === "approval");
              return <g key={group.country.code} transform={`translate(${point.x} ${point.y})`} role="button" tabIndex={0} aria-label={label} aria-pressed={active} onClick={() => select(group.country.code)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(group.country.code); } }} className="cursor-pointer outline-none focus:stroke-white">
                <title>{label}</title>
                <circle r={radius + 7} fill={onlyAttempts ? "#f5b84b" : "#49dbc5"} fillOpacity={active ? "0.35" : "0.12"} />
                <circle r={radius} fill={onlyAttempts ? "#f5b84b" : "#49dbc5"} stroke={active ? "#ffffff" : onlyAttempts ? "#fff2cd" : "#b5fff0"} strokeWidth={active ? "2.5" : "1.2"} />
                <circle r="1.5" fill="#071c23" />
              </g>;
            })}
          </svg>
          {grouped.groups.length === 0 && <div className="pointer-events-none absolute inset-0 flex items-center justify-center p-4"><p className="max-w-sm rounded-md bg-bg/90 px-4 py-3 text-center text-sm text-muted">{loading ? text("Resolving observed peers locally…", "Beobachtete Gegenstellen lokal zuordnen…") : text("No country dots for the current selection. Private or unresolved peers appear below.", "Keine Länderpunkte für diese Auswahl. Private oder nicht zugeordnete Gegenstellen stehen unten.")}</p></div>}
        </div>
        <p className="mt-2 text-[11px] text-muted">{text("Turquoise: observed TCP sockets · Amber: blocked attempts only. A later approval decision is not proof of a successful connection.", "Türkis: beobachtete TCP-Sockets · Gelb: ausschließlich blockierte Versuche. Eine spätere Freigabeentscheidung belegt keine erfolgreiche Verbindung.")}</p>
        <div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-muted">
          <span>{text("IP Geolocation by DB-IP", "IP-Geolokalisierung von DB-IP")} · {geo?.database.release ?? "2026-09"} · CC BY 4.0</span>
          <a href="https://db-ip.com" target="_blank" rel="noreferrer" className="underline">DB-IP.com</a>
          <span>Natural Earth · Public domain</span>
          <span>{text("No endpoint IPs are uploaded.", "Keine Gegenstellen-IP wird hochgeladen.")}</span>
        </div>
        <p className="mt-2 text-[11px] text-muted">{text("Country estimates can be wrong or reflect a VPN, CDN or network operator. They do not identify a person or prove a threat. UDP socket capture exposes no peer; UDP guard events supply the actual remote endpoint. The bundled database updates with application releases.", "Länderschätzungen können falsch sein oder einen VPN-, CDN- oder Netzbetreiber abbilden. Sie identifizieren keine Person und belegen keine Bedrohung. UDP-Sockets liefern keine Gegenstelle; UDP-Wächter-Ereignisse benennen den tatsächlichen entfernten Endpunkt. Die gebündelte Datenbank wird mit Anwendungsversionen aktualisiert.")}</p>
      </section>
      <section className="min-w-0 rounded-lg border border-border bg-surface p-4 sm:p-5">
        <div className="flex flex-wrap gap-2" aria-label={text("Country filter", "Länderfilter")}>
          {[{ code: "all", label: text("All peers", "Alle Gegenstellen"), count: peers.length }, ...grouped.groups.map((group) => ({ code: group.country.code, label: countryName(group.country), count: group.connections.length })), { code: "non-public", label: text("Local / special", "Lokal / Sonderbereich"), count: grouped.nonPublic.length }, { code: "unknown", label: text("No map location", "Keine Kartenposition"), count: grouped.unknown.length }].map((item) => <button key={item.code} type="button" onClick={() => select(item.code)} aria-pressed={selection === item.code} className={cn("rounded-md border px-2 py-1 text-xs", selection === item.code ? "border-info bg-info/10 text-info" : "border-border text-muted hover:text-fg")}>{item.label} <span className="font-mono">{item.count}</span></button>)}
        </div>
        <label className="mt-4 block text-xs text-muted">{text("Filter by IP, program or PID", "Nach IP, Programm oder PID filtern")}<input value={query} onChange={(event) => { setQuery(event.target.value); setVisibleCount(80); }} type="search" className="mt-1 block w-full rounded-md border border-border bg-bg px-3 py-2 text-sm text-fg" /></label>
        <div className="mt-3 space-y-2">
          {filtered.slice(0, visibleCount).map((connection) => {
            const location = locationByIp.get(connection.remoteIp);
            const country = location?.countryCode ? countries[location.countryCode] : undefined;
            const place = country ? countryName(country) : location?.status === "non-public" ? text("Local / special range", "Lokal / Sonderbereich") : location?.countryCode ?? text("Unknown country", "Land unbekannt");
            return <div key={connection.id} className="flex min-w-0 flex-wrap items-center justify-between gap-2 rounded-md border border-border p-3 text-xs">
              <div className="min-w-0"><div className="break-all font-mono text-fg">{connection.remoteIp.includes(":") ? `[${connection.remoteIp}]` : connection.remoteIp}:{connection.remotePort}</div><div className="mt-1 break-all text-muted">{appNames.get(connection.appId) ?? text("Unknown program", "Programm unbekannt")}{connection.source === "kernel" ? ` · PID ${connection.pid ?? "—"} · TCP ${connection.state}` : ` · ${connection.protocol} · ${text("guard event", "Wächter-Ereignis")}`}</div>{connection.approval && <div className="mt-1 text-warning">{text("Blocked outbound attempt", "Blockierter ausgehender Versuch")} · {connection.approval.decision === "pending" ? text("Awaiting decision", "Entscheidung ausstehend") : connection.approval.decision === "deny" ? text("Denied", "Abgelehnt") : text("Subsequently approved", "Nachträglich freigegeben")} · {new Date(connection.approval.lastSeenAt).toLocaleTimeString(language === "de" ? "de-DE" : "en-GB")}</div>}</div>
              <div className="min-w-0 text-right"><span className="inline-flex items-center gap-1 text-info"><MapPin className="size-3" />{place}</span><div className="mt-1 text-muted">{connection.direction === "out" ? text("Outbound (reported)", "Ausgehend (gemeldet)") : connection.direction === "in" ? text("Inbound (reported)", "Eingehend (gemeldet)") : text("Direction unknown", "Richtung unbekannt")}</div></div>
            </div>;
          })}
          {filtered.length === 0 && <p className="py-5 text-center text-sm text-muted">{text("No observed peers match this selection.", "Keine beobachteten Gegenstellen passen zur Auswahl.")}</p>}
        </div>
        {filtered.length > visibleCount && <Button variant="outline" size="sm" className="mt-3" onClick={() => setVisibleCount((count) => count + 80)}>{text("Show more", "Mehr anzeigen")} ({filtered.length - visibleCount})</Button>}
        <p className="mt-3 text-[11px] text-muted">{text("Last socket snapshot", "Letzte Socket-Momentaufnahme")}: {lastSnapshotAt ? new Date(lastSnapshotAt).toLocaleTimeString(language === "de" ? "de-DE" : "en-GB") : "—"}. {text(`Up to ${GEO_ADDRESS_LIMIT} distinct peer addresses are resolved per snapshot; additional peers remain unplaced.`, `Bis zu ${GEO_ADDRESS_LIMIT} verschiedene Gegenstellen-Adressen werden je Momentaufnahme zugeordnet; weitere bleiben ohne Kartenposition.`)}</p>
      </section>
    </div>
  );
}
