import { useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import { LockKeyhole, ShieldCheck, ShieldQuestion, ShieldX } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ModalContent } from "./native-controls";
import { getNativeBridge } from "@/lib/firewall/native-types";
import { useApproval } from "@/lib/firewall/approval-store";
import { useFirewall } from "@/lib/firewall/store";
import type { ApprovalAttempt } from "@/lib/firewall/approval-types";

export function ConnectionApprovalView() {
  const de = useFirewall((s) => s.settings.language) === "de";
  const state = useApproval();
  const [confirm, setConfirm] = useState<"start" | "stop" | null>(null);
  const supported = Boolean(getNativeBridge()?.getApprovalStatus);
  const active = state.status?.active === true;
  const pending = state.status?.attempts.filter((item) => item.decision === "pending") ?? [];
  const decided = state.status?.attempts.filter((item) => item.decision !== "pending") ?? [];
  return (
    <div className="min-w-0 space-y-4">
      <section className="space-y-3 rounded-xl border border-border bg-surface p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <ShieldQuestion className="size-5 text-accent" />
            <h2 className="font-medium">{de ? "Vor dem Internetzugriff fragen" : "Ask before Internet access"}</h2>
          </div>
          <span className={active ? "text-sm text-accent" : "text-sm text-muted"}>
            {de ? (active ? "Freigabemodus aktiv" : "Freigabemodus aus") : (active ? "Approval mode active" : "Approval mode off")}
          </span>
        </div>
        <p className="text-sm text-muted">
          {de
            ? "Im aktiven Modus blockiert der native Schutzkern nicht freigegebene ausgehende TCP- und UDP-Versuche zu öffentlichen IP-Adressen. Du entscheidest über Programm und Ziel. Nach der Freigabe muss das Programm erneut verbinden."
            : "While active, the native guard blocks unapproved outbound TCP and UDP attempts to public IP addresses. You decide which program and destination to allow. The program must retry after approval."}
        </p>
        <p className="text-xs text-muted">
          {de
            ? "Lokales Netzwerk und Loopback bleiben von diesem Modus ausgenommen. Freigaben gelten bis zum Ausschalten oder Beenden von Limen; vorhandene Windows-Sperrregeln bleiben maßgeblich. Das X blendet Limen nur in den Infobereich aus."
            : "Local networks and loopback are outside this mode. Decisions last until you stop the mode or exit Limen; existing Windows block rules still apply. The X only hides Limen in the notification area."}
        </p>
        {!supported ? <p className="text-sm text-warn">{de ? "Diese Funktion benötigt die Windows-Anwendung mit nativem Schutzkern." : "This feature requires the Windows application with its native guard."}</p> : null}
        {state.status?.reason ? <p className="break-words text-sm text-warn">{state.status.reason}</p> : null}
        {state.error ? <p role="alert" className="break-words text-sm text-block">{state.error}</p> : null}
        <div className="flex flex-wrap items-center gap-2">
          <Button disabled={!supported || state.busy || (!active && state.status?.available !== true)} onClick={() => setConfirm(active ? "stop" : "start")}>
            {de ? (active ? "Freigabemodus ausschalten" : "Freigabemodus einschalten") : (active ? "Turn approval mode off" : "Turn approval mode on")}
          </Button>
          <Button variant="outline" disabled={!supported || state.busy} onClick={() => void state.refresh()}>{de ? "Aktualisieren" : "Refresh"}</Button>
        </div>
        {state.refreshedAt ? <p className="text-xs text-muted">{de ? "Vom Schutzkern gelesen: " : "Read from native guard: "}{new Date(state.refreshedAt).toLocaleTimeString(de ? "de-DE" : "en-US")}</p> : null}
      </section>
      {state.status?.droppedEvents ? <p role="alert" className="rounded-lg border border-warn/40 p-3 text-sm text-warn">{de ? `${state.status.droppedEvents} Ereignisse überschritten die Aufzeichnungsgrenze. Die Liste ist unvollständig; daraus entsteht keine Freigabe.` : `${state.status.droppedEvents} events exceeded the recording limit. The list is incomplete; this does not grant access.`}</p> : null}
      <section className="space-y-3" aria-label={de ? "Offene Freigaben" : "Pending approvals"}>
        <h2 className="font-medium">{de ? "Darf dieses Programm ins Internet?" : "May this program access the Internet?"} <span className="text-muted">({pending.length})</span></h2>
        {pending.length ? pending.map((attempt) => <AttemptCard key={attempt.id} attempt={attempt} active={active} de={de} />) : <p className="rounded-lg border border-border p-4 text-sm text-muted">{de ? (active ? "Noch keine offenen Verbindungsversuche erfasst." : "Schalte den Freigabemodus ein, um echte blockierte Verbindungsversuche zu sehen.") : (active ? "No pending connection attempts recorded yet." : "Turn on approval mode to see real blocked connection attempts.")}</p>}
      </section>
      {decided.length ? <section className="space-y-3"><h2 className="font-medium">{de ? "Entscheidungen dieser Sitzung" : "Decisions in this session"}</h2>{decided.map((attempt) => <AttemptCard key={attempt.id} attempt={attempt} active={active} de={de} />)}</section> : null}
      <Dialog.Root open={confirm !== null} onOpenChange={(open) => { if (!open && !state.busy) setConfirm(null); }}>
        <ModalContent title={de ? (confirm === "start" ? "Internetfreigaben aktivieren?" : "Freigabemodus ausschalten?") : (confirm === "start" ? "Enable Internet approvals?" : "Turn approval mode off?")}
          description={de ? (confirm === "start" ? "Programme können vorübergehend ihre Internetverbindung verlieren, bis du ihre Ziele freigibst. Der Modus gilt für öffentliche IPv4- und IPv6-Ziele über TCP und UDP. Er startet bei einem Neustart von Limen nicht automatisch." : "Die temporären Sperren und Freigaben dieser Sitzung werden entfernt. Deine gespeicherten Windows-Firewall-Regeln bleiben erhalten.") : (confirm === "start" ? "Programs may temporarily lose Internet access until you approve their destinations. This mode covers public IPv4 and IPv6 destinations over TCP and UDP. It does not start automatically when Limen restarts." : "Temporary blocks and approvals in this session will be removed. Your saved Windows Firewall rules remain.")}>
          <div className="flex flex-wrap justify-end gap-2">
            <Button variant="outline" disabled={state.busy} onClick={() => setConfirm(null)}>{de ? "Abbrechen" : "Cancel"}</Button>
            <Button disabled={state.busy} onClick={async () => { const ok = await (confirm === "start" ? state.start() : state.stop()); if (ok) setConfirm(null); }}>{de ? (confirm === "start" ? "Aktivieren" : "Ausschalten") : (confirm === "start" ? "Enable" : "Turn off")}</Button>
          </div>
          {state.error ? <p role="alert" className="mt-3 break-words text-sm text-block">{state.error}</p> : null}
        </ModalContent>
      </Dialog.Root>
    </div>
  );
}

function AttemptCard({ attempt, active, de }: { attempt: ApprovalAttempt; active: boolean; de: boolean }) {
  const busy = useApproval((s) => s.busy);
  const decide = useApproval((s) => s.decide);
  const pending = attempt.decision === "pending";
  const denied = attempt.decision === "deny";
  const Icon = pending ? LockKeyhole : denied ? ShieldX : ShieldCheck;
  const name = attempt.program.split(/[\\/]/).pop() || (de ? "Unbekanntes Programm" : "Unknown program");
  return (
    <article className="min-w-0 space-y-3 rounded-lg border border-border bg-surface p-4" data-attempt-id={attempt.id}>
      <div className="flex items-start gap-2"><Icon className="mt-0.5 size-5 shrink-0 text-accent" /><div className="min-w-0"><h3 className="break-all font-medium">{name}</h3><p className="break-all text-xs text-muted">{attempt.program || (de ? "Windows hat keinen freigabefähigen Programmpfad geliefert." : "Windows did not supply an approvable program path.")}</p></div></div>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-sm">
        <dt className="text-muted">{de ? "Ziel" : "Destination"}</dt><dd className="break-all font-mono">{attempt.remoteAddress}:{attempt.remotePort} · {attempt.protocol}</dd>
        <dt className="text-muted">{de ? "Richtung" : "Direction"}</dt><dd>{de ? "Ausgehend · Windows-Filterereignis" : "Outbound · Windows filter event"}</dd>
        <dt className="text-muted">{de ? "Versuche" : "Attempts"}</dt><dd>{attempt.count} · {new Date(attempt.lastSeenAt).toLocaleTimeString(de ? "de-DE" : "en-US")}</dd>
        <dt className="text-muted">Status</dt><dd>{de ? (pending ? "Blockiert · Entscheidung offen" : denied ? "Abgelehnt" : attempt.decision === "allow-program" ? "Programm für diese Sitzung freigegeben" : "Ziel für diese Sitzung freigegeben") : (pending ? "Blocked · awaiting decision" : denied ? "Denied" : attempt.decision === "allow-program" ? "Program allowed for this session" : "Destination allowed for this session")}</dd>
      </dl>
      {pending ? <div className="flex flex-wrap gap-2">
        <Button disabled={busy || !active || !attempt.canApprove} onClick={() => void decide({ id: attempt.id, decision: "allow-endpoint" })}>{de ? "Dieses Ziel freigeben" : "Allow this destination"}</Button>
        <Button variant="outline" disabled={busy || !active || !attempt.canApprove} onClick={() => void decide({ id: attempt.id, decision: "allow-program" })}>{de ? "Programm freigeben" : "Allow program"}</Button>
        <Button variant="outline" disabled={busy || !active} onClick={() => void decide({ id: attempt.id, decision: "deny" })}>{de ? "Ablehnen" : "Deny"}</Button>
      </div> : null}
    </article>
  );
}
