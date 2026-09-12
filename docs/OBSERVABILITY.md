# Blackbox Breaker and War Monitor

Limen 1.3 adds local process inspection and a session recorder to the existing Windows Firewall controls. These features supply evidence for an explicit rule decision. They do not classify a program as malware or silently install a block rule.

## Blackbox Breaker

Open **Blackbox** and search for a process name, executable path, PID or hosted service. Windows reports the services sharing each process. A service's configured DLL is shown when accessible. Inspect a process to read its loaded module paths, parent and child relationships, executable SHA-256 and Authenticode result.

`svchost.exe` commonly hosts services loaded from DLLs. It is not a bundle of independent executable files. Other applications can use child processes and loaded libraries; both are exposed separately. A loaded module or hosted service is a relationship to the process, not proof that it originated one of the process's sockets. The current endpoint provider identifies an owning process, not the originating DLL or hosted service.

Inspection identifies a process by its PID **and start time**. Windows reuses PIDs; a stale selection must not attach results to a different process. Inaccessible, exited, protected or truncated observations are marked explicitly. A missing module list is not evidence that the process has no modules. A valid signature identifies the checked executable's signature result, not the trustworthiness of every loaded module or the application's behavior.

The inventory refreshes separately from network capture while the Blackbox view is open. Module, hash and signature inspection is an explicit action. No command line, process memory, packet payload or user credential is collected. Executable hashing is restricted to supported local files.

## War Monitor

The War Monitor plots actual host interface receive/send rates alongside socket counts, observed socket changes, capture duration and sampling gaps. Rates are host totals, not per-process bandwidth. Blank or unavailable samples remain gaps instead of becoming measured zero traffic.

Its anomaly feed explains the supporting observations for:

- Receive or send bursts compared with a warmed traffic baseline.
- Many distinct TCP peers observed for a program in a short window.
- Approximately periodic appearances of new connections to the same peer.
- Newly observed listening endpoints and elevated SYN-state counts.
- Destinations outside an explicitly frozen Drift Guard baseline.

These are investigation hints. Software updates, synchronization, browsers, discovery services and scheduled jobs can produce the same patterns. Periodic socket sampling can miss short connections, and an unchanged persistent connection does not reveal the timing of packets inside it. The recorder cannot determine the contents or intent of a transfer. TCP direction and UDP remote peers remain unknown when the provider does not expose them.

## Experimental Drift Guard

After observing a program across multiple fresh snapshots, freeze its observed TCP destinations in the War Monitor. Limen keeps that reference unchanged until you remove it. A later destination outside the reference creates an evidence entry. This avoids silently treating every new destination as the new baseline.

The reference is an **observed destination set**, not a complete allowlist or a verdict that the initial activity was safe. It groups the executable path across process instances. It does not cover UDP peers, paths the program has not yet used, hidden traffic inside an established connection or executable relocation. Capture gaps interrupt timing comparisons; they do not authorize new destinations or expand a frozen reference.

Use the existing rule form to review and create an explicit Windows rule if a finding warrants containment. Blocking a shared host executable can affect all services using it. Limen does not automatically block system services on the strength of a heuristic. The experiment makes no claim of worldwide novelty or quantified improvement in protection.

## Local flight recorder

History is bounded and kept in application memory. Closing Limen or resetting the session discards that recorder and its frozen references; this does not remove persistent Windows Firewall rules. The export action saves a JSON copy locally. It can contain executable paths and remote IP addresses; review that file before sharing it.

The recorder is a record of sampled observations, not a complete packet capture. Retention limits and missed capture intervals are exposed in the interface. There is no upload service or cloud analysis.

## Windows references

- [Microsoft: Service host grouping](https://learn.microsoft.com/en-us/windows/application-management/svchost-service-refactoring)
- [Microsoft: Win32_Service and ProcessId](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)
- [Microsoft: Win32_Process and process creation time](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-process)
- [Microsoft: Get-NetTCPConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-nettcpconnection)
