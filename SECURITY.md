# Security model

Limen 1.4 combines a Windows Firewall rule manager, connection monitor and optional native Internet-approval session. Socket capture observes connections after creation. The approval session blocks unapproved public outbound TCP/UDP attempts through Windows Filtering Platform, then offers explicit decisions; an application retries after approval. It does not pend socket calls in a driver. Simulation prompts have no operating-system effect.

## Privilege boundary

The packaged Windows application requests administrator elevation to access the Windows Firewall rule APIs. Its renderer loads bundled local files with Node integration disabled, context isolation and the Chromium sandbox enabled. The preload exposes a fixed set of methods, not a shell or arbitrary IPC access. The main process validates the sender and all rule inputs. The backend accepts structured data through standard input to a bundled fixed-operation PowerShell script.

The desktop application does not run a privileged local HTTP server or fetch a remote UI. Browser development mode has no native bridge and cannot change the firewall. Do not modify the main process to load remote content into the privileged window.

The new C++ approval runtime is a separate binary component. The main process verifies its exact DLL and host SHA-256 digests against the manifest inside the integrity-protected ASAR before spawning it with bounded standard-input/output messages. Decisions contain an observed request ID and a fixed action, never a caller-supplied executable or filter. Native approvals use the captured Windows application identity and validate its local executable before creating and reading back filters.

Packaged Electron disables RunAsNode, NODE_OPTIONS and Node inspection arguments, enables embedded ASAR integrity validation and restricts application loading to ASAR. The native compiler enables stack protection, control-flow guard, DEP and ASLR. These checks do not replace code signing or protect against an administrator who can replace the entire unsigned application. Compiling a DLL is not encryption or a guarantee against reverse engineering.

Rules are scoped to explicit executable paths and managed by Limen's own rule identifiers and group. There is no API to disable Windows Firewall, change profile defaults, execute arbitrary PowerShell, or manage unrelated rules.

## Limitations

- A compromised administrator account can change rules regardless of Limen.
- A program-path rule follows that path, not a cryptographic binary identity. Replacing or relocating an executable changes the practical protection.
- Capture supplies IP endpoints rather than domain identities. UDP endpoint enumeration provides no remote peer. IP rules apply to the selected literal IP only.
- Local administrator rules can be superseded or disabled by domain policy. An allow rule does not override an explicit block rule.
- A rule can be saved and enabled but inactive in Windows' active policy, for example when a filtering category is disabled. The UI reports ActiveStore status and registered external firewall providers. Even `OK / Full` is Windows-reported status, not a successful packet-blocking test; see [the validation record](docs/VALIDATION.md).
- Rules persist in Windows after closing or uninstalling Limen. Review them before uninstalling.
- The optional approval mode covers outbound public TCP/UDP endpoints, not every IP protocol, local network communication or inbound connection authorization. Session decisions are executable-path permissions, not hashes or individual hosted-service identities.
- Approval filters are dynamic and end with their native host. Actual app exit, a crash or host failure ends temporary approval protection; the next app launch starts the mode off. This is not a fail-closed Windows service or boot-time firewall. The X keeps the application and native host running in the notification area.
- Real drop events from Limen's exact filter IDs drive requests. Event collection, policy precedence and bounded queues limit visibility; omitted events are reported and do not grant permission. Windows can reauthorize existing flows when policy changes. Independent block rules can still prevent an approved application from connecting.
- Process paths may be unavailable. Blackbox performs explicit executable signature and SHA-256 inspection; loaded module signatures, per-process traffic measurement and dropped-packet counts are not measured. TCP direction is not inferred from port numbers. The UI does not infer trust or packet delivery from these missing measurements.
- Releases are unsigned until the project obtains a signing certificate; verify published checksums.

## Observation privacy and limits

Blackbox uses PID plus process creation time and withholds mismatched process identities. It reads service relationships and loaded module metadata, not process memory or command lines. A hosted service is not attributed as a socket origin. Hashing and signature inspection use local executable files; a valid signature is not a behavior verdict.

The War Monitor stores bounded observations and frozen destination references in memory. JSON exports are local and can contain paths and IP addresses. Heuristic findings never create firewall rules automatically. Drift Guard is an experimental, incomplete observation reference, not an enforced allowlist. [Observation details](docs/OBSERVABILITY.md).

World-map attribution uses a bundled offline IP-country database. It uploads no observed IP addresses and does not fetch remote map tiles. Country labels are estimates, not exact server locations or human identities. Native approval observations are session-local and bounded; program permissions are never derived from localStorage or heuristic scores. [Connection-control details](docs/CONNECTION-CONTROL.md).

## Reporting

Do not post credentials, private endpoint lists, or exploit details in a public issue. For an ordinary reproducible bug, provide your Windows version, Limen version, a minimal sequence, and the exact error with personal paths redacted. For security-sensitive findings, use GitHub's private vulnerability reporting if available on the repository.

## References

- [Microsoft: Windows Firewall rules and precedence](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules)
- [Microsoft: New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule)
- [Electron: security recommendations](https://www.electronjs.org/docs/latest/tutorial/security)
