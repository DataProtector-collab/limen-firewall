# Security model

Limen 1.2 is an early Windows Firewall rule manager and connection monitor, not a packet interception driver. Real sockets are observed after creation; Limen does not hold connection attempts for approval. Only explicit rule operations change Windows rules. Simulation prompts have no operating-system effect.

## Privilege boundary

The packaged Windows application requests administrator elevation to access the Windows Firewall rule APIs. Its renderer loads bundled local files with Node integration disabled, context isolation and the Chromium sandbox enabled. The preload exposes a fixed set of methods, not a shell or arbitrary IPC access. The main process validates the sender and all rule inputs. The backend accepts structured data through standard input to a bundled fixed-operation PowerShell script.

The desktop application does not run a privileged local HTTP server or fetch a remote UI. Browser development mode has no native bridge and cannot change the firewall. Do not modify the main process to load remote content into the privileged window.

Rules are scoped to explicit executable paths and managed by Limen's own rule identifiers and group. There is no API to disable Windows Firewall, change profile defaults, execute arbitrary PowerShell, or manage unrelated rules.

## Limitations

- A compromised administrator account can change rules regardless of Limen.
- A program-path rule follows that path, not a cryptographic binary identity. Replacing or relocating an executable changes the practical protection.
- Capture supplies IP endpoints rather than domain identities. UDP endpoint enumeration provides no remote peer. IP rules apply to the selected literal IP only.
- Local administrator rules can be superseded or disabled by domain policy. An allow rule does not override an explicit block rule.
- A rule can be saved and enabled but inactive in Windows' active policy, for example when a filtering category is disabled. The UI reports ActiveStore status and registered external firewall providers. Even `OK / Full` is Windows-reported status, not a successful packet-blocking test; see [the validation record](docs/VALIDATION.md).
- Rules persist in Windows after closing or uninstalling Limen. Review them before uninstalling.
- Process paths may be unavailable. Signature verification, per-process traffic measurement, and dropped-packet counts are not implemented. TCP direction is not inferred from port numbers. The UI does not infer trust or packet delivery from these missing measurements.
- Releases are unsigned until the project obtains a signing certificate; verify published checksums.

## Reporting

Do not post credentials, private endpoint lists, or exploit details in a public issue. For an ordinary reproducible bug, provide your Windows version, Limen version, a minimal sequence, and the exact error with personal paths redacted. For security-sensitive findings, use GitHub's private vulnerability reporting if available on the repository.

## References

- [Microsoft: Windows Firewall rules and precedence](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules)
- [Microsoft: New-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule)
- [Electron: security recommendations](https://www.electronjs.org/docs/latest/tutorial/security)
