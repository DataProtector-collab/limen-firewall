# Validation

Limen is an early native Windows application. A saved rule is not proof that packets are blocked. Results below are scoped to the version and scenario tested.

## 1.2.1 capture and desktop repair

The reported false-zero display was reproduced in the installed 1.2.0 application on 2026-09-12 using its real Electron window and native bridge. Three successive snapshots returned 57 sockets with both adapter byte totals equal to zero, while three DNS baseline requests succeeded. The captured monitor displayed `0 B/s` in both directions. This was a counter-read defect, not evidence of an idle network. Windows' adapter statistics provider returned an empty successful result; the .NET interface API supplied positive counters on the same guest.

Version 1.2.1 uses .NET interface statistics when the primary adapter counter read is empty, invalid, or fails. It keeps socket observations available when neither counter provider succeeds. Rates require two comparable readings; counter resets and provider or adapter-set changes establish a new baseline. The first reading no longer creates an invented zero-rate sample. Pending capture, the last successful snapshot time, and stale observations are explicit, and a stalled capture cannot keep its old rates labeled live indefinitely.

All **52 automated tests passed with zero skipped**, including the Windows read smoke test and regressions for empty counter output, fallback selection, unavailable counters with valid sockets, rate baselines, counter changes, slow pending capture, and capture-mode changes. These checks do not substitute for inspecting the installed application.

**The installed 1.2.1 monitor and TCP/UDP rule workflows passed real desktop UI tests.** Automation drove the packaged Electron window through its actual form, buttons, and switches. The application loaded its installed `app.asar` and used its real preload, IPC, and Windows backend; no replacement renderer bridge or test hook supplied the displayed data or rule results.

| Check | Observed result |
| --- | --- |
| Live monitor | Three successive snapshots had advancing timestamps and increasing, nonzero byte totals from the .NET interface provider. The monitor displayed measured rates. |
| Window layout | At 980 × 650, the search field and first rule action were visible. Expanding the optional throughput chart produced a 112-pixel-high chart. |
| Rejected input | The form preserved its input after a rejected save. |
| Create a rule through the form | The isolated executable's outbound rule covered all protocols and remote addresses, as shown in the scope controls. In separate runs, previously successful validated DNS exchanges and fresh TCP connections then timed out. The TCP destination was resolved before rule creation and reused as a literal IPv4 address, so DNS blocking could not stand in for TCP blocking. |
| Disable, re-enable, and remove through the UI | Both DNS replies and TCP connections returned after disabling, failed after re-enabling, and returned after removal. No Limen-owned test rules remained. |
| Renderer errors | No page errors were recorded during the run. |

These observations verify the tested UI and isolated outbound TCP and UDP scenarios. An additional combined run stopped at a DNS baseline timeout before creating any rule and is not counted as an enforcement pass. Each successful protocol-specific run verified the complete UI lifecycle and exact test-rule removal. The debugging listener and owned test/application processes were stopped afterward. The historical 1.2.0 packet and installation results below remain separate evidence.

The installed 1.2.1 application archive and backend matched the release build. Installer SHA-256: `5b85e54489f380191762a4eaf2d44fdc55429ce83d63df79275218408af06e76`. Portable build SHA-256: `46bf8040ba66f50a13f41904065ca718388208b98a4e849d97e427789279c23b`. The UI lifecycle above was executed with the installed application. The [monitor screenshot](monitor-native-1.2.1.png) comes from its real window, filtered to the isolated test executable.

## Local checks for 1.2.0

The development machine runs Windows 10 with Node.js 24.19.0. Automated engine, state, validation, IPC, and backend tests, the opt-in Windows read smoke test, TypeScript checks, ESLint, and the production web build pass. The isolated native lifecycle test passes: create, read back, disable, enable, remove, and verify cleanup. No existing firewall rule is changed by that test. A real DOS 8.3 path regression covers Windows normalizing short paths to their long spelling.

Browser UI checks use a clearly labeled fake native bridge. They cover connection display, IPv6 and UDP unknown peers, rule form controls, a rejected save with preserved input, retry, and a scrollable keyboard-trapped dialog at a 390 × 844 viewport. These checks test the interface, not Windows enforcement.

## Observed enforcement limitation in 1.2.0

The real outbound network block test on the development machine **failed**: the isolated executable could still establish a new HTTPS connection after its block rule had been stored. Windows reported the rule's ActiveStore state as `Inactive / CategoryDisabled`; its PersistentStore state alone did not reveal this problem. A third-party firewall, Bitdefender, was registered on that machine. This is context, not proof of the cause.

Limen now exposes ActiveStore status and registered external firewall providers. It distinguishes inactive, unknown, and profile-dependent enforcement. Windows-reported state alone is not a measured packet result. No global profile, Windows security service, or third-party protection was disabled to obtain a passing test.

## Independent Windows enforcement test for 1.2.0: passed

[GitHub Actions run 34709909905](https://github.com/DataProtector-collab/limen-firewall/actions/runs/34709909905) tested the v1.2.0 release revision `b2b7afbe3659002c524242fd7cf57cd321bb3475` on 2026-09-12. All 47 tests passed with zero skipped; typecheck, lint, the actual packet test, and Windows packaging also succeeded. The disposable runner used Windows Server 2025, build 26100.

| Stage | Observed result |
| --- | --- |
| Baseline HTTPS | Connected successfully. |
| Create outbound TCP block for the isolated test executable | A new connection failed. |
| Disable the rule | A new connection succeeded. |
| Enable the rule again | A new connection failed again. |
| Remove the rule | A new connection succeeded. |
| Cleanup | Test rule and temporary executable directory removed. |

The disposable runner had no registered external firewall provider. Its ActiveStore reported `OK` with `ProfileInactive` and `Enforced` entries: status can differ across profiles, even while the tested connection is blocked. The interface preserves these details instead of treating every code other than `Full` as wholly inactive.

This is evidence for the isolated outbound TCP scenario on that runner. It is not a test of every application, inbound service, UDP flow, policy combination, or third-party firewall. The workflow continues to run the same packet test before packaging later revisions.

## Windows 10 VM validation of release 1.2.0

On 2026-09-12, the v1.2.0 artifacts identified below were tested in a disposable Windows 10 Pro VM, build 19045.

| Check | Observed result |
| --- | --- |
| Installer and uninstall persistence | Installation succeeded. The isolated test rule was verified before uninstalling and remained in Windows afterward. Removal of the test rule, application, and temporary files was confirmed. This checked persistence, not packets. |
| Outbound TCP enforcement | Baseline HTTPS succeeded. A fresh connection failed with the isolated executable's block rule enabled, succeeded after disabling it, failed after re-enabling it, and succeeded after removal. Rule and temporary-executable cleanup was confirmed. |
| Inbound TCP enforcement | A scoped allow rule established successful nonce-echo traffic. With the corresponding block enabled, two fresh probes timed out. Disabling restored replies; re-enabling caused another timeout; removal restored replies again. Test-rule and temporary-file cleanup was confirmed. |
| Inbound UDP enforcement | Each probe used a fresh guest receiver and a unique nonce. Delivery was observed with the scoped allow rule, absent in two blocked probes, restored after disabling the block, absent after re-enabling, and restored after removal. The receiver stayed alive, and all six host send callbacks reported 65 bytes without an error. This measured one-way delivery, not round-trip echo. |
| Outbound UDP enforcement | A dedicated executable exchanged validated DNS queries for `example.com` with the VM's NAT DNS service. Baseline replies succeeded, two blocked probes timed out, disabling restored replies, re-enabling caused another timeout, and removal restored replies. Response source, transaction, question, and answer structure were checked. |
| Portable desktop startup | A 25-second observation recorded a window handle, renderer, and GPU process. The main process and renderer were alive at the end of the observation. No crash events or fatal-log evidence were captured. No firewall mutation was requested. |

Earlier UDP echo baselines failed before a UDP block rule was created. Diagnostics showed the inbound packet reaching the guest and the guest reporting a reply send, while the host saw no reply; the outbound host echo baseline also timed out. Those runs were not counted as enforcement passes. The subsequent UDP-only run passed using direct guest receipt for inbound traffic and a validated DNS exchange for outbound traffic. The cause of the original host echo failure remains unresolved.

All temporary rules, probe files, and scoped NAT forwards were confirmed removed after the final 1.2.0 network run. Global firewall profiles and unrelated rules were unchanged. At the end of that test, the verified application was left installed for further use; its application archive and native backend matched the release build.

**That 1.2.0 startup test did not verify the native visual or interactive UI.** Its report explicitly records `visualUiVerified: false`; process and window presence do not prove correct rendering. Earlier browser checks with a fake native bridge remain separate evidence.

The packet-test guest reported no registered external firewall provider. The tested TCP block rules reported ActiveStore `OK` with `ProfileInactive` and `Enforced` entries. Enforcement conclusions above come from observed packet delivery and replies through repeated rule transitions, not from those status codes alone. These results cover isolated programs in one VM, not every application, Windows policy, or third-party firewall.

### Tested release artifacts

| Artifact | SHA-256 |
| --- | --- |
| `Limen-1.2.0-setup-x64.exe` | `972c4e2a15a3b8efb42b4e6bf7bbfe8c7d217f865b7f0a8e24f787c0499517ea` |
| `Limen-1.2.0-portable-x64.exe` | `42d271feb3196015b49d4a6b2781d63bee6721017ceea7efe31ecb578531f54f` |

The installed native backend matched SHA-256 `b2a48608ba17798624006aaf3e8df942e7497b8244b922404663c334b3c0d93a`. Private machine identifiers, account names, local paths, and raw logs are omitted.

## Reproduce

```sh
npm ci
npm test
npm run typecheck
npm run lint
npm run build
```

For the read-only Windows smoke test, set `LIMEN_WINDOWS_READ_TEST=1` before running `npm test`.

From an elevated terminal on a Windows test machine:

```sh
node desktop/firewall-selftest.cjs --confirm-isolated-firewall-test --report C:\Temp\limen-native-enforcement.json
```

The test copies Windows' own `curl.exe` to a unique temporary directory, verifies a baseline connection, creates a rule only for that copy, checks blocking and recovery through toggles, and removes its rule and executable in `finally`. The default destination is GitHub HTTPS. `--lifecycle-only` skips the packet checks and explicitly records `enforcementTested: false`; it must not be cited as an enforcement pass.

Raw local reports may contain process paths and machine details. Publish a reviewed summary rather than private local reports. CI artifacts contain the disposable runner's report.

The development-only page `/tests/native-ui.html` uses synthetic programs and reserved documentation addresses. It is excluded from the production Vite entry and Electron package.
