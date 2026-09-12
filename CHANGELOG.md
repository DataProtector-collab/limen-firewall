# Changelog

## 1.3.0 — 2026-09-12

- Added Blackbox Breaker: actual hosted Windows services, configured service DLLs, process relationships, loaded module paths and explicit executable SHA-256/Authenticode inspection. PID plus creation time prevents stale process selections from attaching to reused PIDs.
- Added War Monitor with a bounded local flight recorder for host RX/TX, socket observations, capture duration and sampling gaps. Export session observations as local JSON.
- Added explained heuristics for traffic bursts, new TCP peer fan-out, repeated connection appearances, newly observed listeners and sustained SYN pressure. Warmup, capture gaps and missing measurements are handled explicitly.
- Added experimental Drift Guard: freeze an observed program destination set and review later deviations. The reference does not silently expand, does not claim complete coverage and never creates automatic rules.
- Kept native firewall rules explicit and separate from observation hints. Shared service hosts are not falsely attributed to individual services or DLLs.

## 1.2.1 — 2026-09-12

- Fixed a reproduced Windows VM failure: `Get-NetAdapterStatistics` returned an empty result while networking worked, and the monitor displayed false zero rates. A supported .NET interface-counter fallback now supplies actual measurements.
- Require two comparable counter samples before displaying a rate. Reset the baseline when adapters change or counters reset, and show pending, stale, or unavailable capture explicitly.
- Keep socket observations when traffic counters fail. Timestamp counters at the actual read and avoid discarding valid capture on unrelated settings changes.
- Show connections and rule actions before the optional throughput chart, including at 980 × 650. Keep backend warnings visible while allowing routine details to collapse.
- Default new rules to the whole program. A single remote IP restriction is an explicit choice, with scope summarized before saving.

## 1.2.0 — 2026-09-12

### Windows desktop

- Added a packaged Electron application and a restricted Windows PowerShell/NetSecurity bridge.
- Read actual Windows TCP connections, UDP endpoints, process paths and adapter counters.
- Create, list, enable, disable and remove persistent program rules owned by Limen. Confirm each mutation with Windows, including active-policy checks.
- Added portable x64 and installer builds. Native management requires administrator privileges.
- Removed obsolete Linux/web-server, authentication, database and deployment scaffolding from the application.

### Correctness and safety

- Replaced client-only claims of blocking with explicit native rule management. Observations never pretend packets are suspended or dropped.
- Removed invented signature trust, per-process traffic estimates and packet-drop counters.
- Isolated simulation and Windows rules; browser-local policies never migrate into Windows automatically.
- Fixed unstable process identities, invalid stored settings, empty rule persistence, lab rule direction/port matching and stale capture responses.
- Added scrollable accessible dialogs, truthful profile/capture/error status, and labeled local/remote endpoints.
- Added native validation, backend, state, snapshot and policy regression tests plus an opt-in isolated enforcement test.
- Display ActiveStore enforcement status and registered external firewall providers instead of treating a stored rule as proof of packet blocking.

### Known limits

- No first-packet interception, global default-deny, WFP callout driver or DNS-domain rules.
- Windows socket tables cannot reliably identify direction or remote UDP peers; unavailable data stays unknown.
- Current native workflow is translated into German and English; other language selections fall back to English for updated content.
- Initial Windows binaries are unsigned. Rules persist after app exit/uninstall.
- The development machine reports `Inactive / CategoryDisabled` and did not enforce the isolated block rule. See `docs/VALIDATION.md` for separate lifecycle and packet-test results.


What landed, what broke, what got fixed. Newest on top.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), numbers follow SemVer.

The running number lives in `src/lib/version.ts`. Same list under Settings.

---

## [1.1.1] — 2026-09-12

Rename.

### Changed

- Product is now **Limen** (Latin: threshold). Aegis was too common.
- GitHub description and README are English-first. In-app UI is still nine languages, German default.
- Old `aegis-firewall-v1` localStorage is still read, then written as `limen-firewall-v1`.

---

## [1.1.0] — 2026-09-12

Kernel capture. Eight more languages. Lab is optional.

### Added

- Reads the real kernel socket table: `/proc/net/tcp`, `tcp6`, `udp`, `udp6`.
- Inodes map through `/proc/<pid>/fd` to PID, `comm` and binary. Without that a firewall is décor.
- Throughput from `/proc/net/dev` (NIC byte counters), not random numbers.
- New sockets without a rule go through the same allow/block prompt. Loopback and listen are display-only. node / Vite / preview proxy are trusted so the console doesn’t kill itself.
- Languages: German stays default. Plus English, Chinese, Hindi, Spanish, French, Arabic, Bengali, Portuguese — the eight most spoken languages worldwide. Arabic flips the layout to RTL.
- Language and rules in `localStorage`.
- Version history under Settings.

### Changed

- Windows lab (Chrome, Discord, …) is off until you turn it on. The table fills from the kernel.
- Block writes policy. Packet drop would need iptables/nft in userspace — not on this host. Settings says so.

### Docs

- `CHANGELOG.md`, `docs/VERSIONING.md`, README for 1.1.

---

## [1.0.0] — 2026-09-12

First public console.

- Prompt when an app wants the network: this time / app+host / whole app.
- Live table, apps, rules, log.
- German UI only.
- Traffic came from a Windows lab (real process names and destinations, no kernel table).

[1.1.1]: https://github.com/DataProtector-collab/Limen---Windows-Firewall/releases/tag/v1.1.1
[1.1.0]: https://github.com/DataProtector-collab/Limen---Windows-Firewall/releases/tag/v1.1.0
[1.0.0]: https://github.com/DataProtector-collab/Limen---Windows-Firewall/releases/tag/v1.0.0
