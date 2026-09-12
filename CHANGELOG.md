# Changelog

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
