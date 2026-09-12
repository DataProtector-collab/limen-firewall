# Changelog

Alles Neue, Gebrochene und Behobene. Neueste Version oben.
Schema: [Keep a Changelog](https://keepachangelog.com/de/1.1.0/), Nummern nach SemVer.

Die laufende Nummer steht in `src/lib/version.ts`. Dieselbe Liste siehst du unter Einstellungen.

---

## [1.1.0] — 2026-09-12

Kernel-Capture. Acht Sprachen. Labor ist optional.

### Neu

- Die Konsole liest die echte Kernel-Sockettabelle: `/proc/net/tcp`, `tcp6`, `udp`, `udp6`.
- Inodes werden über `/proc/<pid>/fd` auf PID, `comm` und Binary gemappt. Ohne das ist eine Firewall nur Deko.
- Durchsatz kommt aus `/proc/net/dev` (NIC-Bytezähler), nicht aus Zufallszahlen.
- Neue Sockets ohne Regel gehen durch denselben Zulassen/Blockieren-Dialog. Loopback und Listen-Ports werden nur angezeigt, nicht abgefragt. node / Vite / Preview-Proxy sind vertrauenswürdig, sonst würgt sich die Konsole selbst ab.
- Sprachen: Deutsch bleibt Default. Dazu Englisch, Chinesisch, Hindi, Spanisch, Französisch, Arabisch, Bengali, Portugiesisch — die acht meistgesprochenen Sprachen weltweit. Arabisch dreht das Layout auf RTL.
- Sprache und Regeln liegen in `localStorage`.
- Versionshistorie unter Einstellungen.

### Geändert

- Windows-Labor (Chrome, Discord, …) ist abgeschaltet, solange du es nicht unter Einstellungen anmachst. Die Tabelle füllt sich aus dem Kernel.
- Blocken schreibt die Richtlinie. Paket-Drop bräuchte iptables/nft im Userspace — das liegt hier nicht. Steht ehrlich im Settings-Hinweis.

### Doku

- `CHANGELOG.md`, `docs/VERSIONING.md`, README auf 1.1 gezogen.

---

## [1.0.0] — 2026-09-12

Erste öffentliche Konsole.

- Dialog, wenn eine App nach draußen will: Diesmal / App+Ziel / gesamte App.
- Live-Tabelle, Apps, Regeln, Verlauf.
- Nur Deutsch.
- Traffic kam aus einem Windows-Labor (echte Prozessnamen und Ziele, aber keine Kernel-Tabelle).

[1.1.0]: https://github.com/DataProtector-collab/Aegis---Windows-Firewall/releases/tag/v1.1.0
[1.0.0]: https://github.com/DataProtector-collab/Aegis---Windows-Firewall/releases/tag/v1.0.0
