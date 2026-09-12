# Versionen

Aegis zählt nach SemVer. Jedes Upgrade, das man sieht oder merkt, bekommt eine neue Nummer. Kein stilles Drüberbügeln.

| Stelle | Zweck |
| --- | --- |
| `src/lib/version.ts` | `APP_VERSION` + `RELEASES` (Settings-UI) |
| `CHANGELOG.md` | Was sich geändert hat, in Klartext |
| git-Tag `vX.Y.Z` | Freeze der Quelle |
| Sidebar | zeigt `v` + `APP_VERSION` |

## Nummern

- **Major** — Regeldatei oder Speicherformat bricht, oder die Idee der Konsole ändert sich.
- **Minor** — neue Funktion. 1.0 → 1.1 war Kernel-Capture und Sprachen.
- **Patch** — Bugs, Übersetzungen, Kleinkram ohne neues Verhalten.

## Checkliste für ein Release

1. `APP_VERSION` hochsetzen.
2. Block in `RELEASES` oben einfügen (Settings liest das 1:1).
3. Abschnitt in `CHANGELOG.md`.
4. README anfassen, wenn sich Bedienung oder Grenzen ändern.
5. Tag `vX.Y.Z` auf denselben Commit.

Alte Versionen bleiben im Changelog stehen. Nicht umschreiben.

## Bisher

### 1.0.0 — 12.09.2026

Erste Konsole. Dialog, Regeln, Verlauf, Deutsch. Traffic aus einem Windows-Labor, weil auf dem Host kein Filtertreiber liegt.

### 1.1.0 — 12.09.2026

Liest `/proc/net` und mappt Sockets auf Prozesse. Acht Sprachen dazu (en, zh, hi, es, fr, ar, bn, pt). Labor optional, Default aus.

Nächstes Minor wäre z.B. echtes Packet-Drop (nft/WFP) oder Windows-Treiber. Das wäre 1.2, nicht ein stiller Patch.
