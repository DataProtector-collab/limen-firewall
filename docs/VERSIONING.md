# Versions

Limen uses SemVer. Every upgrade you can see or feel gets a new number. No silent overwrites.

| Where | What |
| --- | --- |
| `src/lib/version.ts` | `APP_NAME`, `APP_VERSION`, `RELEASES` (Settings UI) |
| `package.json` and lockfile | Build/package version; must match `APP_VERSION` |
| `CHANGELOG.md` | What changed, in plain language |
| git tag `vX.Y.Z` | freeze of the source |
| Sidebar | shows `v` + `APP_VERSION` |

## Numbers

- **Major** — rule file or storage format breaks, or the idea of the console changes.
- **Minor** — new behaviour. 1.0 → 1.1 was kernel capture and languages.
- **Patch** — bugs, copy, rename, translations with no new behaviour. 1.1 → 1.1.1 was the rename to Limen.

## Release checklist

1. Bump `APP_VERSION`, `package.json`, and the lockfile version together.
2. Put a block at the top of `RELEASES` (Settings reads it as-is).
3. Section in `CHANGELOG.md`.
4. Touch the README if usage or limits changed.
5. Tag `vX.Y.Z` on the same commit.
6. Run tests, typecheck, production UI verification and Windows packaging. Record evidence in `docs/VALIDATION.md`.
7. Attach installer, portable app and SHA-256 checksums to the GitHub release.

Leave old versions in the changelog. Don’t rewrite them.

## So far

### 1.0.0 — 2026-09-12

First console. Prompt, rules, log, German. Traffic from a Windows lab because this host has no filter driver.

### 1.1.0 — 2026-09-12

Reads `/proc/net` and maps sockets to processes. Eight more languages (en, zh, hi, es, fr, ar, bn, pt). Lab optional, default off.

### 1.1.1 — 2026-09-12

Renamed Aegis → Limen. Docs English-first.

### 1.2.0 — 2026-09-12

Native Windows desktop, real Windows Firewall rules and Windows socket enumeration. Explicit rule management replaces client-only blocking claims. No WFP callout driver or pre-connection packet hold is included.
