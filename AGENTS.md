# Limen development

Limen is a Windows desktop application. Read README.md and SECURITY.md before changing native behavior.

- The active entry is src/main.tsx. Browser dev/preview is a lab with no host privileges.
- Native operations live in desktop/ and are exposed only through validated Electron IPC.
- Never infer successful enforcement from local UI state. Read authoritative Windows rule state after changes.
- Never display invented signatures, per-process traffic, direction, or dropped-packet counts.
- Never change global Windows Firewall profiles or unrelated rules as part of tests.
- Keep lab policies separate from native Windows rules. Do not migrate localStorage rules into Windows automatically.
- Native integration tests must use a dedicated temporary executable and exact owned rule identifiers, with cleanup in finally.
- Check npm test, npm run typecheck, npm run build, real UI rendering, and Windows packaging before a release. Record limitations honestly in docs/VALIDATION.md.
- Do not commit generated builds, private capture data, logs, local credentials, or workspace archives. Publish binaries as release assets.
