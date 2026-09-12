# Validation for 1.2.0

This is an early native Windows release. A saved rule is not proof that packets are blocked.

## Local checks

The development machine runs Windows 10 with Node.js 24.19.0. Automated engine, state, validation, IPC, and backend tests, the opt-in Windows read smoke test, TypeScript checks, ESLint, and the production web build pass. The isolated native lifecycle test passes: create, read back, disable, enable, remove, and verify cleanup. No existing firewall rule is changed by that test. A real DOS 8.3 path regression covers Windows normalizing short paths to their long spelling.

Browser UI checks use a clearly labeled fake native bridge. They cover connection display, IPv6 and UDP unknown peers, rule form controls, a rejected save with preserved input, retry, and a scrollable keyboard-trapped dialog at a 390 × 844 viewport. These checks test the interface, not Windows enforcement.

## Observed enforcement limitation

The real outbound network block test on the development machine **failed**: the isolated executable could still establish a new HTTPS connection after its block rule had been stored. Windows reported the rule's ActiveStore state as `Inactive / CategoryDisabled`; its PersistentStore state alone did not reveal this problem. A third-party firewall, Bitdefender, was registered on that machine. This is context, not proof of the cause.

Limen now exposes ActiveStore status and registered external firewall providers. It distinguishes inactive, unknown, and profile-dependent enforcement. Windows-reported state alone is not a measured packet result. No global profile, Windows security service, or third-party protection was disabled to obtain a passing test.

## Independent Windows enforcement test: passed

[GitHub Actions run 34709565018](https://github.com/DataProtector-collab/limen-firewall/actions/runs/34709565018) tested code revision `585bba95097e14b743b3547d0552b31e34a6d26f` on 2026-09-12. Its 41 tests, typecheck, lint, actual packet test, and Windows packaging succeeded.

| Stage | Observed result |
| --- | --- |
| Baseline HTTPS | Connected successfully. |
| Create outbound TCP block for the isolated test executable | A new connection failed. |
| Disable the rule | A new connection succeeded. |
| Enable the rule again | A new connection failed again. |
| Remove the rule | A new connection succeeded. |
| Cleanup | Test rule and temporary executable directory removed. |

The disposable runner had no registered external firewall provider. Its ActiveStore reported `OK` with `ProfileInactive` and `Enforced` entries: status can differ across profiles, even while the tested connection is blocked. The interface preserves these details instead of treating every code other than `Full` as wholly inactive. Later changes refine this status display; the native enforcement implementation is unchanged from the linked tested revision.

This is evidence for the isolated outbound TCP scenario on that runner. It is not a test of every application, inbound service, UDP flow, policy combination, or third-party firewall. The workflow continues to run the same packet test before packaging later revisions.

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
