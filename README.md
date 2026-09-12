# Limen

Ask-first firewall. An app tries to go online — you allow or block. Version **1.1.1**.

*Limen* is Latin for threshold. Every outbound socket has to cross it. Not another “Aegis”.

| | |
| --- | --- |
| EN | Ask-first firewall. App wants the network: allow or block. |
| DE | Firewall mit Nachfrage. App will raus: zulassen oder blockieren. |
| 中文 | 先问再放行。应用要上网：允许或拦截。 |
| हिन्दी | पहले पूछो। ऐप नेटवर्क चाहे: अनुमति या रोक। |
| ES | Firewall que pregunta. La app quiere salir: permitir o bloquear. |
| FR | Pare-feu qui demande. Une app sort : autoriser ou bloquer. |
| العربية | جدار ناري يسأل. التطبيق يريد الشبكة: سماح أو حظر. |
| বাংলা | আগে জিজ্ঞাসা। অ্যাপ নেট চায়: অনুমতি বা ব্লক। |
| PT | Firewall que pergunta. A app quer a rede: permitir ou bloquear. |

UI: English · Deutsch · 中文 · हिन्दी · Español · Français · العربية · বাংলা · Português. Default is German. Switch under Settings. Arabic is RTL.

Windows’ own firewall is fine for inbound. Chrome, Discord, some updater from `%TEMP%` going *out*? Silence. No prompt, no chance. Limen flips that.

When an app opens a connection you get this:

```
Google Chrome  ·  chrome.exe  ·  Google LLC (signed)

is trying to connect to the internet.

Target      www.google.com
IP          142.250.185.46
Protocol    HTTPS
Port        443
Direction   Outbound

Rule applies to:  This time  |  App + host  |  Whole app

[ Block ]                         [ Allow ]
```

Same idea as TinyWall / Little Snitch. Just a console.

<p align="center">
  <img src="docs/prompt.png" alt="Limen prompt: Chrome wants google.com" width="720" />
</p>

## 1.1 — kernel capture

From 1.1 the console reads the kernel socket table. `/proc/net/tcp`, `tcp6`, `udp`, `udp6`. Inodes are mapped to PID and binary through process file descriptors. Throughput comes from `/proc/net/dev`. Without that a firewall is just a panel.

Unknown remote sockets with no rule go through the same prompt. Loopback and listen sockets show up in the table; they don’t nag. node, Vite and the preview proxy are pre-allowed so the console doesn’t hang itself.

The Windows lab (Chrome, Discord, …) is still there, off by default. Turn it on if you want the prompt without a real socket.

What changed per version: [CHANGELOG.md](CHANGELOG.md). How numbers work: [docs/VERSIONING.md](docs/VERSIONING.md). Settings shows the same list without markdown.

## What it does

Live table: process, PID, protocol, host, IP, port, direction, kernel/lab, throughput. Filters for TCP, UDP, HTTP, HTTPS, QUIC, DNS, ICMP, WebSocket, RDP.

Unknown apps hit the prompt. System stuff and this runtime are pre-allowed.

Unsigned binaries and inbound RDP get a warning. Don’t rubber-stamp `pcopt-svc.exe` from Temp.

Rules live in `localStorage`. Per app, or app plus host. Toggle later.

Settings: firewall on/off, kernel capture, lab, language, default ask / block / allow. Inbound is separate — RDP on 3389 is not Chrome on 443.

<p align="center">
  <img src="docs/monitor.png" alt="Limen live monitor with traffic and connection list" width="920" />
</p>

## What it isn’t

No WFP driver, no `netsh advfirewall`. Block writes policy in the console. Dropping packets on the adapter needs nft/iptables in userspace or a Windows filter driver. Neither is on this host. Capture is real. Drop is not. That note is in Settings too, not only here.

## Run

Node 22.

```sh
npm i
npm run dev
```

Open it. The table fills from the kernel. **New connection** forces the prompt with a lab app, even if the lab is off.

```sh
npm run build
```

## Layout

```
src/lib/firewall/            catalog, engine, store, kernel reader
src/lib/firewall/kernel-read.server.ts
                             /proc/net parser, inode → PID
src/lib/i18n/                9 languages
src/lib/version.ts           APP_NAME, APP_VERSION, release notes
src/components/firewall/     prompt, monitor, apps, rules, log
CHANGELOG.md
docs/VERSIONING.md
```

`kernel-read.server.ts` reads the tables. `engine.ts` polls once a second and pushes new sockets into the prompt. `store.ts` is state + persist.

## Notes

Rules survive a reload. The log does not — that’s session data.

Prompt too loud: Settings → default policy Allow. Then only explicit block rules fire. Flip to Block for default-deny.

Next visible feature bump is 1.2, not a silent 1.1.2.

## License

MIT. Do what you want with it.
