# Aegis

Windows-Firewall, die bei *ausgehenden* Verbindungen nachfragt.

Die eingebaute Windows-Firewall ist für Inbound ganz okay. Sobald Chrome, Discord oder irgendein Updater aus `%TEMP%` nach draußen will, passiert nichts. Kein Dialog, keine Chance. Aegis dreht das um.

Sobald eine App eine Verbindung aufbauen will, kommt das hier:

```
Google Chrome  ·  chrome.exe  ·  Google LLC (signiert)

versucht, eine Internetverbindung herzustellen.

Ziel        www.google.com
IP          142.250.185.46
Protokoll   HTTPS
Port        443
Richtung    Ausgehend

Regel gilt für:  Diesmal  |  App + Ziel  |  Gesamte App

[ Blockieren ]                    [ Zulassen ]
```

Genau das, was TinyWall / Little Snitch auf dem Mac machen. Nur halt als Konsole.

<p align="center">
  <img src="docs/prompt.png" alt="Aegis Verbindungsdialog: Chrome will zu google.com" width="720" />
</p>

## Was es kann

Live-Tabelle mit Prozess, PID, Protokoll, Host, IP, Port, Richtung und Durchsatz. Filter für TCP, UDP, HTTP, HTTPS, QUIC, DNS, ICMP, WebSocket, RDP.

Unbekannte Apps landen im Dialog. Windows-Dienste (svchost, Defender, Search, System) sind vorab erlaubt, sonst klickst du dich tot.

Unsignierte Binaries und eingehendes RDP kriegen eine Warnung. Macht Sinn — `pcopt-svc.exe` aus dem Temp-Ordner sollte man nicht aus Gewohnheit durchwinken.

Regeln halten in `localStorage`. Pro App, oder App plus Host. Lässt sich nachträglich an- und ausschalten.

Einstellungen: Firewall an/aus, Standard Nachfragen / Sperren / Zulassen. Eingehend extra, weil RDP auf 3389 was anderes ist als Chrome auf 443.

<p align="center">
  <img src="docs/monitor.png" alt="Aegis Live-Überwachung mit Traffic und Verbindungsliste" width="920" />
</p>

## Was es nicht ist

Kein WFP-Treiber, kein `netsh advfirewall`, kein Packet-Drop auf deinem echten Adapter. Die Konsole hängt an einer simulierten Windows-Maschine (echte Prozessnamen, echte Ziele, echte Ports), damit das Verhalten stimmt. Wenn du Layer-4 auf Hardware droppen willst, brauchst du weiterhin einen Filtertreiber. Das hier ist die UI und die Regel-Logik.

## Start

Node 22.

```sh
npm i
npm run dev
```

Danach im Browser auf. Beim ersten Start klopft Chrome an, etwas später Discord. Über **Neue Verbindung** kannst du jederzeit eine weitere Anfrage erzwingen.

Build:

```sh
npm run build
```

## Ordner

```
src/lib/firewall/            Katalog, Engine, Store
src/components/firewall/     Dialog, Monitor, Apps, Regeln, Verlauf
src/components/ui/           Buttons, Switch, Input
```

`catalog.ts` hat die Prozesse und Ziele. `engine.ts` spawnt Verbindungen und matcht Regeln. `store.ts` ist Zustand + Persistenz.

## Hinweise

UI ist auf Deutsch. Regeln überleben einen Reload, der Verlauf nicht — der ist Session-Kram.

Wenn der Dialog nervt: Einstellungen → Standardrichtlinie auf Zulassen. Dann greifen nur noch explizite Block-Regeln. Umgekehrt Sperren, wenn du Default-Deny willst.

## Lizenz

MIT. Mach damit, was du willst.
