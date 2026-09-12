# World map, notification area and Internet approvals

Limen 1.4 adds an offline world map and an optional native connection-approval
session. The existing Blackbox, War Monitor and persistent Windows rules remain
available.

## World map

Open **World map / Weltkarte**. Dots group observed remote IP addresses by their
approximate country. Select a dot or country, choose a program, or search for an
IP address. Socket observations and actual connection-guard events can be
filtered separately. A subsequently approved attempt is not labeled a delivered
connection.

The bundled DB-IP Lite September 2026 database is queried locally. Limen does not
send observed addresses to a geolocation service, fetch remote map tiles, or
look up the user's own location. Natural Earth supplies the map outlines and
country label coordinates. Attribution and licenses are in `desktop/data/`.

Dots are country labels, **not exact server positions or people**. Anycast,
hosting providers, VPNs and database age can make a country's assignment differ
from the server actually used. Private, special-use and unknown addresses remain
separate instead of receiving invented positions.

Socket enumeration supplies TCP peers but generally not the connection's
initiating direction. Those rows keep direction unknown. Windows Filtering
Platform events from the approval guard identify real outbound attempts,
including UDP destinations. A bound UDP endpoint alone supplies no remote peer
and does not become a map point.

## X and actual exit

The window's **X** hides Limen in the Windows notification area. Click the Limen
icon, use its **Open** menu item, or launch Limen again to restore the same
instance. Observation and an active approval session continue while hidden.

Choose **Quit Limen** in the icon's menu or **Exit Limen** in Settings to actually
exit. A native confirmation dialog explains that observation and temporary
approval protection end. Cancelling keeps Limen running. Windows logoff and
shutdown are not held open by a confirmation dialog.

Persistent Windows Firewall rules are separate: closing Limen does not remove
them. If Windows cannot create the notification icon, Limen keeps its window
accessible instead of disappearing without a restore route.

## Ask before Internet access

Open **Approvals / Freigaben** and explicitly enable approval mode. The native
runtime creates its own dynamic Windows Filtering Platform sublayer with
filters at the IPv4 and IPv6 ALE connection-authorization layers. It does not
rewrite global Windows Firewall profile defaults or existing rules.

While active, unapproved outbound **TCP and UDP attempts to public IP
addresses** are blocked. Loopback, local networks and designated special-use
ranges are outside this mode. Other IP protocols are not covered. Programs may
lose connectivity when the session starts; Windows can reauthorize existing
flows after a filter change.

For an observed blocked attempt, the review shows the executable path, remote
IP and port, transport, time and number of recorded events. Choose:

- **Allow this destination:** allow that executable's same IP, port and transport
  for the current session.
- **Allow program:** allow that executable across destinations for the current
  session.
- **Deny:** keep the attempt blocked and record the decision.

The initial socket operation is **rejected, not paused inside a driver**.
After approval, the application must retry; some applications retry themselves,
while others need a reconnect or reload. A WFP permit does not override an
independent Windows Firewall block. Existing policy can still prevent delivery.

Only actual drop events matching Limen's own filter IDs create requests. Unknown
or unsafe executable paths cannot be approved. Decisions are made against the
captured WFP application identity, not a new executable path supplied by the
renderer. Program-path permissions do not bind future executable contents to a
hash, nor do they distinguish individual services inside a shared executable.

Pending event storage and approvals are bounded. Excess observations are
reported as omitted; exceeding the observation limit does not grant access.
Windows event collection must be available. Limen reports inability to start or
loss of the native session instead of pretending to protect it.

Turning the mode off or actually exiting Limen removes its temporary session
filters and decisions. The mode starts **off** on the next application launch.
A native-host crash also ends the dynamic session, so this mode is not a
persistent, boot-time or fail-closed firewall service. For persistent explicit
program blocks, use the existing Windows rule editor.

## Binary runtime and integrity

The new native core is compiled C++ in `Limen.Approval.Core.dll` with a small
`Limen.Approval.Host.exe`. Its source is retained privately by the project owner.
The public repository contains the interface and integration code, plus pinned
binary hashes and a downloader for the separately distributed runtime.

The main process verifies both binaries before starting the host. Packaged
Electron uses embedded ASAR integrity validation, loads application code only
from ASAR, and disables Electron-as-Node, `NODE_OPTIONS` and Node inspection
arguments. The native compiler enables stack checks, control-flow guard and
address-space randomization. The bridge exposes fixed validated operations;
there is no privileged HTTP server or arbitrary shell operation.

A DLL is not encryption and cannot guarantee secrecy against reverse
engineering. Unsigned files and local administrator compromise remain important
limits. Integrity checks do not turn heuristic observations into malware
verdicts. Existing MIT code keeps its license; the native runtime is covered by
[its separate binary license](../NATIVE-LICENSE.md).

## References

- [Microsoft: ALE layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers)
- [Microsoft: filter arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration)
- [Microsoft: object management and dynamic sessions](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)
- [Microsoft: subscribing to network events](https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmneteventsubscribe0)
- [Electron: fuses](https://www.electronjs.org/docs/latest/tutorial/fuses)
- [DB-IP Lite country database](https://db-ip.com/db/download/ip-to-country-lite)
- [Natural Earth public-domain terms](https://www.naturalearthdata.com/about/terms-of-use/)
