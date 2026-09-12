export const APP_NAME = "Limen";
export const APP_VERSION = "1.4.0";

export interface ReleaseNote {
  version: string;
  date: string;
  title: string;
  items: string[];
}

export const RELEASES: ReleaseNote[] = [
  {
    version: "1.4.0",
    date: "2026-09-12",
    title: "Offline world map, notification area and native Internet approvals",
    items: [
      "Map real peer countries with an offline IP database and explicit location limits.",
      "Keep Limen running in the notification area when X is clicked; confirm actual exit.",
      "Block unknown outbound public TCP/UDP attempts in an explicit native approval session.",
      "Review real WFP events and allow a destination or program for the current session.",
      "Verify the separately licensed native runtime and harden packaged Electron integrity.",
    ],
  },
  {
    version: "1.3.0",
    date: "2026-09-12",
    title: "Blackbox Breaker, War Monitor and experimental Drift Guard",
    items: [
      "Inspect real hosted Windows services, process relationships and loaded modules with executable hashes and signature results.",
      "Record host traffic and observed socket changes in a bounded local session recorder.",
      "Review evidence for traffic bursts, peer fan-out, reconnect patterns, new listeners and SYN pressure.",
      "Freeze an observed program destination baseline with experimental Drift Guard; review deviations before creating explicit Windows rules.",
    ],
  },
  {
    version: "1.2.1",
    date: "2026-09-12",
    title: "Working VM traffic counters and visible rule controls",
    items: [
      "Use real Windows interface counters when a driver returns no adapter statistics.",
      "Show capture freshness and unavailable measurements instead of false zero traffic.",
      "Put connections and rule actions before the optional throughput chart.",
      "Default program rules to all remote addresses; make an IP restriction explicit before saving.",
    ],
  },
  {
    version: "1.2.0",
    date: "2026-09-12",
    title: "Windows desktop and real firewall rules",
    items: [
      "Windows TCP/UDP endpoint capture through a local desktop bridge.",
      "Explicit persistent program rules verified against Windows Firewall; administrator privileges required.",
      "Native capture and simulation are separate. No fabricated signatures, per-app traffic or packet-drop counters.",
      "Connection observations do not hold packets. Windows rules and profile settings determine enforcement.",
      "Safer rule persistence, state validation, polling, accessible dialogs and Windows packages.",
    ],
  },
  {
    version: "1.1.1",
    date: "2026-09-12",
    title: "Rename: Limen",
    items: [
      "Product renamed from Aegis to Limen (Latin: threshold). Same console, different name.",
      "Docs and GitHub description are English-first. In-app UI still has nine languages.",
    ],
  },
  {
    version: "1.1.0",
    date: "2026-09-12",
    title: "Kernel capture + languages",
    items: [
      "Reads the kernel socket table (/proc/net/tcp, tcp6, udp, udp6) and maps inodes to PID and binary.",
      "NIC counters come from /proc/net/dev, not guesses.",
      "New sockets without a rule hit the allow/block prompt. Loopback and listen are display-only.",
      "Eight more UI languages: English, Chinese, Hindi, Spanish, French, Arabic, Bengali, Portuguese.",
      "Arabic flips the layout (RTL). Language sticks in localStorage.",
      "Version history in Settings. Windows lab is optional and off by default.",
    ],
  },
  {
    version: "1.0.0",
    date: "2026-09-12",
    title: "First console",
    items: [
      "Allow/block prompt when an app tries to reach the network.",
      "Rules per app or app+host, live table, log, German UI.",
      "Windows lab traffic for Chrome, Discord and the rest.",
    ],
  },
];
