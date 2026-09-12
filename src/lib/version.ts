export const APP_VERSION = "1.1.0";

export interface ReleaseNote {
  version: string;
  date: string;
  title: string;
  items: string[];
}

export const RELEASES: ReleaseNote[] = [
  {
    version: "1.1.0",
    date: "2026-09-12",
    title: "Kernel-Capture und Sprachen",
    items: [
      "Liest die Kernel-Sockettabelle (/proc/net/tcp, tcp6, udp, udp6) und mappt Inodes auf PID und Binary.",
      "NIC-Zähler kommen aus /proc/net/dev, nicht mehr aus Schätzwerten.",
      "Neue Sockets ohne Regel landen im Zulassen/Blockieren-Dialog. Loopback und Listen werden nur angezeigt.",
      "Acht weitere UI-Sprachen: Englisch, Chinesisch, Hindi, Spanisch, Französisch, Arabisch, Bengali, Portugiesisch.",
      "Arabisch spiegelt das Layout (RTL). Sprache bleibt in localStorage.",
      "Versionshistorie unter Einstellungen. Windows-Labor ist optional und standardmäßig aus.",
    ],
  },
  {
    version: "1.0.0",
    date: "2026-09-12",
    title: "Erste Konsole",
    items: [
      "Zulassen/Blockieren-Dialog, wenn eine App ins Netz will.",
      "Regeln pro App oder App+Host, Live-Tabelle, Verlauf, deutsche Oberfläche.",
      "Windows-Labortraffic für Chrome, Discord und den Rest.",
    ],
  },
];
