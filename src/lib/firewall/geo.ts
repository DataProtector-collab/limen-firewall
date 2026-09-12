import type { GeoCountry, GeoLocation } from "./geo-types";
import type { Connection } from "./types";
import type { ApprovalAttempt } from "./approval-types";

export const GEO_ADDRESS_LIMIT = 512;

export type MapPeer = Omit<Connection, "source"> & {
  source?: "kernel" | "lab" | "approval";
  program?: string;
  approval?: ApprovalAttempt;
};

export function mapConnections(connections: MapPeer[]): MapPeer[] {
  return connections.filter((connection) => ((connection.source === "kernel" && connection.protocol === "TCP") ||
    (connection.source === "approval" && !!connection.approval && ["TCP", "UDP"].includes(connection.protocol))) && !["listen", "bound", "closed"].includes(connection.state) &&
    connection.remotePort > 0 && !!connection.remoteIp && !["0.0.0.0", "::", "—"].includes(connection.remoteIp));
}

export function approvalMapPeers(attempts: ApprovalAttempt[]): MapPeer[] {
  return attempts.map((attempt) => ({
    id: `approval-${attempt.id}`, appId: `native-${encodeURIComponent(attempt.program.replace(/\\/g, "/").toLowerCase())}`,
    protocol: attempt.protocol, direction: "out", remoteIp: attempt.remoteAddress,
    remoteHost: attempt.remoteAddress, remotePort: attempt.remotePort, localPort: 0,
    country: "", state: attempt.decision === "pending" ? "pending" : attempt.decision === "deny" ? "blocked" : "unknown",
    startedAt: attempt.firstSeenAt, source: "approval", program: attempt.program, approval: attempt,
    bytesIn: 0, bytesOut: 0, rateIn: 0, rateOut: 0, trafficMeasured: false,
  }));
}

export function mapAddresses(connections: MapPeer[]): string[] {
  return [...new Set(mapConnections(connections).map((connection) => connection.remoteIp))].sort().slice(0, GEO_ADDRESS_LIMIT);
}

export interface MapGroup {
  country: GeoCountry;
  connections: MapPeer[];
  addresses: string[];
}

export function groupMapConnections(connections: MapPeer[], locations: GeoLocation[], countries: Record<string, GeoCountry>) {
  const byAddress = new Map(locations.map((location) => [location.ip, location]));
  const groups = new Map<string, MapGroup>();
  const nonPublic: MapPeer[] = [];
  const unknown: MapPeer[] = [];
  for (const connection of mapConnections(connections)) {
    const location = byAddress.get(connection.remoteIp);
    if (location?.status === "non-public") { nonPublic.push(connection); continue; }
    const country = location?.status === "located" && location.countryCode ? countries[location.countryCode] : undefined;
    if (!country) { unknown.push(connection); continue; }
    let group = groups.get(country.code);
    if (!group) {
      group = { country, connections: [], addresses: [] };
      groups.set(country.code, group);
    }
    group.connections.push(connection);
    if (!group.addresses.includes(connection.remoteIp)) group.addresses.push(connection.remoteIp);
  }
  return { groups: [...groups.values()].sort((a, b) => b.connections.length - a.connections.length || a.country.code.localeCompare(b.country.code)), nonPublic, unknown };
}

export function mapPoint(country: Pick<GeoCountry, "longitude" | "latitude">) {
  return { x: (country.longitude + 180) * 1000 / 360, y: (90 - country.latitude) * 500 / 180 };
}
