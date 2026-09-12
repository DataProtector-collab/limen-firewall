import test from "node:test";
import assert from "node:assert/strict";
import { approvalMapPeers, groupMapConnections, mapAddresses, mapConnections, mapPoint } from "./geo.ts";
import type { Connection } from "./types.ts";
import countries from "../../assets/geo-countries.json" with { type: "json" };

const conn = (remoteIp: string, overrides: Partial<Connection> = {}): Connection => ({
  id: remoteIp, appId: "app", protocol: "TCP", direction: "unknown", localPort: 51234,
  remoteHost: remoteIp, remoteIp, remotePort: 443, country: "IPv4", state: "established",
  bytesIn: 0, bytesOut: 0, rateIn: 0, rateOut: 0, startedAt: 1, source: "kernel", ...overrides,
});

test("Map uses observed TCP peers only and never borrows simulation country data", () => {
  const peers = [conn("8.8.8.8"), conn("1.1.1.1", { source: "lab", country: "AU" }), conn("", { protocol: "UDP", state: "bound" }), conn("0.0.0.0", { state: "listen", remotePort: 0 }), conn("9.9.9.9", { state: "closed" })];
  assert.deepEqual(mapConnections(peers).map((peer) => peer.remoteIp), ["8.8.8.8"]);
  assert.deepEqual(mapAddresses([...peers, conn("8.8.8.8")]), ["8.8.8.8"]);
  assert.equal(mapAddresses(Array.from({ length: 800 }, (_, i) => conn(`8.8.${Math.floor(i / 256)}.${i % 256}`))).length, 512);
});

test("Map keeps local, unresolved and missing-label countries unplotted without inferring direction", () => {
  const us = { code: "US", name: "United States", nameDe: "Vereinigte Staaten", longitude: -97.38, latitude: 39.54 };
  const peers = [conn("8.8.8.8"), conn("8.8.8.8", { id: "second", localPort: 51235 }), conn("10.0.0.1"), conn("1.1.1.1"), conn("9.9.9.9")];
  const result = groupMapConnections(peers, [
    { ip: "8.8.8.8", status: "located", countryCode: "US" },
    { ip: "10.0.0.1", status: "non-public" },
    { ip: "1.1.1.1", status: "unknown" },
    { ip: "9.9.9.9", status: "located", countryCode: "BQ" },
    { ip: "7.7.7.7", status: "located", countryCode: "US" },
  ], { US: us });
  assert.equal(result.groups.length, 1);
  assert.equal(result.groups[0].connections.length, 2);
  assert.deepEqual(result.groups[0].addresses, ["8.8.8.8"]);
  assert.equal(result.nonPublic.length, 1);
  assert.equal(result.unknown.length, 2);
  assert.ok(result.groups[0].connections.every((peer) => peer.direction === "unknown"));
  assert.deepEqual(mapPoint({ longitude: 0, latitude: 0 }), { x: 500, y: 250 });
});

test("Map separates native outbound UDP guard events from sockets and approval from delivery", () => {
  const attempts = approvalMapPeers([
    { id: "blocked-udp", program: "C:\\Tools\\probe.exe", protocol: "UDP", remoteAddress: "8.8.8.8", remotePort: 53, firstSeenAt: 100, lastSeenAt: 200, count: 2, decision: "pending", canApprove: true },
    { id: "approved-tcp", program: "C:\\Tools\\probe.exe", protocol: "TCP", remoteAddress: "1.1.1.1", remotePort: 443, firstSeenAt: 300, lastSeenAt: 400, count: 1, decision: "allow-endpoint", canApprove: true },
  ]);
  const result = mapConnections([...attempts, conn("9.9.9.9", { protocol: "UDP" })]);
  assert.equal(result.length, 2);
  assert.ok(result.every((peer) => peer.source === "approval" && peer.direction === "out"));
  assert.equal(result[0].protocol, "UDP");
  assert.equal(result[1].state, "unknown");
  assert.equal(result[1].approval?.decision, "allow-endpoint");
  assert.deepEqual(mapAddresses(result), ["1.1.1.1", "8.8.8.8"]);
});

test("Shared ISO country codes use the principal country label instead of an external territory", () => {
  assert.equal(countries.AU.name, "Australia");
  assert.ok(countries.AU.longitude > 125 && countries.AU.longitude < 140);
  assert.ok(countries.AU.latitude < -20 && countries.AU.latitude > -35);
});
