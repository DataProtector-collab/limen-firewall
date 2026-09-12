import assert from "node:assert/strict";
import test from "node:test";
import { isLabRule, matchRule, validateSettings } from "./policy";
import type { Connection, Rule } from "./types";

const connection: Connection = {
  id: "lab-1", source: "lab", appId: "chrome", protocol: "TCP", direction: "out",
  localPort: 52000, remoteHost: "EXAMPLE.COM", remoteIp: "192.0.2.20", remotePort: 443,
  country: "", state: "established", bytesIn: 0, bytesOut: 0, rateIn: 0, rateOut: 0, startedAt: 1,
};
const rule: Rule = { id: "r1", appId: "chrome", action: "allow", scope: "app", enabled: true, createdAt: 1, hits: 0 };

test("block rules win conflicts and host matching is case insensitive", () => {
  const block: Rule = { ...rule, id: "deny", action: "block", scope: "app-host", host: "example.com" };
  assert.equal(matchRule([rule, block], connection)?.action, "block");
  assert.equal(matchRule([block, rule], connection)?.action, "block");
  assert.equal(matchRule([{ ...block, host: "other.example" }], connection), null);
});

test("inbound policies match the local service port and correct direction", () => {
  const inbound = { ...connection, direction: "in" as const, localPort: 3389, remotePort: 52000 };
  assert.ok(matchRule([{ ...rule, direction: "in", port: 3389 }], inbound));
  assert.equal(matchRule([{ ...rule, direction: "out", port: 3389 }], inbound), null);
  assert.equal(matchRule([{ ...rule, direction: "in", port: 52000 }], inbound), null);
});

test("local demo policies cannot apply to native observations", () => {
  assert.equal(matchRule([{ ...rule, action: "block" }], { ...connection, source: "kernel" }), null);
  assert.equal(matchRule([{ ...rule, scope: "app-host", host: "" }], connection), null);
});

test("stored policy validation rejects malformed permissions and restores a valid locale", () => {
  assert.ok(isLabRule(rule));
  for (const invalid of [null, { ...rule, action: "execute" }, { ...rule, enabled: "true" }, { ...rule, port: -1 }, { ...rule, port: 1.2 }, { ...rule, port: 70000 }, { ...rule, scope: "app-host" }, { ...rule, protocol: "ALL" }]) assert.equal(isLabRule(invalid), false);
  assert.equal(validateSettings({}).language, "de");
  assert.equal(validateSettings({ language: "garbage", enabled: "yes", defaultPolicy: "execute" }).enabled, true);
  assert.equal(validateSettings({ language: "en", enabled: false, defaultPolicy: "block" }).language, "en");
});
