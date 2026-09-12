import type {
  LimenNativeBridge,
  NativeRule,
  NativeRuleInput,
  NativeStatus,
} from "../src/lib/firewall/native-types";
import type { KernelSnapshot } from "../src/lib/firewall/kernel-types";

// This module is an explicit dev-only page entry. Production index.html does not
// import it, and it must never replace the real Electron preload bridge.
if (!import.meta.env.DEV || location.pathname !== "/tests/native-ui.html") {
  throw new Error("Native UI fixture is available only at the explicit development test URL.");
}
if (window.limen) throw new Error("Refusing to replace an existing native bridge.");

const banner = document.getElementById("native-ui-fixture-banner")!;
const modeLabel = document.getElementById("fixture-mode")!;
const resize = new ResizeObserver(() => {
  document.documentElement.style.setProperty(
    "--fixture-banner-height",
    `${banner.getBoundingClientRect().height}px`,
  );
});
resize.observe(banner);

let rejectNextSave = true;
let sequence = 0;
let snapshotSequence = 0;
const rules = new Map<string, NativeRule>();
const setModeLabel = () => {
  modeLabel.textContent = rejectNextSave
    ? "Next save will reject with a fixture error."
    : "Saves accepted in page memory only — no Windows changes.";
};
document.getElementById("fixture-reject")!.addEventListener("click", () => {
  rejectNextSave = true;
  setModeLabel();
});
document.getElementById("fixture-accept")!.addEventListener("click", () => {
  rejectNextSave = false;
  setModeLabel();
});

const status: NativeStatus = {
  platform: "win32",
  available: true,
  elevated: true,
  firewallEnabled: true,
  backend: "windows-firewall",
  reason: "UI TEST FIXTURE: simulated Windows status, not this computer's configuration.",
  profiles: [
    {
      name: "Domain (fixture)",
      enabled: false,
      defaultInboundAction: "Block",
      defaultOutboundAction: "Allow",
    },
    {
      name: "Private (fixture)",
      enabled: true,
      defaultInboundAction: "Block",
      defaultOutboundAction: "Allow",
    },
    {
      name: "Public (fixture)",
      enabled: true,
      defaultInboundAction: "Block",
      defaultOutboundAction: "Allow",
    },
  ],
};

function snapshot(): KernelSnapshot {
  snapshotSequence += 1;
  return {
    at: Date.now(),
    sockets: [
      {
        id: "fixture-tcp-alpha",
        proto: "TCP",
        family: 4,
        localIp: "192.0.2.10",
        localPort: 51001,
        remoteIp: "198.51.100.25",
        remotePort: 443,
        state: "established",
        inode: "",
        pid: 4101,
        comm: "FixtureAlpha",
        exe: "C:\\Limen UI Fixture\\FixtureAlpha.exe",
        uid: 0,
        direction: "unknown",
        signature: { status: "unknown" },
      },
      {
        id: "fixture-tcp-beta",
        proto: "TCP",
        family: 6,
        localIp: "2001:db8::10",
        localPort: 51002,
        remoteIp: "2001:db8::25",
        remotePort: 8443,
        state: "established",
        inode: "",
        pid: 4102,
        comm: "FixtureBeta",
        exe: "C:\\Limen UI Fixture\\FixtureBeta.exe",
        uid: 0,
        direction: "unknown",
        signature: { status: "unknown" },
      },
      {
        id: "fixture-udp-beta",
        proto: "UDP",
        family: 4,
        localIp: "192.0.2.10",
        localPort: 5353,
        remoteIp: "",
        remotePort: 0,
        state: "listen",
        inode: "",
        pid: 4102,
        comm: "FixtureBeta",
        exe: "C:\\Limen UI Fixture\\FixtureBeta.exe",
        uid: 0,
        direction: "unknown",
        signature: { status: "unknown" },
      },
    ],
    rxBytes: 100000 + snapshotSequence * 8192,
    txBytes: 50000 + snapshotSequence * 2048,
    tcpInuse: 2,
    udpInuse: 1,
    capture: "windows",
    available: true,
    platform: "win32",
  };
}

function validate(input: NativeRuleInput): NativeRuleInput {
  if (!/^c:\\limen ui fixture\\fixture(?:alpha|beta)\.exe$/i.test(input.program))
    throw new Error("UI TEST FIXTURE: only the two sample programs are allowed.");
  if (
    !["allow", "block"].includes(input.action) ||
    !["in", "out"].includes(input.direction) ||
    !["ANY", "TCP", "UDP"].includes(input.protocol)
  )
    throw new Error("UI TEST FIXTURE: invalid rule fields.");
  for (const port of [input.localPort, input.remotePort]) {
    if (
      port !== undefined &&
      (input.protocol === "ANY" || !Number.isInteger(port) || port < 1 || port > 65535)
    )
      throw new Error("UI TEST FIXTURE: invalid port or transport.");
  }
  let remoteAddress = input.remoteAddress?.trim();
  if (remoteAddress) {
    if (remoteAddress.includes(":")) {
      try {
        const url = new URL(`http://[${remoteAddress}]/`);
        remoteAddress = url.hostname.slice(1, -1);
      } catch {
        throw new Error("UI TEST FIXTURE: enter a literal IPv4 or IPv6 address.");
      }
    } else if (
      !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(remoteAddress) ||
      remoteAddress.split(".").some((part) => Number(part) > 255)
    ) {
      throw new Error("UI TEST FIXTURE: enter a literal IPv4 or IPv6 address.");
    }
  }
  return { ...input, ...(remoteAddress ? { remoteAddress } : {}) };
}

const fixture: LimenNativeBridge = {
  platform: "win32",
  async getStatus() {
    return structuredClone(status);
  },
  async getSnapshot() {
    return snapshot();
  },
  async listRules() {
    return structuredClone([...rules.values()]);
  },
  async applyRule(input) {
    // A short delay makes async button disabling and retained dialog state visible.
    await new Promise((resolve) => setTimeout(resolve, 700));
    if (rejectNextSave) {
      rejectNextSave = false;
      setModeLabel();
      throw new Error(
        "UI TEST FIXTURE: save deliberately rejected. No Windows rule was changed. Choose Accept saves to continue the UI test.",
      );
    }
    const validated = validate(input);
    const rule: NativeRule = {
      ...validated,
      id: `fixture-rule-${++sequence}`,
      enabled: true,
      createdAt: Date.now(),
      primaryStatus: "OK",
      enforcementStatus: ["Full"],
    };
    rules.set(rule.id, rule);
    return structuredClone(rule);
  },
  async removeRule(id) {
    if (!rules.delete(id)) throw new Error("UI TEST FIXTURE: rule does not exist.");
  },
  async setRuleEnabled(id, enabled) {
    const rule = rules.get(id);
    if (!rule) throw new Error("UI TEST FIXTURE: rule does not exist.");
    const updated = {
      ...rule,
      enabled,
      primaryStatus: enabled ? "OK" : "Inactive",
      enforcementStatus: enabled ? ["Full"] : ["DisabledObject"],
    };
    rules.set(id, updated);
    return structuredClone(updated);
  },
};
window.limen = fixture;

// Keep test setup in memory; never overwrite the user's saved lab preferences.
const { useFirewall } = await import("../src/lib/firewall/store");
useFirewall.setState((state) => ({
  hydrated: true,
  settings: { ...state.settings, language: "de", kernelCapture: true, labTraffic: false },
  persist: () => {},
}));
await import("../src/main");
