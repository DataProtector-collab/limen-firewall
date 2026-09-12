import assert from "node:assert/strict";
import test from "node:test";
import { classifyEnforcement } from "./enforcement";

test("development host Inactive / CategoryDisabled is shown as inactive", () => {
  assert.equal(
    classifyEnforcement({ primaryStatus: "Inactive", enforcementStatus: ["CategoryDisabled"] }),
    "inactive",
  );
});

test("successful Windows CI packet case is mixed, not wholly inactive", () => {
  assert.equal(
    classifyEnforcement({
      primaryStatus: "OK",
      enforcementStatus: ["ProfileInactive", "Enforced"],
    }),
    "mixed",
  );
});

test("Enforced and Full indicate Windows-reported enforcement only", () => {
  assert.equal(
    classifyEnforcement({ primaryStatus: "OK", enforcementStatus: ["Enforced"] }),
    "reported",
  );
  assert.equal(
    classifyEnforcement({ primaryStatus: "OK", enforcementStatus: ["Full"] }),
    "reported",
  );
});

test("missing or unfamiliar diagnostic data remains unknown", () => {
  assert.equal(classifyEnforcement({}), "unknown");
  assert.equal(classifyEnforcement({ primaryStatus: "OK" }), "unknown");
  assert.equal(classifyEnforcement({ enforcementStatus: ["Enforced"] }), "unknown");
  assert.equal(
    classifyEnforcement({ primaryStatus: "Unknown", enforcementStatus: ["Enforced"] }),
    "unknown",
  );
  assert.equal(
    classifyEnforcement({
      primaryStatus: "OK",
      enforcementStatus: ["Enforced", "FutureWindowsCode"],
    }),
    "unknown",
  );
});

test("explicitly disabled or absent rules are inactive without affirmative enforcement", () => {
  assert.equal(
    classifyEnforcement({ primaryStatus: "OK", enforcementStatus: ["DisabledObject"] }),
    "inactive",
  );
  assert.equal(
    classifyEnforcement({ primaryStatus: "NotPresent", enforcementStatus: ["CategoryDisabled"] }),
    "inactive",
  );
});

test("conflicting known codes retain a mixed warning rather than a blanket conclusion", () => {
  assert.equal(
    classifyEnforcement({
      primaryStatus: "OK",
      enforcementStatus: ["CategoryDisabled", "Enforced"],
    }),
    "mixed",
  );
  assert.equal(
    classifyEnforcement({ primaryStatus: "Inactive", enforcementStatus: ["Full"] }),
    "mixed",
  );
  assert.equal(
    classifyEnforcement({ primaryStatus: "OK", enforcementStatus: ["ProfileInactive"] }),
    "unknown",
  );
});
