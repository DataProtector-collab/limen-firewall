import type { NativeRule } from "./native-types";

export type EnforcementDisplay = "inactive" | "reported" | "mixed" | "unknown";

const knownPrimary = new Set(["ok", "inactive", "notpresent"]);
const knownEnforcement = new Set([
  "full",
  "enforced",
  "profileinactive",
  "categorydisabled",
  "disabledobject",
]);

/** Classify Windows' diagnostic codes for display, never as a packet-test result. */
export function classifyEnforcement(
  rule: Pick<NativeRule, "primaryStatus" | "enforcementStatus">,
): EnforcementDisplay {
  const primary = rule.primaryStatus?.trim().toLowerCase();
  const codes =
    rule.enforcementStatus?.map((code) => code.trim().toLowerCase()).filter(Boolean) ?? [];
  if (
    !primary ||
    !codes.length ||
    !knownPrimary.has(primary) ||
    codes.some((code) => !knownEnforcement.has(code))
  ) {
    return "unknown";
  }

  const reported = codes.includes("enforced") || codes.includes("full");
  const inactive =
    primary === "inactive" ||
    primary === "notpresent" ||
    codes.includes("categorydisabled") ||
    codes.includes("disabledobject");

  // ActiveStore can report one entry per profile. The Windows CI packet test
  // successfully blocked traffic with OK + [ProfileInactive, Enforced].
  if (reported && (inactive || codes.includes("profileinactive"))) return "mixed";
  if (inactive) return "inactive";
  if (primary === "ok" && reported) return "reported";
  // ProfileInactive alone does not establish the rule's outcome everywhere.
  return "unknown";
}
