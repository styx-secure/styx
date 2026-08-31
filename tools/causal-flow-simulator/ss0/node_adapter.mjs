#!/usr/bin/env node
// Independent JavaScript projection of the bounded evidence-only SS-0 rules.

export const PROFILE = Object.freeze({
  ciphersuite: "0x0001",
  ciphersuite_registry: "IANA_MLS",
  marmot: "4ad4ae21479c3f3fa9950c6fc4556a76941a62e1",
  mdk: "9396adb6aa6b95b521a7979facd5ea7040c07288",
  members: Object.freeze(["MDK_PIN_9396ADB", "STYX_B32A"]),
  openmls: "09e92777dba0528d3d29e2e5e681b7e91637c7be",
  retained_past_epochs: 5,
});

const U64_MAX = 18446744073709551615n;
const OPERATION_FIELDS = new Map([
  ["convergence", ["candidates", "operation", "profile"]],
  ["diagnostic_secret", ["operation", "profile"]],
  ["mutation", ["authoritative", "operation", "profile", "rs_result", "staged"]],
  ["physical_erasure", ["operation", "profile"]],
  ["profile", ["operation", "profile"]],
  ["receive", ["authenticated", "member_count", "opaque_application_bytes", "operation", "profile"]],
  ["recovery", ["operation", "profile"]],
  ["replay", ["already_emitted", "message_identity", "operation", "profile"]],
  ["restored_state", ["operation", "profile"]],
  ["retention", ["current_epoch", "message_epoch", "operation", "profile"]],
  ["transport", ["operation", "profile"]],
  ["welcome", ["asserted_rollback", "consumed", "embedded_tree", "framed", "last_resort", "member_bound", "operation", "profile", "profile_bound"]],
  ["wire_format", ["operation", "profile"]],
]);

const observation = (disposition, fields = {}) => ({
  applied: false,
  disposition,
  emitted_plaintext: false,
  ...fields,
});

const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
export const exactKeys = (value, keys) =>
  record(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const exactProfile = (value) =>
  exactKeys(value, Object.keys(PROFILE)) &&
  value.ciphersuite === PROFILE.ciphersuite &&
  value.ciphersuite_registry === PROFILE.ciphersuite_registry &&
  value.marmot === PROFILE.marmot &&
  value.mdk === PROFILE.mdk &&
  Array.isArray(value.members) &&
  value.members.length === PROFILE.members.length &&
  value.members.every((member, index) => member === PROFILE.members[index]) &&
  value.openmls === PROFILE.openmls &&
  value.retained_past_epochs === PROFILE.retained_past_epochs;
const parseU64 = (value) => {
  if (typeof value !== "string" || value.length > 20 || !/^(?:0|[1-9][0-9]*)$/u.test(value)) return null;
  const parsed = BigInt(value);
  return parsed <= U64_MAX ? parsed : null;
};
const validAccount = (value) =>
  typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
const branchCandidate = (value) =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  exactKeys(value, [
    "account",
    "app_witness_score",
    "authenticated",
    "depth",
    "parent",
    "proposal_free",
    "tip_priority",
  ]) &&
  validAccount(value.account) &&
  value.authenticated === true &&
  value.proposal_free === true &&
  value.depth === "1" &&
  value.app_witness_score === "0" &&
  value.tip_priority === "ordinary" &&
  typeof value.parent === "string" &&
  value.parent.length > 0;

export function evaluate(candidate) {
  if (!record(candidate) || typeof candidate.operation !== "string") {
    return observation("INVALID_SESSION_INPUT");
  }
  const fields = OPERATION_FIELDS.get(candidate.operation) ?? ["operation", "profile"];
  if (!exactKeys(candidate, fields)) return observation("INVALID_SESSION_INPUT");
  if (candidate.operation === "profile") {
    return observation(exactProfile(candidate.profile) ? "ACCEPTED_EVIDENCE" : "DRIFT_INVALIDATED");
  }
  if (!exactProfile(candidate.profile)) return observation("DRIFT_INVALIDATED");

  switch (candidate.operation) {
    case "receive":
      if (candidate.member_count !== 2 || candidate.authenticated !== true) return observation("INVALID_SESSION_INPUT");
      if (candidate.opaque_application_bytes !== true) return observation("UNSUPPORTED_PROFILE_INPUT");
      return observation("AP_AUTHORITY_REQUIRED", { emitted_plaintext: true });
    case "mutation":
      if (candidate.authoritative !== true || candidate.staged !== true) return observation("INVALID_SESSION_INPUT");
      if (candidate.rs_result === "COMMITTED") return observation("COMMITTED_MUTATION", { applied: true });
      if (candidate.rs_result === "NOT_COMMITTED") return observation("NOT_COMMITTED");
      if (candidate.rs_result === undefined || candidate.rs_result === null || candidate.rs_result === "INDETERMINATE") return observation("RS_RESULT_REQUIRED");
      return observation("INVALID_SESSION_INPUT");
    case "retention": {
      const current = parseU64(candidate.current_epoch);
      const message = parseU64(candidate.message_epoch);
      if (current === null || message === null || message > current) return observation("EPOCH_OUT_OF_RANGE");
      const accepted = current - message <= BigInt(PROFILE.retained_past_epochs);
      return observation(accepted ? "ACCEPTED_EVIDENCE" : "EPOCH_OUT_OF_RANGE", { emitted_plaintext: accepted });
    }
    case "replay":
      if (typeof candidate.message_identity !== "string" || candidate.message_identity.length === 0) return observation("INVALID_SESSION_INPUT");
      return candidate.already_emitted === true
        ? observation("DUPLICATE_SUPPRESSED")
        : observation("ACCEPTED_EVIDENCE", { emitted_plaintext: true });
    case "convergence": {
      const values = candidate.candidates;
      if (!Array.isArray(values) || values.length !== 2 || !values.every(branchCandidate) || values[0].parent !== values[1].parent || values[0].account === values[1].account) {
        return observation("UNSUPPORTED_PROFILE_INPUT");
      }
      const selected = [values[0].account, values[1].account].sort()[0];
      return observation("DEFERRED_CANDIDATE", { applied: true, selected });
    }
    case "welcome":
      if (!["framed", "embedded_tree", "profile_bound", "member_bound"].every((name) => candidate[name] === true)) return observation("INVALID_SESSION_INPUT");
      if (candidate.last_resort !== false) return observation("UNSUPPORTED_PROFILE_INPUT");
      if (candidate.consumed === true || candidate.asserted_rollback === true) return observation("REPLAY_REJECTED");
      return observation("WELCOME_ACCEPTED", { applied: true });
    case "restored_state":
      return observation("UNVALIDATED_RESTORED_STATE");
    case "diagnostic_secret":
    case "physical_erasure":
    case "recovery":
    case "transport":
    case "wire_format":
      return observation("NOT_CLAIMED_IN_PROFILE");
    default:
      return observation("UNSUPPORTED_PROFILE_INPUT");
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  let input = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => { input += chunk; });
  process.stdin.on("end", () => {
    try {
      const candidates = JSON.parse(input);
      if (!Array.isArray(candidates)) throw new Error("input must be an array");
      process.stdout.write(`${JSON.stringify(candidates.map(evaluate))}\n`);
    } catch (error) {
      process.stderr.write("invalid SS-0 adapter input\n");
      process.exitCode = 2;
    }
  });
}
