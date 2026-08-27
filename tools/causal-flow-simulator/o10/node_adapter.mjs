import fs from "node:fs";

const rows = new Map([
  ["APPLIED", ["AP", "FINAL_AFTER_S6", "APPLIED", null, "NONE", "TRUSTED_LOCAL_ONLY"]],
  ["AUTHENTIC_BUT_UNAUTHORIZED", ["AP", "EVENT_LOCAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"]],
  ["AUTHORITY_PROJECTION_UNAVAILABLE", ["AP", "S5_AUTHORITY_PROJECTION", "NOT_APPLIED", "PRESERVE_CONTEXT_AND_RESTORE_AUTHORITY_CAPABILITY", "AUTHORITY_CAPABILITY_RESTORED", "TRUSTED_LOCAL_ONLY"]],
  ["COMMITMENT_MISMATCH", ["K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"]],
  ["CONTEXT_CAPACITY_EXHAUSTED", ["K", "S4_GRAPH_ADMISSION|S6_DURABLE_COMMIT", "NOT_APPLIED", "NEW_CONTEXT_OR_RATIFIED_PROFILE_REQUIRED", "NEW_CONTEXT_OR_RATIFIED_PROFILE", "TRUSTED_LOCAL_ONLY"]],
  ["CREDENTIAL_BINDING_MISMATCH", ["K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"]],
  ["CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED", ["K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"]],
  ["CURRENT_OBJECT_OUT_OF_PROFILE", ["K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "NEW_CONTEXT_OR_RATIFIED_PROFILE_REQUIRED", "NEW_CONTEXT_OR_RATIFIED_PROFILE", "TRUSTED_LOCAL_ONLY"]],
  ["DEPENDENCY_DEFERRED", ["K", "S4_GRAPH_ADMISSION|S6_DURABLE_COMMIT", "NOT_APPLIED", "RETRY_AFTER_DEPENDENCY_CHANGE", "AUTHENTICATED_DEPENDENCY_STATE_CHANGED", "TRUSTED_LOCAL_ONLY"]],
  ["DUPLICATE", ["K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "NO_ACTION_IDEMPOTENT", "NONE", "TRUSTED_LOCAL_ONLY"]],
  ["FORK_EVIDENCE", ["K", "EVENT_LOCAL", "NOT_APPLIED", "QUARANTINE_LINEAGE_AND_REPLAY", "RATIFIED_LINEAGE_STATE_CHANGED", "TRUSTED_LOCAL_ONLY"]],
  ["INVALID", ["K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"]],
  ["LENGTH_MISMATCH", ["K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"]],
  ["LINEAGE_QUARANTINED", ["AP", "EVENT_LOCAL", "NOT_APPLIED", "QUARANTINE_LINEAGE_AND_REPLAY", "RATIFIED_LINEAGE_STATE_CHANGED", "TRUSTED_LOCAL_ONLY"]],
  ["OPENING_MISSING", ["K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "SUPPLY_VERIFIED_OPENING_AND_REPLAY", "VERIFIED_OPENING_PRESENT", "TRUSTED_LOCAL_ONLY"]],
  ["PENDING_ANCESTOR", ["K", "EVENT_LOCAL", "NOT_APPLIED", "RETRY_AFTER_DEPENDENCY_CHANGE", "AUTHENTICATED_DEPENDENCY_STATE_CHANGED", "TRUSTED_LOCAL_ONLY"]],
  ["PENDING_OPENING", ["K", "EVENT_LOCAL", "NOT_APPLIED", "SUPPLY_VERIFIED_OPENING_AND_REPLAY", "VERIFIED_OPENING_PRESENT", "TRUSTED_LOCAL_ONLY"]],
  ["POST_REVOCATION", ["AP", "EVENT_LOCAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"]],
  ["PROFILE_ACTIVATION_UNSUPPORTED", ["K", "S0_PROFILE_ACTIVATION", "NOT_APPLIED", "NEW_CONTEXT_OR_RATIFIED_PROFILE_REQUIRED", "NEW_CONTEXT_OR_RATIFIED_PROFILE", "TRUSTED_LOCAL_ONLY"]],
  ["REFERENCE_COLLISION_UNSUPPORTED", ["K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"]],
  ["REMOVAL_INAPPLICABLE", ["K", "EVENT_LOCAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"]],
  ["STALE_EVIDENCE", ["K", "POST_S3_REPLAY_EVIDENCE", "NOT_APPLIED", "REFRESH_LIVE_EVIDENCE_AND_REPLAY", "FRESH_LIVE_EVIDENCE_PRESENT", "TRUSTED_LOCAL_ONLY"]],
  ["STRUCTURAL_REJECTION", ["K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"]],
  ["UNRESOLVABLE_CREDENTIAL", ["K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"]],
  ["UNRESOLVED_CREDENTIAL_BINDING", ["K", "S3_KERNEL_STRUCTURAL", "NOT_APPLIED", "REJECT_SAME_BYTES", "DIFFERENT_CANDIDATE_BYTES", "TRUSTED_LOCAL_ONLY"]],
]);

const kOrder = ["STRUCTURAL_REJECTION", "LENGTH_MISMATCH", "CURRENT_OBJECT_OUT_OF_PROFILE", "COMMITMENT_MISMATCH", "OPENING_MISSING", "UNRESOLVABLE_CREDENTIAL", "UNRESOLVED_CREDENTIAL_BINDING", "CREDENTIAL_BINDING_MISMATCH", "REFERENCE_COLLISION_UNSUPPORTED", "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED", "INVALID"];
const eventOrder = ["FORK_EVIDENCE", "PENDING_OPENING", "PENDING_ANCESTOR", "REMOVAL_INAPPLICABLE", "POST_REVOCATION", "LINEAGE_QUARANTINED", "AUTHENTIC_BUT_UNAUTHORIZED"];
const fields = new Set(["id", "profile_activation_unsupported", "k_failures", "duplicate", "delivery_order", "stale_evidence", "s4_failures", "authority_projection_unavailable", "event_failures", "authorized", "s6_failures", "mutation_provable"]);

function fail(message) { throw new Error(message); }
function strings(value, name, allowed) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) fail(`${name} must be a string array`);
  if (new Set(value).size !== value.length || value.some((item) => !allowed.has(item))) fail(`${name} is outside the closed registry`);
  return value;
}
function choose(order, present) { return order.find((item) => present.has(item)); }
function outcome(primary, auxiliary) {
  const [owner, stage, mutation, recovery, retry_precondition, observability] = rows.get(primary);
  const remote = {result: primary === "APPLIED" ? "APPLIED" : "OPAQUE_REMOTE_FAILURE"};
  return {auxiliary: [...new Set(auxiliary)].sort(), mutation, observability, owner, primary, recovery, remote, retry_precondition, stage};
}

export function evaluate(scenario) {
  if (scenario === null || typeof scenario !== "object" || Array.isArray(scenario)) fail("scenario must be an object");
  const keys = Object.keys(scenario);
  if (keys.length !== fields.size || keys.some((key) => !fields.has(key))) fail("scenario fields do not match the closed grammar");
  if (typeof scenario.id !== "string" || scenario.id.length === 0) fail("scenario id must be non-empty");
  const booleans = [...fields].filter((key) => !["id", "k_failures", "delivery_order", "s4_failures", "event_failures", "s6_failures"].includes(key));
  if (booleans.some((key) => typeof scenario[key] !== "boolean")) fail("scenario flags must be booleans");
  if (!Array.isArray(scenario.delivery_order) || scenario.delivery_order.some((item) => typeof item !== "string" || item.length === 0) || new Set(scenario.delivery_order).size !== scenario.delivery_order.length) fail("delivery_order is invalid");
  if (!scenario.mutation_provable) fail("mutation disposition is not provable");
  const k = strings(scenario.k_failures, "k_failures", new Set(kOrder));
  const events = strings(scenario.event_failures, "event_failures", new Set(eventOrder));
  const resource = new Set(["CONTEXT_CAPACITY_EXHAUSTED", "DEPENDENCY_DEFERRED"]);
  const s4 = strings(scenario.s4_failures, "s4_failures", resource);
  const s6 = strings(scenario.s6_failures, "s6_failures", resource);
  const auxiliary = [...k, ...events, ...s4, ...s6];
  if (scenario.profile_activation_unsupported) return outcome("PROFILE_ACTIVATION_UNSUPPORTED", auxiliary);
  const kPrimary = choose(kOrder, new Set(k));
  if (kPrimary) return outcome(kPrimary, auxiliary);
  if (scenario.duplicate) return outcome("DUPLICATE", auxiliary);
  if (scenario.stale_evidence) return outcome("STALE_EVIDENCE", auxiliary);
  if (s4.length) return outcome(s4.includes("CONTEXT_CAPACITY_EXHAUSTED") ? "CONTEXT_CAPACITY_EXHAUSTED" : "DEPENDENCY_DEFERRED", auxiliary);
  if (scenario.authority_projection_unavailable) return outcome("AUTHORITY_PROJECTION_UNAVAILABLE", auxiliary);
  const eventPrimary = choose(eventOrder, new Set(events));
  if (eventPrimary) return outcome(eventPrimary, auxiliary);
  if (!scenario.authorized) return outcome("AUTHENTIC_BUT_UNAUTHORIZED", auxiliary);
  if (s6.length) return outcome(s6.includes("CONTEXT_CAPACITY_EXHAUSTED") ? "CONTEXT_CAPACITY_EXHAUSTED" : "DEPENDENCY_DEFERRED", auxiliary);
  return outcome("APPLIED", auxiliary);
}

function main() {
  const input = JSON.parse(fs.readFileSync(0, "utf8"));
  process.stdout.write(`${JSON.stringify(evaluate(input))}\n`);
}
if (import.meta.url === `file://${process.argv[1]}`) {
  try { main(); } catch (error) { process.stderr.write(`O-10 adapter rejected input: ${error.message}\n`); process.exitCode = 2; }
}
