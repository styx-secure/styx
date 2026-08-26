#!/usr/bin/env node
// Dependency-independent JavaScript oracle for the O-08 semantic envelope.

import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";

const ROLE_CAPABILITY = "C03_ACTIVATION_CAPABILITY_INPUT";
const ROLE_POST = "POST_C03_LAYER_PROFILE";
const ROLE_EVIDENCE = "EVIDENCE_ONLY";
const DEFERRED = new Set(["PENDING_ROOTS", "PENDING_DESCENDANTS", "HALTED_REPLAY_SPAN"]);

function recovery(dimension, stage, role) {
  if (role === ROLE_EVIDENCE) return "EVIDENCE_ONLY_NO_RUNTIME_OUTCOME";
  if (stage === "S0_PROFILE_ACTIVATION") return "PROFILE_ACTIVATION_UNSUPPORTED";
  if (DEFERRED.has(dimension)) return "DEPENDENCY_DEFERRED";
  if (stage === "S5_AUTHORITY_PROJECTION") return "AUTHORITY_PROJECTION_UNAVAILABLE";
  if (stage === "S4_GRAPH_ADMISSION" || stage === "S6_DURABLE_COMMIT") {
    return "CONTEXT_CAPACITY_EXHAUSTED";
  }
  return "CURRENT_OBJECT_OUT_OF_PROFILE";
}

function evaluate(envelope, item) {
  const observed = typeof item.observed === "string" ? BigInt(item.observed) : BigInt(item.observed);
  if (typeof item.observed !== "string" && !Number.isSafeInteger(item.observed)) throw new Error("invalid observation");
  const entry = envelope.entries[item.dimension];
  if (!entry) throw new Error("unknown dimension");
  if (item.stage !== null && !entry.stages.includes(item.stage)) throw new Error("stage mismatch");
  const stage = item.stage ?? (entry.stages.length > 0 ? entry.stages[0] : null);
  const before = createHash("sha256")
    .update(`O08|PRE|${item.dimension}|${stage ?? ""}`, "utf8").digest("hex");
  if (entry.role === ROLE_POST || entry.role === ROLE_EVIDENCE) {
    return {
      ...item, selected: null, disposition: "POST_C03_NOT_EXECUTED",
      authoritative_state_before: before, authoritative_state_after: before,
      authoritative_state_mutated: false,
    };
  }
  const selected = BigInt(entry.selected_value);
  const passed = observed < 0n ? false
    : item.dimension === "ACTIVATION_CAPABILITY_SET" ? observed === selected
    : item.dimension === "CHUNK_OCTETS" ? entry.closed_values.some((value) => observed === BigInt(value))
    : entry.role === ROLE_CAPABILITY ? observed >= selected
    : observed <= selected;
  const after = !passed ? before : createHash("sha256")
    .update(`O08|POST|${before}|${item.dimension}|${stage ?? ""}|${observed}`, "utf8").digest("hex");
  return {
    ...item,
    selected: entry.selected_value,
    disposition: passed ? "ACCEPT" : recovery(item.dimension, stage, entry.role),
    authoritative_state_before: before,
    authoritative_state_after: after,
    authoritative_state_mutated: before !== after,
  };
}

const request = JSON.parse(readFileSync(0, "utf8"));
if (request.schema !== "styx-o08-oracle-request/v1" || !Array.isArray(request.cases)) {
  throw new Error("request schema mismatch");
}
const result = {
  schema: "styx-o08-oracle-response/v1",
  results: request.cases.map((item) => evaluate(request.envelope, item)),
  verdict: "PASS",
};
process.stdout.write(JSON.stringify(result) + "\n");
