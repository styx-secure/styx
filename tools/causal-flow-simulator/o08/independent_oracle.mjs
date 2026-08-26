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

function couplingResults(envelope) {
  const value = (dimension) => BigInt(envelope.entries[dimension].selected_value);
  const predicate = (observation, lhs, rhs) => ({
    observation, lhs: Number(lhs), operator: "<=", rhs: Number(rhs), passed: lhs <= rhs,
  });
  return [
    predicate("AUTHORITY_WIDTH_STRUCTURAL_CAPACITY", value("AUTHORITY_CONCURRENT_CONTROLS"), value("CREDENTIALS") + value("FORK_SLOTS")),
    predicate("AUTHORITY_TRANSITION_CAPACITY", value("AUTHORITY_TRANSITIONS"), value("AUTHORITY_STATES") * value("AUTHORITY_CONCURRENT_CONTROLS")),
    predicate("DIRECT_EDGE_REPLAY_WORK", value("ANCESTRY_RELATIONS"), value("REPLAYED_EVENT_WORK")),
    predicate("EVENT_SIGNATURE_WORK", value("EVENTS_ADMITTED") * value("SIGNATURE_ATTEMPTS"), value("REPLAYED_EVENT_WORK")),
    predicate("FRESH_REPLAY_WORK_CAPACITY", value("AUTHORITY_TRANSITIONS") * (1n + value("ORDINARY_PREFIX_QUERIES")), value("REPLAYED_EVENT_WORK")),
  ];
}

function maximumAntichainWidth(predecessorObject) {
  const vertices = Object.keys(predecessorObject).sort();
  const known = new Set(vertices);
  const closure = new Map();
  for (const vertex of vertices) {
    const required = predecessorObject[vertex];
    if (!Array.isArray(required) || required.some((item) => !known.has(item))) {
      throw new Error("authority poset references an unknown predecessor");
    }
    closure.set(vertex, new Set(required));
  }
  let changed = true;
  while (changed) {
    changed = false;
    for (const vertex of vertices) {
      const expanded = new Set(closure.get(vertex));
      for (const predecessor of closure.get(vertex)) {
        for (const ancestor of closure.get(predecessor)) expanded.add(ancestor);
      }
      if (expanded.has(vertex)) throw new Error("authority poset is cyclic");
      if (expanded.size !== closure.get(vertex).size) {
        closure.set(vertex, expanded);
        changed = true;
      }
    }
  }
  const matchedRight = new Map();
  function augment(left, seen) {
    for (const right of vertices.filter((vertex) => closure.get(vertex).has(left))) {
      if (seen.has(right)) continue;
      seen.add(right);
      if (!matchedRight.has(right) || augment(matchedRight.get(right), seen)) {
        matchedRight.set(right, left);
        return true;
      }
    }
    return false;
  }
  let matching = 0;
  for (const vertex of vertices) if (augment(vertex, new Set())) matching += 1;
  return vertices.length - matching;
}

const request = JSON.parse(readFileSync(0, "utf8"));
if (request.schema !== "styx-o08-oracle-request/v1" || !Array.isArray(request.cases)) {
  throw new Error("request schema mismatch");
}
const result = {
  schema: "styx-o08-oracle-response/v1",
  results: request.cases.map((item) => evaluate(request.envelope, item)),
  couplings: request.include_couplings ? couplingResults(request.envelope) : [],
  poset_widths: (request.posets ?? []).map((item) => ({
    witness_id: item.witness_id,
    exact_width: maximumAntichainWidth(item.predecessors),
  })),
  verdict: "PASS",
};
process.stdout.write(JSON.stringify(result) + "\n");
