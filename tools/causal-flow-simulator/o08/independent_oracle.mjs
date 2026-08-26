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
    predicate("FRESH_REPLAY_WORK_CAPACITY", value("EVENTS_ADMITTED") + value("AUTHORITY_TRANSITIONS") * (1n + value("ORDINARY_PREFIX_QUERIES")), value("REPLAYED_EVENT_WORK")),
  ].sort((left, right) => left.observation.localeCompare(right.observation));
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

const EVENT_DOMAIN = Buffer.concat([
  Buffer.from([0x53, 0x54, 0x59, 0x58, 0x00, 0x01, 0x00, 0x03]),
  Buffer.alloc(8),
]);
const CONTROL_KINDS = new Set(["GRANT", "REVOKE", "ROTATE", "RECOVER", "POLICY", "CLOSURE"]);

function frame(value) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(value.length);
  return Buffer.concat([length, value]);
}

function eventReference(event) {
  const sequence = Buffer.alloc(8);
  sequence.writeBigUInt64BE(BigInt(event.sequence));
  const text = (value) => Buffer.from(value ?? "", "utf8");
  const hex = (value) => Buffer.from(value ?? "", "hex");
  const fields = [
    text(event.name), hex(event.context_id), text(event.actor_id),
    text(event.actor_suite), hex(event.actor_key), sequence,
    text(event.predecessor), text(event.parents.join("\0")), text(event.role),
    text(event.kind), text(event.content_class), text(event.grantee_suite),
    hex(event.grantee_key), text(event.target_id), text(event.target_reference),
  ];
  const preimage = Buffer.concat(fields.map(frame));
  return createHash("sha256").update(Buffer.concat([EVENT_DOMAIN, frame(preimage)])).digest("hex");
}

function eventDependencies(event) {
  const values = new Set(event.parents);
  if (event.predecessor !== null) values.add(event.predecessor);
  if ((event.kind === "ROTATE" || event.kind === "RECOVER") && event.target_reference !== null) {
    values.add(event.target_reference);
  }
  return values;
}

function causalAncestors(events) {
  const known = new Set(events.map((event) => event.reference));
  const result = new Map(events.map((event) => [event.reference, new Set(
    [...event.parents, event.predecessor].filter((reference) => reference !== null && known.has(reference))
  )]));
  let changed = true;
  while (changed) {
    changed = false;
    for (const [reference, values] of result) {
      const expanded = new Set(values);
      for (const dependency of values) {
        for (const ancestor of result.get(dependency) ?? []) expanded.add(ancestor);
      }
      if (expanded.has(reference)) throw new Error("cyclic causal evidence");
      if (expanded.size !== values.size) {
        result.set(reference, expanded);
        changed = true;
      }
    }
  }
  return result;
}

function isSubset(left, right) {
  return [...left].every((value) => right.has(value));
}

function validAuthorChain(event, raw, ancestors, genesisIds) {
  const canonicalParents = [...new Set(event.parents)].sort();
  if (JSON.stringify(canonicalParents) !== JSON.stringify(event.parents)) return false;
  if (event.parents.includes(event.reference) || event.parents.includes(event.predecessor)) return false;
  for (let index = 0; index < event.parents.length; index += 1) {
    for (let other = index + 1; other < event.parents.length; other += 1) {
      const left = event.parents[index];
      const right = event.parents[other];
      if (ancestors.get(right)?.has(left) || ancestors.get(left)?.has(right)) return false;
    }
  }
  if (event.predecessor !== null && event.parents.some((parent) => ancestors.get(event.predecessor)?.has(parent))) {
    return false;
  }
  if ((event.sequence === 0) !== (event.predecessor === null)) return false;
  if (event.predecessor !== null) {
    const predecessor = raw.get(event.predecessor);
    if (!predecessor || predecessor.actor_id !== event.actor_id || predecessor.sequence + 1 !== event.sequence) return false;
  }
  return genesisIds.has(event.actor_id) || ancestors.get(event.reference)?.has(event.actor_id);
}

function validControlTail(event, admitted) {
  if (event.kind === "GRANT") {
    return event.declared_subject_id === null && event.target_id === null
      && event.target_reference === null && event.grantee_suite === "0x0001"
      && typeof event.grantee_key === "string" && event.grantee_key.length > 0;
  }
  if (event.kind === "REVOKE") {
    return event.target_id !== null && event.target_reference === null
      && event.grantee_suite === null && event.grantee_key === null;
  }
  if (event.kind === "ROTATE" || event.kind === "RECOVER") {
    const replacement = admitted.get(event.target_reference ?? "");
    return event.target_id !== null && replacement?.kind === "GRANT"
      && replacement.role === "CREDENTIAL_CONTROL"
      && (replacement.reference === event.predecessor || event.parents.includes(replacement.reference))
      && event.grantee_suite === null && event.grantee_key === null;
  }
  if (event.kind === "POLICY" || event.kind === "CLOSURE") {
    return event.target_id === null && event.target_reference === null
      && event.grantee_suite === null && event.grantee_key === null;
  }
  return false;
}

function admitTrace(trace) {
  if (trace.schema !== "styx-o08-authority-trace/v1" || !Array.isArray(trace.events)
      || !Array.isArray(trace.genesis_bindings)) throw new Error("authority trace schema mismatch");
  const raw = new Map();
  for (const event of trace.events) {
    if (raw.has(event.reference)) throw new Error("duplicate event reference");
    raw.set(event.reference, event);
  }
  const ancestors = causalAncestors(trace.events);
  const bindings = new Map(trace.genesis_bindings.map((binding) => [binding.credential_id, {...binding}]));
  if (bindings.size !== trace.genesis_bindings.length) throw new Error("duplicate genesis credential");
  const genesisIds = new Set(bindings.keys());
  const admitted = new Map();
  let remaining = [...trace.events].sort((left, right) => left.reference.localeCompare(right.reference));
  let progress = true;
  while (progress && remaining.length > 0) {
    progress = false;
    for (const event of [...remaining]) {
      if (!isSubset(eventDependencies(event), new Set(admitted.keys()))) continue;
      remaining = remaining.filter((candidate) => candidate !== event);
      progress = true;
      if (event.reference !== eventReference(event) || event.context_id !== trace.context_id) continue;
      if (!validAuthorChain(event, raw, ancestors, genesisIds)) continue;
      if (genesisIds.has(event.reference)) continue;
      if (event.role === "CREDENTIAL_CONTROL" && event.content_class !== "NONE") continue;
      if ((event.role === "CREDENTIAL_CONTROL") !== CONTROL_KINDS.has(event.kind)) continue;
      if (event.malformed_tail || (event.role === "CREDENTIAL_CONTROL" && !validControlTail(event, admitted))) continue;
      const actor = bindings.get(event.actor_id);
      if (!actor || actor.suite_id !== event.actor_suite || actor.verification_key !== event.actor_key) continue;
      if (event.kind === "GRANT") {
        if (bindings.has(event.reference)) continue;
        bindings.set(event.reference, {
          credential_id: event.reference, suite_id: event.grantee_suite,
          verification_key: event.grantee_key, issuer_id: event.actor_id,
          grant_reference: event.reference, genesis: false,
        });
      }
      admitted.set(event.reference, event);
    }
  }
  return {admitted, ancestors, bindings};
}

function authorityPoset(admission) {
  const slots = new Map();
  for (const event of admission.admitted.values()) {
    const slot = `${event.actor_id}\0${event.sequence}`;
    if (!slots.has(slot)) slots.set(slot, []);
    slots.get(slot).push(event.reference);
  }
  const joins = [];
  for (const [slot, rawReferences] of [...slots.entries()].sort()) {
    const references = [...new Set(rawReferences)].sort();
    if (references.length < 2) continue;
    const split = slot.lastIndexOf("\0");
    const credentialId = slot.slice(0, split);
    const sequence = Number(slot.slice(split + 1));
    const closure = new Set(references);
    for (const reference of references) {
      for (const ancestor of admission.ancestors.get(reference) ?? []) closure.add(ancestor);
    }
    joins.push({
      reference: `fork:${credentialId}:${sequence}:${references.join(":")}`,
      credential_id: credentialId, sibling_references: references, closure,
    });
  }
  joins.sort((left, right) => left.reference.localeCompare(right.reference));
  const controls = [...admission.admitted.values()].filter((event) => event.role === "CREDENTIAL_CONTROL");
  const controlRefs = new Set(controls.map((event) => event.reference));
  const predecessors = {};
  for (const event of controls) {
    const required = new Set([...(admission.ancestors.get(event.reference) ?? [])].filter((ref) => controlRefs.has(ref)));
    for (const join of joins) {
      if (join.sibling_references.every((ref) => admission.ancestors.get(event.reference)?.has(ref))) required.add(join.reference);
    }
    predecessors[event.reference] = [...required].sort();
  }
  for (const join of joins) {
    const required = new Set([...join.closure].filter((ref) => controlRefs.has(ref)));
    for (const other of joins) {
      if (other.reference !== join.reference && other.sibling_references.every((ref) => join.closure.has(ref))) required.add(other.reference);
    }
    predecessors[join.reference] = [...required].sort();
  }
  return {controls, joins, predecessors};
}

function exactContentionBound(poset, bindings) {
  const references = Object.keys(poset.predecessors).sort();
  const index = new Map(references.map((reference, position) => [reference, position]));
  const closure = new Map(references.map((reference) => [reference, new Set(poset.predecessors[reference])]));
  let changed = true;
  while (changed) {
    changed = false;
    for (const reference of references) {
      const expanded = new Set(closure.get(reference));
      for (const predecessor of closure.get(reference)) {
        for (const ancestor of closure.get(predecessor)) expanded.add(ancestor);
      }
      if (expanded.has(reference)) throw new Error("authority poset is cyclic");
      if (expanded.size !== closure.get(reference).size) { closure.set(reference, expanded); changed = true; }
    }
  }
  function ideals(selectedReferences, selectedClosure) {
    const localIndex = new Map(selectedReferences.map((reference, position) => [reference, position]));
    const predecessorMasks = new Map(selectedReferences.map((reference) => [reference,
      [...selectedClosure.get(reference)].reduce((mask, item) => mask | (1 << localIndex.get(item)), 0)
    ]));
    const seen = new Set([0]);
    const frontier = [0];
    while (frontier.length) {
      const mask = frontier.pop();
      selectedReferences.forEach((reference, position) => {
        const bit = 1 << position;
        if ((mask & bit) || (predecessorMasks.get(reference) & ~mask)) return;
        const candidate = mask | bit;
        if (!seen.has(candidate)) { seen.add(candidate); frontier.push(candidate); }
      });
    }
    return [...seen].sort((left, right) => left - right);
  }
  const allIdeals = ideals(references, closure);
  const descendants = (root) => {
    const result = new Set([root]);
    let grew = true;
    while (grew) {
      grew = false;
      for (const [credentialId, binding] of bindings) {
        if (result.has(binding.issuer_id) && !result.has(credentialId)) { result.add(credentialId); grew = true; }
      }
    }
    return result;
  };
  const actors = [...new Set(poset.controls.map((event) => event.actor_id))].sort();
  const killers = new Map(actors.map((actor) => [actor, new Set()]));
  for (const actor of actors) {
    for (const event of poset.controls) {
      if ((event.kind === "REVOKE" || event.kind === "ROTATE") && event.target_id !== null
          && descendants(event.target_id).has(actor)) killers.get(actor).add(event.reference);
    }
    for (const join of poset.joins) {
      if (descendants(join.credential_id).has(actor)) killers.get(actor).add(join.reference);
    }
  }
  const incomparable = (left, right) => left !== right && !closure.get(right).has(left) && !closure.get(left).has(right);
  const contended = new Set(poset.controls.filter((event) =>
    [...killers.get(event.actor_id)].some((killer) => incomparable(event.reference, killer))
  ).map((event) => event.reference));
  const contendedActors = [...new Set(poset.controls.filter((event) => contended.has(event.reference)).map((event) => event.actor_id))].sort();
  const actorMasks = new Map(contendedActors.map((actor) => [actor, poset.controls
    .filter((event) => event.actor_id === actor)
    .reduce((mask, event) => mask | (1 << index.get(event.reference)), 0)]));
  const contendedMasks = new Map(contendedActors.map((actor) => [actor, poset.controls
    .filter((event) => event.actor_id === actor && contended.has(event.reference))
    .reduce((mask, event) => mask | (1 << index.get(event.reference)), 0)]));
  const cache = new Map();
  function inducedIdealCount(mask) {
    if (cache.has(mask)) return cache.get(mask);
    const selected = references.filter((_, position) => mask & (1 << position));
    const selectedSet = new Set(selected);
    const induced = new Map(selected.map((reference) => [reference,
      new Set([...closure.get(reference)].filter((item) => selectedSet.has(item)))
    ]));
    const count = ideals(selected, induced).length;
    cache.set(mask, count);
    return count;
  }
  let value = 0;
  for (const ideal of allIdeals) {
    let factor = 1;
    for (const actor of contendedActors) {
      const actorMask = ideal & actorMasks.get(actor);
      const contendedCount = (ideal & contendedMasks.get(actor)).toString(2).replaceAll("0", "").length;
      factor *= Math.min(2 ** contendedCount, inducedIdealCount(actorMask));
    }
    value += factor;
  }
  if (!Number.isSafeInteger(value)) throw new Error("B4 exceeds exact JavaScript integer domain");
  const width = maximumAntichainWidth(poset.predecessors);
  const vertices = poset.controls.length + poset.joins.length;
  const choose = (n, k) => { let result = 1; for (let i = 1; i <= k; i += 1) result = result * (n - k + i) / i; return result; };
  const staticBound = [...Array(Math.min(width, vertices) + 1).keys()].reduce((sum, rank) => sum + choose(vertices, rank), 0) * (2 ** poset.controls.length);
  return {
    authority_contention_bound: value,
    authority_ideal_count: allIdeals.length,
    contended_actors: contendedActors,
    contended_controls: [...contended].sort(),
    exact_width: width,
    static_trace_bound: staticBound,
  };
}

function evaluateAuthorityTrace(item) {
  const admission = admitTrace(item.trace);
  const poset = authorityPoset(admission);
  const bound = exactContentionBound(poset, admission.bindings);
  const proof = bound.exact_width <= item.limits.authority_width
    && bound.authority_contention_bound <= item.limits.authority_states
    && bound.exact_width * bound.authority_contention_bound <= item.limits.authority_transitions;
  return {
    witness_id: item.witness_id,
    admitted_references: [...admission.admitted.keys()].sort(),
    ...bound,
    fork_joins: poset.joins.length,
    proof_region: proof ? "PROVED" : "GREY_OR_OUTSIDE",
  };
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
  authority_traces: (request.authority_traces ?? []).map(evaluateAuthorityTrace),
  verdict: "PASS",
};
process.stdout.write(JSON.stringify(result) + "\n");
