#!/usr/bin/env node
/* Independent APP-CORE-IFACE-0 JavaScript evidence adapter.
 *
 * This increment implements the ACV-066 reserved-reachability oracle and the
 * independent V9 fork/join-label preimage.  It deliberately does not yet claim
 * to implement the complete interface evaluator.
 */

import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";
import process from "node:process";


class AdapterFailure extends Error {}


const FORK_JOIN_DOMAIN = Buffer.from("STYX-APP-CORE-IFACE-0-FORK-JOIN-V0\0", "ascii");


function requireCondition(condition, message) {
  if (!condition) throw new AdapterFailure(message);
}


function readJson(filePath) {
  const stat = fs.lstatSync(filePath);
  requireCondition(stat.isFile() && !stat.isSymbolicLink(), `invalid JSON authority: ${filePath}`);
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}


function fixedHex32(value, label) {
  requireCondition(typeof value === "string" && /^[0-9a-f]{64}$/.test(value), `${label} is not FixedHex32`);
  return Buffer.from(value, "hex");
}


function canonicalU64(value, label) {
  requireCondition(typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value), `${label} is not canonical U64 text`);
  const result = BigInt(value);
  requireCondition(result <= 0xffffffffffffffffn, `${label} exceeds u64`);
  return result;
}


function u64be(value) {
  const result = Buffer.alloc(8);
  result.writeBigUInt64BE(value);
  return result;
}


function u32be(value) {
  requireCondition(Number.isInteger(value) && value >= 0 && value <= 0xffffffff, "value exceeds u32");
  const result = Buffer.alloc(4);
  result.writeUInt32BE(value);
  return result;
}


function deriveForkJoinLabel(value, schema) {
  exactKeys(value, ["credentialIdentifierHex", "authorSequence", "siblingReferences"], "fork/join input");
  const credential = fixedHex32(value.credentialIdentifierHex, "credentialIdentifierHex");
  const sequence = canonicalU64(value.authorSequence, "authorSequence");
  requireCondition(Array.isArray(value.siblingReferences), "siblingReferences is not an array");
  const siblingSchema = schema.$defs?.ForkJoinProjectionV0?.properties?.siblingReferences;
  const minimum = siblingSchema?.minItems;
  const maximum = siblingSchema?.maxItems;
  requireCondition(Number.isInteger(minimum) && Number.isInteger(maximum), "fork sibling bounds are not literal");
  requireCondition(
    value.siblingReferences.length >= minimum && value.siblingReferences.length <= maximum,
    "fork sibling count is outside the ratified bounds",
  );
  const siblings = value.siblingReferences.map((item, index) => ({
    hex: item,
    octets: fixedHex32(item, `siblingReferences[${index}]`),
  }));
  const sorted = [...siblings].sort((left, right) => Buffer.compare(left.octets, right.octets));
  requireCondition(
    JSON.stringify(siblings.map((item) => item.hex)) === JSON.stringify(sorted.map((item) => item.hex)),
    "siblingReferences is not bytewise canonical",
  );
  requireCondition(new Set(siblings.map((item) => item.hex)).size === siblings.length, "siblingReferences contains a duplicate");
  const preimage = Buffer.concat([
    FORK_JOIN_DOMAIN,
    credential,
    u64be(sequence),
    u32be(siblings.length),
    ...siblings.map((item) => item.octets),
  ]);
  return crypto.createHash("sha256").update(preimage).digest("hex");
}


const AUTHORITY_CONTROLS = new Set(["GRANT", "RECOVER", "POLICY", "CLOSURE", "REVOKE", "ROTATE"]);
const AUTHORITY_REDUCTIONS = new Set(["REVOKE", "ROTATE"]);


function sortedSet(value) {
  return [...value].sort();
}


function isSubset(left, right) {
  for (const item of left) if (!right.has(item)) return false;
  return true;
}


function stateKey(state) {
  return JSON.stringify([
    sortedSet(state.processed),
    sortedSet(state.authority),
    sortedSet(state.revoked),
    sortedSet(state.forked),
  ]);
}


function lineageDescendants(lineage, roots) {
  const result = new Set(roots);
  let changed = true;
  while (changed) {
    changed = false;
    for (const [credential, parent] of lineage.entries()) {
      if (parent !== null && result.has(parent) && !result.has(credential)) {
        result.add(credential);
        changed = true;
      }
    }
  }
  return result;
}


function authorityMetrics(value) {
  exactKeys(value, ["events", "forks", "lineage", "rootCredential", "stateLimit", "transitionLimit"], "authority input");
  fixedHex32(value.rootCredential, "rootCredential");
  requireCondition(Array.isArray(value.events), "authority events is not an array");
  requireCondition(Array.isArray(value.lineage), "authority lineage is not an array");
  requireCondition(Array.isArray(value.forks), "authority forks is not an array");
  requireCondition(Number.isInteger(value.stateLimit) && value.stateLimit >= 1, "invalid authority state limit");
  requireCondition(Number.isInteger(value.transitionLimit) && value.transitionLimit >= 1, "invalid authority transition limit");

  const lineage = new Map();
  for (const row of value.lineage) {
    exactKeys(row, ["credential", "parent"], "lineage row");
    fixedHex32(row.credential, "lineage credential");
    if (row.parent !== null) fixedHex32(row.parent, "lineage parent");
    requireCondition(!lineage.has(row.credential), "duplicate lineage credential");
    lineage.set(row.credential, row.parent);
  }
  requireCondition(lineage.get(value.rootCredential) === null, "root lineage is absent");

  const events = value.events.map((row, index) => {
    exactKeys(row, ["reference", "actor", "sequence", "kind", "dependencies", "ancestors", "targetCredential"], `authority event ${index}`);
    fixedHex32(row.reference, "event reference");
    fixedHex32(row.actor, "event actor");
    requireCondition(Number.isSafeInteger(row.sequence) && row.sequence >= 0, "invalid event sequence");
    requireCondition(typeof row.kind === "string", "invalid event kind");
    requireCondition(Array.isArray(row.dependencies) && Array.isArray(row.ancestors), "invalid event dependency set");
    row.dependencies.forEach((item) => fixedHex32(item, "event dependency"));
    row.ancestors.forEach((item) => fixedHex32(item, "event ancestor"));
    if (row.targetCredential !== null) fixedHex32(row.targetCredential, "event target credential");
    return {
      ...row,
      dependencies: new Set(row.dependencies),
      ancestors: new Set(row.ancestors),
    };
  });
  requireCondition(new Set(events.map((row) => row.reference)).size === events.length, "duplicate authority event reference");
  const eventByReference = new Map(events.map((row) => [row.reference, row]));
  const controls = events.filter((row) => AUTHORITY_CONTROLS.has(row.kind));
  const controlReferences = new Set(controls.map((row) => row.reference));

  const forkItems = value.forks.map((row, index) => {
    exactKeys(row, ["credential", "sequence", "siblings"], `fork row ${index}`);
    fixedHex32(row.credential, "fork credential");
    requireCondition(Number.isSafeInteger(row.sequence) && row.sequence >= 0, "invalid fork sequence");
    requireCondition(Array.isArray(row.siblings) && row.siblings.length >= 2, "invalid fork siblings");
    row.siblings.forEach((item) => requireCondition(eventByReference.has(item), "fork sibling is not an event"));
    const siblings = [...row.siblings].sort();
    requireCondition(JSON.stringify(siblings) === JSON.stringify(row.siblings), "fork siblings are noncanonical");
    const closure = new Set(siblings);
    for (const reference of siblings) {
      for (const ancestor of eventByReference.get(reference).ancestors) closure.add(ancestor);
    }
    return {
      internalId: `@fork/${index}/${row.credential}/${row.sequence}`,
      credential: row.credential,
      sequence: row.sequence,
      siblings,
      closure,
    };
  });

  const items = new Map(controls.map((row) => [row.reference, { type: "event", value: row }]));
  for (const row of forkItems) items.set(row.internalId, { type: "fork", value: row });
  const predecessors = new Map();
  for (const event of controls) {
    const required = new Set([...event.ancestors].filter((item) => controlReferences.has(item)));
    for (const fork of forkItems) if (fork.siblings.every((item) => event.ancestors.has(item))) required.add(fork.internalId);
    predecessors.set(event.reference, required);
  }
  for (const fork of forkItems) {
    const required = new Set([...fork.closure].filter((item) => controlReferences.has(item)));
    for (const other of forkItems) {
      if (other !== fork && other.siblings.every((item) => fork.closure.has(item))) required.add(other.internalId);
    }
    predecessors.set(fork.internalId, required);
  }

  function advance(state, item) {
    const processed = new Set(state.processed);
    const authority = new Set(state.authority);
    const revoked = new Set(state.revoked);
    const forked = new Set(state.forked);
    if (item.type === "fork") {
      processed.add(item.value.internalId);
      forked.add(item.value.credential);
      for (const credential of lineageDescendants(lineage, new Set([item.value.credential]))) authority.delete(credential);
    } else {
      const event = item.value;
      processed.add(event.reference);
      const terminated = lineageDescendants(lineage, new Set([...revoked, ...forked]));
      const authorized = authority.has(event.actor) && !terminated.has(event.actor);
      if (authorized && event.kind === "GRANT") authority.add(event.reference);
      else if (authorized && AUTHORITY_REDUCTIONS.has(event.kind) && event.targetCredential !== null) {
        revoked.add(event.targetCredential);
        for (const credential of lineageDescendants(lineage, new Set([event.targetCredential]))) authority.delete(credential);
      }
    }
    return { processed, authority, revoked, forked };
  }

  const initial = {
    processed: new Set(),
    authority: new Set([value.rootCredential]),
    revoked: new Set(),
    forked: new Set(),
  };
  let frontier = new Map([[stateKey(initial), initial]]);
  const reachable = new Map(frontier);
  let transitions = 0;
  let maxConcurrent = 0;
  for (let depth = 0; depth < items.size; depth += 1) {
    const following = new Map();
    for (const state of frontier.values()) {
      const ready = [...items.keys()].filter((reference) => (
        !state.processed.has(reference) && isSubset(predecessors.get(reference), state.processed)
      )).sort();
      maxConcurrent = Math.max(maxConcurrent, ready.length);
      for (const reference of ready) {
        transitions += 1;
        if (transitions > value.transitionLimit) {
          return { kind: "UNAVAILABLE", reason: "AUTHORITY_TRANSITIONS" };
        }
        const successor = advance(state, items.get(reference));
        following.set(stateKey(successor), successor);
      }
    }
    requireCondition(following.size > 0, "authority item graph is cyclic");
    for (const [key, state] of following.entries()) reachable.set(key, state);
    if (reachable.size > value.stateLimit) {
      return { kind: "UNAVAILABLE", reason: "AUTHORITY_STATES" };
    }
    frontier = following;
  }
  for (const state of frontier.values()) requireCondition(state.processed.size === items.size, "authority fold ended incompletely");

  const prefixCounts = new Map([...reachable.keys()].map((key) => [key, 0]));
  for (const event of events) {
    if (controlReferences.has(event.reference)) continue;
    const requiredBefore = new Set([...event.ancestors].filter((item) => controlReferences.has(item)));
    const requiredAfter = new Set(controls.filter((item) => item.ancestors.has(event.reference)).map((item) => item.reference));
    for (const fork of forkItems) {
      if (fork.siblings.every((item) => event.ancestors.has(item))) requiredBefore.add(fork.internalId);
      if (fork.closure.has(event.reference)) requiredAfter.add(fork.internalId);
    }
    let found = false;
    for (const [key, state] of reachable.entries()) {
      if (!isSubset(requiredBefore, state.processed)) continue;
      if ([...requiredAfter].some((item) => state.processed.has(item))) continue;
      prefixCounts.set(key, prefixCounts.get(key) + 1);
      found = true;
    }
    requireCondition(found, "ordinary acting prefix is unreachable");
  }
  const prefixTotal = [...prefixCounts.values()].reduce((left, right) => left + right, 0);
  return {
    kind: "AVAILABLE",
    maxConcurrentControls: maxConcurrent,
    ordinaryPrefixQueryMax: Math.max(0, ...prefixCounts.values()),
    reachableStateCount: reachable.size,
    replayedEventWork: events.length + transitions + prefixTotal,
    transitionCount: transitions,
  };
}


function graphProjection(value) {
  exactKeys(value, ["events", "unverifiedRequiredReferences"], "graph input");
  requireCondition(Array.isArray(value.events), "graph events is not an array");
  requireCondition(Array.isArray(value.unverifiedRequiredReferences), "pending set is not an array");
  const events = value.events.map((row, index) => {
    exactKeys(row, ["reference", "credential", "sequence", "dependencies"], `graph event ${index}`);
    fixedHex32(row.reference, "graph event reference");
    fixedHex32(row.credential, "graph event credential");
    requireCondition(Number.isSafeInteger(row.sequence) && row.sequence >= 0, "invalid graph sequence");
    requireCondition(Array.isArray(row.dependencies), "graph dependencies is not an array");
    row.dependencies.forEach((item) => fixedHex32(item, "graph dependency"));
    requireCondition(
      JSON.stringify(row.dependencies) === JSON.stringify([...row.dependencies].sort()),
      "graph dependencies are noncanonical",
    );
    return { ...row, dependencies: new Set(row.dependencies) };
  });
  const byReference = new Map(events.map((row) => [row.reference, row]));
  requireCondition(byReference.size === events.length, "duplicate graph event reference");
  for (const event of events) {
    for (const dependency of event.dependencies) requireCondition(byReference.has(dependency), "graph dependency is absent");
  }
  value.unverifiedRequiredReferences.forEach((item) => requireCondition(byReference.has(item), "pending reference is absent"));
  requireCondition(
    JSON.stringify(value.unverifiedRequiredReferences) === JSON.stringify([...value.unverifiedRequiredReferences].sort()),
    "pending set is noncanonical",
  );

  const emitted = new Set();
  const order = [];
  while (order.length < events.length) {
    const ready = events
      .filter((row) => !emitted.has(row.reference) && isSubset(row.dependencies, emitted))
      .map((row) => row.reference)
      .sort();
    requireCondition(ready.length > 0, "graph is cyclic");
    emitted.add(ready[0]);
    order.push(ready[0]);
  }

  const ancestors = new Map(events.map((row) => [row.reference, new Set()]));
  for (const reference of order) {
    const result = ancestors.get(reference);
    for (const dependency of byReference.get(reference).dependencies) {
      result.add(dependency);
      for (const ancestor of ancestors.get(dependency)) result.add(ancestor);
    }
  }
  const unverified = new Set(value.unverifiedRequiredReferences);
  const pendingRoots = [...unverified]
    .filter((reference) => ![...ancestors.get(reference)].some((item) => unverified.has(item)))
    .sort();
  const rootSet = new Set(pendingRoots);
  const pendingReferences = events
    .filter((row) => !rootSet.has(row.reference) && [...ancestors.get(row.reference)].some((item) => rootSet.has(item)))
    .map((row) => row.reference)
    .sort();

  const slots = new Map();
  for (const event of events) {
    const key = `${event.credential}/${event.sequence}`;
    if (!slots.has(key)) slots.set(key, []);
    slots.get(key).push(event.reference);
  }
  const forks = [...slots.entries()]
    .filter(([, siblings]) => new Set(siblings).size >= 2)
    .map(([key, siblings]) => {
      const separator = key.lastIndexOf("/");
      return {
        credential: key.slice(0, separator),
        sequence: Number(key.slice(separator + 1)),
        siblings: [...new Set(siblings)].sort(),
      };
    })
    .sort((left, right) => (
      left.credential.localeCompare(right.credential) || left.sequence - right.sequence
    ));
  return {
    ancestors: order.map((reference) => ({
      reference,
      ancestors: sortedSet(ancestors.get(reference)),
    })),
    forks,
    pendingReferences,
    pendingRootReferences: pendingRoots,
    protocolKOrder: order,
  };
}


function credentialProjection(value) {
  exactKeys(value, ["root", "grants"], "credential input");
  exactKeys(
    value.root,
    ["credentialIdentifierHex", "signatureSuiteId", "verificationKeyHex"],
    "root binding",
  );
  fixedHex32(value.root.credentialIdentifierHex, "root credential");
  requireCondition(value.root.signatureSuiteId === "1", "unsupported root suite");
  fixedHex32(value.root.verificationKeyHex, "root verification key");
  requireCondition(Array.isArray(value.grants), "grants is not an array");
  const grants = new Map();
  for (const row of value.grants) {
    exactKeys(row, ["reference", "issuerCredentialIdentifierHex", "verificationKeyHex"], "grant binding");
    fixedHex32(row.reference, "grant reference");
    fixedHex32(row.issuerCredentialIdentifierHex, "grant issuer");
    fixedHex32(row.verificationKeyHex, "grant verification key");
    requireCondition(!grants.has(row.reference), "duplicate grant reference");
    grants.set(row.reference, row);
  }
  const root = value.root.credentialIdentifierHex;
  const bindings = new Map([[root, {
    credentialIdentifierHex: root,
    origin: "GENESIS",
    signatureSuiteId: "1",
    verificationKeyHex: value.root.verificationKeyHex,
  }]]);
  const lineage = new Map([[root, null]]);
  while (grants.size > 0) {
    const ready = [...grants.keys()]
      .filter((reference) => bindings.has(grants.get(reference).issuerCredentialIdentifierHex))
      .sort();
    requireCondition(ready.length > 0, "grant has no issuer binding");
    for (const reference of ready) {
      requireCondition(!bindings.has(reference), "credential identifier collision");
      const row = grants.get(reference);
      grants.delete(reference);
      bindings.set(reference, {
        credentialIdentifierHex: reference,
        grantReferenceHex: reference,
        issuerCredentialIdentifierHex: row.issuerCredentialIdentifierHex,
        origin: "GRANT",
        signatureSuiteId: "1",
        verificationKeyHex: row.verificationKeyHex,
      });
      lineage.set(reference, row.issuerCredentialIdentifierHex);
    }
  }
  for (const credential of bindings.keys()) {
    const seen = new Set();
    let cursor = credential;
    while (lineage.get(cursor) !== null) {
      requireCondition(!seen.has(cursor), "credential lineage is cyclic");
      seen.add(cursor);
      cursor = lineage.get(cursor);
      requireCondition(lineage.has(cursor), "credential lineage issuer is absent");
    }
  }
  const aliases = new Map();
  for (const [credential, binding] of bindings.entries()) {
    const key = `${binding.signatureSuiteId}/${binding.verificationKeyHex}`;
    if (!aliases.has(key)) aliases.set(key, []);
    aliases.get(key).push(credential);
  }
  return {
    aliasGroups: [...aliases.values()]
      .filter((group) => group.length >= 2)
      .map((group) => group.sort())
      .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))),
    credentialBindings: [...bindings.values()].sort((left, right) => (
      left.credentialIdentifierHex.localeCompare(right.credentialIdentifierHex)
    )),
  };
}


function exactKeys(value, expected, label) {
  requireCondition(value !== null && typeof value === "object" && !Array.isArray(value), `${label} is not an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  requireCondition(JSON.stringify(actual) === JSON.stringify(wanted), `${label} shape mismatch`);
}


function validateProfile(profile) {
  exactKeys(profile, ["applicationProfileId", "applicationProfileVersion", "styxProtocolVersion"], "profile");
  requireCondition(profile.applicationProfileId === "1", "profile id mismatch");
  requireCondition(profile.applicationProfileVersion === "1", "profile version mismatch");
  requireCondition(profile.styxProtocolVersion === "1", "Styx version mismatch");
}


const OBSERVATION_ENUMS = Object.freeze({
  transcriptVerification: ["VALID", "REJECTED"],
  referenceVerification: ["VALID", "REJECTED", "NOT_REACHED"],
  signatureVerification: ["VALID", "REJECTED", "NOT_EVALUATED"],
  suppliedLengthVerification: ["VALID", "REJECTED", "NOT_EVALUATED", "NOT_APPLICABLE"],
  commitmentVerification: ["VALID", "REJECTED", "PENDING", "NOT_PRESENT", "NOT_EVALUATED"],
  commitmentMatchVerification: ["VALID", "REJECTED", "NOT_EVALUATED", "NOT_APPLICABLE"],
  geometryPredicate1: ["PASS", "FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"],
  geometryPredicate2: ["PASS", "FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"],
  geometryPredicate3: ["PASS", "FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"],
  geometryPredicate4: ["PASS", "FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"],
  geometryPredicate5: ["PASS", "FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"],
  geometryPredicate6: ["PASS", "FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"],
  geometryPredicate7: ["PASS", "FAIL", "NOT_EVALUATED", "NOT_APPLICABLE"],
});


function validateObservations(observations) {
  exactKeys(observations, Object.keys(OBSERVATION_ENUMS), "transcript observations");
  for (const [name, allowed] of Object.entries(OBSERVATION_ENUMS)) {
    requireCondition(allowed.includes(observations[name]), `invalid transcript observation: ${name}`);
  }
}


function validateResponseShapeAndRelation(response, relations) {
  exactKeys(response, ["interfaceVersion", "operation", "profile", "result"], "response");
  requireCondition(response.interfaceVersion === "0", "interface version mismatch");
  validateProfile(response.profile);
  const result = response.result;
  if (response.operation === "VALIDATE_TRANSCRIPT") {
    exactKeys(result, ["kind", "reason", "stage", "observations"], "transcript result");
    validateObservations(result.observations);
  } else if (response.operation === "EVALUATE_GENESIS") {
    exactKeys(result, ["kind", "reason", "stage"], "genesis result");
  } else if (response.operation === "EVALUATE_CANDIDATE") {
    exactKeys(result, ["evaluation"], "candidate result");
    const evaluation = result.evaluation;
    const primary = evaluation.primary ?? evaluation.primaryOnCommit;
    const row = relations.candidateEvaluationPrimaryRelationV0.find((item) => item.primary === primary);
    requireCondition(row !== undefined, "candidate primary is absent from F13");
    requireCondition(evaluation.kind === row.coreResultKind, "candidate result kind violates F13");
    if (evaluation.kind === "TERMINAL_NO_SUCCESSOR") {
      exactKeys(evaluation, ["kind", "primary", "stage"], "candidate terminal");
      requireCondition(evaluation.stage === row.existingO10Stage, "candidate stage violates F13");
    } else {
      exactKeys(evaluation, ["kind", "primaryOnCommit", "proposal"], "candidate proposal");
      exactKeys(evaluation.proposal, ["successor"], "candidate proposal body");
    }
    return;
  } else {
    throw new AdapterFailure("ACV-066 self-test received an unsupported operation");
  }
  const relationName = response.operation === "VALIDATE_TRANSCRIPT"
    ? "transcriptReasonStageRelationV0"
    : "genesisReasonStageRelationV0";
  const member = relations[relationName].some((row) => (
    row.kind === result.kind
      && (row.reason ?? null) === (result.reason ?? null)
      && row.stage === result.stage
  ));
  requireCondition(member, "response violates exact reason/stage relation");
}


function validateBeforeRelease(response, relations, reservedDetector = true) {
  validateResponseShapeAndRelation(response, relations);
  if (reservedDetector && response.operation === "EVALUATE_CANDIDATE") {
    const evaluation = response.result.evaluation;
    const primary = evaluation.primary ?? evaluation.primaryOnCommit;
    const row = relations.candidateEvaluationPrimaryRelationV0.find((item) => item.primary === primary);
    if (row?.reachability === "RESERVED_UNREACHABLE_V0") {
      throw new AdapterFailure("APP-core v0 reserved F13 row was generated");
    }
  }
  const observed = JSON.stringify([
    response.operation,
    response.result.kind,
    response.result.reason ?? null,
    response.result.stage,
  ]);
  const reserved = new Set(
    relations.terminalPredicateRelationV0
      .filter((row) => row.result.reachability === "RESERVED_UNREACHABLE_V0")
      .map((row) => JSON.stringify([
        row.operation,
        row.result.kind,
        row.result.reason ?? null,
        row.result.stage,
      ])),
  );
  if (reservedDetector && (
    reserved.has(observed)
      || response.result.observations?.referenceVerification === "REJECTED"
  )) {
    throw new AdapterFailure("APP-core v0 reserved terminal predicate was generated");
  }
  return response;
}


function referenceObservations() {
  return {
    commitmentMatchVerification: "NOT_APPLICABLE",
    commitmentVerification: "NOT_PRESENT",
    geometryPredicate1: "NOT_APPLICABLE",
    geometryPredicate2: "NOT_APPLICABLE",
    geometryPredicate3: "NOT_APPLICABLE",
    geometryPredicate4: "NOT_APPLICABLE",
    geometryPredicate5: "NOT_APPLICABLE",
    geometryPredicate6: "NOT_APPLICABLE",
    geometryPredicate7: "NOT_APPLICABLE",
    referenceVerification: "REJECTED",
    signatureVerification: "NOT_EVALUATED",
    suppliedLengthVerification: "NOT_APPLICABLE",
    transcriptVerification: "VALID",
  };
}


function containsPropertyName(node, propertyName) {
  if (Array.isArray(node)) return node.some((item) => containsPropertyName(item, propertyName));
  if (node === null || typeof node !== "object") return false;
  if (Object.prototype.hasOwnProperty.call(node.properties ?? {}, propertyName)) return true;
  return Object.values(node).some((item) => containsPropertyName(item, propertyName));
}


function selfTestAcv066(contractPath) {
  const schema = readJson(path.join(contractPath, "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json"));
  const relations = readJson(path.join(contractPath, "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json"));
  const reserved = relations.terminalPredicateRelationV0
    .filter((row) => row.result.reachability === "RESERVED_UNREACHABLE_V0");
  requireCondition(
    JSON.stringify(reserved.map((row) => row.relationRowId).sort())
      === JSON.stringify(["GRS-009", "GRS-010", "GRS-011", "GRS-015", "GRS-016", "TRS-011"]),
    "reserved relation closure drift",
  );
  for (const name of ["ValidateTranscriptInputV0", "EvaluateGenesisInputV0"]) {
    requireCondition(!containsPropertyName(schema.$defs[name], "expectedReferenceHex"), `${name} selects an expected reference`);
  }

  const profile = {
    applicationProfileId: "1",
    applicationProfileVersion: "1",
    styxProtocolVersion: "1",
  };
  const reservedFixtures = reserved.map((row) => ({
    interfaceVersion: "0",
    operation: row.operation,
    profile,
    result: {
      kind: row.result.kind,
      reason: row.result.reason,
      stage: row.result.stage,
      ...(row.operation === "VALIDATE_TRANSCRIPT"
        ? { observations: referenceObservations() }
        : {}),
    },
  }));
  const observationReserved = {
    interfaceVersion: "0",
    operation: "VALIDATE_TRANSCRIPT",
    profile,
    result: {
      kind: "REJECTED",
      reason: "SIGNATURE_LENGTH_MISMATCH",
      stage: "SIGNATURE_VERIFICATION",
      observations: referenceObservations(),
    },
  };
  const fixtures = [...reservedFixtures, observationReserved];
  for (const fixture of fixtures) {
    validateResponseShapeAndRelation(fixture, relations);
    validateBeforeRelease(fixture, relations, false);
    let rejected = false;
    try {
      validateBeforeRelease(fixture, relations, true);
    } catch (error) {
      requireCondition(error instanceof AdapterFailure, "unexpected ACV-066 rejection");
      rejected = true;
    }
    requireCondition(rejected, "ACV-066 detector admitted a reserved response");
  }
  return {
    mutantAccepted: fixtures.length,
    normalRejected: fixtures.length,
    relationAccepted: fixtures.length,
    verdict: "PASS",
  };
}


function parseArguments(argv) {
  let selfTest = false;
  let deriveForkJoin = false;
  let authorityMetricsMode = false;
  let graphProjectionMode = false;
  let credentialProjectionMode = false;
  let validateResponseMode = false;
  let contractPath = null;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--self-test-acv066") selfTest = true;
    else if (argv[index] === "--derive-fork-join") deriveForkJoin = true;
    else if (argv[index] === "--authority-metrics") authorityMetricsMode = true;
    else if (argv[index] === "--graph-projection") graphProjectionMode = true;
    else if (argv[index] === "--credential-projection") credentialProjectionMode = true;
    else if (argv[index] === "--validate-response") validateResponseMode = true;
    else if (argv[index] === "--contract") contractPath = argv[++index];
    else throw new AdapterFailure(`unknown argument: ${argv[index]}`);
  }
  requireCondition(
    Number(selfTest) + Number(deriveForkJoin) + Number(authorityMetricsMode)
      + Number(graphProjectionMode) + Number(credentialProjectionMode)
      + Number(validateResponseMode) === 1,
    "exactly one adapter mode is required",
  );
  requireCondition(contractPath, "--contract is required");
  return {
    authorityMetricsMode, contractPath, credentialProjectionMode, deriveForkJoin,
    graphProjectionMode, selfTest, validateResponseMode,
  };
}


try {
  const {
    authorityMetricsMode, contractPath, credentialProjectionMode, deriveForkJoin,
    graphProjectionMode, selfTest, validateResponseMode,
  } = parseArguments(process.argv.slice(2));
  const resolvedContract = path.resolve(contractPath);
  if (selfTest) {
    process.stdout.write(`${JSON.stringify(selfTestAcv066(resolvedContract))}\n`);
  } else if (deriveForkJoin) {
    const schema = readJson(path.join(resolvedContract, "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json"));
    const input = JSON.parse(fs.readFileSync(0, "utf8"));
    process.stdout.write(`${JSON.stringify({ joinLabelHex: deriveForkJoinLabel(input, schema) })}\n`);
  } else if (authorityMetricsMode) {
    const input = JSON.parse(fs.readFileSync(0, "utf8"));
    process.stdout.write(`${JSON.stringify(authorityMetrics(input))}\n`);
  } else if (graphProjectionMode) {
    const input = JSON.parse(fs.readFileSync(0, "utf8"));
    process.stdout.write(`${JSON.stringify(graphProjection(input))}\n`);
  } else if (credentialProjectionMode) {
    const input = JSON.parse(fs.readFileSync(0, "utf8"));
    process.stdout.write(`${JSON.stringify(credentialProjection(input))}\n`);
  } else if (validateResponseMode) {
    const relations = readJson(path.join(resolvedContract, "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json"));
    const input = JSON.parse(fs.readFileSync(0, "utf8"));
    validateBeforeRelease(input, relations);
    process.stdout.write(`${JSON.stringify({ verdict: "PASS" })}\n`);
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 2;
}
