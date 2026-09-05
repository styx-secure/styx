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
const IMPLEMENTED_COLLECTION_BOUND_TARGETS = Object.freeze([
  "$defs.AliasGroupV0.allOf[0]",
  "$defs.ApplicationEventProjectionV0.causalParentReferences",
  "$defs.AuthorityAvailableV0.necessaryCredentialIdentifiers",
  "$defs.AuthorityAvailableV0.possibleCredentialIdentifiers",
  "$defs.AuthorityAvailableV0.terminalCredentialIdentifiers",
  "$defs.ContentMaterialEvidenceV0.segments",
  "$defs.ContextProjectionV0.aliasGroups",
  "$defs.ContextProjectionV0.appliedControlReferences",
  "$defs.ContextProjectionV0.contentStates",
  "$defs.ContextProjectionV0.credentialBindings",
  "$defs.ContextProjectionV0.eventAuthority",
  "$defs.ContextProjectionV0.forkJoins",
  "$defs.ContextProjectionV0.forkedCredentialIdentifiers",
  "$defs.ContextProjectionV0.pendingReferences",
  "$defs.ContextProjectionV0.pendingRootReferences",
  "$defs.ContextProjectionV0.recordOutcomes",
  "$defs.ContextProjectionV0.records",
  "$defs.ContextProjectionV0.reductionStandings",
  "$defs.ContextProjectionV0.replayDependencyReferences",
  "$defs.ContextProjectionV0.revokedCredentialIdentifiers",
  "$defs.ContextProjectionV0.terminatedCredentialIdentifiers",
  "$defs.EvidenceProjectionV0.contentMaterial",
  "$defs.EvidenceProjectionV0.openingMaterial",
  "$defs.ForkJoinProjectionV0.lineageClosureCredentialIdentifiers",
  "$defs.ForkJoinProjectionV0.siblingReferences",
  "$defs.ProposedContextSnapshotV0.admittedCandidates",
  "$defs.ReplayContextInputV0.candidates",
]);


function requireCondition(condition, message) {
  if (!condition) throw new AdapterFailure(message);
}


function readBytes(filePath) {
  requireCondition(Number.isInteger(fs.constants.O_NOFOLLOW), "O_NOFOLLOW is unavailable");
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
  );
  try {
    const stat = fs.fstatSync(descriptor);
    requireCondition(stat.isFile(), `invalid file authority: ${filePath}`);
    return fs.readFileSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
}


function readJson(filePath) {
  return JSON.parse(readBytes(filePath).toString("utf8"));
}


function loadContractAuthority(contractPath) {
  const lexical = path.resolve(contractPath);
  const real = fs.realpathSync.native(lexical);
  requireCondition(real === lexical, "contract path or ancestor is a symlink");
  requireCondition(fs.statSync(real).isDirectory(), "contract authority is not a directory");
  const manifestName = "APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json";
  const manifest = readJson(path.join(real, manifestName));
  requireCondition(Array.isArray(manifest.artifacts), "candidate manifest artifact relation is absent");
  const artifacts = new Map();
  for (const row of manifest.artifacts) {
    requireCondition(
      row !== null && typeof row === "object" && !Array.isArray(row)
        && typeof row.path === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(row.path)
        && typeof row.sha256 === "string" && /^[0-9a-f]{64}$/.test(row.sha256),
      "candidate manifest artifact row is invalid",
    );
    requireCondition(!artifacts.has(row.path), "candidate manifest contains a duplicate artifact");
    artifacts.set(row.path, row.sha256);
  }
  return Object.freeze({ artifacts, lexical, real });
}


function readManifestBoundJson(authority, filename) {
  requireCondition(authority.artifacts.has(filename), `artifact is absent from candidate manifest: ${filename}`);
  requireCondition(
    fs.realpathSync.native(authority.lexical) === authority.real,
    "contract authority changed during adapter execution",
  );
  const raw = readBytes(path.join(authority.real, filename));
  const digest = crypto.createHash("sha256").update(raw).digest("hex");
  requireCondition(digest === authority.artifacts.get(filename), `candidate manifest digest mismatch: ${filename}`);
  return JSON.parse(raw.toString("utf8"));
}


function validateUnicodeScalars(value) {
  if (typeof value === "string") {
    for (let index = 0; index < value.length; index += 1) {
      const unit = value.charCodeAt(index);
      if (unit >= 0xd800 && unit <= 0xdbff) {
        requireCondition(index + 1 < value.length, "canonical JSON contains a lone surrogate");
        const next = value.charCodeAt(index + 1);
        requireCondition(next >= 0xdc00 && next <= 0xdfff, "canonical JSON contains a lone surrogate");
        index += 1;
      } else {
        requireCondition(!(unit >= 0xdc00 && unit <= 0xdfff), "canonical JSON contains a lone surrogate");
      }
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) validateUnicodeScalars(item);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      validateUnicodeScalars(key);
      validateUnicodeScalars(item);
    }
  }
}


function canonicalStringify(value) {
  validateUnicodeScalars(value);
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    requireCondition(Number.isSafeInteger(value), "canonical JSON number is not a safe integer");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalStringify(item)).join(",")}]`;
  }
  requireCondition(typeof value === "object", "canonical JSON contains an unsupported value");
  const keys = Object.keys(value).sort((left, right) => Buffer.compare(
    Buffer.from(left, "utf8"), Buffer.from(right, "utf8"),
  ));
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalStringify(value[key])}`).join(",")}}`;
}


function readCanonicalInput() {
  const raw = fs.readFileSync(0);
  requireCondition(!raw.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf])), "canonical JSON BOM is forbidden");
  let text;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  } catch (_error) {
    throw new AdapterFailure("canonical JSON is not strict UTF-8");
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch (_error) {
    throw new AdapterFailure("canonical JSON is malformed");
  }
  requireCondition(`${canonicalStringify(value)}\n` === text, "input is not canonical evidence JSON");
  return value;
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


function objectValue(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}


function schemaPointer(root, reference) {
  requireCondition(typeof reference === "string" && reference.startsWith("#/"), "non-local schema reference");
  let node = root;
  for (const raw of reference.slice(2).split("/")) {
    const token = raw.replaceAll("~1", "/").replaceAll("~0", "~");
    requireCondition(objectValue(node) && Object.prototype.hasOwnProperty.call(node, token), "schema reference target absent");
    node = node[token];
  }
  requireCondition(objectValue(node), "schema reference target is not an object");
  return node;
}


function deepEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}


function matchesType(value, kind) {
  if (kind === "object") return objectValue(value);
  if (kind === "array") return Array.isArray(value);
  if (kind === "string") return typeof value === "string";
  if (kind === "integer") return Number.isSafeInteger(value);
  if (kind === "number") return typeof value === "number" && Number.isFinite(value);
  if (kind === "boolean") return typeof value === "boolean";
  if (kind === "null") return value === null;
  throw new AdapterFailure(`unsupported schema type: ${kind}`);
}


function schemaMatches(value, schema, root) {
  try {
    validateSchema(value, schema, root);
    return true;
  } catch (error) {
    if (!(error instanceof AdapterFailure)) throw error;
    return false;
  }
}


function validateSchema(value, schema, root) {
  requireCondition(objectValue(schema), "schema node is not an object");
  if (typeof schema.$ref === "string") validateSchema(value, schemaPointer(root, schema.$ref), root);
  if (Object.prototype.hasOwnProperty.call(schema, "const")) {
    requireCondition(deepEqual(value, schema.const), "schema const mismatch");
  }
  if (Array.isArray(schema.enum)) {
    requireCondition(schema.enum.some((member) => deepEqual(value, member)), "schema enum mismatch");
  }
  if (typeof schema.type === "string") requireCondition(matchesType(value, schema.type), "schema type mismatch");
  if (Array.isArray(schema.type)) {
    requireCondition(schema.type.some((kind) => matchesType(value, kind)), "schema type union mismatch");
  }
  if (Array.isArray(schema.allOf)) {
    for (const arm of schema.allOf) validateSchema(value, arm, root);
  }
  if (Array.isArray(schema.anyOf)) {
    requireCondition(schema.anyOf.some((arm) => schemaMatches(value, arm, root)), "schema anyOf has no matching arm");
  }
  if (Array.isArray(schema.oneOf)) {
    requireCondition(schema.oneOf.filter((arm) => schemaMatches(value, arm, root)).length === 1, "schema oneOf is not exclusive");
  }
  if (objectValue(schema.not)) requireCondition(!schemaMatches(value, schema.not, root), "schema not matched");
  if (objectValue(schema.if)) {
    const branch = schemaMatches(value, schema.if, root) ? schema.then : schema.else;
    if (objectValue(branch)) validateSchema(value, branch, root);
  }
  if (typeof value === "string") {
    if (Number.isInteger(schema.minLength)) requireCondition([...value].length >= schema.minLength, "schema minLength mismatch");
    if (Number.isInteger(schema.maxLength)) requireCondition([...value].length <= schema.maxLength, "schema maxLength mismatch");
    if (typeof schema.pattern === "string") requireCondition(new RegExp(schema.pattern, "u").test(value), "schema pattern mismatch");
    if (typeof schema["x-styx-unsigned-maximum"] === "string") {
      requireCondition(/^(0|[1-9][0-9]*)$/.test(value), "unsigned decimal is noncanonical");
      requireCondition(BigInt(value) <= BigInt(schema["x-styx-unsigned-maximum"]), "unsigned decimal exceeds maximum");
    }
  }
  if (Array.isArray(value)) {
    if (Number.isInteger(schema.minItems)) requireCondition(value.length >= schema.minItems, "schema minItems mismatch");
    if (Number.isInteger(schema.maxItems)) requireCondition(value.length <= schema.maxItems, "schema maxItems mismatch");
    if (schema.uniqueItems === true) {
      requireCondition(new Set(value.map((item) => JSON.stringify(item))).size === value.length, "schema uniqueItems mismatch");
    }
    if (objectValue(schema.items)) for (const item of value) validateSchema(item, schema.items, root);
  }
  if (objectValue(value)) {
    if (Number.isInteger(schema.maxProperties)) requireCondition(Object.keys(value).length <= schema.maxProperties, "schema maxProperties mismatch");
    if (Array.isArray(schema.required)) {
      for (const name of schema.required) requireCondition(Object.prototype.hasOwnProperty.call(value, name), "schema required property absent");
    }
    if (objectValue(schema.properties)) {
      for (const [name, child] of Object.entries(schema.properties)) {
        if (Object.prototype.hasOwnProperty.call(value, name)) validateSchema(value[name], child, root);
      }
      if (schema.additionalProperties === false) {
        const allowed = new Set(Object.keys(schema.properties));
        requireCondition(Object.keys(value).every((name) => allowed.has(name)), "schema additional property present");
      }
    } else if (schema.additionalProperties === false) {
      requireCondition(Object.keys(value).length === 0, "schema additional property present");
    }
  }
}


function interfaceLimits(schema) {
  const properties = schema.$defs?.InterfaceLimitsV0?.properties;
  requireCondition(objectValue(properties), "interface limits are absent");
  const limits = {};
  for (const [name, row] of Object.entries(properties)) {
    requireCondition(objectValue(row) && typeof row.const === "string", `non-literal limit: ${name}`);
    const parsed = Number(row.const);
    requireCondition(Number.isSafeInteger(parsed) && parsed >= 0, `invalid limit: ${name}`);
    limits[name] = parsed;
  }
  return limits;
}


function verifyCollectionTargetClosure(semantics) {
  requireCondition(Array.isArray(semantics.rules), "semantic rules are absent");
  const actual = new Set();
  for (const row of semantics.rules) {
    if (!["ARRAY_COUNT_LIMIT_BEFORE_ITEM_WORK", "DERIVED_ARRAY_COUNT_LIMIT_BEFORE_ITEM_WORK"].includes(row.rule)) continue;
    requireCondition(Array.isArray(row.targets), "collection-bound target list is absent");
    for (const target of row.targets) actual.add(target);
  }
  requireCondition(
    JSON.stringify([...actual].sort()) === JSON.stringify([...IMPLEMENTED_COLLECTION_BOUND_TARGETS].sort()),
    "implemented collection-bound target set drift",
  );
}


function requireCollectionBound(value, maximum, label) {
  if (Array.isArray(value)) requireCondition(value.length <= maximum, `collection exceeds ${label}`);
}


function preflightEvidenceCollections(evidence, limits) {
  if (!objectValue(evidence)) return;
  const content = evidence.contentMaterial;
  requireCollectionBound(content, limits.RECORDS, "EvidenceProjectionV0.contentMaterial/RECORDS");
  requireCollectionBound(evidence.openingMaterial, limits.RECORDS, "EvidenceProjectionV0.openingMaterial/RECORDS");
  if (Array.isArray(content)) {
    for (const row of content) {
      if (objectValue(row)) requireCollectionBound(row.segments, limits.CHUNKS_PER_CONTENT, "ContentMaterialEvidenceV0.segments/CHUNKS_PER_CONTENT");
    }
  }
}


function preflightSnapshotCollections(snapshot, limits) {
  if (!objectValue(snapshot)) return;
  requireCollectionBound(snapshot.admittedCandidates, limits.RECORDS, "ProposedContextSnapshotV0.admittedCandidates/RECORDS");
  preflightEvidenceCollections(snapshot.evidence, limits);
  const projection = snapshot.projection;
  if (!objectValue(projection)) return;
  const fieldLimits = {
    records: limits.RECORDS,
    recordOutcomes: limits.RECORDS,
    credentialBindings: limits.RECORDS + 1,
    aliasGroups: Math.floor((limits.RECORDS + 1) / 2),
    appliedControlReferences: limits.CONTROL_EVENTS,
    reductionStandings: limits.CONTROL_EVENTS,
    eventAuthority: limits.RECORDS,
    revokedCredentialIdentifiers: limits.CREDENTIALS,
    terminatedCredentialIdentifiers: limits.CREDENTIALS,
    forkedCredentialIdentifiers: limits.CREDENTIALS,
    forkJoins: limits.FORK_SLOTS,
    pendingRootReferences: limits.PENDING_ROOTS,
    pendingReferences: limits.PENDING_DESCENDANTS,
    contentStates: limits.RECORDS,
    replayDependencyReferences: limits.RECORDS,
  };
  for (const [field, maximum] of Object.entries(fieldLimits)) {
    requireCollectionBound(projection[field], maximum, `ContextProjectionV0.${field}`);
  }
  if (Array.isArray(projection.records)) {
    for (const row of projection.records) {
      if (objectValue(row)) requireCollectionBound(row.causalParentReferences, limits.PARENTS_PER_EVENT, "ApplicationEventProjectionV0.causalParentReferences/PARENTS_PER_EVENT");
    }
  }
  if (Array.isArray(projection.aliasGroups)) {
    let totalMembers = 0;
    for (const group of projection.aliasGroups) {
      requireCollectionBound(group, limits.RECORDS + 1, "AliasGroupV0/RECORDS+1");
      if (Array.isArray(group)) totalMembers += group.length;
    }
    requireCondition(totalMembers <= limits.RECORDS + 1, "collection exceeds alias-group membership bound");
  }
  if (Array.isArray(projection.forkJoins)) {
    for (const row of projection.forkJoins) {
      if (!objectValue(row)) continue;
      requireCollectionBound(row.siblingReferences, limits.SIBLINGS_PER_FORK, "ForkJoinProjectionV0.siblingReferences/SIBLINGS_PER_FORK");
      requireCollectionBound(row.lineageClosureCredentialIdentifiers, limits.CREDENTIALS, "ForkJoinProjectionV0.lineageClosureCredentialIdentifiers/CREDENTIALS");
    }
  }
  if (objectValue(projection.authority)) {
    for (const field of ["possibleCredentialIdentifiers", "necessaryCredentialIdentifiers", "terminalCredentialIdentifiers"]) {
      requireCollectionBound(projection.authority[field], limits.CREDENTIALS, `AuthorityAvailableV0.${field}/CREDENTIALS`);
    }
  }
}


function preflightCollections(input, schema, semantics) {
  exactKeys(input, ["direction", "message"], "collection preflight input");
  requireCondition(["REQUEST", "RESPONSE"].includes(input.direction), "invalid collection preflight direction");
  requireCondition(objectValue(input.message), "collection preflight message is not an object");
  verifyCollectionTargetClosure(semantics);
  const limits = interfaceLimits(schema);
  const message = input.message;
  if (input.direction === "REQUEST") {
    const value = message.input;
    if (!objectValue(value)) return { verdict: "PASS" };
    if (message.operation === "REPLAY_CONTEXT") {
      requireCollectionBound(value.candidates, limits.RECORDS, "ReplayContextInputV0.candidates/RECORDS");
      preflightEvidenceCollections(value.evidence, limits);
    } else if (message.operation === "EVALUATE_CANDIDATE") {
      preflightSnapshotCollections(value.prior, limits);
      preflightEvidenceCollections(value.evidence, limits);
    } else if (message.operation === "EVALUATE_EVIDENCE_UPDATE") {
      preflightSnapshotCollections(value.prior, limits);
      preflightEvidenceCollections(value.additions, limits);
    }
  } else {
    const result = message.result;
    let successor = null;
    if (objectValue(result) && message.operation === "REPLAY_CONTEXT") successor = result.proposedContext;
    else if (objectValue(result) && ["EVALUATE_CANDIDATE", "EVALUATE_EVIDENCE_UPDATE"].includes(message.operation)) {
      const evaluation = result.evaluation;
      if (objectValue(evaluation) && objectValue(evaluation.proposal)) successor = evaluation.proposal.successor;
    }
    preflightSnapshotCollections(successor, limits);
  }
  return { verdict: "PASS" };
}


function outcomeProjection(input) {
  exactKeys(input, ["authorityUnavailable", "forkedCredentials", "necessaryAuthority", "pendingRoots", "records"], "outcome projection input");
  requireCondition(typeof input.authorityUnavailable === "boolean", "invalid authorityUnavailable");
  requireCondition(Array.isArray(input.forkedCredentials), "invalid forkedCredentials");
  requireCondition(Array.isArray(input.necessaryAuthority), "invalid necessaryAuthority");
  requireCondition(Array.isArray(input.pendingRoots), "invalid pendingRoots");
  for (const value of [...input.forkedCredentials, ...input.necessaryAuthority, ...input.pendingRoots]) fixedHex32(value, "projection reference");
  requireCondition(Array.isArray(input.records), "invalid outcome records");
  const outcomes = input.records.map((row, index) => {
    exactKeys(
      row,
      ["appliedControl", "eventAuthority", "forkSibling", "lineageTerminated", "pendingDescendant", "pendingRoot", "postRevocation", "reference", "removalApplicable", "role"],
      `outcome record ${index}`,
    );
    fixedHex32(row.reference, "outcome reference");
    requireCondition(["CREDENTIAL", "ORDINARY", "REMOVAL"].includes(row.role), "invalid outcome role");
    requireCondition(["MUST_AUTH", "MUST_NOT_AUTH"].includes(row.eventAuthority), "invalid event authority");
    for (const field of ["appliedControl", "forkSibling", "lineageTerminated", "pendingDescendant", "pendingRoot", "postRevocation", "removalApplicable"]) {
      requireCondition(typeof row[field] === "boolean", `invalid outcome flag: ${field}`);
    }
    let primary;
    if (input.authorityUnavailable) primary = "AUTHORITY_PROJECTION_UNAVAILABLE";
    else if (row.forkSibling) primary = "FORK_EVIDENCE";
    else if (row.pendingRoot) primary = "PENDING_OPENING";
    else if (row.pendingDescendant) primary = "PENDING_ANCESTOR";
    else if (row.role === "REMOVAL" && !row.removalApplicable) primary = "REMOVAL_INAPPLICABLE";
    else if (row.role === "CREDENTIAL") primary = row.appliedControl ? "APPLIED" : "AUTHENTIC_BUT_UNAUTHORIZED";
    else if (row.eventAuthority === "MUST_AUTH") primary = "APPLIED";
    else if (row.postRevocation) primary = "POST_REVOCATION";
    else if (row.lineageTerminated) primary = "LINEAGE_QUARANTINED";
    else primary = "AUTHENTIC_BUT_UNAUTHORIZED";
    return { primary, reference: row.reference };
  }).sort((left, right) => left.reference.localeCompare(right.reference));
  const contextState = input.authorityUnavailable
    ? "AUTHORITY_UNAVAILABLE"
    : input.necessaryAuthority.length === 0
      ? "NO_OPERATIONAL_AUTHORITY"
      : input.forkedCredentials.length > 0
        ? "PARTIALLY_LINEAGE_QUARANTINED"
        : input.pendingRoots.length > 0
          ? "PARTIALLY_PENDING"
          : "ACTIVE";
  return { contextState, outcomes };
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


function validateCompleteResponseBeforeRelease(response, schema, relations) {
  validateSchema(response, schema.$defs.InterfaceResponseV0, schema);
  if (response.operation === "EVALUATE_CANDIDATE") {
    const evaluation = response.result.evaluation;
    const primary = evaluation.primary ?? evaluation.primaryOnCommit;
    const row = relations.candidateEvaluationPrimaryRelationV0.find((item) => item.primary === primary);
    requireCondition(row !== undefined, "candidate primary is absent from F13");
    requireCondition(row.reachability !== "RESERVED_UNREACHABLE_V0", "APP-core v0 reserved F13 row was generated");
  }
  if (["VALIDATE_TRANSCRIPT", "EVALUATE_GENESIS"].includes(response.operation)) {
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
    requireCondition(!reserved.has(observed), "APP-core v0 reserved terminal predicate was generated");
    if (response.operation === "VALIDATE_TRANSCRIPT") {
      requireCondition(
        response.result.observations.referenceVerification !== "REJECTED",
        "APP-core v0 reserved reference rejection was generated",
      );
    }
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


function selfTestAcv066(authority) {
  const schema = readManifestBoundJson(authority, "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json");
  const relations = readManifestBoundJson(authority, "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json");
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
  let preflightCollectionsMode = false;
  let outcomeProjectionMode = false;
  let contractPath = null;
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--self-test-acv066") selfTest = true;
    else if (argv[index] === "--derive-fork-join") deriveForkJoin = true;
    else if (argv[index] === "--authority-metrics") authorityMetricsMode = true;
    else if (argv[index] === "--graph-projection") graphProjectionMode = true;
    else if (argv[index] === "--credential-projection") credentialProjectionMode = true;
    else if (argv[index] === "--validate-response") validateResponseMode = true;
    else if (argv[index] === "--preflight-collections") preflightCollectionsMode = true;
    else if (argv[index] === "--outcome-projection") outcomeProjectionMode = true;
    else if (argv[index] === "--contract") contractPath = argv[++index];
    else throw new AdapterFailure(`unknown argument: ${argv[index]}`);
  }
  requireCondition(
    Number(selfTest) + Number(deriveForkJoin) + Number(authorityMetricsMode)
      + Number(graphProjectionMode) + Number(credentialProjectionMode)
      + Number(validateResponseMode) + Number(preflightCollectionsMode)
      + Number(outcomeProjectionMode) === 1,
    "exactly one adapter mode is required",
  );
  requireCondition(contractPath, "--contract is required");
  return {
    authorityMetricsMode, contractPath, credentialProjectionMode, deriveForkJoin,
    graphProjectionMode, outcomeProjectionMode, preflightCollectionsMode,
    selfTest, validateResponseMode,
  };
}


try {
  const {
    authorityMetricsMode, contractPath, credentialProjectionMode, deriveForkJoin,
    graphProjectionMode, outcomeProjectionMode, preflightCollectionsMode,
    selfTest, validateResponseMode,
  } = parseArguments(process.argv.slice(2));
  const authority = loadContractAuthority(contractPath);
  if (selfTest) {
    process.stdout.write(`${JSON.stringify(selfTestAcv066(authority))}\n`);
  } else if (deriveForkJoin) {
    const schema = readManifestBoundJson(authority, "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json");
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
    const schema = readManifestBoundJson(authority, "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json");
    const relations = readManifestBoundJson(authority, "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json");
    const input = readCanonicalInput();
    validateCompleteResponseBeforeRelease(input, schema, relations);
    process.stdout.write(`${JSON.stringify({ verdict: "PASS" })}\n`);
  } else if (preflightCollectionsMode) {
    const schema = readManifestBoundJson(authority, "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json");
    const semantics = readManifestBoundJson(authority, "APP-CORE-IFACE-0-SEMANTIC-CONSTRAINTS-CANDIDATE.json");
    const input = JSON.parse(fs.readFileSync(0, "utf8"));
    process.stdout.write(`${JSON.stringify(preflightCollections(input, schema, semantics))}\n`);
  } else if (outcomeProjectionMode) {
    const input = JSON.parse(fs.readFileSync(0, "utf8"));
    process.stdout.write(`${JSON.stringify(outcomeProjection(input))}\n`);
  }
} catch (error) {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 2;
}
