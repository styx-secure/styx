// STYX_SPIKE_PROTOTYPE — retained-state replay and one-use liveness adapter.

import {
  B23_LIMITS,
  assertBytes,
  bytesEqual,
  bytesToHex,
  copyBytes,
  digestHex,
  epochToDecimal,
  hexToBytes,
  validateProviderSnapshot,
} from '../marmot-phase-b2-3/b2-3-canonical.mjs';
import { canonicalProjectionBytes } from '../marmot-phase-b2-3/b2-3-record.mjs';
import { projectB2Commit } from '../marmot-phase-b2-3/b2-3-engine-adapter.mjs';
import {
  evaluateB24Authorization,
  projectB24Parent,
  requireB24Allow,
  validateB24Parent,
  verifyB24DecisionBinding,
} from '../marmot-phase-b2-4/b2-4-policy.mjs';
import { priorityForAuthorization }
  from '../marmot-phase-b2-5a/b2-5a-convergence.mjs';
import {
  B27_EDGE_ORIGIN,
  B27_ERROR,
  B27_APP_PUBLICATION_KIND,
  B27_GENERATION_STATE,
  B27_HEAD_STATE,
  B27_INBOUND_STATE,
  B27_INPUT_STATE,
  B27_LIMITS,
  B27_MESSAGE_STATE,
  B27_OUTBOX_STATE,
  B27_PASS_STATE,
  B27_PUBLICATION_KIND,
  assertGroupIdHex,
  assertHex64,
  assertSafeInteger,
  assertString,
  compareBranches,
  failB27,
  generationAuthorityDigest,
  requestKey,
} from './b2-7-canonical.mjs';
import {
  GENERATION_FIELDS,
  INPUT_FIELDS,
  OUTBOX_FIELDS,
  buildAppPublication,
  buildEdge,
  buildGeneration,
  buildHead,
  buildInput,
  buildInvalidation,
  buildInbound,
  buildMessageSnapshot,
  buildMessageState,
  buildOutbox,
  buildPass,
  buildPublication,
  buildRelease,
  buildRetainedState,
  buildTransition,
  parseGeneration,
  parseInput,
} from './b2-7-record.mjs';

const ADAPTER_TOKEN = Symbol('B27_ENGINE_ADAPTER_TOKEN');
const PROBE_REQUEST_PREFIX = 'styx-probe:';
const VERIFIED_LEAF_DOMAIN = new TextEncoder().encode('STYX-B2-VERIFIED-LEAVES-v1');
const ELIGIBLE_GENERATION_STATES = new Set([
  B27_GENERATION_STATE.ACKNOWLEDGED,
  B27_GENERATION_STATE.SELECTED,
  B27_GENERATION_STATE.LOSING,
]);

const RETENTION_REQUIRED_GENERATION_STATES = new Set([
  B27_GENERATION_STATE.PREPARED,
  B27_GENERATION_STATE.PUBLISHING,
  ...ELIGIBLE_GENERATION_STATES,
]);
const TERMINAL_GENERATION_STATES = new Set([
  B27_GENERATION_STATE.CANCELLED,
  B27_GENERATION_STATE.DISCARDED,
  B27_GENERATION_STATE.SELECTED,
  B27_GENERATION_STATE.LOSING,
  B27_GENERATION_STATE.REJECTED,
]);
const CLOSED_STAGE_PATTERNS = /malformed|framing|unsupported mlsmessage|privatemessage|group id|wrong group/i;

function safeFree(value) {
  if (value && typeof value.free === 'function') {
    try { value.free(); } catch { /* disposal cannot change durable authority */ }
  }
}

function dispose(session) {
  if (!session) return;
  safeFree(session.group);
  safeFree(session.identity);
  safeFree(session.provider);
}

function parentHead(retained) {
  return Object.freeze({
    groupIdHex: retained.groupIdHex,
    epochDec: retained.epochDec,
    epochDigestHex: retained.groupContextDigestHex,
  });
}

function verifiedLeafDigestHex(parent) {
  const payload = new Uint8Array(27 + 4 + (172 * parent.members.length));
  payload.set(VERIFIED_LEAF_DOMAIN, 0);
  payload[26] = 0;
  const view = new DataView(payload.buffer);
  view.setUint32(27, parent.members.length, false);
  let offset = 31;
  for (const member of parent.members) {
    view.setUint32(offset, member.leafIndex, false);
    offset += 4;
    for (const [label, field] of [
      ['identityHex', member.identityHex],
      ['signatureKeyHex', member.signatureKeyHex],
      ['identityProofHex', member.identityProofHex],
    ]) {
      const bytes = hexToBytes(label, field);
      payload.set(bytes, offset);
      offset += bytes.length;
    }
  }
  if (offset !== payload.length) {
    failB27(B27_ERROR.CORRUPT,
      'verified sender roster has a non-canonical encoded length');
  }
  return digestHex(payload);
}

function authenticatedSender(session, received, context) {
  const receivedGroupId = copyBytes(received.group_id());
  const receivedIdentity = copyBytes(received.sender_credential_identity());
  const receivedSignatureKey = copyBytes(received.sender_signature_key());
  const senderLeafIndex = received.sender_leaf_index();
  if (!bytesEqual(receivedGroupId, session.groupId)
    || epochToDecimal(received.epoch()) !== session.parent.epochDec
    || session.parent.groupContextDigestHex
      !== (context.state?.groupContextDigestHex
        ?? context.retained.groupContextDigestHex)) {
    failB27(B27_ERROR.ENGINE_REJECTED,
      'received application message differs from its restored MLS context');
  }
  const matches = session.parent.members.filter((member) =>
    member.leafIndex === senderLeafIndex);
  if (matches.length !== 1) {
    failB27(B27_ERROR.ENGINE_REJECTED,
      'received application sender is absent or ambiguous in the authenticated roster');
  }
  const member = matches[0];
  if (!bytesEqual(receivedIdentity,
    hexToBytes('senderIdentityHex', member.identityHex))
    || !bytesEqual(receivedSignatureKey,
      hexToBytes('senderSignatureKeyHex', member.signatureKeyHex))) {
    failB27(B27_ERROR.ENGINE_REJECTED,
      'received application sender differs from its authenticated roster member');
  }
  const rosterDigestHex = verifiedLeafDigestHex(session.parent);
  if (context.producingVerifiedLeafDigestHex !== null
    && rosterDigestHex !== context.producingVerifiedLeafDigestHex) {
    failB27(B27_ERROR.ENGINE_REJECTED,
      'restored sender roster differs from its producing replay edge');
  }
  return Object.freeze({
    epochDec: session.parent.epochDec,
    groupContextDigestHex: session.parent.groupContextDigestHex,
    verifiedLeafDigestHex: rosterDigestHex,
    senderLeafIndex,
    senderIdentityHex: member.identityHex,
    senderSignatureKeyHex: member.signatureKeyHex,
    senderIdentityProofHex: member.identityProofHex,
  });
}

function durableInboundResult(status, inbound) {
  return Object.freeze({
    status,
    instanceKeyHex: inbound.instanceKeyHex,
    receivedOrdinal: inbound.receivedOrdinal,
    epochDec: inbound.epochDec,
    groupContextDigestHex: inbound.groupContextDigestHex,
    verifiedLeafDigestHex: inbound.verifiedLeafDigestHex,
    senderLeafIndex: inbound.senderLeafIndex,
    senderIdentityHex: inbound.senderIdentityHex,
    senderSignatureKeyHex: inbound.senderSignatureKeyHex,
    senderIdentityProofHex: inbound.senderIdentityProofHex,
    plaintextBytes: copyBytes(inbound.plaintextBytes),
  });
}

function rebuildInput(record, changes) {
  const fields = {};
  for (const field of INPUT_FIELDS) {
    if (!['format', 'version', 'commitDigestHex', 'commitByteLength',
      'inputDigestHex'].includes(field)) fields[field] = record[field];
  }
  return buildInput({ ...fields, ...changes });
}

function rebuildGeneration(record, changes) {
  const fields = {};
  for (const field of GENERATION_FIELDS) {
    if (!['format', 'version', 'generationDigestHex'].includes(field)) fields[field] = record[field];
  }
  return buildGeneration({ ...fields, ...changes });
}

function rebuildOutbox(record, changes) {
  const fields = {};
  for (const field of OUTBOX_FIELDS) {
    if (!['format', 'version', 'outboxDigestHex'].includes(field)) fields[field] = record[field];
  }
  return buildOutbox({ ...fields, ...changes });
}

function operationPayload(operationKind, operationPayloadBytes) {
  if (operationKind === 'self-update') {
    if (operationPayloadBytes.length !== 0) {
      failB27(B27_ERROR.INVALID, 'self-update payload must be empty');
    }
    return null;
  }
  if (operationKind === 'remove') {
    if (operationPayloadBytes.length !== 4) {
      failB27(B27_ERROR.INVALID, 'remove payload must be one u32 leaf index');
    }
    return new DataView(operationPayloadBytes.buffer,
      operationPayloadBytes.byteOffset, 4).getUint32(0, false);
  }
  if (operationKind !== 'add') failB27(B27_ERROR.INVALID, 'unsupported local operation');
  return operationPayloadBytes;
}

function tipForPath(path, edgeByCommit) {
  if (path.length === 0) return null;
  const edge = edgeByCommit.get(path.at(-1));
  if (edge === undefined) failB27(B27_ERROR.CORRUPT, 'branch tip edge is absent');
  return Object.freeze({ priority: edge.priority,
    committerIdentityHex: edge.committerIdentityHex,
    commitDigestHex: edge.commitDigestHex });
}

function enumerateBranches(anchorSnapshotDigestHex, edges, maxDepth) {
  const outgoing = new Map();
  for (const edge of edges) {
    const list = outgoing.get(edge.parentSnapshotDigestHex) ?? [];
    list.push(edge);
    outgoing.set(edge.parentSnapshotDigestHex, list);
  }
  for (const list of outgoing.values()) list.sort((left, right) =>
    left.commitDigestHex < right.commitDigestHex ? -1 : left.commitDigestHex > right.commitDigestHex ? 1 : 0);
  const branches = [];
  const walk = (snapshotDigestHex, path, seenStates) => {
    const next = outgoing.get(snapshotDigestHex) ?? [];
    if (next.length === 0 || path.length === maxDepth) {
      branches.push(Object.freeze({ path: Object.freeze([...path]),
        snapshotDigestHex, tip: tipForPath(path,
          new Map(edges.map((edge) => [edge.commitDigestHex, edge]))) }));
      return;
    }
    for (const edge of next) {
      if (seenStates.has(edge.successorSnapshotDigestHex)) {
        failB27(B27_ERROR.CORRUPT, 'retained replay graph contains a cycle');
      }
      walk(edge.successorSnapshotDigestHex, [...path, edge.commitDigestHex],
        new Set([...seenStates, edge.successorSnapshotDigestHex]));
    }
  };
  walk(anchorSnapshotDigestHex, [], new Set([anchorSnapshotDigestHex]));
  return Object.freeze(branches.sort(compareBranches));
}

export class B27EngineAdapter {
  #wasm;
  #journal;
  #initializeJournal;
  #commitSettlement;
  #markUnrecoverable;
  #commitPrepared;
  #replaceGeneration;
  #appendPublication;
  #commitOutbound;
  #commitInbound;
  #commitDeferredInbound;
  #appendAppPublication;
  #replaceOutbox;
  #beforeReplay;
  #afterProbeReservation;
  #beforeOutboundCommit;
  #beforeInboundCommit;

  constructor({ wasm, journal, initializeJournal, commitSettlement, markUnrecoverable, commitPrepared,
    replaceGeneration, appendPublication, commitOutbound, commitInbound,
    commitDeferredInbound, appendAppPublication, replaceOutbox,
    beforeReplay, afterProbeReservation, beforeOutboundCommit, beforeInboundCommit }, token) {
    if (token !== ADAPTER_TOKEN || typeof initializeJournal !== 'function'
      || typeof commitSettlement !== 'function' || typeof markUnrecoverable !== 'function'
      || typeof commitPrepared !== 'function'
      || typeof replaceGeneration !== 'function' || typeof appendPublication !== 'function'
      || typeof commitOutbound !== 'function' || typeof commitInbound !== 'function'
      || typeof commitDeferredInbound !== 'function'
      || typeof appendAppPublication !== 'function'
      || typeof replaceOutbox !== 'function') {
      failB27(B27_ERROR.INVALID, 'B2.7 adapter requires journal-private capabilities');
    }
    if (!wasm?.Provider || !wasm?.PhaseB2Group || !wasm?.PhaseB2Identity
      || !journal || typeof journal.readFrozen !== 'function'
      || typeof journal.reserveProbe !== 'function') {
      failB27(B27_ERROR.INVALID, 'exact initialized Phase B2 WASM and B2.7 journal required');
    }
    if (typeof beforeReplay !== 'function' || typeof afterProbeReservation !== 'function'
      || typeof beforeOutboundCommit !== 'function'
      || typeof beforeInboundCommit !== 'function') {
      failB27(B27_ERROR.INVALID, 'test scheduling hooks must be functions');
    }
    this.#wasm = wasm;
    this.#journal = journal;
    this.#initializeJournal = initializeJournal;
    this.#commitSettlement = commitSettlement;
    this.#markUnrecoverable = markUnrecoverable;
    this.#commitPrepared = commitPrepared;
    this.#replaceGeneration = replaceGeneration;
    this.#appendPublication = appendPublication;
    this.#commitOutbound = commitOutbound;
    this.#commitInbound = commitInbound;
    this.#commitDeferredInbound = commitDeferredInbound;
    this.#appendAppPublication = appendAppPublication;
    this.#replaceOutbox = replaceOutbox;
    this.#beforeReplay = beforeReplay;
    this.#afterProbeReservation = afterProbeReservation;
    this.#beforeOutboundCommit = beforeOutboundCommit;
    this.#beforeInboundCommit = beforeInboundCommit;
    Object.freeze(this);
  }

  #restore(retained, allowPending = false) {
    let provider;
    let identity;
    let group;
    try {
      validateProviderSnapshot(retained.snapshotBytes);
      provider = new this.#wasm.Provider();
      provider.restore_state(retained.snapshotBytes);
      const accountKey = hexToBytes('accountKeyHex', retained.accountKeyHex);
      const signatureKey = hexToBytes('signatureKeyHex', retained.signatureKeyHex);
      const groupId = hexToBytes('groupIdHex', retained.groupIdHex);
      identity = this.#wasm.PhaseB2Identity.load(provider, accountKey, signatureKey);
      group = this.#wasm.PhaseB2Group.load(provider, groupId);
      if (identity === undefined || group === undefined
        || !group.matches_own_identity(accountKey, signatureKey)
        || (!allowPending && group.has_pending_commit(provider))
        || epochToDecimal(group.epoch()) !== retained.epochDec
        || bytesToHex(group.group_context_sha256(provider)) !== retained.groupContextDigestHex) {
        failB27(B27_ERROR.ENGINE_REJECTED, 'retained OpenMLS binding is invalid');
      }
      const parent = projectB24Parent({ provider, group, head: parentHead(retained) });
      validateB24Parent(parent);
      return { provider, identity, group, accountKey, signatureKey, groupId, parent };
    } catch (error) {
      dispose({ provider, identity, group });
      if (error?.code) throw error;
      failB27(B27_ERROR.ENGINE_REJECTED, 'retained OpenMLS restore failed', {}, error);
    }
  }

  #successor(session, retained) {
    const epochDec = epochToDecimal(session.group.epoch());
    const groupContextDigestHex = bytesToHex(
      session.group.group_context_sha256(session.provider));
    return buildRetainedState({ groupIdHex: retained.groupIdHex,
      accountKeyHex: retained.accountKeyHex, signatureKeyHex: retained.signatureKeyHex,
      epochDec, groupContextDigestHex,
      snapshotBytes: copyBytes(session.provider.serialize_state()) });
  }

  async initializeStable({ snapshotBytes, groupId, accountKey, signatureKey }) {
    assertBytes('groupId', groupId, { min: 1, max: 64 });
    assertBytes('accountKey', accountKey, { min: 32, max: 32 });
    assertBytes('signatureKey', signatureKey, { min: 32, max: 32 });
    assertBytes('snapshotBytes', snapshotBytes, { min: 8, max: B23_LIMITS.maxSnapshotBytes });
    let provider;
    let identity;
    let group;
    try {
      validateProviderSnapshot(snapshotBytes);
      provider = new this.#wasm.Provider();
      provider.restore_state(snapshotBytes);
      identity = this.#wasm.PhaseB2Identity.load(provider, accountKey, signatureKey);
      group = this.#wasm.PhaseB2Group.load(provider, groupId);
      if (identity === undefined || group === undefined
        || !group.matches_own_identity(accountKey, signatureKey)
        || group.has_pending_commit(provider)) {
        failB27(B27_ERROR.ENGINE_REJECTED, 'initial state is not a stable identity binding');
      }
      const epochDec = epochToDecimal(group.epoch());
      const groupContextDigestHex = bytesToHex(group.group_context_sha256(provider));
      validateB24Parent(projectB24Parent({ provider, group,
        head: { groupIdHex: bytesToHex(groupId), epochDec,
          epochDigestHex: groupContextDigestHex } }));
      return await this.#initializeJournal({ groupIdHex: bytesToHex(groupId),
        accountKeyHex: bytesToHex(accountKey), signatureKeyHex: bytesToHex(signatureKey),
        epochDec, groupContextDigestHex,
        snapshotBytes: copyBytes(snapshotBytes) });
    } catch (error) {
      if (error?.code) throw error;
      failB27(B27_ERROR.ENGINE_REJECTED, 'stable B2.7 initialization failed', {}, error);
    } finally {
      dispose({ provider, identity, group });
    }
  }

  admitCommit(groupIdHex, commitBytes) {
    return this.#journal.admitCommit(groupIdHex, commitBytes);
  }

  freeze(groupIdHex) { return this.#journal.freeze(groupIdHex); }

  async #tryInbound(parent, input) {
    await this.#beforeReplay(input.commitDigestHex, parent.snapshotDigestHex);
    const session = this.#restore(parent);
    let staged;
    let projectionHandle;
    let finalized = false;
    try {
      const before = copyBytes(session.provider.serialize_state());
      try {
        staged = session.group.stage_inbound_commit(session.provider, input.commitBytes);
      } catch (error) {
        return Object.freeze({ matched: false, closed: CLOSED_STAGE_PATTERNS.test(String(error)),
          errorText: String(error) });
      }
      projectionHandle = staged.projection();
      const projection = projectB2Commit(projectionHandle);
      if (!bytesEqual(before, session.provider.serialize_state())) {
        failB27(B27_ERROR.ENGINE_REJECTED, 'staging mutated its retained parent');
      }
      // The pinned engine can parse a previously consumed Commit far enough to
      // expose a projection. Parent discovery therefore also binds the candidate
      // epoch explicitly; successful parsing alone is not parent authority.
      if (BigInt(projection.candidateEpochDec) !== BigInt(parent.epochDec) + 1n) {
        session.group.discard_staged_commit(session.provider, staged);
        finalized = true;
        return Object.freeze({ matched: false, closed: false,
          errorText: 'candidate epoch does not succeed this retained parent' });
      }
      const policyInputs = { parent: session.parent, candidate: projection,
        commitBytes: input.commitBytes };
      const decision = verifyB24DecisionBinding(
        evaluateB24Authorization(policyInputs), policyInputs);
      if (!decision.allowed) {
        session.group.discard_staged_commit(session.provider, staged);
        finalized = true;
        return Object.freeze({ matched: true, allowed: false, reason: decision.reason });
      }
      requireB24Allow(decision);
      session.group.merge_staged_commit(session.provider, staged,
        hexToBytes('verifiedLeafDigestHex', projection.verifiedLeafDigestHex));
      finalized = true;
      staged = undefined;
      const successor = this.#successor(session, parent);
      if (successor.epochDec !== projection.candidateEpochDec
        || successor.groupContextDigestHex !== projection.candidateGroupContextDigestHex) {
        failB27(B27_ERROR.ENGINE_REJECTED, 'replay successor differs from projection');
      }
      const edge = buildEdge({ groupIdHex: parent.groupIdHex,
        commitDigestHex: input.commitDigestHex,
        parentSnapshotDigestHex: parent.snapshotDigestHex,
        successorSnapshotDigestHex: successor.snapshotDigestHex,
        parentEpochDec: parent.epochDec,
        parentGroupContextDigestHex: parent.groupContextDigestHex,
        successorEpochDec: successor.epochDec,
        successorGroupContextDigestHex: successor.groupContextDigestHex,
        projectionDigestHex: digestHex(canonicalProjectionBytes(projection)),
        verifiedLeafDigestHex: projection.verifiedLeafDigestHex,
        operationKind: decision.operationKind,
        priority: priorityForAuthorization(decision),
        committerIdentityHex: projection.committerIdentityHex,
        authorizationContextDigestHex: decision.contextDigestHex,
        authorizationResultDigestHex: decision.resultDigestHex,
        origin: B27_EDGE_ORIGIN.INBOUND, localGenerationDigestHex: null });
      return Object.freeze({ matched: true, allowed: true, edge, successor });
    } finally {
      if (staged !== undefined && !finalized) {
        try { session.group.discard_staged_commit(session.provider, staged); } catch { /* disposable */ }
      }
      safeFree(projectionHandle);
      safeFree(staged);
      dispose(session);
    }
  }

  async #tryLocal(parent, generation, pendingRetained) {
    if (generation.parentSnapshotDigestHex !== parent.snapshotDigestHex) {
      return Object.freeze({ matched: false, closed: false });
    }
    await this.#beforeReplay(generation.commitDigestHex, parent.snapshotDigestHex);
    const session = this.#restore(pendingRetained, true);
    let projectionHandle;
    try {
      if (!session.group.has_pending_commit(session.provider)) {
        failB27(B27_ERROR.CORRUPT, 'local pending snapshot lacks pending state');
      }
      projectionHandle = session.group.pending_projection(session.provider);
      if (projectionHandle === undefined) {
        failB27(B27_ERROR.CORRUPT, 'local pending projection is absent');
      }
      const projection = projectB2Commit(projectionHandle);
      const policyInputs = { parent: session.parent, candidate: projection,
        commitBytes: generation.commitBytes };
      const decision = verifyB24DecisionBinding(
        evaluateB24Authorization(policyInputs), policyInputs);
      requireB24Allow(decision);
      if (digestHex(canonicalProjectionBytes(projection)) !== generation.projectionDigestHex
        || projection.verifiedLeafDigestHex !== generation.verifiedLeafDigestHex
        || decision.contextDigestHex !== generation.authorizationContextDigestHex
        || decision.resultDigestHex !== generation.authorizationResultDigestHex) {
        failB27(B27_ERROR.CORRUPT, 'local generation evidence changed during replay');
      }
      session.group.confirm_pending_commit(session.provider, BigInt(generation.parentEpochDec),
        session.accountKey, session.signatureKey,
        hexToBytes('verifiedLeafDigestHex', generation.verifiedLeafDigestHex));
      const successor = this.#successor(session, parent);
      const edge = buildEdge({ groupIdHex: parent.groupIdHex,
        commitDigestHex: generation.commitDigestHex,
        parentSnapshotDigestHex: parent.snapshotDigestHex,
        successorSnapshotDigestHex: successor.snapshotDigestHex,
        parentEpochDec: parent.epochDec,
        parentGroupContextDigestHex: parent.groupContextDigestHex,
        successorEpochDec: successor.epochDec,
        successorGroupContextDigestHex: successor.groupContextDigestHex,
        projectionDigestHex: generation.projectionDigestHex,
        verifiedLeafDigestHex: generation.verifiedLeafDigestHex,
        operationKind: generation.operationKind, priority: generation.priority,
        committerIdentityHex: generation.committerIdentityHex,
        authorizationContextDigestHex: generation.authorizationContextDigestHex,
        authorizationResultDigestHex: generation.authorizationResultDigestHex,
        origin: B27_EDGE_ORIGIN.LOCAL,
        localGenerationDigestHex: generationAuthorityDigest(generation) });
      return Object.freeze({ matched: true, allowed: true, edge, successor });
    } finally {
      safeFree(projectionHandle);
      dispose(session);
    }
  }

  async #discover(bundle) {
    const stateByDigest = new Map(bundle.retained.map((item) =>
      [item.snapshotDigestHex, item]));
    const pendingStateDigests = new Set(bundle.generations.map((item) =>
      item.pendingSnapshotDigestHex));
    const anchor = stateByDigest.get(bundle.head.anchorSnapshotDigestHex);
    if (anchor === undefined) {
      failB27(B27_ERROR.UNRECOVERABLE, 'retained anchor is missing inside the horizon');
    }
    if (bundle.generations.some((item) => item.contradiction)) {
      failB27(B27_ERROR.UNRECOVERABLE,
        'historical local publication contradiction prevents convergence');
    }
    const sources = bundle.pass.closureCommitDigests.map((digest) => {
      const generation = bundle.generations.find((item) =>
        item.commitDigestHex === digest && ELIGIBLE_GENERATION_STATES.has(item.state));
      if (generation !== undefined) return Object.freeze({ digest, generation, input: null });
      const input = bundle.inputs.find((item) => item.commitDigestHex === digest);
      if (input === undefined) failB27(B27_ERROR.CORRUPT, 'frozen input is absent');
      return Object.freeze({ digest, generation: null, input });
    });
    const discovered = new Map();
    const terminal = new Map();
    const attemptedParents = new Map();
    const successfulParents = new Map();
    const candidateStates = () => [...stateByDigest.values()]
      .filter((state) => !pendingStateDigests.has(state.snapshotDigestHex))
      .filter((state) => BigInt(state.epochDec) - BigInt(anchor.epochDec)
        <= BigInt(B27_LIMITS.rewindCommits + 1))
      .sort((left, right) => left.snapshotDigestHex < right.snapshotDigestHex ? -1 : 1);
    let rounds = 0;
    let changed = true;
    while (changed) {
      changed = false;
      rounds += 1;
      if (rounds > B27_LIMITS.maxEdges + 1) {
        failB27(B27_ERROR.RESOURCE_LIMIT, 'fixed-point round bound exceeded');
      }
      for (const source of sources) {
        if (terminal.has(source.digest)) continue;
        const attempted = attemptedParents.get(source.digest) ?? new Set();
        const matches = successfulParents.get(source.digest) ?? [];
        let closedFailure = false;
        for (const parent of candidateStates()) {
          if (attempted.has(parent.snapshotDigestHex)) continue;
          attempted.add(parent.snapshotDigestHex);
          const pendingRetained = source.generation === null ? null
            : stateByDigest.get(source.generation.pendingSnapshotDigestHex)
              ?? bundle.retained.find((item) =>
                item.snapshotDigestHex === source.generation.pendingSnapshotDigestHex);
          if (source.generation !== null && pendingRetained === undefined) {
            failB27(B27_ERROR.UNRECOVERABLE, 'eligible local pending state is missing');
          }
          let result = source.generation === null
            ? await this.#tryInbound(parent, source.input)
            : await this.#tryLocal(parent, source.generation, pendingRetained);
          if (result.allowed) {
            const priorEdge = bundle.edges.find((edge) =>
              edge.parentSnapshotDigestHex === result.edge.parentSnapshotDigestHex
              && edge.commitDigestHex === result.edge.commitDigestHex);
            if (priorEdge !== undefined) {
              const priorSuccessor = bundle.retained.find((state) =>
                state.snapshotDigestHex === priorEdge.successorSnapshotDigestHex);
              if (priorSuccessor === undefined) {
                failB27(B27_ERROR.UNRECOVERABLE,
                  'existing replay edge lacks its retained successor');
              }
              const stableFields = ['parentEpochDec', 'parentGroupContextDigestHex',
                'successorEpochDec', 'successorGroupContextDigestHex',
                'projectionDigestHex', 'verifiedLeafDigestHex', 'operationKind', 'priority',
                'committerIdentityHex', 'authorizationContextDigestHex',
                'authorizationResultDigestHex', 'origin', 'localGenerationDigestHex'];
              if (stableFields.some((field) => priorEdge[field] !== result.edge[field])) {
                failB27(B27_ERROR.CORRUPT,
                  'fresh replay differs from durable edge evidence');
              }
              result = Object.freeze({ ...result, edge: priorEdge, successor: priorSuccessor });
            }
          }
          if (result.closed) closedFailure = true;
          if (result.matched) matches.push(result);
        }
        attemptedParents.set(source.digest, attempted);
        successfulParents.set(source.digest, matches);
        if (matches.length > 1) {
          terminal.set(source.digest, Object.freeze({ state: B27_INPUT_STATE.AMBIGUOUS,
            reason: B27_ERROR.AMBIGUOUS_PARENT }));
          discovered.delete(source.digest);
          continue;
        }
        if (matches.length === 1) {
          const match = matches[0];
          if (!match.allowed) {
            terminal.set(source.digest, Object.freeze({ state: B27_INPUT_STATE.REJECTED,
              reason: match.reason }));
            discovered.delete(source.digest);
          } else {
            const prior = discovered.get(source.digest);
            if (prior !== undefined && prior.edgeDigestHex !== match.edge.edgeDigestHex) {
              failB27(B27_ERROR.AMBIGUOUS_PARENT,
                `one Commit attached to multiple retained parents (${prior.parentSnapshotDigestHex}/${prior.successorSnapshotDigestHex} versus ${match.edge.parentSnapshotDigestHex}/${match.edge.successorSnapshotDigestHex})`);
            }
            if (prior === undefined) {
              if (discovered.size >= B27_LIMITS.maxEdges) {
                failB27(B27_ERROR.RESOURCE_LIMIT, 'retained graph edge cap is exhausted');
              }
              discovered.set(source.digest, match.edge);
              if (!stateByDigest.has(match.successor.snapshotDigestHex)) {
                if (stateByDigest.size >= B27_LIMITS.maxStates) {
                  failB27(B27_ERROR.RESOURCE_LIMIT, 'retained provider-state cap is exhausted');
                }
                stateByDigest.set(match.successor.snapshotDigestHex, match.successor);
                changed = true;
              }
            }
          }
        } else if (closedFailure) {
          terminal.set(source.digest, Object.freeze({ state: B27_INPUT_STATE.REJECTED,
            reason: 'CLOSED_ENGINE_REJECTION' }));
        }
      }
    }
    // Defensive second pass: a newly reachable parent must not make an existing edge ambiguous.
    for (const source of sources) {
      if (terminal.has(source.digest)) continue;
      const expected = discovered.get(source.digest);
      if (expected === undefined) continue;
      let count = 0;
      for (const parent of candidateStates()) {
        const pendingRetained = source.generation === null ? null
          : stateByDigest.get(source.generation.pendingSnapshotDigestHex)
            ?? bundle.retained.find((item) =>
              item.snapshotDigestHex === source.generation.pendingSnapshotDigestHex);
        const result = source.generation === null
          ? await this.#tryInbound(parent, source.input)
          : await this.#tryLocal(parent, source.generation, pendingRetained);
        if (result.matched) count += 1;
      }
      if (count > 1) {
        terminal.set(source.digest, Object.freeze({ state: B27_INPUT_STATE.AMBIGUOUS,
          reason: B27_ERROR.AMBIGUOUS_PARENT }));
        discovered.delete(source.digest);
      }
    }
    const updatedInputs = bundle.inputs.map((input) => {
      const edge = discovered.get(input.commitDigestHex);
      const closed = terminal.get(input.commitDigestHex);
      if (edge !== undefined) return rebuildInput(input, {
        state: B27_INPUT_STATE.EDGE, edgeDigestHex: edge.edgeDigestHex, reason: null });
      if (closed !== undefined) return rebuildInput(input, {
        state: closed.state, edgeDigestHex: null, reason: closed.reason });
      const anchorAdvanced = BigInt(bundle.head.epochDec) - BigInt(anchor.epochDec)
        >= BigInt(B27_LIMITS.rewindCommits);
      return rebuildInput(input, { state: anchorAdvanced ? B27_INPUT_STATE.STALE
        : B27_INPUT_STATE.DEFERRED, edgeDigestHex: null,
      reason: anchorAdvanced ? B27_ERROR.STALE : 'PARENT_NOT_YET_RETAINED' });
    });
    return Object.freeze({ anchor, states: Object.freeze([...stateByDigest.values()]),
      edges: Object.freeze([...discovered.values()]), inputs: Object.freeze(updatedInputs),
      rounds });
  }

  async settle(passDigestHex) {
    const bundle = await this.#journal.readFrozen(passDigestHex);
    let graph;
    try {
      graph = await this.#discover(bundle);
    } catch (error) {
      if (error?.code === B27_ERROR.UNRECOVERABLE) {
        await this.#markUnrecoverable(bundle.head);
      }
      throw error;
    }
    const branches = enumerateBranches(graph.anchor.snapshotDigestHex,
      graph.edges, B27_LIMITS.rewindCommits + 1);
    const winner = branches[0];
    if (winner === undefined) failB27(B27_ERROR.CORRUPT, 'branch enumeration is empty');
    const winnerState = graph.states.find((item) =>
      item.snapshotDigestHex === winner.snapshotDigestHex);
    if (winnerState === undefined) failB27(B27_ERROR.CORRUPT, 'winner state is absent');
    let anchor = graph.anchor;
    let anchorTipCommitDigestHex = bundle.head.anchorTipCommitDigestHex;
    let anchorAdvanceEdge = null;
    let selectedPath = [...winner.path];
    const releaseCandidates = [];
    if (selectedPath.length > B27_LIMITS.rewindCommits) {
      const firstEdge = graph.edges.find((item) =>
        item.parentSnapshotDigestHex === anchor.snapshotDigestHex
        && item.commitDigestHex === selectedPath[0]);
      if (firstEdge === undefined) failB27(B27_ERROR.CORRUPT, 'anchor advance edge is absent');
      releaseCandidates.push(anchor);
      anchor = graph.states.find((item) =>
        item.snapshotDigestHex === firstEdge.successorSnapshotDigestHex);
      anchorAdvanceEdge = firstEdge;
      anchorTipCommitDigestHex = firstEdge.commitDigestHex;
      selectedPath = selectedPath.slice(1);
    }
    if (BigInt(winnerState.epochDec) < BigInt(bundle.head.epochDec)) {
      failB27(B27_ERROR.CORRUPT, 'settlement cannot lower the canonical epoch');
    }
    const displacedPath = [...bundle.head.canonicalPath];
    const reachableStates = new Set([anchor.snapshotDigestHex]);
    let reachabilityChanged = true;
    while (reachabilityChanged) {
      reachabilityChanged = false;
      for (const edge of graph.edges) {
        if (reachableStates.has(edge.parentSnapshotDigestHex)
          && !reachableStates.has(edge.successorSnapshotDigestHex)) {
          reachableStates.add(edge.successorSnapshotDigestHex);
          reachabilityChanged = true;
        }
      }
    }
    const retainedEdges = graph.edges.filter((edge) =>
      reachableStates.has(edge.parentSnapshotDigestHex)
      && reachableStates.has(edge.successorSnapshotDigestHex));
    const retainedEdgeCommits = new Set(retainedEdges.map((edge) => edge.commitDigestHex));
    const normalizedInputs = graph.inputs.map((input) => {
      if (input.state !== B27_INPUT_STATE.EDGE
        || retainedEdgeCommits.has(input.commitDigestHex)) return input;
      return rebuildInput(input, { state: B27_INPUT_STATE.STALE,
        edgeDigestHex: null, reason: B27_ERROR.STALE });
    });
    const generations = bundle.generations.map((generation) => {
      if (!ELIGIBLE_GENERATION_STATES.has(generation.state)) return generation;
      if (selectedPath.includes(generation.commitDigestHex)) {
        return rebuildGeneration(generation, { state: B27_GENERATION_STATE.SELECTED });
      }
      if (retainedEdgeCommits.has(generation.commitDigestHex)) {
        return rebuildGeneration(generation, { state: B27_GENERATION_STATE.LOSING });
      }
      return rebuildGeneration(generation, { state: B27_GENERATION_STATE.REJECTED });
    });
    for (const generation of generations) {
      if (RETENTION_REQUIRED_GENERATION_STATES.has(generation.state)) {
        reachableStates.add(generation.pendingSnapshotDigestHex);
      }
    }
    const durableStateDigests = new Set(bundle.retained.map((state) =>
      state.snapshotDigestHex));
    for (const state of graph.states) {
      if (durableStateDigests.has(state.snapshotDigestHex)
        && !reachableStates.has(state.snapshotDigestHex)
        && !releaseCandidates.some((item) =>
          item.snapshotDigestHex === state.snapshotDigestHex)) {
        releaseCandidates.push(state);
      }
    }
    const retainedStates = graph.states.filter((state) =>
      reachableStates.has(state.snapshotDigestHex));
    const invalidation = buildInvalidation({ groupIdHex: bundle.head.groupIdHex,
      predecessorHeadDigestHex: bundle.head.headDigestHex,
      successorSnapshotDigestHex: winnerState.snapshotDigestHex,
      commonAncestorSnapshotDigestHex: graph.anchor.snapshotDigestHex,
      displacedPath, selectedPath });
    const transition = buildTransition({ groupIdHex: bundle.head.groupIdHex,
      seq: bundle.head.seq + 1, kind: 'SETTLE',
      predecessorHeadDigestHex: bundle.head.headDigestHex,
      successorSnapshotDigestHex: winnerState.snapshotDigestHex,
      anchorSnapshotDigestHex: anchor.snapshotDigestHex,
      anchorTipCommitDigestHex,
      selectedPath, displacedPath, passDigestHex: bundle.pass.passDigestHex,
      invalidationDigestHex: invalidation.invalidationDigestHex,
      releasedStateDigests: releaseCandidates.map((item) => item.snapshotDigestHex).sort(),
      epochDec: winnerState.epochDec,
      groupContextDigestHex: winnerState.groupContextDigestHex });
    const nextHead = buildHead({ groupIdHex: bundle.head.groupIdHex,
      accountKeyHex: bundle.head.accountKeyHex, signatureKeyHex: bundle.head.signatureKeyHex,
      seq: bundle.head.seq + 1, state: B27_HEAD_STATE.STABLE,
      epochDec: winnerState.epochDec,
      groupContextDigestHex: winnerState.groupContextDigestHex,
      snapshotDigestHex: winnerState.snapshotDigestHex,
      anchorSnapshotDigestHex: anchor.snapshotDigestHex,
      anchorTipCommitDigestHex, canonicalPath: selectedPath,
      priorHeadDigestHex: bundle.head.headDigestHex,
      transitionDigestHex: transition.transitionDigestHex,
      selectedCommitDigestHex: selectedPath.at(-1) ?? null });
    const releases = releaseCandidates.map((item) => buildRelease({
      groupIdHex: item.groupIdHex, snapshotDigestHex: item.snapshotDigestHex,
      epochDec: item.epochDec, groupContextDigestHex: item.groupContextDigestHex,
      retainedDigestHex: item.retainedDigestHex,
      releaseAuthorityDigestHex: transition.transitionDigestHex }));
    const settledPass = buildPass({ groupIdHex: bundle.pass.groupIdHex,
      baseHeadDigestHex: bundle.pass.baseHeadDigestHex,
      closureCommitDigests: bundle.pass.closureCommitDigests,
      state: B27_PASS_STATE.SETTLED, rounds: graph.rounds, selectedPath });
    return this.#commitSettlement({ expectedHead: bundle.head,
      expectedReadSetDigestHex: bundle.readSetDigestHex, settledPass, nextHead,
      transition, invalidation, states: retainedStates, edges: retainedEdges,
      inputs: normalizedInputs, releases, generations, anchorAdvanceEdge });
  }

  async prepareLocal(groupIdHex, operationKind, operationPayloadBytes = new Uint8Array()) {
    assertGroupIdHex(groupIdHex);
    assertBytes('operationPayloadBytes', operationPayloadBytes,
      { min: 0, max: B27_LIMITS.maxCommitBytes });
    const bundle = await this.#journal.snapshot(groupIdHex);
    if (bundle.head.state !== B27_HEAD_STATE.STABLE) {
      failB27(B27_ERROR.STATE_CONFLICT, 'local preparation requires stable group');
    }
    if (bundle.activeLocal?.generationDigestHex !== null) {
      failB27(B27_ERROR.STATE_CONFLICT, 'one local generation is already active');
    }
    const retained = bundle.retained.find((item) =>
      item.snapshotDigestHex === bundle.head.snapshotDigestHex);
    if (retained === undefined) failB27(B27_ERROR.UNRECOVERABLE, 'canonical state is absent');
    const session = this.#restore(retained);
    let pending;
    let keyPackage;
    let projectionHandle;
    try {
      const argument = operationPayload(operationKind, operationPayloadBytes);
      if (operationKind === 'self-update') {
        pending = session.group.prepare_self_update(session.provider, session.identity);
      } else if (operationKind === 'add') {
        keyPackage = this.#wasm.PhaseB2KeyPackage.from_framed_bytes(argument);
        pending = session.group.prepare_add(session.provider, session.identity, keyPackage);
      } else {
        const own = session.parent.members.find((member) =>
          member.identityHex === bundle.head.accountKeyHex);
        if (own?.leafIndex === argument) failB27(B27_ERROR.INVALID, 'self-removal is excluded');
        pending = session.group.prepare_remove(session.provider, session.identity, argument);
      }
      const commitBytes = copyBytes(pending.commit());
      projectionHandle = pending.projection();
      const projection = projectB2Commit(projectionHandle);
      const inputs = { parent: session.parent, candidate: projection, commitBytes };
      const decision = verifyB24DecisionBinding(evaluateB24Authorization(inputs), inputs);
      requireB24Allow(decision);
      const scope = session.parent.members.map((member) => member.identityHex)
        .filter((identity) => identity !== retained.accountKeyHex).sort();
      if (scope.length === 0 || new Set(scope).size !== scope.length) {
        failB27(B27_ERROR.INVALID, 'publication scope must contain unique peers');
      }
      const pendingRetained = buildRetainedState({ groupIdHex: retained.groupIdHex,
        accountKeyHex: retained.accountKeyHex, signatureKeyHex: retained.signatureKeyHex,
        epochDec: retained.epochDec, groupContextDigestHex: retained.groupContextDigestHex,
        snapshotBytes: copyBytes(session.provider.serialize_state()) });
      const generationFloor = Math.max(bundle.generationTruncation?.throughGeneration ?? 0,
        ...bundle.generations.map((item) => item.generation));
      const generation = buildGeneration({ groupIdHex,
        generation: generationFloor + 1, state: B27_GENERATION_STATE.PREPARED,
        operationKind, parentHeadDigestHex: bundle.head.headDigestHex,
        parentSnapshotDigestHex: retained.snapshotDigestHex,
        parentEpochDec: retained.epochDec,
        parentGroupContextDigestHex: retained.groupContextDigestHex,
        pendingSnapshotDigestHex: pendingRetained.snapshotDigestHex,
        commitDigestHex: digestHex(commitBytes), commitBytes,
        commitByteLength: commitBytes.length,
        verifiedLeafDigestHex: projection.verifiedLeafDigestHex,
        projectionDigestHex: digestHex(canonicalProjectionBytes(projection)),
        candidateEpochDec: projection.candidateEpochDec,
        candidateGroupContextDigestHex: projection.candidateGroupContextDigestHex,
        priority: priorityForAuthorization(decision),
        committerIdentityHex: projection.committerIdentityHex,
        authorizationContextDigestHex: decision.contextDigestHex,
        authorizationResultDigestHex: decision.resultDigestHex,
        recipientScope: scope, publishAttempts: 0, ackCount: 0, failureCount: 0,
        contradiction: false });
      return this.#commitPrepared({ expectedHead: bundle.head, generation, pendingRetained });
    } finally {
      safeFree(projectionHandle); safeFree(pending); safeFree(keyPackage); dispose(session);
    }
  }

  async #activeGeneration(groupIdHex) {
    const view = await this.#journal.snapshot(groupIdHex);
    if (view.head.state !== B27_HEAD_STATE.STABLE) {
      failB27(B27_ERROR.STATE_CONFLICT, 'local publication requires stable group');
    }
    const digest = view.activeLocal?.generationDigestHex;
    if (digest === null || digest === undefined) {
      failB27(B27_ERROR.STATE_CONFLICT, 'active local generation is absent');
    }
    const generation = view.generations.find((item) => item.generationDigestHex === digest);
    if (generation === undefined) failB27(B27_ERROR.CORRUPT, 'active pointer target is absent');
    return Object.freeze({ view, generation });
  }

  async recordAttempt(groupIdHex) {
    const { view, generation } = await this.#activeGeneration(groupIdHex);
    if (![B27_GENERATION_STATE.PREPARED, B27_GENERATION_STATE.PUBLISHING]
      .includes(generation.state)) {
      failB27(B27_ERROR.STATE_CONFLICT, 'attempt requires prepared generation');
    }
    const existing = view.publications.filter((item) =>
      item.artifactDigestHex === generation.commitDigestHex);
    if (existing.length >= B27_LIMITS.maxPublicationRecordsPerGeneration - 1) {
      failB27(B27_ERROR.RESOURCE_LIMIT, 'publication capacity cannot reserve an outcome');
    }
    const ordinal = generation.publishAttempts + 1;
    const next = rebuildGeneration(generation, {
      state: B27_GENERATION_STATE.PUBLISHING, publishAttempts: ordinal });
    const evidence = buildPublication({ groupIdHex: generation.groupIdHex,
      generationDigestHex: generation.generationDigestHex, sequence: existing.length + 1,
      kind: B27_PUBLICATION_KIND.ATTEMPT, attemptOrdinal: ordinal,
      artifactDigestHex: generation.commitDigestHex, recipientIdentityHex: null,
      payloadBytes: new Uint8Array() });
    return this.#appendPublication({ expectedGeneration: generation, evidence,
      nextGeneration: next });
  }

  recordAcknowledgement(groupIdHex, attemptOrdinal, recipientIdentityHex,
    payloadBytes = new Uint8Array()) {
    return this.#recordOutcome(groupIdHex, B27_PUBLICATION_KIND.ACK,
      attemptOrdinal, recipientIdentityHex, payloadBytes);
  }

  recordFailure(groupIdHex, attemptOrdinal, recipientIdentityHex,
    payloadBytes = new Uint8Array()) {
    return this.#recordOutcome(groupIdHex, B27_PUBLICATION_KIND.FAILURE,
      attemptOrdinal, recipientIdentityHex, payloadBytes);
  }

  async #recordOutcome(groupIdHex, requestedKind, attemptOrdinal, recipientIdentityHex,
    payloadBytes) {
    assertSafeInteger('attemptOrdinal', attemptOrdinal, 1, B27_LIMITS.maxPublicationAttempts);
    assertHex64('recipientIdentityHex', recipientIdentityHex);
    assertBytes('payloadBytes', payloadBytes,
      { min: 0, max: B27_LIMITS.maxPublicationPayloadBytes });
    const { view, generation } = await this.#activeGeneration(groupIdHex);
    return this.#recordGenerationOutcome(view, generation, requestedKind,
      attemptOrdinal, recipientIdentityHex, payloadBytes);
  }

  async recordHistoricalAcknowledgement(groupIdHex, commitDigestHex, attemptOrdinal,
    recipientIdentityHex, payloadBytes = new Uint8Array()) {
    assertGroupIdHex(groupIdHex);
    assertHex64('commitDigestHex', commitDigestHex);
    assertSafeInteger('attemptOrdinal', attemptOrdinal, 1, B27_LIMITS.maxPublicationAttempts);
    assertHex64('recipientIdentityHex', recipientIdentityHex);
    assertBytes('payloadBytes', payloadBytes,
      { min: 0, max: B27_LIMITS.maxPublicationPayloadBytes });
    const view = await this.#journal.snapshot(groupIdHex);
    const generation = view.generations.find((item) => item.commitDigestHex === commitDigestHex);
    if (generation === undefined) {
      failB27(B27_ERROR.UNKNOWN_GENERATION,
        'historical publication generation is unavailable', {
          commitDigestHex,
          truncationMarker: view.generationTruncation,
        });
    }
    return this.#recordGenerationOutcome(view, generation, B27_PUBLICATION_KIND.ACK,
      attemptOrdinal, recipientIdentityHex, payloadBytes);
  }

  async #recordGenerationOutcome(view, generation, requestedKind, attemptOrdinal,
    recipientIdentityHex, payloadBytes) {
    if (!generation.recipientScope.includes(recipientIdentityHex)) {
      failB27(B27_ERROR.INVALID, 'publication recipient is outside exact scope');
    }
    const publications = view.publications.filter((item) =>
      item.artifactDigestHex === generation.commitDigestHex);
    const attempt = publications.find((item) => item.kind === B27_PUBLICATION_KIND.ATTEMPT
      && item.attemptOrdinal === attemptOrdinal);
    if (attempt === undefined) failB27(B27_ERROR.INVALID, 'outcome lacks durable attempt');
    const terminal = TERMINAL_GENERATION_STATES.has(generation.state);
    const kind = requestedKind === B27_PUBLICATION_KIND.ACK && terminal
      ? (generation.state === B27_GENERATION_STATE.CANCELLED
        || generation.state === B27_GENERATION_STATE.DISCARDED
          ? B27_PUBLICATION_KIND.CONTRADICTION : B27_PUBLICATION_KIND.LATE_ACK)
      : requestedKind;
    const duplicate = publications.find((item) => item.kind === kind
      && item.attemptOrdinal === attemptOrdinal
      && item.recipientIdentityHex === recipientIdentityHex
      && item.payloadDigestHex === digestHex(payloadBytes));
    if (duplicate !== undefined) return Object.freeze({ status: 'duplicate', evidence: duplicate,
      generation });
    if (publications.length >= B27_LIMITS.maxPublicationRecordsPerGeneration) {
      failB27(B27_ERROR.RESOURCE_LIMIT, 'generation evidence capacity is exhausted');
    }
    const next = rebuildGeneration(generation, {
      state: !terminal && requestedKind === B27_PUBLICATION_KIND.ACK
        ? B27_GENERATION_STATE.ACKNOWLEDGED : generation.state,
      ackCount: generation.ackCount
        + (!terminal && requestedKind === B27_PUBLICATION_KIND.ACK ? 1 : 0),
      failureCount: generation.failureCount
        + (!terminal && requestedKind === B27_PUBLICATION_KIND.FAILURE ? 1 : 0),
      contradiction: generation.contradiction || kind === B27_PUBLICATION_KIND.CONTRADICTION,
    });
    const evidence = buildPublication({ groupIdHex: generation.groupIdHex,
      generationDigestHex: generation.generationDigestHex,
      sequence: publications.length + 1, kind, attemptOrdinal,
      artifactDigestHex: generation.commitDigestHex, recipientIdentityHex,
      payloadBytes });
    return this.#appendPublication({ expectedGeneration: generation, evidence,
      nextGeneration: next });
  }

  async cancelBeforeAttempt(groupIdHex) {
    const { generation } = await this.#activeGeneration(groupIdHex);
    if (generation.state !== B27_GENERATION_STATE.PREPARED
      || generation.publishAttempts !== 0) {
      failB27(B27_ERROR.STATE_CONFLICT, 'cancel requires pre-attempt generation');
    }
    return this.#replaceGeneration(generation,
      rebuildGeneration(generation, { state: B27_GENERATION_STATE.CANCELLED }),
      { clearActive: true });
  }

  async discardAfterFailure(groupIdHex) {
    const { generation } = await this.#activeGeneration(groupIdHex);
    if (generation.state !== B27_GENERATION_STATE.PUBLISHING
      || generation.failureCount < 1 || generation.ackCount !== 0) {
      failB27(B27_ERROR.STATE_CONFLICT, 'discard requires failure and no ACK');
    }
    return this.#replaceGeneration(generation,
      rebuildGeneration(generation, { state: B27_GENERATION_STATE.DISCARDED }),
      { clearActive: true });
  }

  #restoreMessageContext(context) {
    const source = context.snapshot === null
      ? context.retained
      : Object.freeze({
          ...context.retained,
          epochDec: context.state.epochDec,
          groupContextDigestHex: context.state.groupContextDigestHex,
          snapshotBytes: context.snapshot.snapshotBytes,
        });
    return this.#restore(source);
  }

  #messageScope(session, localIdentityHex) {
    const scope = session.parent.members
      .map((member) => member.identityHex)
      .filter((identityHex) => identityHex !== localIdentityHex)
      .sort();
    if (scope.length === 0 || scope.length > B27_LIMITS.maxMembers
      || new Set(scope).size !== scope.length) {
      failB27(B27_ERROR.INVALID, 'application recipient scope is invalid');
    }
    return Object.freeze(scope);
  }

  #nextMessageState(context, snapshot, { sentDelta, receivedDelta }) {
    const prior = context.state;
    return buildMessageState({
      groupIdHex: context.head.groupIdHex,
      instanceKeyHex: context.instanceKeyHex,
      baseHeadDigestHex: prior?.baseHeadDigestHex ?? context.head.headDigestHex,
      tipCommitDigestHex: prior?.tipCommitDigestHex ?? context.tipCommitDigestHex,
      epochDec: prior?.epochDec ?? context.retained.epochDec,
      groupContextDigestHex:
        prior?.groupContextDigestHex ?? context.retained.groupContextDigestHex,
      localMemberIdentityHex: context.head.accountKeyHex,
      baseRetainedSnapshotDigestHex:
        prior?.baseRetainedSnapshotDigestHex ?? context.retained.snapshotDigestHex,
      sequence: (prior?.sequence ?? 0) + 1,
      sentCount: (prior?.sentCount ?? 0) + sentDelta,
      receivedCount: (prior?.receivedCount ?? 0) + receivedDelta,
      snapshotDigestHex: snapshot.snapshotDigestHex,
      priorStateDigestHex: prior?.stateDigestHex ?? null,
      state: B27_MESSAGE_STATE.ACTIVE,
    });
  }

  async queueApplicationMessage(groupIdHex, requestId, plaintextBytes) {
    assertGroupIdHex(groupIdHex);
    assertString('requestId', requestId,
      { min: 1, max: B27_LIMITS.maxRequestIdBytes, pattern: /^[\x21-\x7e]+$/ });
    if (requestId.startsWith(PROBE_REQUEST_PREFIX)) {
      failB27(B27_ERROR.INVALID, 'request id uses the reserved liveness-probe namespace');
    }
    assertBytes('application plaintext', plaintextBytes,
      { min: 1, max: B27_LIMITS.maxApplicationPayloadBytes });
    return this.#queueApplicationMessage(
      groupIdHex, requestId, plaintextBytes, null);
  }

  async #queueApplicationMessage(groupIdHex, requestId, plaintextBytes,
    expectedInstanceKeyHex) {
    const context = await this.#journal.readMessageContext(groupIdHex);
    if (expectedInstanceKeyHex !== null
      && context.instanceKeyHex !== expectedInstanceKeyHex) {
      failB27(B27_ERROR.CAS_CONFLICT,
        'canonical message instance changed after probe reservation');
    }
    const session = this.#restoreMessageContext(context);
    try {
      const recipientScope = this.#messageScope(session, context.head.accountKeyHex);
      const payloadDigestHex = digestHex(plaintextBytes);
      const existing = await this.#journal.findOutboxRequest(
        context.instanceKeyHex, requestId);
      if (existing !== null) {
        if (existing.payloadDigestHex !== payloadDigestHex
          || existing.recipientScope.length !== recipientScope.length
          || existing.recipientScope.some((item, index) => item !== recipientScope[index])) {
          failB27(B27_ERROR.REQUEST_CONFLICT,
            'request id was reused with different application inputs');
        }
        return Object.freeze({ status: 'duplicate',
          instanceKeyHex: existing.instanceKeyHex, ordinal: existing.ordinal });
      }
      const ciphertextBytes = copyBytes(session.group.create_application_message(
        session.provider, session.identity, plaintextBytes));
      const snapshot = buildMessageSnapshot({
        groupIdHex,
        instanceKeyHex: context.instanceKeyHex,
        epochDec: context.retained.epochDec,
        groupContextDigestHex: context.retained.groupContextDigestHex,
        snapshotBytes: copyBytes(session.provider.serialize_state()),
      });
      const state = this.#nextMessageState(context, snapshot,
        { sentDelta: 1, receivedDelta: 0 });
      const outbox = buildOutbox({
        groupIdHex,
        instanceKeyHex: context.instanceKeyHex,
        requestId,
        requestKeyHex: requestKey(context.instanceKeyHex, requestId),
        ordinal: state.sentCount,
        payloadDigestHex,
        recipientScope,
        ciphertextBytes,
        ciphertextDigestHex: digestHex(ciphertextBytes),
        state: B27_OUTBOX_STATE.DURABLE,
        attemptCount: 0,
        ackCount: 0,
        failureCount: 0,
      });
      await this.#beforeOutboundCommit(Object.freeze({
        instanceKeyHex: context.instanceKeyHex,
        ordinal: outbox.ordinal,
        priorStateDigestHex: context.state?.stateDigestHex ?? null,
      }));
      const committed = await this.#commitOutbound({
        expectedHead: context.head,
        expectedRetained: context.retained,
        expectedMessageState: context.state,
        nextMessageState: state,
        nextSnapshot: snapshot,
        outbox,
      });
      return Object.freeze({ status: committed.status,
        instanceKeyHex: committed.outbox.instanceKeyHex,
        ordinal: committed.outbox.ordinal });
    } finally {
      dispose(session);
    }
  }

  async readQueuedApplicationMessage(instanceKeyHex, ordinal) {
    assertHex64('instanceKeyHex', instanceKeyHex);
    assertSafeInteger('outbox ordinal', ordinal, 1, Number.MAX_SAFE_INTEGER);
    const durable = await this.#journal.readOutbox(instanceKeyHex, ordinal);
    if (![B27_OUTBOX_STATE.DURABLE, B27_OUTBOX_STATE.ATTEMPTED]
      .includes(durable.state)) {
      failB27(durable.state === B27_OUTBOX_STATE.SUSPENDED
        ? B27_ERROR.OUTBOX_SUSPENDED : B27_ERROR.OUTBOX_TERMINAL,
      'outbox bytes are not releasable in their current state');
    }
    return durable;
  }

  async recordApplicationAttempt(instanceKeyHex, ordinal, recipientIdentityHex) {
    assertHex64('instanceKeyHex', instanceKeyHex);
    assertSafeInteger('outbox ordinal', ordinal, 1, Number.MAX_SAFE_INTEGER);
    assertHex64('recipientIdentityHex', recipientIdentityHex);
    const prior = await this.#journal.readOutbox(instanceKeyHex, ordinal);
    if (![B27_OUTBOX_STATE.DURABLE, B27_OUTBOX_STATE.ATTEMPTED]
      .includes(prior.state)) {
      failB27(B27_ERROR.OUTBOX_TERMINAL,
        'publication attempt requires a live durable outbox');
    }
    if (!prior.recipientScope.includes(recipientIdentityHex)) {
      failB27(B27_ERROR.INVALID, 'attempt recipient is outside the immutable scope');
    }
    if (prior.attemptCount >= B27_LIMITS.maxMessagePublicationRecords) {
      failB27(B27_ERROR.RESOURCE_LIMIT, 'application attempt bound is exhausted');
    }
    const records = await this.#journal.readAppPublications(instanceKeyHex, ordinal);
    if (records.length >= B27_LIMITS.maxMessagePublicationRecords - 1) {
      failB27(B27_ERROR.RESOURCE_LIMIT,
        'application evidence capacity cannot reserve an outcome');
    }
    const attemptOrdinal = prior.attemptCount + 1;
    const empty = new Uint8Array();
    const evidence = buildAppPublication({
      groupIdHex: prior.groupIdHex,
      instanceKeyHex,
      ordinal,
      sequence: records.length + 1,
      kind: B27_APP_PUBLICATION_KIND.ATTEMPT,
      attemptOrdinal,
      recipientIdentityHex,
      payloadBytes: empty,
      payloadDigestHex: digestHex(empty),
    });
    const next = rebuildOutbox(prior, {
      state: B27_OUTBOX_STATE.ATTEMPTED,
      attemptCount: attemptOrdinal,
    });
    const appended = await this.#appendAppPublication({
      expectedOutbox: prior, nextOutbox: next, evidence });
    return Object.freeze({ instanceKeyHex, ordinal,
      attemptOrdinal, evidence: appended.evidence });
  }

  recordApplicationAcknowledgement(instanceKeyHex, ordinal, attemptOrdinal,
    recipientIdentityHex, payloadBytes = new Uint8Array()) {
    return this.#recordApplicationOutcome(instanceKeyHex, ordinal,
      B27_APP_PUBLICATION_KIND.ACK, attemptOrdinal, recipientIdentityHex, payloadBytes);
  }

  recordApplicationFailure(instanceKeyHex, ordinal, attemptOrdinal,
    recipientIdentityHex, payloadBytes = new Uint8Array()) {
    return this.#recordApplicationOutcome(instanceKeyHex, ordinal,
      B27_APP_PUBLICATION_KIND.FAILURE, attemptOrdinal, recipientIdentityHex, payloadBytes);
  }

  async #recordApplicationOutcome(instanceKeyHex, ordinal, kind, attemptOrdinal,
    recipientIdentityHex, payloadBytes) {
    assertHex64('instanceKeyHex', instanceKeyHex);
    assertSafeInteger('outbox ordinal', ordinal, 1, Number.MAX_SAFE_INTEGER);
    assertSafeInteger('attemptOrdinal', attemptOrdinal, 1,
      B27_LIMITS.maxMessagePublicationRecords);
    assertHex64('recipientIdentityHex', recipientIdentityHex);
    assertBytes('application evidence payload', payloadBytes,
      { min: 0, max: B27_LIMITS.maxPublicationPayloadBytes });
    const prior = await this.#journal.readOutbox(instanceKeyHex, ordinal);
    if (!prior.recipientScope.includes(recipientIdentityHex)) {
      failB27(B27_ERROR.INVALID, 'outcome recipient is outside the immutable scope');
    }
    const records = await this.#journal.readAppPublications(instanceKeyHex, ordinal);
    const attempt = records.find((item) =>
      item.kind === B27_APP_PUBLICATION_KIND.ATTEMPT
      && item.attemptOrdinal === attemptOrdinal
      && item.recipientIdentityHex === recipientIdentityHex);
    if (attempt === undefined) failB27(B27_ERROR.INVALID,
      'application outcome lacks its exact durable attempt');
    const terminal = [B27_OUTBOX_STATE.ACKNOWLEDGED,
      B27_OUTBOX_STATE.INVALIDATED, B27_OUTBOX_STATE.FAILED_DISCARDED]
      .includes(prior.state);
    const effectiveKind = kind === B27_APP_PUBLICATION_KIND.ACK && terminal
      ? B27_APP_PUBLICATION_KIND.LATE_ACK : kind;
    const payloadDigestHex = digestHex(payloadBytes);
    const requestedDuplicate = records.find((item) => item.kind === kind
      && item.attemptOrdinal === attemptOrdinal
      && item.recipientIdentityHex === recipientIdentityHex
      && item.payloadDigestHex === payloadDigestHex);
    if (requestedDuplicate !== undefined) {
      return Object.freeze({ status: 'duplicate', outbox: prior,
        evidence: requestedDuplicate });
    }
    const duplicate = records.find((item) => item.kind === effectiveKind
      && item.attemptOrdinal === attemptOrdinal
      && item.recipientIdentityHex === recipientIdentityHex
      && item.payloadDigestHex === payloadDigestHex);
    if (duplicate !== undefined) {
      return Object.freeze({ status: 'duplicate', outbox: prior, evidence: duplicate });
    }
    if (records.length >= B27_LIMITS.maxMessagePublicationRecords) {
      failB27(B27_ERROR.RESOURCE_LIMIT, 'application evidence bound is exhausted');
    }
    if (kind === B27_APP_PUBLICATION_KIND.FAILURE
      && records.length >= B27_LIMITS.maxMessagePublicationRecords - 1) {
      failB27(B27_ERROR.RESOURCE_LIMIT,
        'failure evidence cannot consume the final acknowledgement slot');
    }
    const acknowledgedRecipients = new Set(records
      .filter((item) => item.kind === B27_APP_PUBLICATION_KIND.ACK)
      .map((item) => item.recipientIdentityHex));
    if (!terminal && kind === B27_APP_PUBLICATION_KIND.ACK) {
      acknowledgedRecipients.add(recipientIdentityHex);
    }
    const next = terminal ? prior : rebuildOutbox(prior, {
      state: acknowledgedRecipients.size === prior.recipientScope.length
        ? B27_OUTBOX_STATE.ACKNOWLEDGED : prior.state,
      ackCount: prior.ackCount + (kind === B27_APP_PUBLICATION_KIND.ACK ? 1 : 0),
      failureCount: prior.failureCount
        + (kind === B27_APP_PUBLICATION_KIND.FAILURE ? 1 : 0),
    });
    const evidence = buildAppPublication({
      groupIdHex: prior.groupIdHex,
      instanceKeyHex,
      ordinal,
      sequence: records.length + 1,
      kind: effectiveKind,
      attemptOrdinal,
      recipientIdentityHex,
      payloadBytes,
      payloadDigestHex,
    });
    const appended = await this.#appendAppPublication({
      expectedOutbox: prior, nextOutbox: next, evidence });
    return Object.freeze({ status: 'recorded',
      outbox: appended.outbox, evidence: appended.evidence });
  }

  async discardApplicationAfterFailure(instanceKeyHex, ordinal) {
    assertHex64('instanceKeyHex', instanceKeyHex);
    assertSafeInteger('outbox ordinal', ordinal, 1, Number.MAX_SAFE_INTEGER);
    const prior = await this.#journal.readOutbox(instanceKeyHex, ordinal);
    if (prior.state !== B27_OUTBOX_STATE.ATTEMPTED
      || prior.failureCount < 1 || prior.ackCount !== 0) {
      failB27(B27_ERROR.STATE_CONFLICT,
        'discard requires failure evidence and no acknowledgement');
    }
    return this.#replaceOutbox({
      expectedOutbox: prior,
      nextOutbox: rebuildOutbox(prior, {
        state: B27_OUTBOX_STATE.FAILED_DISCARDED,
      }),
    });
  }

  async processApplicationMessage(groupIdHex, ciphertextBytes,
    retainedSnapshotDigestHex = null) {
    assertGroupIdHex(groupIdHex);
    assertBytes('application ciphertext', ciphertextBytes,
      { min: 1, max: B27_LIMITS.maxApplicationCiphertextBytes });
    if (retainedSnapshotDigestHex !== null) {
      assertHex64('retainedSnapshotDigestHex', retainedSnapshotDigestHex);
    }
    const context = retainedSnapshotDigestHex === null
      ? await this.#journal.readMessageContext(groupIdHex)
      : await this.#journal.readRetainedMessageContext(
          groupIdHex, retainedSnapshotDigestHex);
    const ciphertextDigestHex = digestHex(ciphertextBytes);
    const existing = await this.#journal.readInbound(
      context.instanceKeyHex, ciphertextDigestHex);
    if (existing !== null) {
      if (existing.disposition === B27_INBOUND_STATE.ACCEPTED) {
        return durableInboundResult('duplicate', existing);
      }
      if (context.canonical !== true
        || existing.disposition !== B27_INBOUND_STATE.DEFERRED) {
        failB27(B27_ERROR.STATE_CONFLICT,
          'duplicate ciphertext has no accepted durable delivery');
      }
    }
    if (context.canonical === false) {
      const deferred = buildInbound({
        groupIdHex,
        instanceKeyHex: context.instanceKeyHex,
        baseRetainedSnapshotDigestHex: context.retained.snapshotDigestHex,
        ciphertextBytes,
        ciphertextDigestHex,
        disposition: B27_INBOUND_STATE.DEFERRED,
        receivedOrdinal: 0,
        epochDec: null,
        groupContextDigestHex: null,
        verifiedLeafDigestHex: null,
        senderLeafIndex: null,
        senderIdentityHex: null,
        senderSignatureKeyHex: null,
        senderIdentityProofHex: null,
        plaintextBytes: new Uint8Array(),
        plaintextDigestHex: null,
      });
      await this.#beforeInboundCommit(Object.freeze({
        instanceKeyHex: context.instanceKeyHex,
        ciphertextDigestHex,
        disposition: B27_INBOUND_STATE.DEFERRED,
      }));
      const committed = await this.#commitDeferredInbound({
        expectedHead: context.head,
        expectedRetained: context.retained,
        tipCommitDigestHex: context.tipCommitDigestHex,
        inbound: deferred,
      });
      return Object.freeze({ status: committed.status,
        instanceKeyHex: context.instanceKeyHex,
        ciphertextDigestHex });
    }
    const session = this.#restoreMessageContext(context);
    let received;
    try {
      received = session.group.receive_application_message(
        session.provider, ciphertextBytes);
      const sender = authenticatedSender(session, received, context);
      const plaintextBytes = copyBytes(received.plaintext());
      const snapshot = buildMessageSnapshot({
        groupIdHex,
        instanceKeyHex: context.instanceKeyHex,
        epochDec: context.retained.epochDec,
        groupContextDigestHex: context.retained.groupContextDigestHex,
        snapshotBytes: copyBytes(session.provider.serialize_state()),
      });
      const state = this.#nextMessageState(context, snapshot,
        { sentDelta: 0, receivedDelta: 1 });
      const inbound = buildInbound({
        groupIdHex,
        instanceKeyHex: context.instanceKeyHex,
        baseRetainedSnapshotDigestHex: context.retained.snapshotDigestHex,
        ciphertextBytes,
        ciphertextDigestHex,
        disposition: B27_INBOUND_STATE.ACCEPTED,
        receivedOrdinal: state.receivedCount,
        ...sender,
        plaintextBytes,
        plaintextDigestHex: digestHex(plaintextBytes),
      });
      await this.#beforeInboundCommit(Object.freeze({
        instanceKeyHex: context.instanceKeyHex,
        receivedOrdinal: inbound.receivedOrdinal,
        ciphertextDigestHex,
        priorStateDigestHex: context.state?.stateDigestHex ?? null,
      }));
      const committed = await this.#commitInbound({
        expectedHead: context.head,
        expectedRetained: context.retained,
        expectedMessageState: context.state,
        nextMessageState: state,
        nextSnapshot: snapshot,
        inbound,
        senderAuthority: sender,
      });
      const durable = await this.#journal.readInbound(
        context.instanceKeyHex, ciphertextDigestHex);
      if (durable === null || durable.disposition !== B27_INBOUND_STATE.ACCEPTED) {
        failB27(B27_ERROR.CORRUPT,
          'committed inbound delivery cannot be read back');
      }
      return durableInboundResult(committed.status, durable);
    } finally {
      safeFree(received);
      dispose(session);
    }
  }

  async createLivenessProbe(groupIdHex, plaintextBytes) {
    assertBytes('probe plaintext', plaintextBytes,
      { min: 1, max: B27_LIMITS.maxProbePayloadBytes });
    const reserved = await this.#journal.reserveProbe(groupIdHex);
    await this.#afterProbeReservation(reserved.reservation.probeKeyHex);
    const queued = await this.#queueApplicationMessage(
      groupIdHex,
      PROBE_REQUEST_PREFIX + reserved.reservation.probeKeyHex,
      plaintextBytes,
      reserved.reservation.probeKeyHex);
    const durable = await this.readQueuedApplicationMessage(
      queued.instanceKeyHex, queued.ordinal);
    return Object.freeze({ probeKeyHex: reserved.reservation.probeKeyHex,
      reservationDigestHex: reserved.reservation.reservationDigestHex,
      senderIdentityHex: reserved.reservation.localMemberIdentityHex,
      plaintextDigestHex: digestHex(plaintextBytes),
      ciphertextDigestHex: durable.ciphertextDigestHex,
      ciphertextBytes: copyBytes(durable.ciphertextBytes) });
  }

  async processLivenessProbe(groupIdHex, ciphertextBytes) {
    assertBytes('probe ciphertext', ciphertextBytes,
      { min: 1, max: B27_LIMITS.maxProbePayloadBytes * 2 });
    const delivered = await this.processApplicationMessage(groupIdHex, ciphertextBytes);
    return copyBytes(delivered.plaintextBytes);
  }

  completeLivenessProbe(probe, peerIdentityHex) {
    assertHex64('peerIdentityHex', peerIdentityHex);
    return this.#journal.completeProbe({ probeKeyHex: probe.probeKeyHex,
      ciphertextDigestHex: probe.ciphertextDigestHex,
      plaintextDigestHex: probe.plaintextDigestHex, peerIdentityHex });
  }
}

export function createBoundB27EngineAdapter(options) {
  return new B27EngineAdapter(options, ADAPTER_TOKEN);
}
