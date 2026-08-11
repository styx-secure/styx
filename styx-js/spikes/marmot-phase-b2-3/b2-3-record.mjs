// STYX_SPIKE_PROTOTYPE — strict Phase B2.3 durable-record codec.

import {
  B23_ERROR,
  B23_FORMAT,
  B23_LIMITS,
  B23_PROFILE,
  B23_RUNTIME,
  B23_VERSION,
  assertBytes,
  assertGroupIdHex,
  assertHex40,
  assertHex64,
  assertRuntimeTuple,
  assertSafeInteger,
  assertString,
  canonicalBytes,
  copyBytes,
  digestHex,
  fail,
  hexToBytes,
  parseEpochDecimal,
  snapshotClosedObject,
} from './b2-3-canonical.mjs';

export const HEAD_STABLE = 'STABLE';
export const HEAD_PREPARED = 'PREPARED';

export const HEAD_FIELDS = Object.freeze([
  'format', 'version', 'profile', 'groupIdHex', 'accountKeyHex', 'signatureKeyHex',
  'openMlsRevision', 'wasmArtifactSha256', 'ciphersuite', 'seq', 'state',
  'epochDec', 'epochDigestHex', 'snapshotKeyHex', 'snapshotBytes',
  'transitionIdHex', 'priorHeadDigestHex', 'pendingCommitDigestHex',
  'pendingWelcomeDigestHex', 'candidateEpochDec', 'candidateEpochDigestHex',
  'verifiedLeafDigestHex', 'artifactId', 'artifactDigestHex', 'publishAttempts',
  'evidenceCount', 'lastAppliedCommitDigestHex', 'headDigestHex',
]);

export const TRANSITION_FIELDS = Object.freeze([
  'format', 'version', 'idHex', 'kind', 'groupIdHex', 'seq', 'priorHeadDigestHex',
  'state', 'epochDec', 'epochDigestHex', 'snapshotKeyHex', 'commitBytes',
  'welcomeBytes', 'projection', 'projectionDigestHex', 'candidateEpochDec',
  'candidateEpochDigestHex', 'verifiedLeafDigestHex', 'artifactId', 'artifactBytes',
  'artifactDigestHex', 'publishAttempts', 'evidenceCount',
  'appliedCommitDigestHex', 'transitionDigestHex',
]);

export const EVIDENCE_FIELDS = Object.freeze([
  'format', 'version', 'idHex', 'groupIdHex', 'transitionIdHex',
  'artifactDigestHex', 'payload', 'payloadDigestHex', 'evidenceDigestHex',
]);

const TRANSITION_KINDS = Object.freeze([
  'initialize', 'prepare', 'publish-intent', 'publication-evidence',
  'confirm', 'discard', 'inbound-accept',
]);

function nullableHex64(name, value) {
  if (value !== null) assertHex64(name, value);
  return value;
}

function nullableEpoch(name, value) {
  if (value !== null) parseEpochDecimal(value, name);
  return value;
}

function nullableArtifactId(value) {
  if (value !== null) assertString('artifactId', value, { min: 1, max: 256, pattern: /^[\x21-\x7e]+$/ });
  return value;
}

function assertHeadShape(head) {
  if (head.format !== `${B23_FORMAT}-head` || head.version !== B23_VERSION
    || head.profile !== B23_PROFILE) fail(B23_ERROR.INVALID, 'head magic or version is invalid');
  assertGroupIdHex(head.groupIdHex);
  assertHex64('accountKeyHex', head.accountKeyHex);
  assertHex64('signatureKeyHex', head.signatureKeyHex);
  assertRuntimeTuple(head);
  assertSafeInteger('seq', head.seq, 1);
  if (head.state !== HEAD_STABLE && head.state !== HEAD_PREPARED) {
    fail(B23_ERROR.INVALID, 'head state is invalid');
  }
  parseEpochDecimal(head.epochDec);
  assertHex64('epochDigestHex', head.epochDigestHex);
  assertHex64('snapshotKeyHex', head.snapshotKeyHex);
  assertSafeInteger('snapshotBytes', head.snapshotBytes, 1, B23_LIMITS.maxSnapshotBytes);
  assertHex64('transitionIdHex', head.transitionIdHex);
  nullableHex64('priorHeadDigestHex', head.priorHeadDigestHex);
  nullableHex64('pendingCommitDigestHex', head.pendingCommitDigestHex);
  nullableHex64('pendingWelcomeDigestHex', head.pendingWelcomeDigestHex);
  nullableEpoch('candidateEpochDec', head.candidateEpochDec);
  nullableHex64('candidateEpochDigestHex', head.candidateEpochDigestHex);
  nullableHex64('verifiedLeafDigestHex', head.verifiedLeafDigestHex);
  nullableArtifactId(head.artifactId);
  nullableHex64('artifactDigestHex', head.artifactDigestHex);
  assertSafeInteger('publishAttempts', head.publishAttempts, 0, B23_LIMITS.maxPublishAttempts);
  assertSafeInteger('evidenceCount', head.evidenceCount, 0, B23_LIMITS.maxEvidence);
  nullableHex64('lastAppliedCommitDigestHex', head.lastAppliedCommitDigestHex);
  assertHex64('headDigestHex', head.headDigestHex);

  if (head.state === HEAD_STABLE) {
    for (const field of [
      'pendingCommitDigestHex', 'pendingWelcomeDigestHex', 'candidateEpochDec',
      'candidateEpochDigestHex', 'verifiedLeafDigestHex', 'artifactId', 'artifactDigestHex',
    ]) {
      if (head[field] !== null) fail(B23_ERROR.INVALID, 'stable head contains pending fields');
    }
    if (head.publishAttempts !== 0 || head.evidenceCount !== 0) {
      fail(B23_ERROR.INVALID, 'stable head contains publication counters');
    }
  } else {
    for (const field of [
      'pendingCommitDigestHex', 'candidateEpochDec', 'candidateEpochDigestHex',
      'verifiedLeafDigestHex',
    ]) {
      if (head[field] === null) fail(B23_ERROR.INVALID, 'prepared head lacks pending fields');
    }
    if (BigInt(head.candidateEpochDec) !== BigInt(head.epochDec) + 1n) {
      fail(B23_ERROR.INVALID, 'prepared candidate epoch does not advance exactly once');
    }
    if (head.publishAttempts === 0) {
      if (head.artifactId !== null || head.artifactDigestHex !== null || head.evidenceCount !== 0) {
        fail(B23_ERROR.INVALID, 'unattempted prepared head contains publication data');
      }
    } else if (head.artifactId === null || head.artifactDigestHex === null) {
      fail(B23_ERROR.INVALID, 'attempted prepared head lacks frozen artifact data');
    }
    if (head.evidenceCount > 0 && head.publishAttempts === 0) {
      fail(B23_ERROR.INVALID, 'publication evidence exists without an attempt');
    }
  }
  return head;
}

export function headCanonicalBytes(head) {
  return canonicalBytes('STYX-B2-3-HEAD-V1', [
    head.format, head.version, head.profile, head.groupIdHex, head.accountKeyHex,
    head.signatureKeyHex, head.openMlsRevision, head.wasmArtifactSha256,
    head.ciphersuite, head.seq, head.state, head.epochDec, head.epochDigestHex,
    head.snapshotKeyHex, head.snapshotBytes, head.transitionIdHex,
    head.priorHeadDigestHex, head.pendingCommitDigestHex, head.pendingWelcomeDigestHex,
    head.candidateEpochDec, head.candidateEpochDigestHex, head.verifiedLeafDigestHex,
    head.artifactId, head.artifactDigestHex, head.publishAttempts, head.evidenceCount,
    head.lastAppliedCommitDigestHex,
  ]);
}

export function buildHead(fields) {
  const draft = { format: `${B23_FORMAT}-head`, version: B23_VERSION, profile: B23_PROFILE,
    ...B23_RUNTIME, ...fields, headDigestHex: '0'.repeat(64) };
  const validated = assertHeadShape(snapshotClosedObject(draft, HEAD_FIELDS, 'head'));
  validated.headDigestHex = digestHex(headCanonicalBytes(validated));
  return Object.freeze(validated);
}

export function parseHead(raw) {
  const head = assertHeadShape(snapshotClosedObject(raw, HEAD_FIELDS, 'head'));
  const computed = digestHex(headCanonicalBytes(head));
  if (computed !== head.headDigestHex) fail(B23_ERROR.CORRUPT, 'head digest mismatch');
  return Object.freeze(head);
}

const PROJECTION_FIELDS = Object.freeze([
  'format', 'version', 'priorEpochDec', 'candidateEpochDec', 'committerSource',
  'committerLeafIndex', 'committerIdentityHex', 'committerSignatureKeyHex',
  'administratorPolicyHex', 'lifecycleHex', 'requiredComponentIds',
  'candidateGroupContextTlsHex', 'candidateGroupContextDigestHex',
  'verifiedLeafDigestHex', 'candidateMembers', 'proposals', 'updatePath',
]);
const MEMBER_FIELDS = Object.freeze([
  'leafIndex', 'identityHex', 'signatureKeyHex', 'identityProofHex',
  'componentIds', 'supportedComponentIds',
]);
const PROPOSAL_FIELDS = Object.freeze([
  'kind', 'source', 'senderSource', 'senderLeafIndex', 'addedLeafIndex',
  'addedIdentityHex', 'addedSignatureKeyHex', 'addedIdentityProofHex',
  'addedComponentIds', 'addedSupportedComponentIds', 'removedParentLeafIndex',
  'removedIdentityHex', 'removedSignatureKeyHex', 'removedIdentityProofHex',
]);
const UPDATE_PATH_FIELDS = Object.freeze([
  'leafIndex', 'identityHex', 'signatureKeyHex', 'identityProofHex',
  'componentIds', 'supportedComponentIds',
]);

function snapshotClosedArray(value, label, { min = 0, max }) {
  if (!Array.isArray(value) || value.length < min || value.length > max) {
    fail(B23_ERROR.RESOURCE_LIMIT, `${label} count exceeds its bound`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || !keys.includes('length')) {
    fail(B23_ERROR.INVALID, `${label} contains unexpected fields`);
  }
  const copy = [];
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      fail(B23_ERROR.INVALID, `${label} contains a hole or accessor`);
    }
    copy.push(descriptor.value);
  }
  return Object.freeze(copy);
}

function assertHexBytes(name, value, bytes, maxBytes = bytes) {
  return assertString(name, value, {
    min: bytes * 2, max: maxBytes * 2, pattern: /^(?:[0-9a-f]{2})+$/,
  });
}

function componentIds(value, label) {
  const values = snapshotClosedArray(value, label, { max: 64 });
  for (const component of values) assertSafeInteger(label, component, 0, 0xffff);
  return Object.freeze(values);
}

function nullableNumber(name, value) {
  if (value !== null) assertSafeInteger(name, value, 0, 0xffffffff);
  return value;
}

function nullableExactHex(name, value, bytes) {
  if (value !== null) assertHexBytes(name, value, bytes);
  return value;
}

function nullableComponents(value, label) {
  return value === null ? null : componentIds(value, label);
}

function validateMember(raw, label) {
  const member = snapshotClosedObject(raw, MEMBER_FIELDS, label);
  assertSafeInteger(`${label}.leafIndex`, member.leafIndex, 0, 0xffffffff);
  assertHex64(`${label}.identityHex`, member.identityHex);
  assertHex64(`${label}.signatureKeyHex`, member.signatureKeyHex);
  assertHexBytes(`${label}.identityProofHex`, member.identityProofHex, 104);
  member.componentIds = componentIds(member.componentIds, `${label}.componentIds`);
  member.supportedComponentIds = componentIds(
    member.supportedComponentIds, `${label}.supportedComponentIds`,
  );
  return Object.freeze(member);
}

function validateProposal(raw, label) {
  const proposal = snapshotClosedObject(raw, PROPOSAL_FIELDS, label);
  for (const field of ['kind', 'source', 'senderSource']) {
    assertString(`${label}.${field}`, proposal[field], { min: 1, max: 48, pattern: /^[a-z0-9_-]+$/ });
  }
  assertSafeInteger(`${label}.senderLeafIndex`, proposal.senderLeafIndex, 0, 0xffffffff);
  nullableNumber(`${label}.addedLeafIndex`, proposal.addedLeafIndex);
  nullableExactHex(`${label}.addedIdentityHex`, proposal.addedIdentityHex, 32);
  nullableExactHex(`${label}.addedSignatureKeyHex`, proposal.addedSignatureKeyHex, 32);
  nullableExactHex(`${label}.addedIdentityProofHex`, proposal.addedIdentityProofHex, 104);
  proposal.addedComponentIds = nullableComponents(proposal.addedComponentIds, `${label}.addedComponentIds`);
  proposal.addedSupportedComponentIds = nullableComponents(
    proposal.addedSupportedComponentIds, `${label}.addedSupportedComponentIds`,
  );
  nullableNumber(`${label}.removedParentLeafIndex`, proposal.removedParentLeafIndex);
  nullableExactHex(`${label}.removedIdentityHex`, proposal.removedIdentityHex, 32);
  nullableExactHex(`${label}.removedSignatureKeyHex`, proposal.removedSignatureKeyHex, 32);
  nullableExactHex(`${label}.removedIdentityProofHex`, proposal.removedIdentityProofHex, 104);
  return Object.freeze(proposal);
}

function validateUpdatePath(raw) {
  if (raw === null) return null;
  const path = snapshotClosedObject(raw, UPDATE_PATH_FIELDS, 'projection.updatePath');
  nullableNumber('projection.updatePath.leafIndex', path.leafIndex);
  nullableExactHex('projection.updatePath.identityHex', path.identityHex, 32);
  nullableExactHex('projection.updatePath.signatureKeyHex', path.signatureKeyHex, 32);
  nullableExactHex('projection.updatePath.identityProofHex', path.identityProofHex, 104);
  path.componentIds = nullableComponents(path.componentIds, 'projection.updatePath.componentIds');
  path.supportedComponentIds = nullableComponents(
    path.supportedComponentIds, 'projection.updatePath.supportedComponentIds',
  );
  return Object.freeze(path);
}

function validateProjection(value) {
  const copy = snapshotClosedObject(value, PROJECTION_FIELDS, 'projection');
  if (copy.format !== 'styx-b2-3-projection' || copy.version !== 1) {
    fail(B23_ERROR.INVALID, 'projection magic or version is invalid');
  }
  parseEpochDecimal(copy.priorEpochDec, 'projection.priorEpochDec');
  parseEpochDecimal(copy.candidateEpochDec, 'projection.candidateEpochDec');
  if (BigInt(copy.candidateEpochDec) !== BigInt(copy.priorEpochDec) + 1n) {
    fail(B23_ERROR.INVALID, 'projection candidate epoch does not advance exactly once');
  }
  assertString('projection.committerSource', copy.committerSource, {
    min: 1, max: 48, pattern: /^[a-z0-9_-]+$/,
  });
  assertSafeInteger('projection.committerLeafIndex', copy.committerLeafIndex, 0, 0xffffffff);
  assertHex64('projection.committerIdentityHex', copy.committerIdentityHex);
  assertHex64('projection.committerSignatureKeyHex', copy.committerSignatureKeyHex);
  assertHexBytes('projection.administratorPolicyHex', copy.administratorPolicyHex, 1, 1024);
  assertHexBytes('projection.lifecycleHex', copy.lifecycleHex, 1, 64);
  copy.requiredComponentIds = componentIds(copy.requiredComponentIds, 'projection.requiredComponentIds');
  assertHexBytes(
    'projection.candidateGroupContextTlsHex', copy.candidateGroupContextTlsHex,
    1, B23_LIMITS.maxGroupContextBytes,
  );
  assertHex64('projection.candidateGroupContextDigestHex', copy.candidateGroupContextDigestHex);
  if (digestHex(hexToBytes(
    'projection.candidateGroupContextTlsHex', copy.candidateGroupContextTlsHex,
  )) !== copy.candidateGroupContextDigestHex) {
    fail(B23_ERROR.CORRUPT, 'projection GroupContext TLS digest mismatch');
  }
  assertHex64('projection.verifiedLeafDigestHex', copy.verifiedLeafDigestHex);
  const members = snapshotClosedArray(copy.candidateMembers, 'projection.candidateMembers', {
    min: 1, max: B23_LIMITS.maxMembers,
  }).map((member, index) => validateMember(member, `projection.candidateMembers[${index}]`));
  for (let index = 1; index < members.length; index += 1) {
    if (members[index - 1].leafIndex >= members[index].leafIndex) {
      fail(B23_ERROR.INVALID, 'projection candidate members are not strictly ordered');
    }
  }
  if (!members.some((member) => member.leafIndex === copy.committerLeafIndex
    && member.identityHex === copy.committerIdentityHex
    && member.signatureKeyHex === copy.committerSignatureKeyHex)) {
    fail(B23_ERROR.INVALID, 'projection committer is absent from the candidate members');
  }
  copy.candidateMembers = Object.freeze(members);
  copy.proposals = Object.freeze(snapshotClosedArray(copy.proposals, 'projection.proposals', {
    max: B23_LIMITS.maxProposals,
  }).map((proposal, index) => validateProposal(proposal, `projection.proposals[${index}]`)));
  copy.updatePath = validateUpdatePath(copy.updatePath);
  const encoded = new TextEncoder().encode(JSON.stringify(copy));
  if (encoded.length > B23_LIMITS.maxCommitBytes) fail(B23_ERROR.RESOURCE_LIMIT, 'projection is oversized');
  return Object.freeze(copy);
}

function transitionPayloadDigests(record) {
  return [
    record.commitBytes === null ? null : digestHex(record.commitBytes),
    record.welcomeBytes === null ? null : digestHex(record.welcomeBytes),
    record.artifactBytes === null ? null : digestHex(record.artifactBytes),
  ];
}

function assertTransitionShape(record) {
  if (record.format !== `${B23_FORMAT}-transition` || record.version !== B23_VERSION) {
    fail(B23_ERROR.INVALID, 'transition magic or version is invalid');
  }
  assertHex64('idHex', record.idHex);
  if (!TRANSITION_KINDS.includes(record.kind)) fail(B23_ERROR.INVALID, 'transition kind is invalid');
  assertGroupIdHex(record.groupIdHex);
  assertSafeInteger('seq', record.seq, 1);
  nullableHex64('priorHeadDigestHex', record.priorHeadDigestHex);
  if (record.state !== HEAD_STABLE && record.state !== HEAD_PREPARED) {
    fail(B23_ERROR.INVALID, 'transition state is invalid');
  }
  parseEpochDecimal(record.epochDec);
  assertHex64('epochDigestHex', record.epochDigestHex);
  assertHex64('snapshotKeyHex', record.snapshotKeyHex);
  if (record.commitBytes !== null) assertBytes('commitBytes', record.commitBytes, { min: 1, max: B23_LIMITS.maxCommitBytes });
  if (record.welcomeBytes !== null) assertBytes('welcomeBytes', record.welcomeBytes, { min: 1, max: B23_LIMITS.maxWelcomeBytes });
  if (record.projection !== null) record.projection = validateProjection(record.projection);
  nullableHex64('projectionDigestHex', record.projectionDigestHex);
  nullableEpoch('candidateEpochDec', record.candidateEpochDec);
  nullableHex64('candidateEpochDigestHex', record.candidateEpochDigestHex);
  nullableHex64('verifiedLeafDigestHex', record.verifiedLeafDigestHex);
  nullableArtifactId(record.artifactId);
  if (record.artifactBytes !== null) assertBytes('artifactBytes', record.artifactBytes, { min: 1, max: B23_LIMITS.maxArtifactBytes });
  nullableHex64('artifactDigestHex', record.artifactDigestHex);
  assertSafeInteger('publishAttempts', record.publishAttempts, 0, B23_LIMITS.maxPublishAttempts);
  assertSafeInteger('evidenceCount', record.evidenceCount, 0, B23_LIMITS.maxEvidence);
  nullableHex64('appliedCommitDigestHex', record.appliedCommitDigestHex);
  assertHex64('transitionDigestHex', record.transitionDigestHex);

  const [commitDigest, welcomeDigest, artifactDigest] = transitionPayloadDigests(record);
  if ((record.commitBytes === null) !== (record.projection === null)
    || (record.projection === null) !== (record.projectionDigestHex === null)) {
    fail(B23_ERROR.INVALID, 'transition Commit and projection fields are incoherent');
  }
  if (record.projection !== null
    && digestHex(canonicalProjectionBytes(record.projection)) !== record.projectionDigestHex) {
    fail(B23_ERROR.CORRUPT, 'projection digest mismatch');
  }
  if (record.artifactBytes === null) {
    if (record.artifactId !== null || record.artifactDigestHex !== null) {
      fail(B23_ERROR.INVALID, 'transition artifact fields are incoherent');
    }
  } else if (record.artifactId === null || artifactDigest !== record.artifactDigestHex) {
    fail(B23_ERROR.CORRUPT, 'transition artifact digest mismatch');
  }
  if (record.commitBytes === null && record.appliedCommitDigestHex !== null) {
    fail(B23_ERROR.INVALID, 'applied Commit digest lacks exact Commit bytes');
  }
  if (record.appliedCommitDigestHex !== null && commitDigest !== record.appliedCommitDigestHex) {
    fail(B23_ERROR.CORRUPT, 'applied Commit digest mismatch');
  }
  if (record.welcomeBytes !== null && welcomeDigest === null) {
    fail(B23_ERROR.CORRUPT, 'Welcome digest could not be computed');
  }
  const hasCommit = record.commitBytes !== null;
  const completeCandidate = record.projection !== null && record.projectionDigestHex !== null
    && record.candidateEpochDec !== null && record.candidateEpochDigestHex !== null
    && record.verifiedLeafDigestHex !== null;
  if (hasCommit !== completeCandidate) {
    fail(B23_ERROR.INVALID, 'transition candidate fields are incomplete');
  }
  if (hasCommit) {
    if (record.projection.candidateEpochDec !== record.candidateEpochDec
      || record.projection.candidateGroupContextDigestHex !== record.candidateEpochDigestHex
      || record.projection.verifiedLeafDigestHex !== record.verifiedLeafDigestHex) {
      fail(B23_ERROR.CORRUPT, 'transition candidate fields differ from the bounded projection');
    }
    const successorKind = record.kind === 'confirm' || record.kind === 'inbound-accept';
    const expectedEpoch = successorKind
      ? record.projection.candidateEpochDec : record.projection.priorEpochDec;
    if (record.epochDec !== expectedEpoch) {
      fail(B23_ERROR.INVALID, 'transition epoch is incoherent with its phase');
    }
    if (successorKind && record.epochDigestHex !== record.candidateEpochDigestHex) {
      fail(B23_ERROR.CORRUPT, 'successor transition epoch digest differs from its candidate');
    }
  }
  if (record.evidenceCount > 0 && (record.publishAttempts === 0 || record.artifactBytes === null)) {
    fail(B23_ERROR.INVALID, 'transition evidence lacks a publication attempt');
  }
  if (record.publishAttempts > 0 && record.artifactBytes === null) {
    fail(B23_ERROR.INVALID, 'transition publication attempt lacks its frozen artifact');
  }
  const noPublication = record.artifactBytes === null
    && record.publishAttempts === 0 && record.evidenceCount === 0;
  switch (record.kind) {
    case 'initialize':
      if (record.seq !== 1 || record.priorHeadDigestHex !== null || record.state !== HEAD_STABLE
        || hasCommit || !noPublication || record.appliedCommitDigestHex !== null) {
        fail(B23_ERROR.INVALID, 'initialize transition fields are incoherent');
      }
      break;
    case 'prepare':
      if (record.state !== HEAD_PREPARED || !hasCommit || !noPublication
        || record.appliedCommitDigestHex !== null) {
        fail(B23_ERROR.INVALID, 'prepare transition fields are incoherent');
      }
      break;
    case 'publish-intent':
      if (record.state !== HEAD_PREPARED || !hasCommit || record.publishAttempts < 1
        || record.artifactBytes === null || record.appliedCommitDigestHex !== null) {
        fail(B23_ERROR.INVALID, 'publish-intent transition fields are incoherent');
      }
      break;
    case 'publication-evidence':
      if (record.state !== HEAD_PREPARED || !hasCommit || record.publishAttempts < 1
        || record.evidenceCount < 1 || record.artifactBytes === null
        || record.appliedCommitDigestHex !== null) {
        fail(B23_ERROR.INVALID, 'publication-evidence transition fields are incoherent');
      }
      break;
    case 'confirm':
      if (record.state !== HEAD_STABLE || !hasCommit || record.publishAttempts < 1
        || record.artifactBytes === null || record.appliedCommitDigestHex === null) {
        fail(B23_ERROR.INVALID, 'confirm transition fields are incoherent');
      }
      break;
    case 'discard':
      if (record.state !== HEAD_STABLE || !hasCommit || !noPublication
        || record.appliedCommitDigestHex !== null) {
        fail(B23_ERROR.INVALID, 'discard transition fields are incoherent');
      }
      break;
    case 'inbound-accept':
      if (record.state !== HEAD_STABLE || !hasCommit || !noPublication
        || record.welcomeBytes !== null || record.appliedCommitDigestHex === null) {
        fail(B23_ERROR.INVALID, 'inbound-accept transition fields are incoherent');
      }
      break;
    default:
      fail(B23_ERROR.INVALID, 'transition kind is invalid');
  }
  return record;
}

export function canonicalProjectionBytes(projection) {
  const safeProjection = validateProjection(projection);
  // Engine projection builders create this object with a frozen field order and
  // primitive/array leaves. Parser tests reject accessors and extra fields at
  // the projection-builder boundary; this digest is never an authorization token.
  return canonicalBytes('STYX-B2-3-PROJECTION-V1', [JSON.stringify(safeProjection)]);
}

export function transitionCanonicalBytes(record) {
  const [commitDigest, welcomeDigest, artifactDigest] = transitionPayloadDigests(record);
  return canonicalBytes('STYX-B2-3-TRANSITION-V1', [
    record.format, record.version, record.idHex, record.kind, record.groupIdHex,
    record.seq, record.priorHeadDigestHex, record.state, record.epochDec,
    record.epochDigestHex, record.snapshotKeyHex, commitDigest, welcomeDigest,
    record.projectionDigestHex, record.candidateEpochDec,
    record.candidateEpochDigestHex, record.verifiedLeafDigestHex, record.artifactId,
    artifactDigest, record.publishAttempts, record.evidenceCount,
    record.appliedCommitDigestHex,
  ]);
}

export function buildTransition(fields) {
  const draft = {
    format: `${B23_FORMAT}-transition`, version: B23_VERSION, ...fields,
    commitBytes: copyBytes(fields.commitBytes),
    welcomeBytes: copyBytes(fields.welcomeBytes),
    artifactBytes: copyBytes(fields.artifactBytes),
    transitionDigestHex: '0'.repeat(64),
  };
  const validated = assertTransitionShape(snapshotClosedObject(draft, TRANSITION_FIELDS, 'transition'));
  validated.transitionDigestHex = digestHex(transitionCanonicalBytes(validated));
  return Object.freeze(validated);
}

export function parseTransition(raw) {
  const record = assertTransitionShape(snapshotClosedObject(raw, TRANSITION_FIELDS, 'transition'));
  const computed = digestHex(transitionCanonicalBytes(record));
  if (computed !== record.transitionDigestHex) fail(B23_ERROR.CORRUPT, 'transition digest mismatch');
  return Object.freeze(record);
}

export function evidenceCanonicalBytes(record) {
  return canonicalBytes('STYX-B2-3-EVIDENCE-V1', [
    record.format, record.version, record.idHex, record.groupIdHex,
    record.transitionIdHex, record.artifactDigestHex, record.payloadDigestHex,
  ]);
}

export function buildEvidence(fields) {
  const draft = { format: `${B23_FORMAT}-evidence`, version: B23_VERSION,
    ...fields, payload: copyBytes(fields.payload), evidenceDigestHex: '0'.repeat(64) };
  const record = snapshotClosedObject(draft, EVIDENCE_FIELDS, 'evidence');
  if (record.format !== `${B23_FORMAT}-evidence` || record.version !== B23_VERSION) {
    fail(B23_ERROR.INVALID, 'evidence magic or version is invalid');
  }
  assertHex64('idHex', record.idHex);
  assertGroupIdHex(record.groupIdHex);
  assertHex64('transitionIdHex', record.transitionIdHex);
  assertHex64('artifactDigestHex', record.artifactDigestHex);
  assertBytes('payload', record.payload, { min: 1, max: B23_LIMITS.maxEvidenceBytes });
  assertHex64('payloadDigestHex', record.payloadDigestHex);
  if (digestHex(record.payload) !== record.payloadDigestHex) fail(B23_ERROR.CORRUPT, 'evidence payload digest mismatch');
  record.evidenceDigestHex = digestHex(evidenceCanonicalBytes(record));
  return Object.freeze(record);
}

export function parseEvidence(raw) {
  const safe = snapshotClosedObject(raw, EVIDENCE_FIELDS, 'evidence');
  const record = buildEvidence(safe);
  if (record.evidenceDigestHex !== safe.evidenceDigestHex) fail(B23_ERROR.CORRUPT, 'evidence digest mismatch');
  return record;
}
