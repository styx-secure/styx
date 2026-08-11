// STYX_SPIKE_PROTOTYPE — deterministic bounded Commit policy for Phase B2.4.

import { verifyAccountIdentityProofV2 } from '../marmot-phase-b1/identity-proof-v2.js';
import {
  B23_LIMITS,
  assertBytes,
  assertGroupIdHex,
  assertHex64,
  assertSafeInteger,
  bytesEqual,
  bytesToHex,
  digestHex,
  epochToDecimal,
  hexToBytes,
  parseEpochDecimal,
} from '../marmot-phase-b2-3/b2-3-canonical.mjs';
import { canonicalProjectionBytes } from '../marmot-phase-b2-3/b2-3-record.mjs';
import {
  B24_ACTIVE_LIFECYCLE_HEX,
  B24_CONTEXT_DOMAIN,
  B24_ERROR,
  B24_LIMITS,
  B24_PARENT_FORMAT,
  B24_POLICY_VERSION,
  B24_REASON,
  B24_REQUIRED_COMPONENT_IDS,
  assertAuthorizationContext,
  assertDirectObject,
  assertHexBytes,
  assertSortedU16,
  assertU32,
  authorizationContextDigest,
  authorizationResultDigest,
  failB24,
} from './b2-4-canonical.mjs';

const MEMBER_FIELDS = Object.freeze([
  'leafIndex', 'identityHex', 'signatureKeyHex', 'identityProofHex',
]);
const PARENT_FIELDS = Object.freeze([
  'format', 'version', 'groupIdHex', 'epochDec', 'groupContextDigestHex',
  'administratorPolicyHex', 'lifecycleHex', 'requiredComponentIds', 'members',
]);
const DECISION_FIELDS = Object.freeze([
  'verdict', 'allowed', 'reason', 'operationKind', 'context',
  'contextDigestHex', 'resultDigestHex',
]);

function compareHex(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function equalArray(left, right) {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function normalizeMember(member, label) {
  const safe = assertDirectObject(member, MEMBER_FIELDS, label);
  assertU32(`${label}.leafIndex`, safe.leafIndex);
  assertHexBytes(`${label}.identityHex`, safe.identityHex, 32);
  assertHexBytes(`${label}.signatureKeyHex`, safe.signatureKeyHex, 32);
  assertHexBytes(`${label}.identityProofHex`, safe.identityProofHex, 104);
  return Object.freeze({ ...safe });
}

function normalizeMembers(members, label) {
  if (!Array.isArray(members) || members.length < 1 || members.length > B24_LIMITS.maxMembers) {
    failB24(B24_ERROR.INVALID, `${label} must be a nonempty bounded array`);
  }
  const out = [];
  const accounts = new Set();
  let priorLeaf = -1;
  for (let index = 0; index < members.length; index += 1) {
    const member = normalizeMember(members[index], `${label}[${index}]`);
    if (member.leafIndex <= priorLeaf) {
      failB24(B24_ERROR.INVALID, `${label} leaves must be strictly sorted and unique`);
    }
    if (accounts.has(member.identityHex)) {
      failB24(B24_ERROR.INVALID, `${label} contains a duplicate account identity`);
    }
    priorLeaf = member.leafIndex;
    accounts.add(member.identityHex);
    out.push(member);
  }
  return Object.freeze(out);
}

function normalizeParent(parent) {
  const safe = assertDirectObject(parent, PARENT_FIELDS, 'parent projection');
  if (safe.format !== B24_PARENT_FORMAT || safe.version !== B24_POLICY_VERSION) {
    failB24(B24_ERROR.INVALID, 'parent projection domain or version is invalid');
  }
  assertGroupIdHex(safe.groupIdHex);
  parseEpochDecimal(safe.epochDec, 'parent epoch');
  assertHex64('parent GroupContext digest', safe.groupContextDigestHex);
  if (typeof safe.administratorPolicyHex !== 'string'
    || !/^(?:[0-9a-f]{2})+$/.test(safe.administratorPolicyHex)
    || safe.administratorPolicyHex.length > B24_LIMITS.maxAdminPolicyBytes * 2) {
    failB24(B24_ERROR.INVALID, 'parent administrator policy is not bounded canonical hex');
  }
  if (safe.lifecycleHex !== B24_ACTIVE_LIFECYCLE_HEX) {
    // Kept structurally valid so the policy can produce a stable lifecycle rejection.
    assertHexBytes('parent lifecycle', safe.lifecycleHex, 1);
  }
  const requiredComponentIds = assertSortedU16(
    'parent required components', safe.requiredComponentIds,
  );
  const members = normalizeMembers(safe.members, 'parent members');
  return Object.freeze({ ...safe, requiredComponentIds, members });
}

function vlBytesLength(bytes) {
  if (bytes.length < 1) failB24(B24_ERROR.INVALID, 'administrator policy is empty');
  const width = 1 << (bytes[0] >> 6);
  if (bytes.length < width) failB24(B24_ERROR.INVALID, 'administrator policy prefix is truncated');
  let value = BigInt(bytes[0] & 0x3f);
  for (let index = 1; index < width; index += 1) value = (value << 8n) | BigInt(bytes[index]);
  const minimum = Object.freeze({ 1: 0n, 2: 64n, 4: 16384n, 8: 1073741824n })[width];
  if (value < minimum || value > BigInt(Number.MAX_SAFE_INTEGER)) {
    failB24(B24_ERROR.INVALID, 'administrator policy prefix is non-canonical');
  }
  return { width, length: Number(value) };
}

export function decodeB24AdministratorPolicy(policyHex) {
  if (typeof policyHex !== 'string' || !/^(?:[0-9a-f]{2})+$/.test(policyHex)
    || policyHex.length > B24_LIMITS.maxAdminPolicyBytes * 2) {
    failB24(B24_ERROR.INVALID, 'administrator policy is not bounded canonical hex');
  }
  const bytes = hexToBytes('administratorPolicyHex', policyHex);
  const { width, length } = vlBytesLength(bytes);
  if (length < 32 || length > B24_LIMITS.maxAdmins * 32 || length % 32 !== 0
    || width + length !== bytes.length) {
    failB24(B24_ERROR.INVALID, 'administrator policy payload length is invalid');
  }
  const admins = [];
  let prior = null;
  for (let offset = width; offset < bytes.length; offset += 32) {
    const account = bytesToHex(bytes.slice(offset, offset + 32));
    if (prior !== null && compareHex(prior, account) >= 0) {
      failB24(B24_ERROR.INVALID, 'administrator accounts must be strictly sorted and unique');
    }
    prior = account;
    admins.push(account);
  }
  return Object.freeze(admins);
}

function verifyProofs(members) {
  for (const member of members) {
    verifyAccountIdentityProofV2(
      hexToBytes('identityProofHex', member.identityProofHex),
      hexToBytes('identityHex', member.identityHex),
      hexToBytes('signatureKeyHex', member.signatureKeyHex),
    );
  }
}

export function validateB24Parent(parent) {
  const safeParent = normalizeParent(parent);
  try { verifyProofs(safeParent.members); } catch (error) {
    failB24(B24_ERROR.POLICY_REJECTED, 'parent identity proof validation failed', {
      reason: B24_REASON.INVALID_PARENT_PROOF,
    }, error);
  }
  let admins;
  try { admins = decodeB24AdministratorPolicy(safeParent.administratorPolicyHex); } catch (error) {
    failB24(B24_ERROR.POLICY_REJECTED, 'parent administrator policy validation failed', {
      reason: B24_REASON.ADMIN_POLICY,
    }, error);
  }
  const accounts = new Set(safeParent.members.map((member) => member.identityHex));
  if (admins.some((account) => !accounts.has(account))) {
    failB24(B24_ERROR.POLICY_REJECTED, 'parent administrator is not a current member', {
      reason: B24_REASON.ADMIN_POLICY,
    });
  }
  if (safeParent.lifecycleHex !== B24_ACTIVE_LIFECYCLE_HEX) {
    failB24(B24_ERROR.POLICY_REJECTED, 'parent lifecycle is not active', {
      reason: B24_REASON.LIFECYCLE,
    });
  }
  if (!equalArray(safeParent.requiredComponentIds, B24_REQUIRED_COMPONENT_IDS)) {
    failB24(B24_ERROR.POLICY_REJECTED, 'parent required-component set is unsupported', {
      reason: B24_REASON.COMPONENTS,
    });
  }
  return Object.freeze({ parent: safeParent, admins });
}

function memberMap(members) {
  return new Map(members.map((member) => [member.leafIndex, member]));
}

function sameMember(left, right) {
  return left !== undefined && right !== undefined
    && left.leafIndex === right.leafIndex
    && left.identityHex === right.identityHex
    && left.signatureKeyHex === right.signatureKeyHex
    && left.identityProofHex === right.identityProofHex;
}

function sameMemberCore(left, right) {
  return left !== undefined && right !== undefined
    && left.leafIndex === right.leafIndex
    && left.identityHex === right.identityHex
    && left.signatureKeyHex === right.signatureKeyHex;
}

function pathMatchesMember(path, member) {
  return path !== null && path.leafIndex === member.leafIndex
    && path.identityHex === member.identityHex
    && path.signatureKeyHex === member.signatureKeyHex
    && path.identityProofHex === member.identityProofHex
    && Array.isArray(path.componentIds)
    && Array.isArray(path.supportedComponentIds)
    && equalArray(path.componentIds, member.componentIds)
    && equalArray(path.supportedComponentIds, member.supportedComponentIds);
}

function proposalHasOnly(proposal, kind) {
  if (proposal.kind !== kind || proposal.source !== 'inline'
    || proposal.senderSource !== 'member') return false;
  if (kind === 'add') {
    return proposal.addedLeafIndex !== null && proposal.addedIdentityHex !== null
      && proposal.addedSignatureKeyHex !== null && proposal.addedIdentityProofHex !== null
      && proposal.addedComponentIds !== null && proposal.addedSupportedComponentIds !== null
      && proposal.removedParentLeafIndex === null && proposal.removedIdentityHex === null
      && proposal.removedSignatureKeyHex === null && proposal.removedIdentityProofHex === null;
  }
  return proposal.addedLeafIndex === null && proposal.addedIdentityHex === null
    && proposal.addedSignatureKeyHex === null && proposal.addedIdentityProofHex === null
    && proposal.addedComponentIds === null && proposal.addedSupportedComponentIds === null
    && proposal.removedParentLeafIndex !== null && proposal.removedIdentityHex !== null
    && proposal.removedSignatureKeyHex !== null && proposal.removedIdentityProofHex !== null;
}

function classifyOperation(candidate) {
  if (candidate.proposals.length === 0) return 'self-update';
  if (candidate.proposals.length === 1 && candidate.proposals[0].kind === 'add') return 'add';
  if (candidate.proposals.length === 1 && candidate.proposals[0].kind === 'remove') return 'remove';
  return 'unsupported';
}

function buildContext(parent, candidate, commitBytes, operationKind) {
  assertBytes('Commit', commitBytes, { min: 1, max: B23_LIMITS.maxCommitBytes });
  const context = {
    domain: B24_CONTEXT_DOMAIN,
    version: B24_POLICY_VERSION,
    groupIdHex: parent.groupIdHex,
    parentEpochDec: parent.epochDec,
    parentGroupContextDigestHex: parent.groupContextDigestHex,
    commitDigestHex: digestHex(commitBytes),
    projectionDigestHex: digestHex(canonicalProjectionBytes(candidate)),
    candidateEpochDec: candidate.candidateEpochDec,
    candidateGroupContextDigestHex: candidate.candidateGroupContextDigestHex,
    verifiedLeafDigestHex: candidate.verifiedLeafDigestHex,
    operationKind,
    committerLeafIndex: candidate.committerLeafIndex,
    committerIdentityHex: candidate.committerIdentityHex,
    committerSignatureKeyHex: candidate.committerSignatureKeyHex,
  };
  return assertAuthorizationContext(context);
}

function decision(context, allowed, reason) {
  const verdict = allowed ? 'ALLOW' : 'REJECT';
  const contextDigestHex = authorizationContextDigest(context);
  return Object.freeze({
    verdict,
    allowed,
    reason,
    operationKind: context.operationKind,
    context,
    contextDigestHex,
    resultDigestHex: authorizationResultDigest({ contextDigestHex, verdict, reason }),
  });
}

function rejected(context, reason) {
  return decision(context, false, reason);
}

function allowed(context, reason) {
  return decision(context, true, reason);
}

function rosterPreserved(parentMembers, candidateMembers, committerLeaf, excludedLeaf = null) {
  const candidateByLeaf = memberMap(candidateMembers);
  for (const parentMember of parentMembers) {
    if (parentMember.leafIndex === excludedLeaf) continue;
    const candidateMember = candidateByLeaf.get(parentMember.leafIndex);
    if (parentMember.leafIndex === committerLeaf) {
      if (!sameMemberCore(parentMember, candidateMember)) return false;
    } else if (!sameMember(parentMember, candidateMember)) return false;
  }
  return true;
}

export function projectB24Parent({ provider, group, head }) {
  try {
    const memberCount = assertSafeInteger(
      'parent member count', group.member_count(), 1, B24_LIMITS.maxMembers,
    );
    const members = [];
    let priorLeaf = -1;
    for (let index = 0; index < memberCount; index += 1) {
      const leafIndex = assertSafeInteger('parent leaf index', group.member_leaf_index(index), 0, 0xffffffff);
      if (leafIndex <= priorLeaf) failB24(B24_ERROR.ENGINE_REJECTED, 'parent leaves are not strictly ordered');
      priorLeaf = leafIndex;
      const identity = group.member_identity(index);
      const signatureKey = group.member_signature_key(index);
      const proof = group.member_identity_proof(index);
      assertBytes('parent identity', identity, { min: 32, max: 32 });
      assertBytes('parent signature key', signatureKey, { min: 32, max: 32 });
      assertBytes('parent identity proof', proof, { min: 104, max: 104 });
      members.push({
        leafIndex,
        identityHex: bytesToHex(identity),
        signatureKeyHex: bytesToHex(signatureKey),
        identityProofHex: bytesToHex(proof),
      });
    }
    const groupIdHex = bytesToHex(group.group_id());
    const epochDec = epochToDecimal(group.epoch());
    const groupContextDigestHex = bytesToHex(group.group_context_sha256(provider));
    if (groupIdHex !== head.groupIdHex || epochDec !== head.epochDec
      || groupContextDigestHex !== head.epochDigestHex) {
      failB24(B24_ERROR.BINDING_MISMATCH, 'fresh parent does not match the durable B2.3 head');
    }
    return normalizeParent({
      format: B24_PARENT_FORMAT,
      version: B24_POLICY_VERSION,
      groupIdHex,
      epochDec,
      groupContextDigestHex,
      administratorPolicyHex: bytesToHex(group.administrator_policy()),
      lifecycleHex: bytesToHex(group.lifecycle()),
      requiredComponentIds: Array.from(group.required_component_ids()),
      members,
    });
  } catch (error) {
    if (error?.code) throw error;
    failB24(B24_ERROR.ENGINE_REJECTED, 'parent projection failed closed', {}, error);
  }
}

export function evaluateB24Authorization({ parent, candidate, commitBytes }) {
  const safeParent = normalizeParent(parent);
  // This validates the complete strict B2.3 projection before any policy access.
  canonicalProjectionBytes(candidate);
  const operationKind = classifyOperation(candidate);
  const context = buildContext(safeParent, candidate, commitBytes, operationKind);
  const parentByLeaf = memberMap(safeParent.members);
  const candidateByLeaf = memberMap(candidate.candidateMembers);

  try { verifyProofs(safeParent.members); } catch { return rejected(context, B24_REASON.INVALID_PARENT_PROOF); }
  try { verifyProofs(candidate.candidateMembers); } catch { return rejected(context, B24_REASON.INVALID_CANDIDATE_PROOF); }

  const parentAccounts = new Set(safeParent.members.map((member) => member.identityHex));
  const candidateAccounts = new Set(candidate.candidateMembers.map((member) => member.identityHex));
  if (parentAccounts.size !== safeParent.members.length
    || candidateAccounts.size !== candidate.candidateMembers.length) {
    return rejected(context, B24_REASON.DUPLICATE_ACCOUNT);
  }

  let admins;
  try { admins = decodeB24AdministratorPolicy(safeParent.administratorPolicyHex); } catch {
    return rejected(context, B24_REASON.ADMIN_POLICY);
  }
  if (admins.some((account) => !parentAccounts.has(account))) {
    return rejected(context, B24_REASON.ADMIN_POLICY);
  }
  if (candidate.administratorPolicyHex !== safeParent.administratorPolicyHex) {
    return rejected(context, B24_REASON.POLICY_MUTATION);
  }
  if (safeParent.lifecycleHex !== B24_ACTIVE_LIFECYCLE_HEX
    || candidate.lifecycleHex !== B24_ACTIVE_LIFECYCLE_HEX) {
    return rejected(context, B24_REASON.LIFECYCLE);
  }
  if (!equalArray(safeParent.requiredComponentIds, B24_REQUIRED_COMPONENT_IDS)
    || !equalArray(candidate.requiredComponentIds, B24_REQUIRED_COMPONENT_IDS)) {
    return rejected(context, B24_REASON.COMPONENTS);
  }
  const parentEpoch = parseEpochDecimal(safeParent.epochDec, 'parent epoch');
  if (candidate.priorEpochDec !== safeParent.epochDec
    || parseEpochDecimal(candidate.candidateEpochDec, 'candidate epoch') !== parentEpoch + 1n) {
    return rejected(context, B24_REASON.EPOCH);
  }
  if (candidate.committerSource !== 'member') return rejected(context, B24_REASON.COMMITTER);
  const parentCommitter = parentByLeaf.get(candidate.committerLeafIndex);
  const candidateCommitter = candidateByLeaf.get(candidate.committerLeafIndex);
  if (parentCommitter === undefined || candidateCommitter === undefined
    || candidate.committerIdentityHex !== candidateCommitter.identityHex
    || candidate.committerSignatureKeyHex !== candidateCommitter.signatureKeyHex) {
    return rejected(context, B24_REASON.COMMITTER);
  }
  if (candidateCommitter.identityHex !== parentCommitter.identityHex) {
    return rejected(context, B24_REASON.MEMBER_TRANSITION);
  }
  if (candidateCommitter.signatureKeyHex !== parentCommitter.signatureKeyHex) {
    return rejected(context, B24_REASON.SIGNING_KEY_ROTATION);
  }
  if (!pathMatchesMember(candidate.updatePath, candidateCommitter)) {
    return rejected(context, B24_REASON.COMMITTER);
  }

  if (operationKind === 'add') {
    const proposal = candidate.proposals[0];
    if (!proposalHasOnly(proposal, 'add')
      || proposal.senderLeafIndex !== candidate.committerLeafIndex) {
      return rejected(context, B24_REASON.UNSUPPORTED_SHAPE);
    }
    if (!admins.includes(parentCommitter.identityHex)) return rejected(context, B24_REASON.NOT_ADMIN);
    if (safeParent.members.length + 1 !== candidate.candidateMembers.length
      || parentByLeaf.has(proposal.addedLeafIndex)
      || !rosterPreserved(safeParent.members, candidate.candidateMembers, candidate.committerLeafIndex)) {
      return rejected(context, B24_REASON.MEMBER_TRANSITION);
    }
    const added = candidateByLeaf.get(proposal.addedLeafIndex);
    if (added === undefined || added.identityHex !== proposal.addedIdentityHex
      || added.signatureKeyHex !== proposal.addedSignatureKeyHex
      || added.identityProofHex !== proposal.addedIdentityProofHex
      || !equalArray(added.componentIds, proposal.addedComponentIds)
      || !equalArray(added.supportedComponentIds, proposal.addedSupportedComponentIds)
      || parentAccounts.has(added.identityHex)) {
      return rejected(context, B24_REASON.MEMBER_TRANSITION);
    }
    return allowed(context, B24_REASON.ALLOW_ADD);
  }

  if (operationKind === 'remove') {
    const proposal = candidate.proposals[0];
    if (!proposalHasOnly(proposal, 'remove')
      || proposal.senderLeafIndex !== candidate.committerLeafIndex) {
      return rejected(context, B24_REASON.UNSUPPORTED_SHAPE);
    }
    if (!admins.includes(parentCommitter.identityHex)) return rejected(context, B24_REASON.NOT_ADMIN);
    const removed = parentByLeaf.get(proposal.removedParentLeafIndex);
    if (removed === undefined || !sameMember(removed, {
      leafIndex: removed.leafIndex,
      identityHex: proposal.removedIdentityHex,
      signatureKeyHex: proposal.removedSignatureKeyHex,
      identityProofHex: proposal.removedIdentityProofHex,
    })) return rejected(context, B24_REASON.MEMBER_TRANSITION);
    if (removed.leafIndex === candidate.committerLeafIndex) return rejected(context, B24_REASON.SELF_REMOVE);
    if (admins.includes(removed.identityHex)) return rejected(context, B24_REASON.ADMIN_REMOVE);
    if (candidate.candidateMembers.length !== safeParent.members.length - 1
      || candidate.candidateMembers.length < 1 || candidateByLeaf.has(removed.leafIndex)
      || !rosterPreserved(
        safeParent.members, candidate.candidateMembers,
        candidate.committerLeafIndex, removed.leafIndex,
      )) return rejected(context, B24_REASON.MEMBER_TRANSITION);
    return allowed(context, B24_REASON.ALLOW_REMOVE);
  }

  if (operationKind === 'self-update') {
    if (candidate.proposals.length !== 0
      || candidate.candidateMembers.length !== safeParent.members.length
      || !rosterPreserved(safeParent.members, candidate.candidateMembers, candidate.committerLeafIndex)) {
      return rejected(context, B24_REASON.MEMBER_TRANSITION);
    }
    return allowed(context, B24_REASON.ALLOW_SELF_UPDATE);
  }

  return rejected(context, B24_REASON.UNSUPPORTED_SHAPE);
}

export function verifyB24DecisionBinding(decisionValue, inputs) {
  const safe = assertDirectObject(decisionValue, DECISION_FIELDS, 'authorization result');
  if (typeof safe.allowed !== 'boolean' || safe.verdict !== (safe.allowed ? 'ALLOW' : 'REJECT')) {
    failB24(B24_ERROR.BINDING_MISMATCH, 'authorization result verdict is incoherent');
  }
  let recomputed;
  try {
    recomputed = evaluateB24Authorization(inputs);
  } catch (error) {
    failB24(B24_ERROR.BINDING_MISMATCH, 'authorization inputs are no longer valid', {}, error);
  }
  if (safe.verdict !== recomputed.verdict || safe.reason !== recomputed.reason
    || safe.operationKind !== recomputed.operationKind
    || safe.contextDigestHex !== recomputed.contextDigestHex
    || safe.resultDigestHex !== recomputed.resultDigestHex) {
    failB24(B24_ERROR.BINDING_MISMATCH, 'authorization result does not bind the exact transition');
  }
  return recomputed;
}

export function requireB24Allow(decisionValue) {
  if (decisionValue?.allowed !== true) {
    failB24(B24_ERROR.POLICY_REJECTED, 'bounded Commit authorization rejected', {
      reason: decisionValue?.reason ?? B24_REASON.INVALID_CANDIDATE,
    });
  }
  return decisionValue;
}
