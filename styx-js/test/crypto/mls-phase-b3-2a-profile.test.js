// SPDX-License-Identifier: AGPL-3.0-or-later

import {
  B32A_ERROR,
  B32A_PREPARATION,
  B32A_PROFILE,
  B32A_PROJECTION_DOMAIN,
  b32aProjectionRecordSha256,
  normalizeB32aPreparationEvidence,
  normalizeB32aProjection,
  projectB32aNative,
} from '../../spikes/marmot-phase-b3-2a/b3-2a-canonical.mjs';
import {
  b32aFixture,
  fakeNativeProjection,
} from '../../spikes/marmot-phase-b3-2a/b3-2a-test-support.mjs';

describe('Phase B3.2a exact two-profile projection', () => {
  test('projects the complete native surface and independently verifies both proofs', () => {
    const values = b32aFixture();
    const normalized = normalizeB32aProjection(values.projection);
    expect(projectB32aNative(fakeNativeProjection(values.projection))).toEqual(normalized);
    expect(b32aProjectionRecordSha256(normalized)).toMatch(/^[0-9a-f]{64}$/);
  });

  test.each([
    ['hybrid Styx dictionary', (value) => { value.members[1].componentIds = [1, 2, 0x8009]; }],
    ['unknown profile', (value) => { value.members[1].profileTag = 'GENERIC'; }],
    ['wrong exact-profile flag', (value) => { value.members[0].emitsEmptySafeAad = false; }],
    ['reversed profile roles', (value) => {
      value.members[0] = { ...value.members[0], profileTag: B32A_PROFILE.STYX,
        componentIds: [1, 0x8009], listsDefaultRequiredCapabilities: false,
        emitsEmptySafeAad: false };
    }],
    ['bad Schnorr proof', (value) => { value.members[1].identityProofHex = '00'.repeat(104); }],
    ['third member', (value) => { value.members.push(structuredClone(value.members[1])); }],
    ['wrong Provider format', (value) => { value.providerFormat = 'legacy'; }],
    ['unknown projection field', (value) => { value.untrusted = true; }],
  ])('rejects %s', (_label, mutate) => {
    const value = structuredClone(b32aFixture().projection);
    mutate(value);
    expect(() => normalizeB32aProjection(value)).toThrow();
  });

  test('does not invoke hostile projection accessors', () => {
    const value = b32aFixture().projection;
    let invoked = false;
    Object.defineProperty(value, 'domain', { get() { invoked = true; return B32A_PROJECTION_DOMAIN; } });
    expect(() => normalizeB32aProjection(value)).toThrow();
    expect(invoked).toBe(false);
  });
});

describe('Phase B3.2a bounded preparation evidence codec', () => {
  test('admits only coherent byte-identical or MessageSecrets-bounded evidence', () => {
    const candidate = '11'.repeat(32);
    expect(normalizeB32aPreparationEvidence({
      classification: B32A_PREPARATION.BYTE_IDENTICAL,
      secondCandidateStateSha256Hex: candidate,
      differingStorageKeyHex: '',
    }, candidate)).toMatchObject({ classification: B32A_PREPARATION.BYTE_IDENTICAL });
    expect(normalizeB32aPreparationEvidence({
      classification: B32A_PREPARATION.RETENTION_TIMESTAMP_BOUNDED,
      secondCandidateStateSha256Hex: '22'.repeat(32),
      differingStorageKeyHex: Buffer.from('MessageSecretsjoined-group').toString('hex'),
    }, candidate)).toMatchObject({
      classification: B32A_PREPARATION.RETENTION_TIMESTAMP_BOUNDED,
    });
  });

  test.each([
    ['unknown class', { classification: 'OTHER', secondCandidateStateSha256Hex: '11'.repeat(32), differingStorageKeyHex: '' }],
    ['byte-identical with different digest', { classification: B32A_PREPARATION.BYTE_IDENTICAL, secondCandidateStateSha256Hex: '22'.repeat(32), differingStorageKeyHex: '' }],
    ['bounded with non-MessageSecrets key', { classification: B32A_PREPARATION.RETENTION_TIMESTAMP_BOUNDED, secondCandidateStateSha256Hex: '22'.repeat(32), differingStorageKeyHex: Buffer.from('Group').toString('hex') }],
    ['bounded with identical digest', { classification: B32A_PREPARATION.RETENTION_TIMESTAMP_BOUNDED, secondCandidateStateSha256Hex: '11'.repeat(32), differingStorageKeyHex: Buffer.from('MessageSecretsx').toString('hex') }],
  ])('rejects %s', (_label, evidence) => {
    expect(() => normalizeB32aPreparationEvidence(evidence, '11'.repeat(32))).toThrow(
      expect.objectContaining({ code: B32A_ERROR.PREPARATION_EVIDENCE_INVALID }),
    );
  });
});
