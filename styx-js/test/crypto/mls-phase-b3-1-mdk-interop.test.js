// SPDX-License-Identifier: AGPL-3.0-or-later

import { describe, expect, test } from '@jest/globals';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  B31_FORMAT,
  B31_PRIVATE_ROOT,
  B31_RUN_ROOT,
  B31_SUPPORTED_COMPONENT_IDS,
  B31_VERSION,
  canonicalJson,
  sha256,
  validateB31Report,
  validateTranscript,
} from '../../spikes/marmot-phase-b3-1/b3-1-canonical.mjs';

function transcriptRecord(evidence, operation, sequence, previousRecordSha256) {
  const record = { evidence, operation, previousRecordSha256, sequence };
  return Object.freeze({ ...record, recordSha256: sha256(canonicalJson(record)) });
}

function syntheticNoGo(head) {
  return {
    acceptedBeforeBoundary: {
      mdkAcceptedB31Advertisement: false,
      styxDurableRestart: true,
      styxInternalGroupProfileCodecValidated: true,
      styxKeyPackageSha256: 'a'.repeat(64),
      styxSupportedComponentIdsDecodedFromEmittedBytes:
        [...B31_SUPPORTED_COMPONENT_IDS],
    },
    claim: 'B3.1 did not establish Styx/MDK interoperability at the tested pins.',
    compatibilityEstablished: false,
    disposition: 'NO-GO',
    firstIncompatibleOperation: 'mdk_create_group_from_styx_b31_key_package',
    format: B31_FORMAT,
    profileEvidence: {
      exactProfileByteEquality: null,
    },
    rejectedValue: {
      keyPackageSha256: 'a'.repeat(64),
      kind: 'mdk_group_creation_rejection',
    },
    testedPins: {},
    transcriptHeadSha256: head,
    typedOutcomes: {
      mdk: { code: 'mdk_peer_error', details: null },
      styx: { code: 'STYX_B31_ADVERTISEMENT_NOT_ACCEPTED' },
    },
    version: B31_VERSION,
  };
}

function loadRun(name) {
  const directory = resolve(B31_RUN_ROOT, name);
  return {
    report: JSON.parse(readFileSync(resolve(directory, 'report.json'), 'utf8')),
    transcript: JSON.parse(readFileSync(resolve(directory, 'transcript.json'), 'utf8')),
  };
}

function evidenceKeys(value, result = []) {
  if (Array.isArray(value)) {
    for (const item of value) evidenceKeys(item, result);
  } else if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      result.push(key);
      evidenceKeys(item, result);
    }
  }
  return result;
}

describe('Phase B3.1 exact-pin MDK bounded evidence', () => {
  test('hash-linked evidence and compatibility claims fail closed', () => {
    const first = transcriptRecord({ pin: 'exact' }, 'verify_pins', 1, '0'.repeat(64));
    const head = validateTranscript([first]);
    const report = syntheticNoGo(head);
    expect(validateB31Report(report, head)).toBe(report);
    expect(() => validateB31Report(
      { ...report, compatibilityEstablished: true },
      head,
    )).toThrow('must fail closed without compatibility');

    const mutated = JSON.parse(JSON.stringify([first]));
    mutated[0].evidence.pin = 'drifted';
    expect(() => validateTranscript(mutated)).toThrow('transcript record digest mismatch');
  });

  test('paired exact runs, when present, agree on sequence and typed boundary', () => {
    const runAExists = existsSync(resolve(B31_RUN_ROOT, 'run-a', 'report.json'));
    const runBExists = existsSync(resolve(B31_RUN_ROOT, 'run-b', 'report.json'));
    expect(runAExists).toBe(runBExists);
    if (!runAExists) return;

    const runs = [loadRun('run-a'), loadRun('run-b')];
    for (const { report, transcript } of runs) {
      const head = validateTranscript(transcript);
      validateB31Report(report, head);
      expect(report.compatibilityEstablished).toBe(false);
      expect(report.acceptedBeforeBoundary.styxDurableRestart).toBe(true);
      expect(report.acceptedBeforeBoundary.styxInternalGroupProfileCodecValidated).toBe(true);
      expect(report.acceptedBeforeBoundary.styxSupportedComponentIdsDecodedFromEmittedBytes)
        .toEqual(B31_SUPPORTED_COMPONENT_IDS);
      const publicEvidenceKeys = evidenceKeys({ report, transcript });
      for (const forbiddenKey of [
        'accountPrivateKey',
        'databaseKey',
        'databasePath',
        'database_key',
        'database_path',
        'privateDirectory',
        'privateKey',
        'providerSnapshot',
        'providerState',
        'secretPath',
        'signerSecret',
      ]) expect(publicEvidenceKeys).not.toContain(forbiddenKey);
    }
    expect(runs[0].transcript.map((record) => record.operation))
      .toEqual(runs[1].transcript.map((record) => record.operation));
    expect(runs[0].report.firstIncompatibleOperation)
      .toBe(runs[1].report.firstIncompatibleOperation);
    expect(runs[0].report.disposition).toBe(runs[1].report.disposition);
    expect(runs[0].report.rejectedValue.kind).toBe(runs[1].report.rejectedValue.kind);
    expect(runs[0].report.acceptedBeforeBoundary.styxKeyPackageSha256)
      .not.toBe(runs[1].report.acceptedBeforeBoundary.styxKeyPackageSha256);
    expect(existsSync(resolve(B31_PRIVATE_ROOT, 'run-a'))).toBe(false);
    expect(existsSync(resolve(B31_PRIVATE_ROOT, 'run-b'))).toBe(false);
  });
});
