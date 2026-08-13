// SPDX-License-Identifier: AGPL-3.0-or-later

import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, realpathSync, statSync } from 'node:fs';
import { dirname, relative, resolve, sep } from 'node:path';

export const B3_FORMAT = 'styx-marmot-openmls-b3';
export const B3_VERSION = 1;
export const B3_BASE_SHA = '925554ef89921ee6b6fa8ea1c976ed3a05977a26';
export const B3_BASE_TREE = '48899a558c67e9ec0aad8a6814a1d56078d2f54c';
export const B3_MARMOT_REVISION = '4ad4ae21479c3f3fa9950c6fc4556a76941a62e1';
export const B3_MARMOT_TREE = '10d941f358de5d9fe4ee1db75581f3e5363f5e92';
export const B3_MDK_REVISION = '9396adb6aa6b95b521a7979facd5ea7040c07288';
export const B3_MDK_TREE = 'a1145de604e616634dae9a1ef6bf5033c9c9e879';
export const B3_MDK_LOCK_SHA256 =
  'edb8c706e12934b8d94239203f73d24a2d480033c3ec6830f19d06c85a247b09';
export const B3_WASM_SHA256 =
  'ed5e740d9c93aa46aa1afb7b6065e4b5b92be972a8a080ddd0a35091260691bb';

export const B3_RUN_ROOT = '/home/mverde/.local/share/styx-b3-runs/issue-165';
export const B3_PRIVATE_ROOT = '/home/mverde/.local/share/styx-b3-private/issue-165';

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

export function assertPlainObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError(`${label} must be a plain object`);
  }
  if (Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must have the default object prototype`);
  }
  return value;
}

export function assertExactKeys(value, keys, label) {
  assertPlainObject(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`${label} fields are not exact`);
  }
  return value;
}

export function assertLowerHex(value, byteLength, label) {
  if (
    typeof value !== 'string' ||
    value.length !== byteLength * 2 ||
    !/^[0-9a-f]+$/.test(value)
  ) {
    throw new TypeError(`${label} must be ${byteLength}-byte lowercase hex`);
  }
  return value;
}

export function hexBytes(value, label, maximumBytes = 2 * 1024 * 1024) {
  if (
    typeof value !== 'string' ||
    value.length % 2 !== 0 ||
    value.length > maximumBytes * 2 ||
    (value.length > 0 && !/^[0-9a-f]+$/.test(value))
  ) {
    throw new TypeError(`${label} must be bounded lowercase hex`);
  }
  return Uint8Array.from(Buffer.from(value, 'hex'));
}

export function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

export function canonicalJson(value) {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}

export function validateTranscript(transcript) {
  if (!Array.isArray(transcript) || transcript.length === 0) {
    throw new TypeError('transcript must be a non-empty array');
  }
  let previous = '0'.repeat(64);
  for (const [index, record] of transcript.entries()) {
    assertExactKeys(
      record,
      ['evidence', 'operation', 'previousRecordSha256', 'recordSha256', 'sequence'],
      `transcript record ${index + 1}`,
    );
    if (record.sequence !== index + 1) throw new TypeError('transcript sequence is not contiguous');
    if (typeof record.operation !== 'string' || record.operation.length === 0) {
      throw new TypeError('transcript operation must be non-empty');
    }
    assertLowerHex(record.previousRecordSha256, 32, 'previous transcript digest');
    assertLowerHex(record.recordSha256, 32, 'transcript digest');
    if (record.previousRecordSha256 !== previous) throw new TypeError('transcript chain is broken');
    const expected = sha256(canonicalJson({
      evidence: record.evidence,
      operation: record.operation,
      previousRecordSha256: record.previousRecordSha256,
      sequence: record.sequence,
    }));
    if (record.recordSha256 !== expected) throw new TypeError('transcript record digest mismatch');
    previous = record.recordSha256;
  }
  return previous;
}

export function validateCapabilityNoGoReport(report, transcriptHeadSha256) {
  assertExactKeys(report, [
    'acceptedBeforeBoundary',
    'claim',
    'compatibilityEstablished',
    'disposition',
    'firstIncompatibleOperation',
    'format',
    'pinnedNormativeRule',
    'rejectedValue',
    'remedyOutsideContract',
    'smallestHypotheticalRemedy',
    'testedPins',
    'transcriptHeadSha256',
    'typedOutcomes',
    'version',
  ], 'B3 report');
  if (report.format !== B3_FORMAT || report.version !== B3_VERSION) {
    throw new TypeError('B3 report identity mismatch');
  }
  if (report.disposition !== 'NO-GO' || report.compatibilityEstablished !== false) {
    throw new TypeError('B3 capability report must fail closed as NO-GO');
  }
  if (report.firstIncompatibleOperation !== 'mdk_create_group_from_styx_key_package') {
    throw new TypeError('B3 report does not identify the first incompatible operation');
  }
  if (
    report.rejectedValue?.kind !== 'missing_required_application_component' ||
    report.rejectedValue?.componentIdDecimal !== 0x8001 ||
    report.rejectedValue?.componentIdHex !== '8001'
  ) {
    throw new TypeError('B3 report does not identify component 0x8001 exactly');
  }
  if (
    report.typedOutcomes?.mdk?.code !== 'mdk_missing_required_capabilities' ||
    report.typedOutcomes?.styx?.code !==
      'STYX_KEY_PACKAGE_MISSING_MDK_REQUIRED_GROUP_PROFILE_COMPONENT'
  ) {
    throw new TypeError('B3 report is missing the two typed capability outcomes');
  }
  if (
    !Array.isArray(report.typedOutcomes.mdk.details?.missing_app_components) ||
    report.typedOutcomes.mdk.details.missing_app_components.length !== 1 ||
    report.typedOutcomes.mdk.details.missing_app_components[0] !== 0x8001
  ) {
    throw new TypeError('MDK typed outcome does not isolate component 0x8001');
  }
  assertLowerHex(report.transcriptHeadSha256, 32, 'report transcript head');
  if (report.transcriptHeadSha256 !== transcriptHeadSha256) {
    throw new TypeError('report does not bind the transcript head');
  }
  if (!report.claim.includes('did not establish Styx/MDK interoperability')) {
    throw new TypeError('B3 report contains an invalid compatibility claim');
  }
  return report;
}

function isStrictChild(parent, child) {
  const rel = relative(parent, child);
  return rel.length > 0 && rel !== '..' && !rel.startsWith(`..${sep}`) && !rel.startsWith(sep);
}

export function prepareScopedDirectory(path, parent, mode = 0o700) {
  const absoluteParent = resolve(parent);
  mkdirSync(absoluteParent, { recursive: true, mode: 0o700 });
  chmodSync(absoluteParent, 0o700);
  const resolvedParent = realpathSync(absoluteParent);
  const candidate = resolve(path);
  if (!isStrictChild(resolvedParent, candidate)) {
    throw new Error(`refusing non-child directory ${candidate}`);
  }
  mkdirSync(candidate, { recursive: false, mode });
  chmodSync(candidate, mode);
  const real = realpathSync(candidate);
  if (!isStrictChild(resolvedParent, real) || !statSync(real).isDirectory()) {
    throw new Error(`directory escaped its approved parent: ${real}`);
  }
  return real;
}

export function assertExistingScopedDirectory(path, parent) {
  const resolvedParent = realpathSync(resolve(parent));
  const real = realpathSync(resolve(path));
  if (!isStrictChild(resolvedParent, real) || !statSync(real).isDirectory()) {
    throw new Error(`${real} is not a validated child of ${resolvedParent}`);
  }
  return real;
}

export function parentDirectory(path) {
  return dirname(resolve(path));
}
