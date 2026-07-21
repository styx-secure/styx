// test/unlock-errors.test.js — the unlock UI must never surface raw error text.
// describeUnlockError is the single choke point: every code maps to a fixed
// Italian message, everything else falls back to a generic safe message, and
// nothing from err.message/err.details can leak into what the user reads
// (US-001, residual item 3 of docs/security/2026-07-12-review-mls-state-envelope.md).
import { describe, test, expect, jest, afterEach } from '@jest/globals';
import { describeUnlockError } from '../src/lib/unlock-errors.js';

const MLS_CODES = [
  'MLS_STATE_INVALID',
  'MLS_STATE_CORRUPTED',
  'MLS_STATE_VERSION_UNSUPPORTED',
  'MLS_STATE_SCHEMA_UNSUPPORTED',
  'MLS_STATE_OPENMLS_INCOMPATIBLE',
  'MLS_STATE_CIPHERSUITE_MISMATCH',
  'MLS_STATE_MIGRATION_FAILED',
  'MLS_STATE_RESTORE_FAILED',
];

// NOTE: no VAULT_* codes here on purpose. The runtime unlock path uses
// EncryptedKeyStore (plain Errors, no code); the coded vault errors belong to
// modules that are not runtime-integrated and whose identifiers must not
// reach the production bundle (Blocco 3 CI gate). The map will grow vault
// codes in the PR that wires the vault in and revises that gate.

const RAW_MARKER = 'RAW_TECHNICAL_MESSAGE_MARKER';

function fakeError(code, details) {
  const err = new Error(RAW_MARKER);
  if (code !== undefined) err.code = code;
  if (details !== undefined) err.details = details;
  return err;
}

describe('describeUnlockError', () => {
  afterEach(() => jest.restoreAllMocks());

  test.each(MLS_CODES)('%s maps to a fixed Italian message', (code) => {
    const { message, actions } = describeUnlockError(fakeError(code));
    expect(typeof message).toBe('string');
    expect(message.length).toBeGreaterThan(0);
    expect(message).not.toContain(RAW_MARKER);
    expect(message).not.toContain(code); // codes are for logs, not for users
    expect(Array.isArray(actions)).toBe(true);
  });

  test('the wrong-password Error from EncryptedKeyStore gets a specific message', () => {
    // The runtime key store throws a plain Error whose stable message is the
    // dispatch key; only the fixed Italian text may reach the user.
    const { message, actions } = describeUnlockError(new Error('Invalid password'));
    expect(message.toLowerCase()).toContain('password');
    expect(message).not.toContain('Invalid password');
    expect(actions).toHaveLength(0);
  });

  test('wrong-password dispatch is exact-match only, never substring', () => {
    const { message } = describeUnlockError(new Error(`Invalid password ${RAW_MARKER}`));
    expect(message).not.toContain(RAW_MARKER);
    expect(message.toLowerCase()).not.toContain('password errata');
  });

  test('OPENMLS_INCOMPATIBLE exposes exactly the three foreseen actions, least destructive first', () => {
    const { actions } = describeUnlockError(fakeError('MLS_STATE_OPENMLS_INCOMPATIBLE'));
    expect(actions).toHaveLength(3);
    expect(actions[0].toLowerCase()).toContain('riapri');
    expect(actions[1].toLowerCase()).toContain('attendi');
    expect(actions[2].toLowerCase()).toContain('factory reset');
  });

  test('actions never come from the library payload, even when details.actions is present', () => {
    const { actions } = describeUnlockError(fakeError('MLS_STATE_OPENMLS_INCOMPATIBLE', {
      actions: [RAW_MARKER, `${RAW_MARKER}-2`],
    }));
    expect(JSON.stringify(actions)).not.toContain(RAW_MARKER);
  });

  test.each(MLS_CODES.filter((c) => c !== 'MLS_STATE_OPENMLS_INCOMPATIBLE'))(
    '%s carries no recovery actions', (code) => {
      expect(describeUnlockError(fakeError(code)).actions).toHaveLength(0);
    },
  );

  test('unknown code falls back to the generic safe message', () => {
    const { message, actions } = describeUnlockError(fakeError('SOMETHING_NEW'));
    expect(message).not.toContain(RAW_MARKER);
    expect(message).not.toContain('SOMETHING_NEW');
    expect(actions).toHaveLength(0);
  });

  test.each([
    ['no code', fakeError(undefined)],
    ['null error', null],
    ['undefined error', undefined],
    ['non-error value', 'boom'],
  ])('%s falls back to the generic safe message without throwing', (_label, err) => {
    const { message, actions } = describeUnlockError(err);
    expect(typeof message).toBe('string');
    expect(message.length).toBeGreaterThan(0);
    expect(actions).toHaveLength(0);
  });

  test('the production bundle gate sentinels never appear in what this module can emit', () => {
    // Blocco 3 CI gate: these identifiers must not reach dist/. The mapper is
    // bundled, so its whole output surface must be free of them.
    for (const sentinel of ['styx-vault-wrapper', 'VAULT_WRAPPER_INVALID', 'styx/vault/identity/v1']) {
      for (const code of [...MLS_CODES, 'UNKNOWN', undefined]) {
        expect(JSON.stringify(describeUnlockError(fakeError(code)))).not.toContain(sentinel);
      }
    }
  });

  test('anti-leak: nothing from err.message or err.details reaches the described output', () => {
    for (const code of [...MLS_CODES, 'UNKNOWN_CODE']) {
      const out = describeUnlockError(fakeError(code, {
        limit: RAW_MARKER, saved: RAW_MARKER, causeCode: RAW_MARKER, actions: [RAW_MARKER],
      }));
      expect(JSON.stringify(out)).not.toContain(RAW_MARKER);
    }
  });

  test('outside a dev build nothing is written to the console', () => {
    // Under Jest import.meta.env is undefined, which is exactly the non-dev
    // (production-like) branch: the mapper must stay silent on every path.
    const spies = ['error', 'warn', 'debug', 'log'].map((m) => jest.spyOn(console, m));
    describeUnlockError(fakeError('MLS_STATE_CORRUPTED', { limit: 1 }));
    describeUnlockError(fakeError('UNKNOWN_CODE'));
    for (const spy of spies) expect(spy).not.toHaveBeenCalled();
  });
});
