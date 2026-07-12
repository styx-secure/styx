// wasm-gate.test.js — decision table of the required "WASM integrity gate"
// aggregator (.github/scripts/wasm-integrity-gate.sh). Review K9: the gate
// must be FAIL-CLOSED — green-skip is only reachable when change detection
// itself completed successfully; failure/cancelled/skipped must turn the
// required check red, never green.
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const SCRIPT = fileURLToPath(new URL('../../../.github/scripts/wasm-integrity-gate.sh', import.meta.url));

/** Run the aggregator with the given env; return {code, out}. */
const gate = (env) => {
  try {
    const out = execFileSync('bash', [SCRIPT], {
      env: { PATH: process.env.PATH, ...env },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { code: 0, out };
  } catch (e) {
    return { code: e.status, out: `${e.stdout ?? ''}${e.stderr ?? ''}` };
  }
};

const allFalse = {
  LIGHT_NEEDED: 'false', CRATE_NEEDED: 'false', KDF_NEEDED: 'false', KDFLIGHT_NEEDED: 'false',
  LIGHT: 'skipped', HERMETIC: 'skipped', KDF_LIGHT: 'skipped', KDF_HERMETIC: 'skipped',
};

describe('WASM integrity gate: fail-closed decision table (review K9)', () => {
  test('changes=success + tutti false → green-skip', () => {
    const r = gate({ CHANGES_RESULT: 'success', ...allFalse });
    expect(r.code).toBe(0);
    expect(r.out).toContain('skipped (green)');
  });

  test('changes=success + KDF needed + job success → success', () => {
    const r = gate({
      CHANGES_RESULT: 'success',
      ...allFalse,
      KDF_NEEDED: 'true',
      KDFLIGHT_NEEDED: 'true',
      KDF_LIGHT: 'success',
      KDF_HERMETIC: 'success',
    });
    expect(r.code).toBe(0);
    expect(r.out).toContain('passed');
  });

  test('changes=success + KDF needed + job failure → failure', () => {
    const r = gate({
      CHANGES_RESULT: 'success',
      ...allFalse,
      KDF_NEEDED: 'true',
      KDFLIGHT_NEEDED: 'true',
      KDF_LIGHT: 'success',
      KDF_HERMETIC: 'failure',
    });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain('FAILED');
  });

  test.each(['failure', 'cancelled', 'skipped'])('changes=%s + output vuoti → failure (mai green-skip)', (result) => {
    const r = gate({
      CHANGES_RESULT: result,
      LIGHT_NEEDED: '', CRATE_NEEDED: '', KDF_NEEDED: '', KDFLIGHT_NEEDED: '',
      LIGHT: '', HERMETIC: '', KDF_LIGHT: '', KDF_HERMETIC: '',
    });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain('did not complete successfully');
  });

  test('CHANGES_RESULT assente → failure (nessun default che apra il gate)', () => {
    const r = gate({
      LIGHT_NEEDED: '', CRATE_NEEDED: '', KDF_NEEDED: '', KDFLIGHT_NEEDED: '',
      LIGHT: '', HERMETIC: '', KDF_LIGHT: '', KDF_HERMETIC: '',
    });
    expect(r.code).not.toBe(0);
    expect(r.out).toContain('did not complete successfully');
  });

  test('tier needed con risultato skipped/cancelled conta come fallimento', () => {
    for (const bad of ['skipped', 'cancelled', '']) {
      const r = gate({
        CHANGES_RESULT: 'success',
        ...allFalse,
        LIGHT_NEEDED: 'true',
        LIGHT: bad,
      });
      expect(r.code).not.toBe(0);
    }
  });

  test('openmls e kdf sono tier indipendenti: un fallimento openmls non è mascherato dal kdf verde', () => {
    const r = gate({
      CHANGES_RESULT: 'success',
      LIGHT_NEEDED: 'true', CRATE_NEEDED: 'true', KDF_NEEDED: 'true', KDFLIGHT_NEEDED: 'true',
      LIGHT: 'success', HERMETIC: 'failure', KDF_LIGHT: 'success', KDF_HERMETIC: 'success',
    });
    expect(r.code).not.toBe(0);
  });
});
