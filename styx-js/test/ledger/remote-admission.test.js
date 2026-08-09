import { describe, expect, test } from '@jest/globals';
import {
  V1_REMOTE_ADMISSION_DISABLED_CODE,
  V1_REMOTE_ADMISSION_DISABLED_MESSAGE,
  V1_REMOTE_ADMISSION_DISABLED_RESULT,
} from '../../src/ledger/remote-admission.js';

describe('v1 remote-admission containment', () => {
  test('exports one stable immutable rejection result', () => {
    expect(V1_REMOTE_ADMISSION_DISABLED_CODE).toBe(
      'STYX_V1_REMOTE_ADMISSION_DISABLED'
    );
    expect(V1_REMOTE_ADMISSION_DISABLED_MESSAGE).toBe(
      'Styx v1 remote ledger admission is disabled until safe bootstrap and atomic admission are implemented.'
    );
    expect(V1_REMOTE_ADMISSION_DISABLED_RESULT).toEqual({
      accepted: false,
      code: V1_REMOTE_ADMISSION_DISABLED_CODE,
      message: V1_REMOTE_ADMISSION_DISABLED_MESSAGE,
    });
    expect(Object.isFrozen(V1_REMOTE_ADMISSION_DISABLED_RESULT)).toBe(true);
  });

  test('publishes the same result from the ledger entry point', async () => {
    const ledgerApi = await import('../../src/ledger/index.js');

    expect(ledgerApi.V1_REMOTE_ADMISSION_DISABLED_CODE).toBe(
      V1_REMOTE_ADMISSION_DISABLED_CODE
    );
    expect(ledgerApi.V1_REMOTE_ADMISSION_DISABLED_MESSAGE).toBe(
      V1_REMOTE_ADMISSION_DISABLED_MESSAGE
    );
    expect(ledgerApi.V1_REMOTE_ADMISSION_DISABLED_RESULT).toBe(
      V1_REMOTE_ADMISSION_DISABLED_RESULT
    );
  });
});
