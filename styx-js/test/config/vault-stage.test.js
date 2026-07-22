// vault-stage.test.js — the styx.vault.stage flag guards the vault lifecycle
// (US-006, F3). Under Jest `import.meta.env` is undefined, i.e. the flag is
// OFF (the production default), so the guard must deny access and the guarded
// dynamic import must not resolve to the module. The flag-OFF bundle exclusion
// is proven separately by the anti-bundle CI step.
import { describe, test, expect } from '@jest/globals';
import {
  vaultStageEnabled, loadVaultLifecycle, VAULT_STAGE_DEVELOPER_ONLY,
} from '../../src/config/vault-stage.js';

describe('vault-stage flag', () => {
  test('the canonical developer stage value is "developer-only" (plan B3.0.6)', () => {
    expect(VAULT_STAGE_DEVELOPER_ONLY).toBe('developer-only');
  });

  test('with the flag off (default), the guard denies and loads nothing', async () => {
    expect(vaultStageEnabled()).toBe(false);
    expect(await loadVaultLifecycle()).toBeNull();
  });
});
