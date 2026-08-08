import { describe, test, expect } from '@jest/globals';
import { createVaultIdentityCoordinator } from '../src/lib/vault-identity.js';

const identity = Object.freeze({
  v: 1,
  iterations: 210000,
  salt: Buffer.alloc(16, 1).toString('base64'),
  iv: Buffer.alloc(12, 2).toString('base64'),
  ct: Buffer.alloc(48, 3).toString('base64'),
});

function harness({
  stored = JSON.stringify(identity), storageError = null, failRequest = false, divergent = false,
} = {}) {
  const calls = [];
  const events = [];
  const storage = {
    getItem(key) {
      calls.push(['get', key]);
      if (storageError) throw storageError;
      return stored;
    },
  };
  let migrated;
  const request = async (type, payload) => {
    calls.push(['request', type, payload]);
    if (failRequest) {
      throw Object.assign(new Error('worker failure containing secret-like text'), {
        code: 'VAULT_WRONG_STATE',
      });
    }
    if (type === 'MIGRATE') {
      migrated = payload.identity;
      return { state: 'verified', matched: true, recordVersion: 1 };
    }
    return {
      found: true,
      record: { value: divergent ? { ...migrated, iterations: 1 } : migrated },
    };
  };
  const coordinator = createVaultIdentityCoordinator({
    storage, request, onDiagnostic: (event) => events.push(event),
  });
  return { coordinator, calls, events };
}

describe('vault identity coordinator', () => {
  test('reads exactly the default identity key, migrates only while idle, and verifies GET', async () => {
    const { coordinator, calls, events } = harness();
    expect(await coordinator.synchronize({ pairingActive: false })).toEqual({
      synchronized: true, present: true,
    });
    expect(calls[0]).toEqual(['get', 'styxchat:styx:identity']);
    expect(calls[1]).toEqual(['request', 'MIGRATE', {
      namespace: 'identity', identity, pairingActive: false,
    }]);
    expect(calls[2]).toEqual(['request', 'GET', {
      namespace: 'identity', recordKey: 'self',
    }]);
    expect(events).toEqual([{
      code: 'IDENTITY_SYNC_VERIFIED', phase: 'verify', markerState: 'verified',
      mismatch: false, sourceCount: 1, writtenCount: 1,
    }]);
    expect(events[0]).not.toHaveProperty('digest');
  });

  test('a missing legacy identity is a no-op with no worker request', async () => {
    const { coordinator, calls, events } = harness({ stored: null });
    expect(await coordinator.synchronize({ pairingActive: false })).toEqual({
      synchronized: false, present: false,
    });
    expect(calls).toEqual([['get', 'styxchat:styx:identity']]);
    expect(events[0]).toMatchObject({ code: 'IDENTITY_NOT_PRESENT', sourceCount: 0 });
  });

  test('malformed legacy data produces only a bounded value-free diagnostic', async () => {
    const secretText = 'definitely-not-an-identity-secret';
    const { coordinator, calls, events } = harness({ stored: secretText });
    expect(await coordinator.synchronize({ pairingActive: false })).toEqual({
      synchronized: false, present: true,
    });
    expect(calls).toEqual([['get', 'styxchat:styx:identity']]);
    expect(events[0]).toMatchObject({
      code: 'IDENTITY_LEGACY_INVALID', phase: 'legacy-read', markerState: 'unknown',
    });
    expect(JSON.stringify(events)).not.toContain(secretText);
  });

  test('an unavailable storage surface reports identity presence as unknown', async () => {
    const storageError = new Error('browser denied storage access');
    const { coordinator, calls, events } = harness({ storageError });
    expect(await coordinator.synchronize({ pairingActive: false })).toEqual({
      synchronized: false, present: null,
    });
    expect(calls).toEqual([['get', 'styxchat:styx:identity']]);
    expect(events[0]).toMatchObject({ code: 'IDENTITY_SYNC_FAILED', phase: 'legacy-read' });
    expect(JSON.stringify(events)).not.toContain('denied storage');
  });

  test('worker refusal preserves legacy fallback and does not issue GET', async () => {
    const { coordinator, calls, events } = harness({ failRequest: true });
    expect(await coordinator.synchronize({ pairingActive: true })).toEqual({
      synchronized: false, present: true,
    });
    expect(calls.map((call) => call.slice(0, 2))).toEqual([
      ['get', 'styxchat:styx:identity'],
      ['request', 'MIGRATE'],
    ]);
    expect(events[0]).toMatchObject({ code: 'VAULT_WRONG_STATE', phase: 'migrate' });
    expect(JSON.stringify(events)).not.toContain('secret-like');
  });

  test('divergent authenticated readback is diagnosed and never treated as synchronized', async () => {
    const { coordinator, events } = harness({ divergent: true });
    expect(await coordinator.synchronize({ pairingActive: false })).toEqual({
      synchronized: false, present: true,
    });
    expect(events[0]).toMatchObject({ code: 'IDENTITY_DIVERGENCE', mismatch: true });
  });
});
