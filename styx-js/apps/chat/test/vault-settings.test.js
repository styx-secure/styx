import { describe, test, expect } from '@jest/globals';
import { createVaultSettingsCoordinator } from '../src/lib/vault-settings.js';

function harness({ values = {}, failWrite = false, failRequest = false, divergent = false } = {}) {
  const events = [];
  const calls = [];
  const state = new Map(Object.entries(values));
  const storage = {
    getItem(key) { calls.push(['get', key]); return state.get(key) ?? null; },
    setItem(key, value) {
      calls.push(['set', key, value]);
      if (failWrite) throw new Error('quota');
      state.set(key, value);
    },
  };
  let migrated = null;
  const request = async (type, payload) => {
    calls.push(['request', type, payload]);
    if (failRequest) throw Object.assign(new Error('terminated'), { code: 'WORKER_TERMINATED' });
    if (type === 'MIGRATE') {
      migrated = payload.preferences;
      return { state: 'verified', matched: true, digest: 'a'.repeat(64), recordVersion: 1 };
    }
    return { found: true, record: { value: divergent ? { ...migrated, theme: 'dark' } : migrated } };
  };
  const coordinator = createVaultSettingsCoordinator({
    storage, request, onDiagnostic: (event) => events.push(event),
  });
  return { coordinator, calls, events };
}

describe('vault settings coordinator', () => {
  test('migrates only the exact legacy values and verifies the worker readback', async () => {
    const { coordinator, calls, events } = harness({
      values: { 'styx-theme': 'light', 'styx-install-dismissed': '1' },
    });
    expect(await coordinator.synchronize()).toEqual({
      synchronized: true,
      preferences: { v: 1, theme: 'light', installHintDismissed: true },
    });
    expect(calls.slice(0, 2)).toEqual([
      ['get', 'styx-theme'], ['get', 'styx-install-dismissed'],
    ]);
    expect(calls[2]).toEqual(['request', 'MIGRATE', {
      namespace: 'settings', preferences: { v: 1, theme: 'light', installHintDismissed: true },
    }]);
    expect(events.at(-1)).toMatchObject({ code: 'SETTINGS_SYNC_VERIFIED', mismatch: false });
  });

  test('dual-write commits legacy first and legacy remains authoritative on divergence', async () => {
    const { coordinator, calls, events } = harness({ divergent: true });
    const result = await coordinator.setTheme('light');
    expect(calls[0]).toEqual(['set', 'styx-theme', 'light']);
    expect(result).toEqual({
      synchronized: false,
      preferences: { v: 1, theme: 'light', installHintDismissed: false },
    });
    expect(events.at(-1)).toMatchObject({ code: 'SETTINGS_DIVERGENCE', mismatch: true });
  });

  test('a failed legacy write never sends a vault mutation', async () => {
    const { coordinator, calls, events } = harness({ failWrite: true });
    expect(await coordinator.dismissInstallHint()).toEqual({ synchronized: false, preferences: null });
    expect(calls).toEqual([['set', 'styx-install-dismissed', '1']]);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ code: 'SETTINGS_LEGACY_WRITE_FAILED', phase: 'legacy-write' });
  });

  test('worker failure after the legacy write is diagnosed and retryable from legacy', async () => {
    const { coordinator, calls, events } = harness({ failRequest: true });
    const result = await coordinator.setTheme('dark');
    expect(calls[0]).toEqual(['set', 'styx-theme', 'dark']);
    expect(calls[1][0]).toBe('get');
    expect(result).toEqual({
      synchronized: false,
      preferences: { v: 1, theme: 'dark', installHintDismissed: false },
    });
    expect(events.at(-1)).toMatchObject({ code: 'WORKER_TERMINATED', phase: 'migrate' });
    expect(JSON.stringify(events)).not.toContain('terminated');
  });

  test('storage failure before or during legacy read performs no worker request', async () => {
    const calls = [];
    const coordinator = createVaultSettingsCoordinator({
      storage: { getItem() { calls.push('get'); throw new Error('denied'); } },
      request: async () => { calls.push('request'); },
      onDiagnostic: () => {},
    });
    expect(await coordinator.synchronize()).toEqual({ synchronized: false, preferences: null });
    expect(calls).toEqual(['get']);
  });

  test('invalid theme values are rejected before either storage boundary', () => {
    const { coordinator, calls } = harness();
    expect(() => coordinator.setTheme('sepia')).toThrow('SETTINGS_PAYLOAD_INVALID');
    expect(calls).toEqual([]);
  });
});
