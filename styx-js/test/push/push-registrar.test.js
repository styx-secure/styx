// test/push/push-registrar.test.js — the client fetches the VAPID key, subscribes
// via the browser pushManager, signs the registration with its Nostr key, and
// POSTs it to the bridge. With no bridge URL configured it must be a no-op.
import { describe, test, expect, jest } from '@jest/globals';
import { PushRegistrar, urlBase64ToUint8Array } from '../../src/push/push-registrar.js';

function harness() {
  const calls = [];
  const fetchImpl = jest.fn(async (url, opts) => {
    calls.push({ url, opts });
    if (url.endsWith('/vapidPublicKey')) return { ok: true, json: async () => ({ key: 'BPk_valid-base64url' }) };
    return { ok: true, json: async () => ({ ok: true }) };
  });
  const pushManager = { subscribe: jest.fn(async () => ({ toJSON: () => ({ endpoint: 'https://push/xyz', keys: { p256dh: 'a', auth: 'b' } }) })) };
  const sign = jest.fn(async (action, endpoint) => `sig(${action},${endpoint})`);
  return { calls, fetchImpl, pushManager, sign };
}

describe('PushRegistrar', () => {
  test('is a no-op (returns false) when no bridgeUrl is configured', async () => {
    const { fetchImpl, pushManager, sign } = harness();
    const r = new PushRegistrar({ bridgeUrl: '', pubkey: 'pk', sign, fetchImpl, pushManager });
    expect(await r.enable()).toBe(false);
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(pushManager.subscribe).not.toHaveBeenCalled();
  });

  test('subscribes and POSTs a signed registration to the bridge', async () => {
    const { calls, fetchImpl, pushManager, sign } = harness();
    const r = new PushRegistrar({ bridgeUrl: 'https://bridge', pubkey: 'pk', sign, fetchImpl, pushManager });
    expect(await r.enable()).toBe(true);

    expect(pushManager.subscribe).toHaveBeenCalledWith(expect.objectContaining({ userVisibleOnly: true }));
    expect(sign).toHaveBeenCalledWith('register', 'https://push/xyz');

    const post = calls.find((c) => c.url === 'https://bridge/register');
    expect(post).toBeTruthy();
    const body = JSON.parse(post.opts.body);
    expect(body.pubkey).toBe('pk');
    expect(body.subscription.endpoint).toBe('https://push/xyz');
    expect(body.sig).toBe('sig(register,https://push/xyz)');
  });

  test('resolves to false (never throws) when the bridge is unreachable', async () => {
    const pushManager = { subscribe: jest.fn() };
    const sign = jest.fn();
    const fetchImpl = jest.fn(async () => { throw new Error('network down'); });
    const r = new PushRegistrar({ bridgeUrl: 'https://bridge', pubkey: 'pk', sign, fetchImpl, pushManager });
    await expect(r.enable()).resolves.toBe(false);
    expect(pushManager.subscribe).not.toHaveBeenCalled();
  });
});

describe('urlBase64ToUint8Array', () => {
  test('decodes a URL-safe base64 VAPID key to bytes', () => {
    const out = urlBase64ToUint8Array('AAAA'); // 3 zero bytes
    expect(out).toBeInstanceOf(Uint8Array);
    expect(out.length).toBe(3);
    expect([...out]).toEqual([0, 0, 0]);
  });
});
