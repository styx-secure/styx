// test/styx-adapter.test.js
// The adapter must never fall back to fake data outside demo mode. Under jest (native
// ESM, not Vite) `import.meta.env` is undefined, so the demo branch is skipped and we
// exercise exactly the real-lib-vs-hard-fail path.
import { describe, test, expect, jest, beforeEach } from '@jest/globals';

// Force the real-lib import to fail, so getStyxChat must throw FatalCryptoError
// (never swap in the mock).
jest.unstable_mockModule('styx-js', () => {
  throw new Error('wasm unavailable');
});

beforeEach(() => jest.resetModules());

describe('styx-adapter — no silent mock fallback', () => {
  test('outside demo mode, a missing real lib throws FatalCryptoError', async () => {
    const { getStyxChat } = await import('../src/lib/styx-adapter.js');
    await expect(getStyxChat()).rejects.toMatchObject({ name: 'FatalCryptoError' });
  });

  test('the thrown error carries the underlying cause', async () => {
    const { getStyxChat } = await import('../src/lib/styx-adapter.js');
    const err = await getStyxChat().catch((e) => e);
    expect(err.name).toBe('FatalCryptoError');
    expect(err.cause).toBeInstanceOf(Error);
  });
});
