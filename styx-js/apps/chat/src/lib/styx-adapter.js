// styx-adapter.js — picks the real StyxChat library when available, else the mock.
//
// The real library (once published) is imported as `import { StyxChat } from 'styx-js'`.
// Until then (or when running the UI in isolation) we fall back to the in-memory mock,
// which implements the exact same contract. Components never import either directly —
// they go through useStyxChat(), which uses getStyxChat().

let _cached = null;

/**
 * Resolve the StyxChat implementation (class/constructor).
 * @returns {Promise<Function>} a class with the StyxChat contract.
 */
export async function getStyxChat() {
  if (_cached) return _cached;
  try {
    // `styx-js` is resolved via a Vite alias to the library source. If that
    // ever fails to load, fall back to the in-memory mock so the UI still runs.
    const mod = await import('styx-js');
    if (mod && mod.StyxChat) {
      _cached = mod.StyxChat;
      return _cached;
    }
    throw new Error('styx-js loaded but StyxChat export missing');
  } catch (e) {
    console.warn('[styx-adapter] real lib unavailable, using mock:', e?.message);
    const { MockStyxChat } = await import('./styx-lib-mock.js');
    _cached = MockStyxChat;
    return _cached;
  }
}
