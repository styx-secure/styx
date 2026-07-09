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
    // Optional: the real library isn't a build-time dependency yet. The
    // @vite-ignore + variable specifier keeps the bundler from trying to
    // resolve it; at runtime it loads if present, else we fall back to the mock.
    const spec = 'styx-js';
    const mod = await import(/* @vite-ignore */ spec);
    if (mod && mod.StyxChat) {
      _cached = mod.StyxChat;
      return _cached;
    }
    throw new Error('styx-js loaded but StyxChat export missing');
  } catch {
    const { MockStyxChat } = await import('./styx-lib-mock.js');
    _cached = MockStyxChat;
    return _cached;
  }
}
