// styx-adapter.js — resolves the chat implementation.
//
// Demo build (VITE_DEMO === '1'): the in-memory mock, and ONLY the mock.
// Every other build: the real library. If it cannot load, throw — never fall back to
// fake data. A silent downgrade would show seeded contacts and fake "delivered" ticks
// while the user believes they are talking securely. Components never import either
// directly — they go through useStyxChat(), which uses getStyxChat().

import { FatalCryptoError } from './fatal-error.js';

let _cached = null;

/**
 * Resolve the StyxChat implementation (class/constructor).
 * @returns {Promise<Function>} a class with the StyxChat contract.
 * @throws {FatalCryptoError} outside demo mode, if the real library is unavailable.
 */
export async function getStyxChat() {
  if (_cached) return _cached;

  // Statically foldable: Vite replaces the exact token `import.meta.env.VITE_DEMO` with
  // the literal value, so in a production build this whole branch — and the mock import —
  // is dead-code eliminated and never ships. The `import.meta.env &&` guard short-circuits
  // in runtimes where the object is absent (e.g. jest) without hiding that token from Vite.
  if (import.meta.env && import.meta.env.VITE_DEMO === '1') {
    const { MockStyxChat } = await import('./styx-lib-mock.js');
    _cached = MockStyxChat;
    return _cached;
  }

  try {
    const mod = await import('styx-js');
    if (!mod?.StyxChat) throw new Error('styx-js loaded but StyxChat export missing');
    _cached = mod.StyxChat;
    return _cached;
  } catch (e) {
    throw new FatalCryptoError(e);
  }
}
