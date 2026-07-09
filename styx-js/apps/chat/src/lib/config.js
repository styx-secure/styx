// config.js — transport selection for the app.
//
// - `?local=1`  → no relays → BroadcastChannel (same-machine / offline / tests).
// - `?relay=…`  → use the given relay(s) (repeatable).
// - otherwise   → DEFAULT_RELAYS (public Nostr relays) so the deployed app
//                 connects real people out of the box.
const DEFAULT_RELAYS = ['wss://relay.damus.io', 'wss://nos.lol'];

export function getRelays() {
  try {
    const q = new URLSearchParams(window.location.search);
    if (q.get('local') === '1') return [];
    const explicit = q.getAll('relay');
    return explicit.length ? explicit : DEFAULT_RELAYS;
  } catch {
    return DEFAULT_RELAYS;
  }
}
