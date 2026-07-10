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

/**
 * The transport options to hand StyxChat.init. Having no relays means `?local=1`,
 * i.e. the same-origin BroadcastChannel transport, which carries no signatures —
 * so the insecure opt-in is granted there and only there. Pure, for testing.
 * @param {string[]} relays
 * @returns {{relays: string[], allowInsecureTransport: boolean}}
 */
export function transportOptions(relays) {
  const list = Array.isArray(relays) ? relays : [];
  return { relays: list, allowInsecureTransport: list.length === 0 };
}

/**
 * Parse the opt-in bridge URL from a query string. Pure (no window) for testing.
 * @param {string} search e.g. '?bridge=https://b'
 * @param {string} [fallback] build-time default
 * @returns {string} bridge base URL, '' when unset
 */
export function parseBridgeUrl(search, fallback = '') {
  try {
    const v = new URLSearchParams(search).get('bridge');
    return (v || fallback).replace(/\/$/, '');
  } catch {
    return fallback.replace(/\/$/, '');
  }
}

/** The bridge URL for this session: ?bridge=… or the build-time VITE_BRIDGE_URL. */
export function getBridgeUrl() {
  const fallback = (import.meta.env && import.meta.env.VITE_BRIDGE_URL) || '';
  try { return parseBridgeUrl(window.location.search, fallback); } catch { return ''; }
}
