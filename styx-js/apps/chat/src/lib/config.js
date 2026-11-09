// config.js — transport selection for the app.
//
// - `?local=1`  → no relays → BroadcastChannel (same-machine / offline / tests).
// - `?relay=…`  → use the given relay(s) (repeatable).
// - `?bridge=…` → register push notifications with the given bridge.
// - otherwise   → DEFAULT_RELAYS (public Nostr relays) so the deployed app
//                 connects real people out of the box.
//
// A link can carry these parameters, so they are hostile input: the app uses
// them only after the user confirms them, once per page load. Declined, the
// app keeps the default relays and the build-time bridge.
const DEFAULT_RELAYS = ['wss://relay.damus.io', 'wss://nos.lol'];

function buildTimeBridge() {
  try { return (import.meta.env && import.meta.env.VITE_BRIDGE_URL) || ''; } catch { return ''; }
}

/**
 * The connection parameters a query string asks for. Pure, for testing.
 * @param {string} search e.g. '?relay=wss://r&bridge=https://b'
 * @returns {{local: boolean, relays: string[], bridge: string}} what is present
 */
export function parseUrlOverrides(search) {
  try {
    const q = new URLSearchParams(search);
    return {
      local: q.get('local') === '1',
      relays: q.getAll('relay').filter(Boolean),
      bridge: (q.get('bridge') || '').replace(/\/$/, ''),
    };
  } catch {
    return { local: false, relays: [], bridge: '' };
  }
}

/** Whether a query string asks for any non-default connection. Pure. */
export function hasUrlOverrides(search) {
  const o = parseUrlOverrides(search);
  return o.local || o.relays.length > 0 || o.bridge !== '';
}

/**
 * The confirmation text for the overrides a query string asks for. Pure.
 * @param {string} search
 * @returns {string} '' when nothing needs confirming
 */
export function describeUrlOverrides(search) {
  if (!hasUrlOverrides(search)) return '';
  const o = parseUrlOverrides(search);
  const lines = ['Questo link chiede di cambiare le connessioni di Styx:'];
  if (o.local) lines.push('- nessun relay: messaggi solo fra schede di questo dispositivo');
  else if (o.relays.length) lines.push(`- relay: ${o.relays.join(', ')}`);
  if (o.bridge) lines.push(`- bridge delle notifiche: ${o.bridge}`);
  lines.push('', 'Usa queste impostazioni solo se le hai chieste tu. Annulla per usare quelle predefinite.');
  return lines.join('\n');
}

/**
 * Decide the connection for a query string. Pure: `confirm` is injected and is
 * called only when the query string asks for something non-default.
 * @param {string} search
 * @param {{confirm: (message: string) => boolean, fallbackBridge?: string}} opts
 * @returns {{relays: string[], bridge: string, fromUrl: boolean}}
 */
export function resolveConnection(search, { confirm, fallbackBridge = '' } = {}) {
  const defaults = { relays: [...DEFAULT_RELAYS], bridge: String(fallbackBridge).replace(/\/$/, ''), fromUrl: false };
  if (!hasUrlOverrides(search)) return defaults;
  let accepted = false;
  try { accepted = confirm?.(describeUrlOverrides(search)) === true; } catch { accepted = false; }
  if (!accepted) return defaults;
  const o = parseUrlOverrides(search);
  return {
    relays: o.local ? [] : (o.relays.length ? o.relays : [...DEFAULT_RELAYS]),
    bridge: o.bridge || defaults.bridge,
    fromUrl: true,
  };
}

let decided = null; // the connection chosen for this page load

/** The connection for this page load, asking the user at most once. */
function connection() {
  if (decided) return decided;
  try {
    decided = resolveConnection(window.location.search, {
      confirm: (message) => window.confirm(message),
      fallbackBridge: buildTimeBridge(),
    });
  } catch {
    decided = { relays: [...DEFAULT_RELAYS], bridge: '', fromUrl: false };
  }
  return decided;
}

export function getRelays() {
  return [...connection().relays];
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
 * It does not ask for confirmation: getBridgeUrl() does.
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

/** The bridge URL for this session: a confirmed ?bridge=… or the build-time VITE_BRIDGE_URL. */
export function getBridgeUrl() {
  return connection().bridge;
}
