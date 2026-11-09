// factory-reset.js — a real, total device reset.
//
// After this the origin holds nothing recoverable about the identity. The active
// vault worker is shut down before its database is deleted; the chat wipe is
// fail-closed, while optional browser surfaces remain best-effort.
import { getBridgeUrl } from './config.js';

const PRODUCT_VAULT_DB = 'styx-vault-default';
/** Every StyxChat identity on this origin, whatever its ?ns=, lives under this prefix. */
const CHAT_STORAGE_PREFIX = 'styxchat:';
/** How long the reset waits for the push bridge before going on without it. */
export const BRIDGE_UNREGISTER_TIMEOUT_MS = 5000;

/**
 * Remove every key under CHAT_STORAGE_PREFIX, so the reset also erases the
 * identities of other ?ns= namespaces on this origin, not only the open one.
 */
function clearAllChatNamespaces() {
  if (typeof localStorage === 'undefined' || typeof localStorage.key !== 'function') return;
  const doomed = [];
  for (let i = 0; i < localStorage.length; i += 1) {
    const k = localStorage.key(i);
    if (k != null && k.startsWith(CHAT_STORAGE_PREFIX)) doomed.push(k);
  }
  doomed.forEach((k) => localStorage.removeItem(k));
}

/** fetch() that gives up after `ms`, aborting the request where the platform allows. */
async function fetchWithTimeout(url, init, ms) {
  const controller = typeof AbortController === 'function' ? new AbortController() : null;
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller?.abort();
      reject(new Error('bridge did not answer in time'));
    }, ms);
  });
  try {
    return await Promise.race([fetch(url, { ...init, signal: controller?.signal }), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function deleteDatabase(name) {
  if (typeof indexedDB === 'undefined') return Promise.resolve();
  return new Promise((resolve, reject) => {
    let settled = false;
    let timeout;
    const request = indexedDB.deleteDatabase(name);
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (error) reject(error);
      else resolve();
    };
    timeout = setTimeout(() => finish(new Error('database deletion timed out')), 5000);
    request.onsuccess = () => finish();
    request.onerror = () => finish(request.error || new Error('database deletion failed'));
    // BLOCKED means deletion is pending; allow connections to close before
    // the bounded timeout decides that the reset cannot complete.
    request.onblocked = () => {};
  });
}

async function revokePush(chat, bridge, bridgeTimeoutMs) {
  if (typeof navigator === 'undefined' || !navigator.serviceWorker) return;
  try {
    const reg = await navigator.serviceWorker.getRegistration();
    const sub = await reg?.pushManager?.getSubscription();
    if (!sub) return;
    // Tell the bridge to forget us, signed so it cannot be spoofed, before we drop the
    // local subscription (after unsubscribe the endpoint is gone).
    if (bridge && chat?.signBridgeRegistration) {
      try {
        const sig = await chat.signBridgeRegistration('unregister', sub.endpoint);
        // Bounded: a bridge that never answers must not hold the reset back.
        await fetchWithTimeout(`${bridge}/unregister`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ pubkey: chat.me?.pubkey, endpoint: sub.endpoint, sig }),
        }, bridgeTimeoutMs);
      } catch { /* bridge unreachable or too slow — still drop the local subscription */ }
    }
    await sub.unsubscribe();
  } catch { /* no push / not permitted */ }
}

/**
 * Wipe everything this origin stores for the current identity, then reload.
 * @param {object} opts
 * @param {object} opts.chat the live StyxChat instance (for wipe + signed push unregister)
 * @param {Function} opts.stopVault terminates the product worker before deletion
 * @param {boolean} [opts.reload=true] reload the page afterwards (false in tests)
 * @param {string} [opts.bridgeUrl] push bridge to unregister from (default: this session's)
 * @param {number} [opts.bridgeTimeoutMs] how long to wait for the bridge
 */
export async function factoryReset({
  chat, destroyVault = () => {}, stopVault = () => {}, reload = true,
  bridgeUrl, bridgeTimeoutMs = BRIDGE_UNREGISTER_TIMEOUT_MS,
} = {}) {
  // The product vault is the only reset step that must be deterministic. If
  // it cannot be removed, abort before touching identity or legacy settings.
  try { await destroyVault(); }
  finally { await stopVault(); }
  await deleteDatabase(PRODUCT_VAULT_DB);
  let bridge = bridgeUrl;
  if (bridge === undefined) { try { bridge = getBridgeUrl(); } catch { bridge = ''; } }
  await revokePush(chat, bridge, bridgeTimeoutMs);
  await chat?.wipe?.();

  // Cache Storage (Workbox precache: app shell + WASM).
  try {
    const names = await caches.keys();
    await Promise.all(names.map((n) => caches.delete(n)));
  } catch { /* not available / already gone */ }

  // Service worker.
  try {
    const regs = (await navigator.serviceWorker?.getRegistrations?.()) ?? [];
    await Promise.all(regs.map((r) => r.unregister()));
  } catch { /* ignore */ }

  // Defensive: the ledger DB the chat never writes, in case a prior build did.
  try { await deleteDatabase('styx-ledger'); } catch { /* best effort */ }

  // Legacy / app-level unprefixed keys the lib does not own, and the chat data
  // of every ?ns= namespace (the wipe above only cleared the open one).
  try {
    localStorage.removeItem('styx-identity');
    localStorage.removeItem('styx-theme');
    localStorage.removeItem('styx-install-dismissed');
  } catch { /* ignore */ }
  try { clearAllChatNamespaces(); } catch { /* ignore */ }

  if (reload) location.reload();
}
