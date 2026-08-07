// factory-reset.js — a real, total device reset.
//
// After this the origin holds nothing recoverable about the identity. The active
// vault worker is shut down before its database is deleted; the chat wipe is
// fail-closed, while optional browser surfaces remain best-effort.
import { getBridgeUrl } from './config.js';

const PRODUCT_VAULT_DB = 'styx-vault-default';

function deleteDatabase(name) {
  if (typeof indexedDB === 'undefined') return Promise.resolve();
  return new Promise((resolve, reject) => {
    let settled = false;
    const request = indexedDB.deleteDatabase(name);
    const finish = (error) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve();
    };
    request.onsuccess = () => finish();
    request.onerror = () => finish(request.error || new Error('database deletion failed'));
    request.onblocked = () => finish(new Error('database deletion blocked'));
  });
}

async function revokePush(chat) {
  if (typeof navigator === 'undefined' || !navigator.serviceWorker) return;
  try {
    const reg = await navigator.serviceWorker.getRegistration();
    const sub = await reg?.pushManager?.getSubscription();
    if (!sub) return;
    // Tell the bridge to forget us, signed so it cannot be spoofed, before we drop the
    // local subscription (after unsubscribe the endpoint is gone).
    const bridge = getBridgeUrl();
    if (bridge && chat?.signBridgeRegistration) {
      try {
        const sig = await chat.signBridgeRegistration('unregister', sub.endpoint);
        await fetch(`${bridge}/unregister`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ pubkey: chat.me?.pubkey, endpoint: sub.endpoint, sig }),
        });
      } catch { /* bridge unreachable — still drop the local subscription */ }
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
 */
export async function factoryReset({ chat, stopVault = () => {}, reload = true } = {}) {
  // The product vault is the only reset step that must be deterministic. If
  // it cannot be removed, abort before touching identity or legacy settings.
  try { stopVault(); } catch { /* the deletion still provides the final guard */ }
  await deleteDatabase(PRODUCT_VAULT_DB);
  await revokePush(chat);
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

  // Legacy / app-level unprefixed keys the lib does not own.
  try {
    localStorage.removeItem('styx-identity');
    localStorage.removeItem('styx-theme');
    localStorage.removeItem('styx-install-dismissed');
  } catch { /* ignore */ }

  if (reload) location.reload();
}
