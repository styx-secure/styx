// factory-reset.js — a real, total device reset.
//
// After this the origin holds nothing recoverable about the identity. Order: destroy
// the identity and revoke push FIRST (via the lib and the push subscription), then wipe
// the physical surfaces, so an interrupted reset cannot leave a working key behind a
// half-cleared cache. Every step is best-effort: a missing API or an already-gone
// surface must not stop the rest.
import { getBridgeUrl } from './config.js';

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
 * @param {boolean} [opts.reload=true] reload the page afterwards (false in tests)
 */
export async function factoryReset({ chat, reload = true } = {}) {
  await revokePush(chat);
  try { await chat?.wipe?.(); } catch { /* best effort */ }

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
  try { indexedDB.deleteDatabase('styx-ledger'); } catch { /* ignore */ }

  // Legacy / app-level unprefixed keys the lib does not own.
  try {
    localStorage.removeItem('styx-identity');
    localStorage.removeItem('styx-theme');
  } catch { /* ignore */ }

  if (reload) location.reload();
}
