// dispatcher.js — turn "pubkey X has a new event" into Web Pushes. Coalesces
// bursts per pubkey (one wake per window), fans out to every registered device,
// and prunes subscriptions the push service reports as gone (410/404).
const GONE = new Set([404, 410]);

export class Dispatcher {
  constructor({ registry, send, now, coalesceMs = 4000 }) {
    this._registry = registry;
    this._send = send;
    this._now = now;
    this._coalesceMs = coalesceMs;
    this._lastSentAt = new Map(); // pubkey → ms
  }

  /** @returns {Promise<{sent:number, skipped:boolean}>} */
  async notify(pubkey) {
    const t = this._now();
    const last = this._lastSentAt.get(pubkey) ?? -Infinity;
    if (t - last < this._coalesceMs) return { sent: 0, skipped: true };
    this._lastSentAt.set(pubkey, t);

    const subs = this._registry.get(pubkey);
    let sent = 0;
    for (const sub of subs) {
      try {
        // eslint-disable-next-line no-await-in-loop
        await this._send(sub);
        sent += 1;
      } catch (e) {
        if (GONE.has(e?.statusCode)) await this._registry.remove(pubkey, sub.endpoint);
        else console.error('[dispatcher] push failed:', e?.statusCode || e?.message);
      }
    }
    return { sent, skipped: false };
  }
}
