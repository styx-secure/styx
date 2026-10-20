/**
 * Inbound catch-up -- PROTOTYPE (branch proto/sdk-demo-2026-10, not for merge).
 *
 * Problem (demo run1): a message published while this host's network was
 * stalled is accepted by the relays but never pushed to this client, because
 * the socket stayed open and the subscription is never asked again. Nothing
 * re-requests it, so it is lost for the receiver.
 *
 * Fix, the simplest that works: the relay set's pools are created through
 * this module's transport port, so every subscription the relay set issues
 * can be re-issued with a `since` bound.
 *
 *  - Per relay, the largest `created_at` seen on a frame of the client's
 *    subscription is remembered (capped at the local clock, so a relay cannot
 *    push it into the future; a relay only moves its own value).
 *  - Every CATCH_UP_INTERVAL_MS, and whenever a pool (re)subscribes, the REQ
 *    is sent again with the same subscription id and
 *    `since = lastSeen - CATCH_UP_MARGIN_SEC`. A relay that was stalled
 *    answers it with what it stored meanwhile as soon as it is reachable
 *    again; a relay that never stalled answers with a few duplicates.
 *  - Duplicates are dropped by event id in the inbound processor (I-ACK, the
 *    C-DLV section 8 window of 4 096 ids, checked BEFORE the session port's
 *    `open`), so a replayed event is never decrypted twice and no second
 *    receipt is sent. The MLS replay protection is unchanged behind it.
 *
 * The first subscription of a relay (nothing seen yet) carries no `since`, as
 * before, so messages stored while the client was offline are still fetched.
 * Limit: an event whose `created_at` is more than the margin older than the
 * last event seen from that relay (sender clock skew) is not re-requested.
 */

import { RelayPool } from '../transport/nostr-transport.js';

/** Period of the catch-up re-request, in milliseconds. */
export const CATCH_UP_INTERVAL_MS = 10000;

/** Margin subtracted from the last `created_at` seen, in seconds (clock skew). */
export const CATCH_UP_MARGIN_SEC = 120;

/**
 * @param {object} options
 * @param {{ now: Function, setTimer: Function, clearTimer: Function }} options.clock
 * @param {number} [options.intervalMs]
 * @param {number} [options.marginSec]
 * @param {(url: string) => object} [options.createPool] - test seam; default `new RelayPool([url])`
 */
export function createCatchUp(options) {
  const { clock, intervalMs = CATCH_UP_INTERVAL_MS, marginSec = CATCH_UP_MARGIN_SEC } = options;
  const makePool = options.createPool ?? ((url) => new RelayPool([url]));
  const records = new Map(); // url -> { pool, subscribe, subId, base }
  const lastSeen = new Map(); // url -> largest created_at seen (seconds)
  let handle = null;
  let running = false;
  let rounds = 0;

  const nowSec = () => {
    try {
      const n = Math.floor(clock.now() / 1000);
      return Number.isSafeInteger(n) && n >= 0 ? n : null;
    } catch {
      return null;
    }
  };

  const sinceFor = (url) => {
    const seen = lastSeen.get(url);
    return seen === undefined ? null : Math.max(0, seen - marginSec);
  };

  const withSince = (url, filter) => {
    const since = sinceFor(url);
    if (since === null || filter === null || typeof filter !== 'object') return filter;
    return { ...filter, since };
  };

  const transport = Object.freeze({
    create(url) {
      const pool = makePool(url);
      const subscribe = pool.subscribe.bind(pool);
      const rec = { pool, subscribe, subId: null, base: null };
      // Every subscription the relay set issues on this pool goes through here,
      // so a replacement pool (reconnect) subscribes with `since` too.
      pool.subscribe = (subId, filter) => {
        rec.subId = subId;
        rec.base = filter;
        return subscribe(subId, withSince(url, filter));
      };
      records.set(url, rec);
      return pool;
    },
  });

  /** Frame listener of the relay set: frames of the client's subscription only. */
  const observe = (record) => {
    try {
      const data = record && record.data;
      if (!Array.isArray(data) || data[0] !== 'EVENT') return;
      const createdAt = data[2] && data[2].created_at;
      if (!Number.isSafeInteger(createdAt) || createdAt < 0) return;
      const now = nowSec();
      const value = now === null ? createdAt : Math.min(createdAt, now);
      const url = record.relay;
      if (typeof url !== 'string') return;
      const prev = lastSeen.get(url);
      if (prev === undefined || value > prev) lastSeen.set(url, value);
    } catch {
      /* never escapes */
    }
  };

  /** Re-issue the subscription on every current pool with its `since` bound. */
  const catchUpNow = () => {
    rounds += 1;
    for (const [url, rec] of records) {
      if (rec.subId === null || rec.base === null) continue;
      const since = sinceFor(url);
      if (since === null) continue; // nothing seen yet: the open subscription has no lower bound
      try {
        rec.subscribe(rec.subId, { ...rec.base, since });
      } catch {
        /* a pool that refuses simply stays as it is */
      }
    }
  };

  const arm = () => {
    if (!running) return;
    try {
      handle = clock.setTimer(() => {
        handle = null;
        if (!running) return;
        catchUpNow();
        arm();
      }, intervalMs);
    } catch {
      handle = null;
    }
  };

  return Object.freeze({
    transport,
    observe,
    catchUpNow,
    start() {
      if (running) return;
      running = true;
      arm();
    },
    stop() {
      running = false;
      if (handle !== null) {
        try { clock.clearTimer(handle); } catch { /* ignore */ }
        handle = null;
      }
    },
    /** Diagnostics for tests: rounds run and the current per-relay `since`. */
    inspect() {
      return Object.freeze({ rounds, since: Object.freeze(Object.fromEntries([...records.keys()].map((u) => [u, sinceFor(u)]))) });
    },
  });
}
