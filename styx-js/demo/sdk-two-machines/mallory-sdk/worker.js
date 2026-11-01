// styx-demo-mallory -- "Mallory", the simulated attacker of the M3 demo run, on Cloudflare Workers.
//
// She runs at the Cloudflare edge: a server outside both demo networks. She has no capture capability
// and no member key. Everything she uses she reads from the public Nostr relays, exactly as any
// stranger could. Her attacks are a FIXED script against FIXED triggers: no model, no adaptation.
//
// She is autonomous: her attack workflow lives in a Durable Object (`Arm`) that holds her throwaway
// key, her log, her state and the event ids she published. One measured caveat: on this account the
// object's own alarms did not fire (setAlarm was accepted and never ran), so her step is driven by the
// caller's `GET /poke` -- best effort, and the log read never waits for it. The ATTACKS are still
// triggered inside her object by intercepted messages; nothing outside can trigger one:
//
// the harness only ARMS her once (POST /arm) and reads her log (GET /log). Her log is the only
// control surface, read-only.
//
// Why polling instead of one long-lived socket: a Durable Object is frozen when no request is in
// flight, and long outbound sockets are lost with it. So each of her ticks is a self-contained read:
// it opens a fresh socket per relay, asks for what the relay holds for `#p=Bob`, listens a couple of
// seconds for live events too, then closes the sockets. A tick takes a few seconds and is atomic, so
// a freeze can only delay her, never corrupt her state (every field is written through storage).
//
// Endpoints:
//   GET  /health        -> colo, country, egress hash, relays, armed state (no secret, no account data)
//   POST /arm?p=<bob>&r=wss://a,wss://b[&skip=3][&ttl=1800][&silence=6000]
//                       -> arm her against the recipient public key and run the first tick.
//                          Answers { armed, subscribed, relays, pk, log }. Messages published
//                          BEFORE this call are not attacked: the script starts from here.
//   GET  /tick          -> advance one tick now (each /log call does the same in the background)
//   GET  /log[?since=N] -> the whole timestamped log, her state, the attacks and the ids she published
//   POST /disarm        -> stand down
//
// The script (fixed triggers, fixed order). On the first kind-4741 intercepted after arming, once
// `skip` earlier messages of this run have gone by (skip=0 means the first one), she runs, 1.5 s apart:
//   1 replay    : re-publish the captured event byte-identical, with its original signature
//   2a tamper   : flip one byte of the content, keep the author's pubkey and signature
//   2b tamper   : flip one byte of the content, re-sign with her own throwaway key
//   3 injection : a well-formed kind-4741 tagged to the recipient, signed by her (not a group member)
//   4 forged receipt : if no kind-4742 naming that event reached the relays within `silence` ms,
//                      she publishes a kind-4742 addressed to its author, signed by her
// Every relay answer (OK / NOTICE / CLOSED / silence) is recorded per event id.
//
// Synthetic data only. No secret, no account data and no key of either participant is read, stored
// or returned.
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';

const DEFAULT_RELAYS = ['wss://relay.primal.net', 'wss://offchain.pub', 'wss://relay.damus.io'];
const VERSION = 'styx-m3-sdk/0.3.0-experimental';
const KIND_MESSAGE = 4741;
const KIND_RECEIPT = 4742;
const LISTEN_MS = 2200;       // live listen window of one tick, per relay
const PAUSE_MS = 1500;        // between the attacks, so each one is distinguishable
const LOOKBACK_S = 90;        // how far back a tick reads
const LOG_MAX = 900;

const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const unhex = (s) => Uint8Array.from((s.match(/../g) || []).map((h) => parseInt(h, 16)));
const h12 = (s) => hex(sha256(new TextEncoder().encode(s))).slice(0, 12);
const b64 = (u8) => btoa(String.fromCharCode(...u8));
const at = () => new Date().toISOString().slice(11, 23) + 'Z';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const isHex = (s, n) => new RegExp(`^[0-9a-f]{${n}}$`).test(s || '');

/** NIP-01 event id: sha256 of the canonical serialization. */
function eventId(ev) {
  return hex(sha256(new TextEncoder().encode(JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]))));
}
/** NIP-01 signing (BIP-340 schnorr) exactly as the delivery layer does it: the digest is the 32 bytes
 *  of sha256 over the canonical serialization, and the signature is schnorr over those bytes. */
function signEvent(sk, draft) {
  const ev = { ...draft };
  ev.id = eventId(ev);
  ev.sig = hex(schnorr.sign(unhex(ev.id), sk));
  return ev;
}

/* ------------------------------ one relay connection ------------------------------ */
class Relay {
  constructor(url, index, session, subId) {
    this.url = url;
    this.name = new URL(url).host;
    this.rn = index + 1;
    this.tag = `R${index + 1} ${this.name}`;
    this.session = session;
    this.subId = subId;
    this.events = [];
    this.oks = new Map();
    this.notes = [];
    this.frames = 0;
    this.state = 'idle';
    this.subscribed = false;
    this.ws = null;
  }
  async open() {
    const ws = new WebSocket(this.url);
    this.ws = ws;
    this.state = 'connecting';
    await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error('timeout opening')), 7000);
      ws.addEventListener('open', () => { clearTimeout(t); resolve(); }, { once: true });
      ws.addEventListener('error', () => { clearTimeout(t); reject(new Error('socket error')); }, { once: true });
    });
    this.state = 'open';
    ws.addEventListener('message', (e) => {
      const text = typeof e.data === 'string' ? e.data : '';
      if (!text) return;
      this.frames += 1;
      let m;
      try { m = JSON.parse(text); } catch { return; }
      if (!Array.isArray(m)) return;
      if (m[0] === 'EVENT' && m[2]) {
        if (m[1] === this.subId) this.subscribed = true;
        this.events.push(m[2]);
      } else if (m[0] === 'EOSE' && m[1] === this.subId) {
        this.subscribed = true;
      } else if (m[0] === 'OK') {
        this.oks.set(m[1], { ok: m[2] === true, msg: String(m[3] ?? '') });
      } else if (m[0] === 'NOTICE') this.notes.push(String(m[1] ?? ''));
      else if (m[0] === 'CLOSED') { this.notes.push('CLOSED: ' + String(m[2] ?? '')); this.state = 'closed'; }
    });
    ws.addEventListener('close', () => { this.state = 'closed'; });
    return this;
  }
  send(obj) { try { this.ws.send(JSON.stringify(obj)); return true; } catch { return false; } }
  subscribe(since) {
    const filters = [{ kinds: [KIND_MESSAGE, KIND_RECEIPT], '#p': [this.session.bobPk], since }];
    // v5: she also reads the receipts addressed to the group's sender (public on the relays), so she can
    // tell which delivery the recipient has NOT acknowledged -- that is the one she forges a receipt for
    const g = this.session.groupAuthor;
    if (g) filters.push({ kinds: [KIND_RECEIPT], '#p': [g], since });
    return this.send(['REQ', this.subId, ...filters]);
  }
  closeReq() { return this.send(['CLOSE', this.subId]); }
  publish(ev) { return this.send(['EVENT', ev]); }
  /** the relay's own answer to one event: OK true/false, a NOTICE that refused it, or silence */
  async waitOk(id, ms = 5000) {
    const t0 = Date.now();
    for (;;) {
      const ok = this.oks.get(id);
      if (ok) return { kind: 'OK', ok: ok.ok, msg: ok.msg };
      if (this.notes.length > 0 && this.state === 'closed') return { kind: 'NOTICE', ok: false, msg: this.notes.join(' | ') };
      const left = ms - (Date.now() - t0);
      if (left <= 0) return { kind: 'NO_RESPONSE', ok: null, msg: `no OK/NOTICE within ${ms} ms` };
      await sleep(Math.min(120, left));
    }
  }
  close() { try { this.ws.close(); } catch { /* already closed */ } }
}

/* ------------------------------------- the attacker ------------------------------------- */
export class Arm {
  constructor(state, env) {
    this.state = state;
    this.ctx = state;
    this.env = env;
    this.conns = [];
    this.scriptRunning = false;
    this.ticking = false;
    this.reset();
  }

  reset() {
    this.log = [];
    this.cfg = null;
    this.phase = 'idle';
    this.attacks = [];
    this.published = {};
    this.messages = [];
    this.collected = new Map();
    this.receiptsSeen = new Set();
    this.attackOf = null;
    this.pendingReceipt = null;   // { target, author, since, ids }
    this.subscribed = new Set();
    this.sk = schnorr.utils.randomPrivateKey();
    this.skHex = hex(this.sk);
    this.pk = hex(schnorr.getPublicKey(this.sk));
    this.subId = 'mallory-' + h12(String(Math.random()));
    this.startedAt = null;
    this.armEpoch = null;
    this.scriptDone = false;
    this.groupAuthor = null;
    this.lastError = null;
    this.expiresAt = null;
    this.since = Math.floor(Date.now() / 1000) - LOOKBACK_S;
    this.ticks = 0;
  }

  /* ---- log ---- */
  say(step, result, relayTag) {
    this.log.push({ t: at(), ms: Date.now(), ...(relayTag ? { relay: relayTag } : {}), step, result });
    if (this.log.length > LOG_MAX) this.log.splice(0, this.log.length - LOG_MAX);
  }

  /* ---- storage ---- */
  snapshot() {
    return {
      log: this.log, cfg: this.cfg, phase: this.phase, attacks: this.attacks, published: this.published,
      messages: this.messages.map((m) => ({ id: m.id, pubkey: m.pubkey, created_at: m.created_at, kind: m.kind, tags: m.tags, content: m.content, sig: m.sig, via: m.via })),
      armEpoch: this.armEpoch, groupAuthor: this.groupAuthor,
      pk: this.pk, subscribed: [...this.subscribed], startedAt: this.startedAt, expiresAt: this.expiresAt,
      since: this.since, ticks: this.ticks, subId: this.subId, sk: this.skHex, pendingReceipt: this.pendingReceipt,
      scriptDone: this.scriptDone,
      receipted: [...this.receiptsSeen].slice(-200), attackOf: this.attackOf,
    };
  }
  async persist() {
    await this.state.storage.put('mallory', this.snapshot());
  }
  async restore() {
    const s = await this.state.storage.get('mallory');
    if (!s) return false;
    this.log = s.log || [];
    this.cfg = s.cfg || null;
    this.phase = s.phase || 'idle';
    this.attacks = s.attacks || [];
    this.published = s.published || {};
    this.messages = s.messages || [];
    this.pk = s.pk || this.pk;
    if (s.sk && /^[0-9a-f]{64}$/.test(s.sk)) { this.sk = unhex(s.sk); this.skHex = s.sk; }
    this.subscribed = new Set(s.subscribed || []);
    this.startedAt = s.startedAt || null;
    this.expiresAt = s.expiresAt || null;
    this.since = s.since ?? this.since;
    this.ticks = s.ticks || 0;
    this.subId = s.subId || this.subId;
    this.pendingReceipt = s.pendingReceipt || null;
    this.attackOf = s.attackOf ?? null;
    this.scriptDone = s.scriptDone === true;
    this.armEpoch = s.armEpoch ?? null;
    this.groupAuthor = s.groupAuthor ?? null;
    for (const id of s.receipted || []) this.receiptsSeen.add(id);
    return true;
  }

  get bobPk() { return this.cfg?.bobPk ?? ''; }
  get helped() { return this.log.some((l) => l.step === 'help'); }

  /* ---- one self-contained read: open, ask, listen, close ---- */
  async readRelays() {
    const cfg = this.cfg;
    const relays = cfg.relays;
    const since = this.since;
    const conns = [];
    await Promise.all(relays.map(async (url, i) => {
      const r = new Relay(url, i, this, this.subId);
      try {
        await r.open();
        r.subscribe(since);
        conns.push(r);
      } catch (e) {
        this.say('connect', `FAILED: ${e.message}`, r.tag);
      }
    }));
    await sleep(LISTEN_MS);
    for (const r of conns) { try { r.closeReq(); } catch { /* ignore */ } }
    const first = this.ticks === 1;
    for (const r of conns) {
      if (r.subscribed) this.subscribed.add(r.rn);
      if (first) this.say('connect', `socket open, REQ sent, ${r.events.length} event(s) already on this relay (kinds 4741/4742, #p=${this.bobPk.slice(0, 8)}…)`, r.tag);
      for (const ev of r.events) this.ingest(r, ev);
      r.close();
    }
    this.lastRead = { relays: conns.length, of: relays.length, events: conns.reduce((a, r) => a + r.events.length, 0) };
    this.conns = conns.filter((r) => r.state === 'open');
  }
  ingest(r, ev) {
    if (!ev || !ev.id || this.collected.has(ev.id)) return;
    // anything created before the arming belongs to some earlier traffic, not to this run
    if (this.armEpoch !== null && this.armEpoch !== undefined && Number(ev.created_at) < this.armEpoch) return;
    this.collected.set(ev.id, { ev, via: r.rn });
    if (ev.kind === KIND_MESSAGE) {
      if (this.groupAuthor === null && ev.pubkey !== this.pk) this.groupAuthor = ev.pubkey;
      this.messages.push({ ...ev, via: r.rn });
      this.say('read', `kind 4741 ${ev.id.slice(0, 8)}… from author ${ev.pubkey.slice(0, 8)}… read off the public relays: content ${ev.content.length} chars base64 ciphertext, sha256 ${h12(ev.content)}`, r.tag);
    } else if (ev.kind === KIND_RECEIPT) {
      const e = (ev.tags.find((t) => t[0] === 'e') || [])[1] || '-';
      this.receiptsSeen.add(e);
      this.say('read', `kind 4742 receipt ${ev.id.slice(0, 8)}… from ${ev.pubkey.slice(0, 8)}… naming event ${e.slice(0, 8)}…`, r.tag);
    }
  }

  /** the messages of this run with each ciphertext counted once: a retried delivery republishes the
   * same bytes (only the nonce tag changes), so wire copies of one message must not count twice. */
  distinctMessages() {
    const seen = new Set();
    const out = [];
    for (const ev of this.messages) {
      // her own forged events carry #p = the recipient too, but they are not the group's messages
      if (this.groupAuthor !== null && ev.pubkey !== this.groupAuthor) continue;
      const k = h12(ev.content);
      if (seen.has(k)) continue;
      seen.add(k);
      out.push(ev);
    }
    return out;
  }

  /* ---- the fixed script: only publishes, no waiting for the harness ---- */
  openForPublish() {
    const cfg = this.cfg;
    const jobs = cfg.relays.map(async (url, i) => {
      const r = new Relay(url, i, this, this.subId);
      try { await r.open(); this.conns[i] = r; } catch (e) { this.say('connect', `FAILED on publish: ${e.message}`, r.tag); }
    });
    return Promise.all(jobs);
  }

  async runScript() {
    if (this.scriptRunning) return;
    this.scriptRunning = true;
    try {
      const cfg = this.cfg;
      const distinct = this.distinctMessages();
      const observed = distinct[cfg.skip] || distinct[distinct.length - 1];
      const victim = observed && Object.fromEntries(['id','pubkey','created_at','kind','tags','content','sig'].map(k => [k, observed[k]]));
      if (!victim) return;
      this.attackOf = victim.id;
      const author = victim.pubkey;
      if (!this.helped) {
        this.log.push({ t: at(), ms: Date.now(), step: 'help', result: 'the relay answers of this run are recorded below, one line per event id she published; her whole log is pulled with GET /log' });
      }
      this.say('plan', `fixed script on intercepted event ${victim.id.slice(0, 8)}… (author ${author.slice(0, 8)}…): 1 replay, 2a/2b tamper, 3 injection, then 4 forged receipt if no kind-4742 naming it has reached the relays within ${(cfg.silenceMs / 1000).toFixed(1)} s`);
      await this.openForPublish();
      await sleep(PAUSE_MS);

      /* 1 -- replay, byte-identical, original signature */
      {
        const r = this.conns[0];
        this.say('attack 1 replay', `re-publishing event ${victim.id.slice(0, 8)}… unchanged, still signed by its author ${author.slice(0, 8)}…`, r?.tag);
        let answer = { kind: 'NO_CONNECTION', ok: null, msg: 'no relay socket' };
        if (r) { r.publish(victim); answer = await r.waitOk(victim.id, 6000); }
        this.say('attack 1 replay', `relay answer: ${answer.kind} ok=${answer.ok} "${answer.msg}"`, r?.tag);
        this.published[1] = [victim.id];
        this.attacks.push({ n: 1, name: 'replay', what: `re-publish intercepted event ${victim.id} unchanged, still signed by the author`, ids: [victim.id], relayAnswer: `${r?.tag ?? '-'}: ${answer.kind} ok=${answer.ok} "${answer.msg}"` });
        await this.persist();
      }
      await sleep(PAUSE_MS);

      /* 2a and 2b -- tamper */
      {
        const swapped = (victim.content[0] === 'A' ? 'B' : 'A') + victim.content.slice(1);
        const a = { ...victim, content: swapped };   // author's pubkey and signature kept
        const b = signEvent(this.sk, { pubkey: this.pk, created_at: Math.floor(Date.now() / 1000), kind: KIND_MESSAGE, tags: victim.tags, content: swapped });
        const ids = [];
        const answers = [];
        for (const r of this.conns) {
          this.say('attack 2a tamper, author key + broken signature', `last base64 character of the content flipped: event ${a.id.slice(0, 8)}… keeps the author's key, so its signature no longer verifies`, r.tag);
          r.publish(a);
          const ans = await r.waitOk(a.id, 5000);
          ids.push(a.id);
          answers.push(`R${r.rn} ${ans.kind} ok=${ans.ok} "${ans.msg}"`);
          this.say('attack 2a tamper, author key + broken signature', `relay answer: ${ans.kind} ok=${ans.ok} "${ans.msg}"`, r.tag);
        }
        for (const r of this.conns) {
          this.say('attack 2b tamper, re-signed with her own key', `same altered bytes, re-signed by non-member ${this.pk.slice(0, 8)}…: event ${b.id.slice(0, 8)}…`, r.tag);
          r.publish(b);
          const ans = await r.waitOk(b.id, 5000);
          ids.push(b.id);
          answers.push(`R${r.rn} ${ans.kind} ok=${ans.ok} "${ans.msg}"`);
          this.say('attack 2b tamper, re-signed with her own key', `relay answer: ${ans.kind} ok=${ans.ok} "${ans.msg}"`, r.tag);
        }
        this.published[2] = ids;
        this.attacks.push({ n: 2, name: 'tamper', what: `flip the last base64 character of the content of ${victim.id} (2a keeps the author's key and signature; 2b re-signs with her own key ${this.pk})`, ids, relayAnswer: answers.join('; ') });
        await this.persist();
      }
      await sleep(PAUSE_MS);

      /* 3 -- injection as a non-member */
      {
        const payload = new Uint8Array(160);
        crypto.getRandomValues(payload);
        const forged = signEvent(this.sk, {
          pubkey: this.pk, created_at: Math.floor(Date.now() / 1000), kind: KIND_MESSAGE,
          tags: [['p', this.bobPk], ['v', VERSION], ['n', hex(crypto.getRandomValues(new Uint8Array(16)))], ['r', '1']],
          content: b64(payload),
        });
        const r = this.conns[0];
        this.say('attack 3 injection as a non-member', `publishing well-formed kind-4741 event ${forged.id.slice(0, 8)}… tagged to the recipient, signed by non-member ${this.pk.slice(0, 8)}…`, r?.tag);
        let answer = { kind: 'NO_CONNECTION', ok: null, msg: 'no relay socket' };
        if (r) { r.publish(forged); answer = await r.waitOk(forged.id, 6000); }
        this.say('attack 3 injection as a non-member', `relay answer: ${answer.kind} ok=${answer.ok} "${answer.msg}"`, r?.tag);
        this.published[3] = [forged.id];
        this.attacks.push({ n: 3, name: 'injection', what: `publish a kind-4741 event tagged to the recipient, signed by non-member ${this.pk}; content 160 random bytes`, ids: [forged.id], relayAnswer: `${r?.tag ?? '-'}: ${answer.kind} ok=${answer.ok} "${answer.msg}"` });
        await this.persist();
      }

      /* 4 -- the forged receipt is armed now and fired by the NEXT tick: never inside this one, so
       * her answers stay inside one request and the harness can poll for it. */
      this.pendingReceipt = { target: null, author, armedAt: Date.now(), dueAt: Date.now() + cfg.silenceMs };
      this.say('attack 4 forged receipt', `armed: at ${new Date(this.pendingReceipt.dueAt).toISOString().slice(11, 19)}Z (${(cfg.silenceMs / 1000).toFixed(1)} s) she picks the newest message of this run that NO kind-4742 on the relays names (the delivery the recipient has not acknowledged) and publishes her own receipt for it`);
      await this.persist();
      for (const r of this.conns) r.close();
    } catch (e) {
      this.lastError = `${e?.name ?? 'Error'}: ${e?.message ?? e}`;
      this.say('error', `the script faulted (${this.lastError}); she records it and stands down. This is a fault of the attacker, not of the delivery layer`);
    } finally {
      this.scriptRunning = false;
      if (this.published['3'] || this.published['2'] || this.published['1']) this.scriptDone = true;
      await this.persist();
    }
  }

  /** attack 4, on a later tick, once the silence window has passed */
  async fireForgedReceipt() {
    const p = this.pendingReceipt;
    if (!p) return;
    if (Date.now() < p.dueAt) return;   // not due yet: keep waiting on later ticks
    // a retried delivery republishes the same ciphertext under a new id: acknowledged = any wire copy named
    const ackedHashes = new Set(this.messages.filter((m) => this.receiptsSeen.has(m.id)).map((m) => h12(m.content)));
    const isAcked = (m) => ackedHashes.has(h12(m.content));
    const open = this.distinctMessages().filter((m) => !isAcked(m))
      .sort((x, y) => (Number(x.created_at) - Number(y.created_at)));
    const acked = this.distinctMessages().filter((m) => isAcked(m)).map((m) => m.id.slice(0, 8) + '…');
    this.say('attack 4 forged receipt', `receipts seen on the relays for: ${acked.join(', ') || 'none'}; unacknowledged: ${open.map((m) => m.id.slice(0, 8) + '…').join(', ') || 'none'}`);
    if (open.length === 0) {
      this.say('attack 4 forged receipt', 'NOT RUN: every message of this run already has a receipt on the relays');
      this.attacks.push({ n: 4, name: 'forged receipt', what: 'not run: every message of this run was already acknowledged', ids: [], relayAnswer: 'not run' });
      this.pendingReceipt = null;
      return;
    }
    p.target = open[open.length - 1].id;
    p.author = open[open.length - 1].pubkey;
    const ids = [];
    const answers = [];
    await this.openForPublish();
    for (const r of this.conns) {
      const forged = signEvent(this.sk, {
        pubkey: this.pk, created_at: Math.floor(Date.now() / 1000), kind: KIND_RECEIPT,
        tags: [['p', p.author], ['e', p.target], ['v', VERSION], ['n', hex(crypto.getRandomValues(new Uint8Array(16)))]],
        content: '',
      });
      ids.push(forged.id);
      this.say('attack 4 forged receipt', `forged kind-4742 ${forged.id.slice(0, 8)}… addressed to the author ${p.author.slice(0, 8)}…, naming their event ${p.target.slice(0, 8)}…, signed by non-member ${this.pk.slice(0, 8)}…`, r.tag);
      r.publish(forged);
      const ans = await r.waitOk(forged.id, 5000);
      answers.push(`R${r.rn} ${ans.kind} ok=${ans.ok} "${ans.msg}"`);
      this.say('attack 4 forged receipt', `relay answer: ${ans.kind} ok=${ans.ok} "${ans.msg}"`, r.tag);
    }
    for (const r of this.conns) r.close();
    this.published[4] = ids;
    this.attacks.push({ n: 4, name: 'forged receipt', what: `publish a kind-4742 addressed to the sender of ${p.target}, signed by non-member ${this.pk}, while that delivery is still unacknowledged (target ${p.target})`, target: p.target, ids, relayAnswer: answers.join('; ') });
    this.pendingReceipt = null;
    await this.persist();
  }

  /* ---- one tick: read, decide, act ---- */
  async tick() {
    if (this.ticking) return { skipped: true };
    this.ticking = true;
    try {
      await this.restore();
      if (this.phase !== 'armed' && this.phase !== 'script') return { phase: this.phase };
      if (this.expiresAt && Date.now() > this.expiresAt) {
        this.say('stop', 'TTL reached: standing down');
        this.phase = 'expired';
        await this.persist();
        return { phase: 'expired' };
      }
      this.ticks += 1;
      // while one forged receipt is due, reading is not needed: attack 4 goes out at once, so her
      // answer never depends on a long request surviving
      await this.readRelays();   // v5: always read; the forged-receipt target depends on the receipts seen
      const need = this.cfg.skip + 1;
      const live = this.messages.length;
      if (live > 0) this.say('observe', `tick ${this.ticks}: read ${this.lastRead.events} event(s) from ${this.lastRead.relays}/${this.lastRead.of} relay(s); ${live} message(s) of this run intercepted, ${this.receiptsSeen.size} acknowledged`);
      await this.fireForgedReceipt();
      if (!this.scriptDone && this.distinctMessages().length >= need) {
        this.say('trigger', `the fixed script is triggered: ${this.distinctMessages().length} distinct message(s) of this run intercepted, skip=${this.cfg.skip}`);
        await this.persist();
        await this.runScript();
        this.say('stop', `script published: ${Object.values(this.published).flat().length} event(s) from ${this.collected.size} read off the public relays`);
      }
      await this.persist();
      return { ticks: this.ticks, messages: live, attacks: Object.keys(this.published).length };
    } finally {
      this.ticking = false;
    }
  }

  /* the alarm keeps her alive between requests, where the platform allows it */
  async alarm() {
    await this.restore();
    if (this.phase === 'armed') await this.tick();
    await this.state.storage.setAlarm(Date.now() + 5000);
  }

  /* ---- HTTP ---- */
  async fetch(request) {
    const url = new URL(request.url);
    const cors = { 'access-control-allow-origin': '*' };
    const json = (o, s = 200) => Response.json(o, { status: s, headers: cors });
    await this.restore();

    if (url.pathname === '/arm' && request.method === 'POST') {
      const bobPk = url.searchParams.get('p') || '';
      const groupAuthor = url.searchParams.get('g') || '';
      const relaysParam = (url.searchParams.get('r') || '').split(',').map((x) => x.trim()).filter(Boolean);
      const relays = relaysParam.length > 0 && relaysParam.every((u) => /^wss:\/\/[a-z0-9.-]+(:\d+)?$/i.test(u))
        ? relaysParam.slice(0, 4) : DEFAULT_RELAYS.slice();
      if (!isHex(bobPk, 64)) return json({ error: 'p must be 64-char lowercase hex (the recipient public key)' }, 400);
      const skip = Math.max(0, Math.min(50, Number.parseInt(url.searchParams.get('skip') ?? '0', 10) || 0));
      const ttl = Math.max(60, Math.min(3600, Number.parseInt(url.searchParams.get('ttl') ?? '1800', 10) || 1800));
      const silenceMs = Math.max(1000, Math.min(60000, Number.parseInt(url.searchParams.get('silence') ?? '6000', 10) || 6000));
      this.reset();
      this.cfg = { bobPk, groupAuthor: /^[0-9a-f]{64}$/.test(groupAuthor) ? groupAuthor : null, relays, skip, ttl, silenceMs, label: url.searchParams.get('label') || '' };
      this.groupAuthor = this.cfg.groupAuthor;
      this.phase = 'armed';
      this.startedAt = Date.now();
      this.expiresAt = this.startedAt + ttl * 1000;
      // ONLY what is published from now on counts as traffic of this run: older events on the relays
      // (other tests, other users) are ignored, so the fixed script can never chase stale traffic.
      this.armEpoch = Math.floor(Date.now() / 1000);
      this.since = this.armEpoch;
      this.say('arm', `ARMED at the Cloudflare edge: no key material and no capture; she reads the public relays only (kinds 4741/4742, #p=${bobPk.slice(0, 8)}…). skip=${skip}; the script fires on the ${skip + 1}th message of this run; TTL ${ttl} s; silence window ${(silenceMs / 1000).toFixed(1)} s`);
      this.say('key', `fresh throwaway Nostr key ${this.pk.slice(0, 8)}… generated inside the Durable Object; never a member of the MLS group`);
      this.ticks = 0;
      await this.persist();
      const r = await this.tick();
      await this.state.storage.setAlarm(Date.now() + 5000);
      return json({ armed: true, subscribed: this.subscribed.size, relays: relays.map((u) => new URL(u).host), pk: this.pk, since: this.since, firstTick: r, log: this.log });
    }

    if (url.pathname === '/tick') {
      const r = await this.tick();
      return json({ ...r, phase: this.phase, log: this.log.slice(-8) });
    }

    if (url.pathname === '/poke') {
      // one best-effort step of hers; the caller gives up early and simply asks again
      try { this.ctx.waitUntil(this.tick()); } catch { /* ignore */ }
      return json({ poked: true, phase: this.phase, ticks: this.ticks, attacks: this.attacks.length }, 200);
    }

    if (url.pathname === '/log') {
      const since = Number.parseInt(url.searchParams.get('since') ?? '0', 10) || 0;
      // a read of her log NEVER drives a tick: it would have to wait for a relay round trip. The caller
      // drives her with GET /poke, which is best-effort, so her attacks are triggered by her own state
      // and never by the harness. A read is always immediate.
      return json({
        armed: this.phase === 'armed', phase: this.phase, ticks: this.ticks, cfg: this.cfg,
        pk: this.pk, subscribed: [...this.subscribed], since: this.since,
        attacks: this.attacks, published: this.published, scriptTarget: this.attackOf, groupAuthor: this.groupAuthor,
        pendingReceipt: this.pendingReceipt, lastRead: this.lastRead ?? null,
        messages: this.messages.map((m) => ({ id: m.id, pubkey: m.pubkey, created_at: m.created_at, via: `R${m.via}`, contentLen: (m.content || '').length })), distinct: this.distinctMessages().length,
        collected: [...this.collected.values()].map((x) => ({ id: x.ev.id, kind: x.ev.kind, pubkey: x.ev.pubkey, via: `R${x.via}`, tags: x.ev.tags, contentLen: x.ev.content.length, contentSha256: h12(x.ev.content) })),
        log: this.log.slice(since), total: this.log.length,
      });
    }

    if (url.pathname === '/disarm' && request.method === 'POST') {
      this.phase = 'disarmed';
      this.say('stop', 'DISARMED by the owner');
      await this.persist();
      return json({ armed: false, log: this.log.slice(-6) });
    }

    if (url.pathname === '/health') {
      let ipHash = 'unavailable';
      try { ipHash = h12(await (await fetch('https://api.ipify.org')).text()); } catch { /* egress probe failed */ }
      return json({
        worker: 'styx-demo-mallory', colo: request.cf?.colo ?? 'unknown', country: request.cf?.country ?? 'unknown',
        asn: request.cf?.asn ?? null, city: request.cf?.city ?? null, egressIpHash: ipHash,
        relays: (this.cfg?.relays ?? DEFAULT_RELAYS).map((u) => new URL(u).host),
        armed: this.phase === 'armed', phase: this.phase, ticks: this.ticks,
        note: 'simulated attacker; no secret and no account data is read or stored',
      });
    }
    return json({ error: 'not found', endpoints: ['GET /health', 'POST /arm?p=&r=&skip=&silence=', 'GET /log', 'GET /tick', 'POST /disarm'] }, 404);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (['/health', '/arm', '/log', '/tick', '/disarm'].includes(url.pathname)) {
      return env.ARM.get(env.ARM.idFromName('mallory')).fetch(request);
    }
    return Response.json({ error: 'not found', endpoints: ['GET /health', 'POST /arm', 'GET /log', 'GET /tick', 'POST /disarm'] }, { status: 404 });
  },
};
