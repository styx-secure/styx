/* styx-lib-mock.js — ESM in-memory mock of the StyxChat contract.
 *
 * Drop-in for `src/lib/styx-lib-mock.js`. Selected by styx-adapter.js when the
 * real `styx-js` package is not installed. Exports:
 *   MockStyxChat  — class implementing the StyxChat contract (see §2 of the brief)
 *   identicon, qrPayloadToMatrix, shortKey, mnemonic  — UI-side helpers (optional)
 *
 * Aligned to the brief:
 *   - static async hasIdentity()
 *   - init({ password }) THROWS new Error('Invalid password') on wrong password
 *   - me is a getter
 *   - first run: init({ password }) then setAlias(alias)   (init ignores alias)
 *   - every on*() returns an unsubscribe function
 *   - joinRemotePairing returns { doubleCheckCode, contactPubkey }
 *   - text-only (no attachments)
 *
 * This is a demo double: it simulates tick progression, auto-replies, typing and
 * presence so the UI is fully navigable in isolation. NOT production code.
 */

// ---------- deterministic hashing / PRNG ----------
export function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193); }
  return h >>> 0;
}
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---------- UI helpers (can live in src/lib/identicon.js etc. too) ----------
export function shortKey(pubkey) {
  const s = String(pubkey || '');
  return s.length <= 14 ? s : s.slice(0, 8) + '…' + s.slice(-6);
}

/** Deterministic 5×5 symmetric identicon as an SVG data-URI. */
export function identicon(pubkey) {
  const seed = fnv1a(String(pubkey || 'anon'));
  const rnd = mulberry32(seed);
  const hue = seed % 360;
  const fg = `hsl(${hue} 58% 52%)`;
  const bg = `hsl(${hue} 30% 94%)`;
  const N = 5, s = 20;
  const grid = [];
  for (let x = 0; x < 3; x++) { grid[x] = []; for (let y = 0; y < N; y++) grid[x][y] = rnd() > 0.5; }
  let rects = '';
  for (let x = 0; x < N; x++) {
    const sx = x < 3 ? x : N - 1 - x;
    for (let y = 0; y < N; y++) if (grid[sx][y]) rects += `<rect x="${x * s}" y="${y * s}" width="${s}" height="${s}"/>`;
  }
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="${bg}"/><g fill="${fg}">${rects}</g></svg>`;
  return 'data:image/svg+xml,' + encodeURIComponent(svg);
}

// ---------- mnemonic wordlist (small demo set) ----------
const WORDS = ('abaco alba ancora aroma barca bosco calma cielo corda dado delta faro fiume fuoco '
  + 'gara gelo giada isola lampo luna mare melo nave nodo onda orso pane pino pioggia porto quadro '
  + 'remo riva rosa sale sasso sole terra torre uva vela vento verde vetta viola zenit zolla nube '
  + 'nord sud est ovest pietra fiore neve ghiaccio bronzo argento oro rame ferro cedro').split(/\s+/);

export function mnemonic() {
  const out = [];
  for (let i = 0; i < 12; i++) out[i] = WORDS[(Math.random() * WORDS.length) | 0];
  return out.join(' ');
}
function sixDigits(seedStr) { return ('000000' + (fnv1a(String(seedStr)) % 1000000)).slice(-6); }
function randKey() {
  const cs = 'abcdef0123456789';
  let s = '';
  for (let i = 0; i < 44; i++) s += cs[(Math.random() * cs.length) | 0];
  return 'STX_' + s;
}

const now = () => Date.now();
let msgSeq = 1;
const mid = () => 'm' + (msgSeq++) + '_' + ((Math.random() * 1e6) | 0);

const IDENTITY_KEY = 'styx-identity';

// ---------- MockStyxChat ----------
export class MockStyxChat {
  /** static async — matches the real lib's first-run detection. */
  static async hasIdentity() {
    try { return !!JSON.parse(localStorage.getItem(IDENTITY_KEY) || 'null'); }
    catch { return false; }
  }

  constructor() {
    this._me = null;
    this._contacts = [];
    this._messages = {};              // pubkey -> Message[]
    this._subs = { message: [], state: [], contacts: [], typing: [], pairing: [] };
    this._timers = [];
    this._presence = null;
    this._pendingMnemonic = null;
  }

  /** getter, like the real lib. */
  get me() { return this._me; }

  async init({ password } = {}) {
    await sleep(260);
    let id = null;
    try { id = JSON.parse(localStorage.getItem(IDENTITY_KEY) || 'null'); } catch { id = null; }

    if (id) {
      if (String(id.pwHash) !== String(fnv1a(String(password || '')))) {
        throw new Error('Invalid password');
      }
      this._me = { pubkey: id.pubkey, alias: id.alias };
    } else {
      // first run — create identity WITHOUT alias (UI calls setAlias next)
      const pubkey = randKey();
      this._me = { pubkey, alias: 'Io' };
      localStorage.setItem(IDENTITY_KEY, JSON.stringify({ pubkey, alias: 'Io', pwHash: fnv1a(String(password || '')) }));
    }
    this._seedDemo();
    this._startLife();
    return this._me;
  }

  async setAlias(alias) {
    this._me.alias = String(alias);
    try {
      const id = JSON.parse(localStorage.getItem(IDENTITY_KEY) || 'null') || {};
      id.alias = this._me.alias;
      localStorage.setItem(IDENTITY_KEY, JSON.stringify(id));
    } catch { /* ignore */ }
    return this._me;
  }

  async listContacts() {
    return this._contacts.slice().sort((a, b) => (b.lastTs || 0) - (a.lastTs || 0));
  }

  onContactsChanged(cb) { this._subs.contacts.push(cb); return () => this._off('contacts', cb); }
  onMessage(cb)         { this._subs.message.push(cb);  return () => this._off('message', cb); }
  onMessageState(cb)    { this._subs.state.push(cb);    return () => this._off('state', cb); }
  onTyping(cb)          { this._subs.typing.push(cb);   return () => this._off('typing', cb); }
  onPairing(cb)         { this._subs.pairing.push(cb);  return () => this._off('pairing', cb); }

  /** Deterministic 60-digit stand-in — NOT cryptographic, mock only. */
  safetyNumber(pubkey) {
    let h = 0n;
    for (const ch of String(pubkey)) h = (h * 131n + BigInt(ch.charCodeAt(0))) % (10n ** 60n);
    return h.toString().padStart(60, '0').match(/.{5}/g).join(' ');
  }

  async setVerified(pubkey, verified) {
    const c = this._contacts.find((x) => x.pubkey === pubkey);
    if (c) {
      c.verified = !!verified;
      c.verifiedAt = verified ? now() : null;
      this._emit('contacts');
    }
    return c;
  }

  listPendingPairings() { return []; }

  async createQrInvite() {
    return { qr: 'styx://invite/' + this._me.pubkey + '#' + ((Math.random() * 1e6) | 0).toString(36) };
  }
  async acceptQrInvite(/* payload */) {
    await sleep(300);
    return { contactPubkey: randKey() };
  }
  async startRemotePairing() {
    this._pendingMnemonic = mnemonic();
    return { mnemonic: this._pendingMnemonic };
  }
  async joinRemotePairing(words) {
    await sleep(300);
    return { doubleCheckCode: sixDigits(words), contactPubkey: 'STX_' + fnv1a(String(words)).toString(16) };
  }
  async confirmPairing({ contactPubkey, alias } = {}) {
    const pubkey = contactPubkey || randKey();
    if (!this._contacts.some((c) => c.pubkey === pubkey)) {
      this._contacts.push({
        pubkey, alias: alias || shortKey(pubkey),
        online: true, unread: 0, lastPreview: 'Contatto aggiunto', lastTs: now(),
        verified: false, verifiedAt: null,
      });
      this._messages[pubkey] = this._messages[pubkey] || [];
      this._emit('contacts');
    }
    return { contactPubkey: pubkey };
  }
  async removeContact(pubkey) {
    this._contacts = this._contacts.filter((c) => c.pubkey !== pubkey);
    delete this._messages[pubkey];
    this._emit('contacts');
  }

  async listMessages(pubkey, { before, limit = 25 } = {}) {
    const all = (this._messages[pubkey] || []).slice();
    const arr = before ? all.filter((m) => m.ts < before) : all;
    return arr.slice(Math.max(0, arr.length - limit));
  }

  async sendText(pubkey, text) {
    const msg = { id: mid(), contactPubkey: pubkey, direction: 'out', text: String(text), ts: now(), state: 'sending' };
    (this._messages[pubkey] = this._messages[pubkey] || []).push(msg);
    this._touch(pubkey, text, msg.ts, 0);
    this._emit('message', msg);
    this._emit('contacts');

    const tick = (state, delay) => this._timers.push(setTimeout(() => { msg.state = state; this._emit('state', msg.id, state); }, delay));
    tick('sent', 500); tick('delivered', 1100); tick('read', 2200);

    const contact = this._contacts.find((c) => c.pubkey === pubkey);
    if (contact && contact.online) {
      this._timers.push(setTimeout(() => this._emit('typing', pubkey, true), 1600));
      this._timers.push(setTimeout(() => { this._emit('typing', pubkey, false); this._deliverIncoming(pubkey, pickReply(text)); }, 3200));
    }
    return msg;
  }

  async setTyping(/* pubkey, isTyping */) { return true; } // outgoing typing: no-op in mock
  async markRead(pubkey /* , messageId */) {
    const c = this._contacts.find((x) => x.pubkey === pubkey);
    if (c && c.unread) { c.unread = 0; this._emit('contacts'); }
    return true;
  }

  destroy() {
    this._timers.forEach(clearTimeout);
    if (this._presence) clearInterval(this._presence);
    this._subs = { message: [], state: [], contacts: [], typing: [], pairing: [] };
  }

  // ---- internals ----
  _off(kind, cb) { this._subs[kind] = (this._subs[kind] || []).filter((f) => f !== cb); }
  _emit(kind, ...args) { (this._subs[kind] || []).forEach((cb) => { try { cb(...args); } catch (e) { console.warn(e); } }); }
  _touch(pubkey, preview, ts, unreadDelta) {
    const c = this._contacts.find((x) => x.pubkey === pubkey);
    if (!c) return;
    c.lastPreview = preview; c.lastTs = ts;
    if (unreadDelta) c.unread = (c.unread || 0) + unreadDelta;
  }
  _deliverIncoming(pubkey, text) {
    const msg = { id: mid(), contactPubkey: pubkey, direction: 'in', text, ts: now(), state: 'delivered' };
    (this._messages[pubkey] = this._messages[pubkey] || []).push(msg);
    this._touch(pubkey, text, msg.ts, 1);
    this._emit('message', msg);
    this._emit('contacts');
  }
  _seedDemo() {
    if (this._contacts.length) return;
    const t = now(), min = 60000;
    const defs = [
      { alias: 'Aurora', online: true, unread: 2, msgs: [
        ['in', 'Ciao! Hai visto il nuovo protocollo di pairing?', 42],
        ['out', 'Sì, il double-check a 6 cifre è elegante', 40],
        ['in', 'Cifrato end-to-end su relay federati 🔐', 6],
        ['in', 'Ci vediamo dopo per la review?', 3] ] },
      { alias: 'Marco', online: false, unread: 0, msgs: [
        ['out', 'Ti mando le chiavi via QR', 70],
        ['in', 'Perfetto, scansiono ora', 66],
        ['out', 'Fatto ✅', 55] ] },
      { alias: 'Nodo Berlino', online: true, unread: 0, msgs: [
        ['in', 'Forward secrecy attiva su tutte le sessioni', 140],
        ['out', 'Ottimo, nessun messaggio recuperabile a posteriori', 132],
        ['in', 'Esatto. Sovranità totale.', 130] ] },
      { alias: 'Lucia', online: false, unread: 1, msgs: [
        ['in', 'La modalità remota funziona benissimo', 1450],
        ['out', 'Le 12 parole sono facili da dettare', 1445],
        ['in', 'A domani!', 1440] ] }
    ];
    for (const d of defs) {
      const pubkey = randKey();
      const list = d.msgs.map((m) => ({ id: mid(), contactPubkey: pubkey, direction: m[0], text: m[1], ts: t - m[2] * min, state: m[0] === 'out' ? 'read' : 'delivered' }));
      this._messages[pubkey] = list;
      const last = list[list.length - 1];
      this._contacts.push({ pubkey, alias: d.alias, online: d.online, unread: d.unread, lastPreview: last.text, lastTs: last.ts });
    }
  }
  _startLife() {
    if (this._presence) return;
    this._presence = setInterval(() => {
      if (!this._contacts.length) return;
      const c = this._contacts[(Math.random() * this._contacts.length) | 0];
      c.online = !c.online;
      this._emit('contacts');
    }, 12000);
  }
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

const REPLIES = [
  'Ricevuto, chiaro 👍', 'Interessante, dimmi di più', 'Perfetto, procediamo così',
  'Sono d\'accordo', 'Ci penso e ti aggiorno', 'Ottimo lavoro!',
  'Tutto cifrato end-to-end, tranquillo', 'Ok, ci sentiamo dopo'
];
function pickReply(text) {
  if (/\?$/.test(String(text).trim())) return 'Buona domanda — sì, direi di sì.';
  return REPLIES[(Math.random() * REPLIES.length) | 0];
}

export default MockStyxChat;
