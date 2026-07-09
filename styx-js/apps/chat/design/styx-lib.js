/* styx-lib.js — self-contained utilities + in-memory mock of the StyxChat contract.
 * Exposes:
 *   window.StyxChat      : mock implementation of the messaging library
 *   window.StyxUtil      : { identicon(pubkey), qrSvg(text), shortKey(pubkey) }
 * No network. All state lives in memory (+ a tiny identity stub in localStorage).
 */
(function () {
  'use strict';

  // ---------- tiny deterministic hashing / PRNG ----------
  function fnv1a(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = Math.imul(h, 0x01000193);
    }
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

  // ---------- identicon (symmetric 5x5, deterministic) ----------
  function identicon(pubkey) {
    const key = String(pubkey || 'anon');
    const seed = fnv1a(key);
    const rnd = mulberry32(seed);
    const hue = seed % 360;
    // sober two-tone: teal-leaning accent unless hash pushes elsewhere
    const fg = 'hsl(' + hue + ' 58% 52%)';
    const bg = 'hsl(' + hue + ' 30% 94%)';
    const cells = [];
    const N = 5;
    const grid = [];
    for (let x = 0; x < 3; x++) {
      grid[x] = [];
      for (let y = 0; y < N; y++) grid[x][y] = rnd() > 0.5;
    }
    let rects = '';
    const s = 20; // cell size in a 100x100 viewbox
    for (let x = 0; x < N; x++) {
      const sx = x < 3 ? x : N - 1 - x; // mirror
      for (let y = 0; y < N; y++) {
        if (grid[sx][y]) rects += '<rect x="' + (x * s) + '" y="' + (y * s) + '" width="' + s + '" height="' + s + '"/>';
      }
    }
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">' +
      '<rect width="100" height="100" fill="' + bg + '"/>' +
      '<g fill="' + fg + '">' + rects + '</g></svg>';
    return 'data:image/svg+xml,' + encodeURIComponent(svg);
  }

  // ---------- decorative QR-style matrix (deterministic from text) ----------
  // Not a scannable QR (this is a demo/mock); renders finder patterns + seeded data.
  function qrSvg(text) {
    const N = 29;
    const rnd = mulberry32(fnv1a(String(text || '')));
    const m = [];
    for (let i = 0; i < N; i++) { m[i] = []; for (let j = 0; j < N; j++) m[i][j] = false; }
    function finder(r, c) {
      for (let i = -1; i <= 7; i++) for (let j = -1; j <= 7; j++) {
        const rr = r + i, cc = c + j;
        if (rr < 0 || cc < 0 || rr >= N || cc >= N) continue;
        const border = (i === 0 || i === 6 || j === 0 || j === 6);
        const core = (i >= 2 && i <= 4 && j >= 2 && j <= 4);
        m[rr][cc] = (i >= 0 && i <= 6 && j >= 0 && j <= 6) && (border || core) ? true : false;
      }
    }
    function reserved(r, c) {
      // keep finder zones (+quiet) clear of random data
      const zones = [[0, 0], [0, N - 7], [N - 7, 0]];
      for (const [zr, zc] of zones) {
        if (r >= zr - 1 && r <= zr + 7 && c >= zc - 1 && c <= zc + 7) return true;
      }
      // timing rows
      if (r === 6 || c === 6) return true;
      return false;
    }
    // data field
    for (let i = 0; i < N; i++) for (let j = 0; j < N; j++) {
      if (!reserved(i, j)) m[i][j] = rnd() > 0.52;
    }
    // timing patterns
    for (let k = 8; k < N - 8; k++) { m[6][k] = k % 2 === 0; m[k][6] = k % 2 === 0; }
    finder(0, 0); finder(0, N - 7); finder(N - 7, 0);

    let rects = '';
    for (let i = 0; i < N; i++) for (let j = 0; j < N; j++) {
      if (m[i][j]) rects += '<rect x="' + j + '" y="' + i + '" width="1" height="1"/>';
    }
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="-2 -2 ' + (N + 4) + ' ' + (N + 4) + '" shape-rendering="crispEdges">' +
      '<rect x="-2" y="-2" width="' + (N + 4) + '" height="' + (N + 4) + '" fill="#ffffff"/>' +
      '<g fill="#0b1f1a">' + rects + '</g></svg>';
    return 'data:image/svg+xml,' + encodeURIComponent(svg);
  }

  function shortKey(pubkey) {
    const s = String(pubkey || '');
    if (s.length <= 14) return s;
    return s.slice(0, 8) + '…' + s.slice(-6);
  }

  window.StyxUtil = { identicon: identicon, qrSvg: qrSvg, shortKey: shortKey };

  // ---------- mnemonic wordlist (small BIP-ish demo set) ----------
  const WORDS = ('abaco alba ancora aroma barca bosco calma cielo corda dado delta '
    + 'faro fiume fuoco gara gelo giada isola lampo luna mare melo nave nodo onda '
    + 'orso pane pino pioggia porto quadro remo riva rosa sale sasso sole terra '
    + 'torre uva vela vento verde vetta viola zenit zolla nube nord sud est ovest '
    + 'pietra fiore neve ghiaccio bronzo argento oro rame ferro cedro').split(/\s+/);

  function randKey() {
    let s = '';
    const cs = 'abcdef0123456789';
    for (let i = 0; i < 44; i++) s += cs[Math.floor(Math.random() * cs.length)];
    return 'STX_' + s;
  }
  function mnemonic() {
    const out = [];
    for (let i = 0; i < 12; i++) out[i] = WORDS[Math.floor(Math.random() * WORDS.length)];
    return out.join(' ');
  }
  function sixDigits(seedStr) {
    const n = fnv1a(String(seedStr)) % 1000000;
    return ('000000' + n).slice(-6);
  }

  const now = () => Date.now();
  let msgSeq = 1;
  const mid = () => 'm' + (msgSeq++) + '_' + Math.floor(Math.random() * 1e6);

  // ---------- Mock StyxChat ----------
  function StyxChat() {
    this.me = null;
    this._contacts = [];               // Contact[]
    this._messages = {};               // pubkey -> Message[] (chronological)
    this._subs = { message: [], state: [], contacts: [], typing: [] };
    this._replyTimers = [];
    this._presenceTimer = null;
  }

  StyxChat.prototype._emit = function (kind, ...args) {
    (this._subs[kind] || []).forEach((cb) => { try { cb(...args); } catch (e) { console.warn(e); } });
  };

  StyxChat.prototype.init = async function (opts) {
    opts = opts || {};
    await new Promise((r) => setTimeout(r, 260)); // feel of unlocking
    let id = null;
    try { id = JSON.parse(localStorage.getItem('styx-identity') || 'null'); } catch (e) { id = null; }

    if (id) {
      if (String(id.pwHash) !== String(fnv1a(String(opts.password || '')))) {
        const err = new Error('Password errata');
        err.code = 'BAD_PASSWORD';
        throw err;
      }
      this.me = { pubkey: id.pubkey, alias: id.alias };
    } else {
      // first run — create identity
      const pubkey = randKey();
      const alias = (opts.alias && String(opts.alias).trim()) || 'Io';
      this.me = { pubkey: pubkey, alias: alias };
      localStorage.setItem('styx-identity', JSON.stringify({
        pubkey: pubkey, alias: alias, pwHash: fnv1a(String(opts.password || ''))
      }));
    }
    this._seedDemo();
    this._startLife();
    return this.me;
  };

  StyxChat.hasIdentity = function () {
    try { return !!JSON.parse(localStorage.getItem('styx-identity') || 'null'); }
    catch (e) { return false; }
  };

  StyxChat.prototype.setAlias = async function (alias) {
    this.me.alias = String(alias);
    try {
      const id = JSON.parse(localStorage.getItem('styx-identity') || 'null') || {};
      id.alias = this.me.alias; localStorage.setItem('styx-identity', JSON.stringify(id));
    } catch (e) { /* ignore */ }
    return this.me;
  };

  StyxChat.prototype.listContacts = async function () {
    return this._contacts.slice().sort((a, b) => (b.lastTs || 0) - (a.lastTs || 0));
  };

  StyxChat.prototype.onContactsChanged = function (cb) { this._subs.contacts.push(cb); return () => this._off('contacts', cb); };
  StyxChat.prototype.onMessage = function (cb) { this._subs.message.push(cb); return () => this._off('message', cb); };
  StyxChat.prototype.onMessageState = function (cb) { this._subs.state.push(cb); return () => this._off('state', cb); };
  StyxChat.prototype.onTyping = function (cb) { this._subs.typing.push(cb); return () => this._off('typing', cb); };
  StyxChat.prototype._off = function (kind, cb) { this._subs[kind] = (this._subs[kind] || []).filter((f) => f !== cb); };

  StyxChat.prototype.createQrInvite = async function () {
    return { qr: 'styx://invite/' + this.me.pubkey + '#' + Math.floor(Math.random() * 1e6).toString(36) };
  };
  StyxChat.prototype.acceptQrInvite = async function (payload) {
    await new Promise((r) => setTimeout(r, 300));
    return { contactPubkey: randKey() };
  };
  StyxChat.prototype.startRemotePairing = async function () {
    this._pendingMnemonic = mnemonic();
    return { mnemonic: this._pendingMnemonic };
  };
  StyxChat.prototype.joinRemotePairing = async function (words) {
    await new Promise((r) => setTimeout(r, 300));
    this._pendingContact = randKey();
    return { doubleCheckCode: sixDigits(words), contactPubkey: this._pendingContact };
  };
  StyxChat.prototype.confirmPairing = async function (opts) {
    opts = opts || {};
    const pubkey = opts.contactPubkey || randKey();
    if (this._contacts.some((c) => c.pubkey === pubkey)) return { contactPubkey: pubkey };
    const c = {
      pubkey: pubkey, alias: opts.alias || StyxUtil.shortKey(pubkey),
      online: true, unread: 0, lastPreview: 'Contatto aggiunto', lastTs: now()
    };
    this._contacts.push(c);
    this._messages[pubkey] = this._messages[pubkey] || [];
    this._emit('contacts');
    return { contactPubkey: pubkey };
  };

  StyxChat.prototype.removeContact = async function (pubkey) {
    this._contacts = this._contacts.filter((c) => c.pubkey !== pubkey);
    delete this._messages[pubkey];
    this._emit('contacts');
  };

  StyxChat.prototype.listMessages = async function (pubkey, opts) {
    opts = opts || {};
    const limit = opts.limit || 25;
    const all = (this._messages[pubkey] || []).slice();
    let arr = all;
    if (opts.before) arr = all.filter((m) => m.ts < opts.before);
    return arr.slice(Math.max(0, arr.length - limit));
  };

  StyxChat.prototype.sendText = async function (pubkey, text) {
    const msg = {
      id: mid(), contactPubkey: pubkey, direction: 'out', text: String(text),
      ts: now(), state: 'sending'
    };
    (this._messages[pubkey] = this._messages[pubkey] || []).push(msg);
    this._touchContact(pubkey, text, msg.ts, 0);
    this._emit('message', msg);
    this._emit('contacts');

    // simulate delivery progression
    const bump = (state, delay) => this._replyTimers.push(setTimeout(() => {
      msg.state = state; this._emit('state', msg.id, state);
    }, delay));
    bump('sent', 500);
    bump('delivered', 1100);
    bump('read', 2200);

    // sometimes an auto-reply from the (online) contact
    const contact = this._contacts.find((c) => c.pubkey === pubkey);
    if (contact && contact.online) {
      this._replyTimers.push(setTimeout(() => this.setTyping(pubkey, true, true), 1600));
      this._replyTimers.push(setTimeout(() => {
        this.setTyping(pubkey, false, true);
        this._deliverIncoming(pubkey, pickReply(text));
      }, 3200));
    }
    return msg;
  };

  StyxChat.prototype._deliverIncoming = function (pubkey, text) {
    const msg = {
      id: mid(), contactPubkey: pubkey, direction: 'in', text: text,
      ts: now(), state: 'delivered'
    };
    (this._messages[pubkey] = this._messages[pubkey] || []).push(msg);
    const contact = this._contacts.find((c) => c.pubkey === pubkey);
    this._touchContact(pubkey, text, msg.ts, 1);
    this._emit('message', msg);
    this._emit('contacts');
  };

  StyxChat.prototype.setTyping = async function (pubkey, isTyping, _internal) {
    // outgoing typing is a no-op in the mock; incoming (internal) drives the indicator
    if (_internal) this._emit('typing', pubkey, !!isTyping);
    return true;
  };

  StyxChat.prototype.markRead = async function (pubkey, messageId) {
    const c = this._contacts.find((x) => x.pubkey === pubkey);
    if (c && c.unread) { c.unread = 0; this._emit('contacts'); }
    return true;
  };

  StyxChat.prototype._touchContact = function (pubkey, preview, ts, unreadDelta) {
    const c = this._contacts.find((x) => x.pubkey === pubkey);
    if (!c) return;
    c.lastPreview = preview; c.lastTs = ts;
    if (unreadDelta) c.unread = (c.unread || 0) + unreadDelta;
  };

  // ---------- demo data ----------
  StyxChat.prototype._seedDemo = function () {
    if (this._contacts.length) return;
    const t = now();
    const min = 60000;
    const defs = [
      { alias: 'Aurora', online: true, unread: 2, mins: 3, msgs: [
        ['in', 'Ciao! Hai visto il nuovo protocollo di pairing?', 42],
        ['out', 'Sì, il double-check a 6 cifre è elegante', 40],
        ['in', 'Zero server, tutto peer-to-peer 🔐', 6],
        ['in', 'Ci vediamo dopo per la review?', 3]
      ] },
      { alias: 'Marco', online: false, unread: 0, mins: 55, msgs: [
        ['out', 'Ti mando le chiavi via QR', 70],
        ['in', 'Perfetto, scansiono ora', 66],
        ['out', 'Fatto ✅', 55]
      ] },
      { alias: 'Nodo Berlino', online: true, unread: 0, mins: 130, msgs: [
        ['in', 'Forward secrecy attiva su tutte le sessioni', 140],
        ['out', 'Ottimo, nessun messaggio recuperabile a posteriori', 132],
        ['in', 'Esatto. Sovranità totale.', 130]
      ] },
      { alias: 'Lucia', online: false, unread: 1, mins: 1440, msgs: [
        ['in', 'La modalità remota funziona benissimo', 1450],
        ['out', 'Le 12 parole sono facili da dettare', 1445],
        ['in', 'A domani!', 1440]
      ] }
    ];
    defs.forEach((d) => {
      const pubkey = randKey();
      const list = d.msgs.map((m) => ({
        id: mid(), contactPubkey: pubkey, direction: m[0],
        text: m[1], ts: t - m[2] * min,
        state: m[0] === 'out' ? 'read' : 'delivered'
      }));
      this._messages[pubkey] = list;
      const last = list[list.length - 1];
      this._contacts.push({
        pubkey: pubkey, alias: d.alias, online: d.online, unread: d.unread,
        lastPreview: last.text, lastTs: last.ts
      });
    });
  };

  // presence flicker to feel live
  StyxChat.prototype._startLife = function () {
    if (this._presenceTimer) return;
    this._presenceTimer = setInterval(() => {
      if (!this._contacts.length) return;
      const c = this._contacts[Math.floor(Math.random() * this._contacts.length)];
      c.online = !c.online;
      this._emit('contacts');
    }, 12000);
  };

  StyxChat.prototype.destroy = function () {
    this._replyTimers.forEach(clearTimeout);
    if (this._presenceTimer) clearInterval(this._presenceTimer);
    this._subs = { message: [], state: [], contacts: [], typing: [] };
  };

  const REPLIES = [
    'Ricevuto, chiaro 👍',
    'Interessante, dimmi di più',
    'Perfetto, procediamo così',
    'Sono d\'accordo',
    'Ci penso e ti aggiorno',
    'Ottimo lavoro!',
    'Tutto cifrato end-to-end, tranquillo',
    'Ok, ci sentiamo dopo'
  ];
  function pickReply(text) {
    if (/\?$/.test(String(text).trim())) return 'Buona domanda — sì, direi di sì.';
    return REPLIES[Math.floor(Math.random() * REPLIES.length)];
  }

  // Only install the mock if the real library isn't present.
  if (!window.StyxChat) window.StyxChat = StyxChat;
})();
