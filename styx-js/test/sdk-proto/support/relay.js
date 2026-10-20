// Minimal loopback Nostr relay for prototype tests (NIP-01 subset): stores
// events, answers OK, serves REQ with ids/authors/kinds/#p/#e/since/limit
// filters, sends EOSE, pushes live events to matching subscriptions.
// `stall(pubkey, on)` black-holes every connection whose subscription asks for
// `#p` = pubkey (frames dropped both ways, socket kept open): the relay-side
// picture of that member's network stalling. Test-only.
import { WebSocketServer } from 'ws';

export function matches(f, ev) {
  if (f.ids && !f.ids.includes(ev.id)) return false;
  if (f.authors && !f.authors.includes(ev.pubkey)) return false;
  if (f.kinds && !f.kinds.includes(ev.kind)) return false;
  if (Number.isInteger(f.since) && ev.created_at < f.since) return false;
  for (const k of Object.keys(f)) {
    if (k[0] === '#') {
      const vals = f[k];
      if (!ev.tags.some((t) => t[0] === k.slice(1) && vals.includes(t[1]))) return false;
    }
  }
  return true;
}

export async function startRelay({ silent = false } = {}) {
  const wss = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((r) => wss.once('listening', r));
  const events = [];
  const conns = new Set();
  const stalled = new Set();
  const reqs = []; // { owner, filters } of every REQ served (not stalled)
  let connections = 0;
  const isStalled = (ws) => ws._owners && [...ws._owners].some((p) => stalled.has(p));
  const send = (ws, frame) => { if (!isStalled(ws)) ws.send(JSON.stringify(frame)); };
  wss.on('connection', (ws) => {
    connections += 1;
    conns.add(ws);
    const subs = new Map();
    ws._owners = new Set();
    ws.on('close', () => conns.delete(ws));
    ws.on('message', (raw) => {
      if (silent || isStalled(ws)) return;
      let m;
      try { m = JSON.parse(String(raw)); } catch { return; }
      if (m[0] === 'EVENT') {
        const ev = m[1];
        if (!events.some((e) => e.id === ev.id)) events.push(ev);
        send(ws, ['OK', ev.id, true, '']);
        for (const c of conns) {
          for (const [id, filters] of c._subs ?? []) {
            if (filters.some((f) => matches(f, ev))) send(c, ['EVENT', id, ev]);
          }
        }
      } else if (m[0] === 'REQ') {
        const [, id, ...filters] = m;
        for (const f of filters) for (const p of f['#p'] ?? []) ws._owners.add(p);
        if (isStalled(ws)) return;
        subs.set(id, filters);
        ws._subs = subs;
        reqs.push({ owners: [...ws._owners], filters });
        for (const f of filters) {
          let list = events.filter((e) => matches(f, e));
          if (f.limit) list = list.slice(-f.limit);
          for (const ev of list) send(ws, ['EVENT', id, ev]);
        }
        send(ws, ['EOSE', id]);
      } else if (m[0] === 'CLOSE') {
        subs.delete(m[1]);
      }
    });
  });
  const port = wss.address().port;
  return {
    url: `ws://127.0.0.1:${port}`,
    events,
    reqs,
    stall(pubkey, on) { if (on) stalled.add(pubkey); else stalled.delete(pubkey); },
    get connections() { return connections; },
    get open() { return conns.size; },
    async close() {
      for (const c of conns) c.terminate();
      await new Promise((r) => wss.close(() => r()));
    },
  };
}
