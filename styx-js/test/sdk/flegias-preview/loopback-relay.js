// Flegias preview (synthetic data only)
import { WebSocketServer } from 'ws';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8Encode } from '../../../src/utils.js';
export async function startLoopbackRelay() {
  const connections = []; const events = new Map(); const faults = [];
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0 });
  await new Promise((resolve,reject) => { server.once('listening',resolve); server.once('error',reject); });
  const base = `ws://127.0.0.1:${server.address().port}`;
  server.on('connection',(socket,request) => {
    const role = request.url.slice(1);
    const connection = { role, url: base+request.url, upgrade: request.headers['sec-websocket-key'], messages: [], socket, closed: false, subscriptions: new Map() };
    connections.push(connection);
    socket.on('close',() => { connection.closed = true; });
    socket.on('error',error => faults.push(error));
    if (!['handler','case-reporter','outside-reporter'].includes(role)) { faults.push(new Error('unknown relay role')); socket.close(); return; }
    const send = frame => { const text = JSON.stringify(frame); connection.messages.push({ direction:'in', binary:false, bytes: utf8Encode(text) }); socket.send(text); };
    const matches = (event,filter) => (!filter.kinds || filter.kinds.includes(event.kind)) && (!filter.ids || filter.ids.includes(event.id)) && (!filter['#p'] || event.tags.some(t => t[0] === 'p' && filter['#p'].includes(t[1]))) && (filter.since === undefined || event.created_at >= filter.since);
    connection.deliver = event => { for (const [id,filters] of connection.subscriptions) if (filters.some(f => matches(event,f))) send(['EVENT',id,event]); };
    socket.on('message',(data,binary) => {
      connection.messages.push({ direction:'out',binary,bytes: new Uint8Array(data) });
      try {
        if (binary) throw new Error('binary relay input');
        const f = JSON.parse(data.toString());
        if (f[0] === 'EVENT') {
          const e = f[1]; const id = bytesToHex(sha256(utf8Encode(JSON.stringify([0,e.pubkey,e.created_at,e.kind,e.tags,e.content]))));
          if (id !== e.id) { send(['OK',e.id,false,'invalid: id']); return; }
          events.set(id,e); send(['OK',id,true,'']);
          for (const c of connections) if (!c.closed && c.deliver) c.deliver(e);
        } else if (f[0] === 'REQ') {
          const filters = f.slice(2); connection.subscriptions.set(f[1],filters);
          for (const e of events.values()) if (filters.some(filter => matches(e,filter))) send(['EVENT',f[1],e]);
          send(['EOSE',f[1]]);
        } else if (f[0] === 'CLOSE') connection.subscriptions.delete(f[1]);
        else throw new Error('unknown relay frame');
      } catch(error) { faults.push(error); }
    });
  });
  let closed = false;
  return { base, connections, events, faults, get closed() { return closed; },
    stop: () => new Promise((resolve,reject) => {
      for (const c of connections) if (!c.closed) c.socket.close();
      server.close(error => { closed = true; error ? reject(error) : resolve(); });
    })
  };
}
