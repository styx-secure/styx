// PROTOTYPE: three separate loopback relay histories, retained across clients.
import { WebSocketServer } from 'ws';
import { verifyEvent } from 'nostr-tools/pure';
const servers = [], urls = [];
const matches = (f,e) => (!f.kinds || f.kinds.includes(e.kind)) && (!f.authors || f.authors.includes(e.pubkey)) && (!f['#p'] || e.tags.some((t)=>t[0]==='p' && f['#p'].includes(t[1]))) && (!f.since || e.created_at>=f.since);
for(let i=0;i<3;i++) {
  const events = new Map(), subscriptions = new Map();
  const server = new WebSocketServer({host:'127.0.0.1',port:0});
  await new Promise((r)=>server.once('listening',r)); servers.push(server); urls.push('ws://127.0.0.1:'+server.address().port);
  server.on('connection',(s)=>{
    subscriptions.set(s,new Map()); s.on('close',()=>subscriptions.delete(s));
    s.on('message',(raw)=>{
      const f=JSON.parse(String(raw));
      if(f[0]==='REQ') { subscriptions.get(s).set(f[1],f[2]); for(const e of events.values()) if(matches(f[2],e))s.send(JSON.stringify(['EVENT',f[1],e])); s.send(JSON.stringify(['EOSE',f[1]])); }
      else if(f[0]==='EVENT') { const e=f[1],valid=verifyEvent(e); s.send(JSON.stringify(['OK',e.id,valid,valid?'accepted':'invalid'])); if(!valid)return; events.set(e.id,e); for(const [socket,subs] of subscriptions)for(const [id,filter]of subs)if(socket.readyState===1&&matches(filter,e))socket.send(JSON.stringify(['EVENT',id,e])); }
      else if(f[0]==='CLOSE')subscriptions.get(s).delete(f[1]);
    });
  });
}
console.log(JSON.stringify({urls}));
process.on('SIGTERM',()=>{ for(const server of servers){for(const s of server.clients)s.terminate();server.close();} });
