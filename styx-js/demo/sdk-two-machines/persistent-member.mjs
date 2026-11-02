// PROTOTYPE — DO NOT MERGE. JSON command harness, synthetic messages only.
import { createInterface } from 'node:readline';
import { WebSocket } from 'ws';
import { createStyxClient, SDK_INTERFACE_VERSION } from '../../src/sdk/index.js';
import { stateFile, persistentSession, persistentOutbox } from './persistent-ports.mjs';
import { clock } from './ports.mjs';
const role = process.env.ROLE;
const log = (phase, data = {}) => console.log(JSON.stringify({ role, phase, ...data }));
const store = stateFile(process.env.STATE_DIR, process.env.DEMO_STATE_KEY);
delete process.env.DEMO_STATE_KEY;
if (process.env.PUBLIC_KEY_ONLY === '1') { log('public-key', { publicKey: store.identity.getPublicKey() }); store.identity.destroy(); store.destroy(); process.exit(0); }
const peer = process.env.PEER, relays = process.env.RELAYS.split(',');
const mls = await persistentSession(store), outbox = persistentOutbox(store);
let crashArmed = false;
class Socket extends WebSocket {
  send(raw, ...args) {
    const result = super.send(raw, ...args);
    const f = JSON.parse(String(raw));
    if (crashArmed && f[0] === 'EVENT' && f[1].kind === 4741) {
      crashArmed = false;
      log('crash-ready', { eventId: f[1].id, kind: f[1].kind, boundary: 'first relay send returned, pending SDK delivery; SIGSTOP then external SIGKILL' });
      process.kill(process.pid, 'SIGSTOP');
    }
    return result;
  }
}
globalThis.WebSocket = Socket;
const need = (r) => { if (!r.ok) throw Error(r.code); return r.value; };
const client = need(createStyxClient({ interfaceVersion: SDK_INTERFACE_VERSION, relays,
  ...(relays.every((r) => r.startsWith('ws://127.0.0.1:')) ? {} : { publicRelayHosts: relays.map((r) => new URL(r).hostname) }),
  ports: { identity: store.identity, session: mls.port, storage: outbox.port }, clock,
  delivery: { receiptMode: 'RECIPIENT_RECEIPT', maxAttempts: 5, deadlineMs: 60000, perRelayTimeoutMs: 12000 } }));
need(await client.onEvent((event) => {
  if (event.kind === 'MESSAGE_RECEIVED') {
    const payload = JSON.parse(new TextDecoder().decode(event.payload));
    if (payload.groupId) mls.bindGroup(event.sender, payload.groupId);
    // A durable application inbox is not a transactional SDK receive guarantee.
    store.data.inbox ??= [];
    const duplicate = store.data.inbox.some((e) => e.id === payload.id);
    if (!duplicate) { store.data.inbox.push({ id: payload.id, sender: event.sender }); store.save(); }
    log('message', { id: payload.id, sender: event.sender, duplicate, inboxCount: store.data.inbox.length });
  } else if (event.kind === 'DELIVERY_STATE_CHANGED') log('delivery', { deliveryId: event.deliveryId, state: event.state });
  else if (event.kind === 'INBOUND_DISCARDED') log('discard', { code: event.code });
}));
need(await client.start());
log('started', { self: store.identity.getPublicKey(), groupId: mls.groupId(peer) ?? null,
  fingerprint: mls.groupId(peer) ? mls.fingerprint(peer) : null, recovered: outbox.recovered,
  inbox: store.data.inbox ?? [], archivedOutboxes: store.data.outboxes.length - 1 });
const lines = createInterface({ input: process.stdin });
try {
  for await (const line of lines) {
    const command = JSON.parse(line);
    if (command.op === 'pair') {
      if (role === 'invitee') {
        const published = need(await client.publishKeyPackage()); log('waiting-for-invite');
        need(await client.acceptInvite({ inviter: peer, keyPackageEventId: published.keyPackageEventId }));
      } else need(await client.invite({ invitee: peer }));
      log('paired', { fingerprint: mls.fingerprint(peer), groupId: mls.groupId(peer) ?? null });
    } else if (command.op === 'send') {
      crashArmed = command.crash === true;
      const sent = need(await client.send({ recipient: peer, payload: new TextEncoder().encode(JSON.stringify({ id: command.id, groupId: mls.groupId(peer) })) }));
      log('sent', { id: command.id, ...sent });
      const end = Date.now() + 75000;
      let status;
      do { status = need(await client.getDelivery({ deliveryId: sent.deliveryId })); if (status.terminal) break; await new Promise((r) => setTimeout(r, 100)); } while (Date.now() < end);
      log('terminal', { id: command.id, ...status });
      if (status.state !== 'RECIPIENT_RECEIPT_RECEIVED') throw Error('no recipient receipt');
    } else if (command.op === 'snapshot') {
      const states = Object.values(store.data.outboxes.at(-1).records).map((r) => ({ deliveryId: r.deliveryId, state: r.state }));
      log('snapshot', { self: store.identity.getPublicKey(), groupId: mls.groupId(peer), fingerprint: mls.fingerprint(peer), inbox: store.data.inbox ?? [], states, recovered: outbox.recovered });
    } else if (command.op === 'stop') {
      need(await client.shutdown()); store.save(); log('stopped'); break;
    } else throw Error('unknown command');
  }
} catch (error) { log('failure', { error: error.message }); process.exitCode = 1; }
finally { await client.shutdown(); store.identity.destroy(); store.destroy(); }
process.exit(process.exitCode ?? 0);
