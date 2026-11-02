// PROTOTYPE — DO NOT MERGE. Passive wire observation; synthetic messages only.
import { createInterface } from 'node:readline';
import { WebSocket } from 'ws';
import { createStyxClient, SDK_INTERFACE_VERSION } from '../../src/sdk/index.js';
import { stateFile, persistentSession, persistentOutbox } from './persistent-ports.mjs';
import { clock } from './ports.mjs';
const role = process.env.ROLE;
const log = (phase, data = {}) => console.log(JSON.stringify({ role, phase, at: Date.now(), ...data }));
const store = stateFile(process.env.STATE_DIR, process.env.DEMO_STATE_KEY);
delete process.env.DEMO_STATE_KEY;
if (process.env.PUBLIC_KEY_ONLY === '1') { log('public-key', { publicKey: store.identity.getPublicKey() }); store.identity.destroy(); store.destroy(); process.exit(0); }
const peer = process.env.PEER, relays = process.env.RELAYS.split(',');
const mls = await persistentSession(store), outbox = persistentOutbox(store);
const eventBindings = new Map();
const storagePort = { ...outbox.port };
for (const name of ['put', 'update']) {
  storagePort[name] = (...args) => {
    const record = args.at(-1);
    if (record.event && !eventBindings.has(record.deliveryId)) {
      eventBindings.set(record.deliveryId, record.event.id);
      log('binding', { deliveryId: record.deliveryId, eventId: record.event.id });
    }
    return outbox.port[name](...args);
  };
}
// Observe original frames without changing REQ, cursors, events or ordering.
class Socket extends WebSocket {
  constructor(url, ...args) {
    super(url, ...args); this.relay = String(url);
    this.on('message', (raw) => log('wire', { direction: 'in', relay: this.relay, frame: JSON.parse(String(raw)) }));
  }
  send(raw, ...args) {
    log('wire', { direction: 'out', relay: this.relay, frame: JSON.parse(String(raw)) });
    return super.send(raw, ...args);
  }
}
globalThis.WebSocket = Socket;
const need = (r) => { if (!r.ok) throw Error(r.code); return r.value; };
const client = need(createStyxClient({ interfaceVersion: SDK_INTERFACE_VERSION, relays,
  ...(relays.every((r) => r.startsWith('ws://127.0.0.1:')) ? {} : { publicRelayHosts: relays.map((r) => new URL(r).hostname) }),
  ports: { identity: store.identity, session: mls.port, storage: storagePort }, clock,
  delivery: { receiptMode: 'RECIPIENT_RECEIPT', maxAttempts: 5, deadlineMs: 90000, perRelayTimeoutMs: 12000 } }));
need(await client.onEvent((event) => {
  if (event.kind === 'MESSAGE_RECEIVED') {
    const payload = JSON.parse(new TextDecoder().decode(event.payload));
    if (payload.groupId) mls.bindGroup(event.sender, payload.groupId);
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
const deliveries = new Map(), monitors = new Set();
async function sendMessage(command) {
  const sent = need(await client.send({ recipient: peer, payload: new TextEncoder().encode(JSON.stringify({ id: command.id, groupId: mls.groupId(peer) })) }));
  deliveries.set(command.id, sent.deliveryId); log('sent', { id: command.id, ...sent });
  const end = Date.now() + 105000;
  let status;
  do { status = need(await client.getDelivery({ deliveryId: sent.deliveryId })); if (status.terminal) break; await new Promise((r) => setTimeout(r, 100)); } while (Date.now() < end);
  log('terminal', { id: command.id, ...status });
}
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
      const task = sendMessage(command).catch((error) => log('failure', { error: error.message }));
      monitors.add(task); task.finally(() => monitors.delete(task));
    } else if (command.op === 'snapshot') {
      const states = Object.values(store.data.outboxes.at(-1).records).map((r) => ({ deliveryId: r.deliveryId, state: r.state }));
      const current = Object.fromEntries(await Promise.all([...deliveries].map(async ([id, deliveryId]) => [id, { ...need(await client.getDelivery({ deliveryId })), eventId: eventBindings.get(deliveryId) ?? null }])));
      log('snapshot', { deliveries: current, self: store.identity.getPublicKey(), groupId: mls.groupId(peer), fingerprint: mls.fingerprint(peer), inbox: store.data.inbox ?? [], states, recovered: outbox.recovered });
    } else if (command.op === 'stop') {
      need(await client.shutdown()); store.save(); log('stopped'); break;
    } else throw Error('unknown command');
  }
} catch (error) { log('failure', { error: error.message }); process.exitCode = 1; }
finally { await client.shutdown(); await Promise.all(monitors); store.identity.destroy(); store.destroy(); }
process.exit(process.exitCode ?? 0);
