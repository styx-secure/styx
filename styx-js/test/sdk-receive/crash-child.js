// M3-RECEIVE-2 crash suite: one process run of Bob's SDK client over the
// reference receiver. Started by crash.test.js with a JSON configuration;
// stops itself with SIGKILL at the configured kill point. Every observation
// is appended to a log file with fsync before the process continues, so the
// log survives the kill. Not a test file (it is not matched by *.test.js).
import { openSync, writeSync, fsyncSync, closeSync, readFileSync } from 'node:fs';
import { WebSocket } from 'ws';
import { hexToBytes, bytesToHex } from '../../src/utils.js';
import { createReferenceReceiver } from '../../reference/receive-state/index.js';
import { makeClient, fastClock, until, sleep, WASM, SCOPE } from './helpers.js';

globalThis.WebSocket = WebSocket;
const config = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const logFd = openSync(config.logPath, 'a');
function log(record) {
  writeSync(logFd, JSON.stringify({ run: config.phase, ...record }) + '\n');
  fsyncSync(logFd);
}
function die(where) {
  log({ kind: 'kill', where });
  process.kill(process.pid, 'SIGKILL');
}

const kill = config.killAt;
const occurrences = new Map();
const hooks = {
  beforeStep: (step, operation) => {
    if (step === 'temp-create') occurrences.set(operation, (occurrences.get(operation) ?? 0) + 1);
    if (kill !== null && kill.operation === operation && kill.step === step && occurrences.get(operation) === kill.occurrence) {
      die(`${operation}/${step}#${kill.occurrence}`);
    }
  },
  beforeCandidate: () => {
    occurrences.set('candidate', (occurrences.get('candidate') ?? 0) + 1);
    if (kill !== null && kill.operation === 'candidate' && occurrences.get('candidate') === kill.occurrence) die(`candidate#${kill.occurrence}`);
  },
};

const keys = { secret: hexToBytes(config.secretHex), publicKey: config.identity };
const options = {
  directory: config.directory, atRestKey: hexToBytes(config.atRestKeyHex), identity: config.identity, mode: 'open', wasmBytes: WASM,
};
const receiver = createReferenceReceiver({ ...options, hooks });

// Log every successful durable write and every MLS open, by event id.
const byCiphertext = new Map();
const receiveState = { ...receiver.receiveState };
for (const name of ['stage', 'commit', 'ack', 'receiptDone', 'commitCursor']) {
  receiveState[name] = async (argument) => {
    const value = await receiver.receiveState[name](argument);
    if (value && value.code === undefined && value.revision !== undefined) {
      if (name === 'stage') byCiphertext.set(bytesToHex(argument.event.ciphertext), argument.event.eventId);
      log({ kind: `${name}-ok`, id: argument.eventId ?? argument.event?.eventId ?? argument.relay, type: argument.result?.type });
    }
    return value;
  };
}
receiveState.load = async (argument) => {
  const value = await receiver.receiveState.load(argument);
  if (value.code === undefined) for (const entry of value.pending) byCiphertext.set(bytesToHex(entry.ciphertext), entry.eventId);
  log({ kind: 'load', code: value.code ?? null, pending: value.pending?.map((e) => e.eventId), seen: value.seen });
  return value;
};
const session = { ...receiver.session };
session.openCandidate = async (argument) => {
  log({ kind: 'open', id: byCiphertext.get(bytesToHex(argument.ciphertext)) ?? null });
  return receiver.session.openCandidate(argument);
};

const delivered = new Map();
// The clock stands still during every port call (helpers.js), so a slow real write never ages a timer.
const h = makeClient({ urls: config.relays, keys, ports: { receiveState, session }, clock: fastClock(5) });
const started = await h.start({
  onMessage: async (message) => {
    log({ kind: 'delivered', id: message.eventId, payload: new TextDecoder().decode(message.payload) });
    delivered.set(message.eventId, true);
    const acked = await h.client.acknowledgeMessage({ eventId: message.eventId });
    log({ kind: 'acknowledge', id: message.eventId, ok: acked.ok, code: acked.code ?? null });
  },
});
log({ kind: 'started', ok: started.ok, code: started.code ?? null });
if (!started.ok) process.exit(3);

const wanted = new Set(config.expected);
const finished = () => {
  const now = receiver.inspect();
  const cursors = readFileSync(config.logPath, 'utf8').trim().split('\n').map((line) => JSON.parse(line))
    .some((l) => l.kind === 'commitCursor-ok' && l.run === config.phase);
  return [...wanted].every((id) => now.acknowledged.includes(id)) && now.receiptsDue.length === 0 && cursors;
};
const done = await until(finished, config.timeoutMs);
log({ kind: 'settled', done });
if (done && (config.phase === 'reply' || (kill !== null && kill.operation === 'seal'))) {
  const sent = await h.client.send({ recipient: config.peer, payload: new TextEncoder().encode(`reply-${config.phase}`) });
  log({ kind: 'send', ok: sent.ok, code: sent.code ?? null });
  if (sent.ok) {
    const accepted = await until(() => h.events.some((e) => e.deliveryId === sent.value.deliveryId
      && (e.state === 'RELAY_ACCEPTED' || e.state === 'RECIPIENT_RECEIPT_RECEIVED')), config.timeoutMs);
    log({ kind: 'sent', accepted });
  }
}
await sleep(50);
await h.client.shutdown();
// The final durable state, read by a fresh instance (as the next process would).
const reader = createReferenceReceiver(options);
const snapshot = await reader.receiveState.load({ identity: config.identity, scope: SCOPE });
log({
  kind: 'final', code: snapshot.code ?? null, seen: snapshot.seen, pending: snapshot.pending?.map((e) => e.eventId),
  ready: snapshot.ready?.map((e) => e.eventId), acknowledged: snapshot.acknowledged,
  receiptsDue: snapshot.receiptsDue?.map((e) => e.eventId), cursors: snapshot.cursors?.length,
});
closeSync(logFd);
process.exit(done ? 0 : 4);
