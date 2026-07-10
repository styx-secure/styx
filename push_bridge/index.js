// index.js — entrypoint. Wires the registry, HTTP API, relay listener and
// dispatcher from environment config, then starts listening. Blind + stateless:
// the only persisted thing is the subscription registry.
import { Registry } from './src/registry.js';
import { verifyRegistration } from './src/signature.js';
import { Dispatcher } from './src/dispatcher.js';
import { RelayListener } from './src/relay-listener.js';
import { makeSender } from './src/web-push-sender.js';
import { createServer } from './src/server.js';

const {
  VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT = 'mailto:admin@styx.local',
  RELAYS = 'wss://relay.damus.io,wss://nos.lol',
  PORT = '8095', REGISTRY_FILE = './registry.json',
} = process.env;

if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
  console.error('Set VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY (npx web-push generate-vapid-keys).');
  process.exit(1);
}

const registry = new Registry({ filePath: REGISTRY_FILE });
await registry.load();

const send = makeSender({ subject: VAPID_SUBJECT, publicKey: VAPID_PUBLIC_KEY, privateKey: VAPID_PRIVATE_KEY });
const dispatcher = new Dispatcher({ registry, send, now: () => Date.now() });

const listener = new RelayListener({
  relays: RELAYS.split(',').map((s) => s.trim()).filter(Boolean),
  onEvent: (pubkey) => dispatcher.notify(pubkey),
});
await listener.start(registry.pubkeys());

const server = createServer({
  registry,
  vapidPublicKey: VAPID_PUBLIC_KEY,
  verify: verifyRegistration,
  onRegister: (pubkey) => listener.watch(pubkey),
});
server.listen(Number(PORT), () => console.log(`[push-bridge] http on :${PORT}, watching ${registry.pubkeys().length} pubkeys`));
