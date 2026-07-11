// harness.js — STYX_SPIKE_PROTOTYPE. External module (the production CSP has no
// 'unsafe-inline' for scripts, so the harness bootstrap must be a real file —
// exactly like the app).
import { CryptoWorkerClient } from './worker-client.js';

window.CryptoWorkerClient = CryptoWorkerClient;
window.newClient = () => new CryptoWorkerClient(new URL('./crypto-worker.js', import.meta.url));
window.__cryptoSpikeReady = true;
