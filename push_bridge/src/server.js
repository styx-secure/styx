// server.js — the bridge's small HTTP API. Hands out the VAPID public key and
// accepts signed register/unregister requests. All crypto (verify) and state
// (registry) are injected so this stays a thin, testable request router.
import { createServer as httpCreateServer } from 'node:http';

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(body ? JSON.parse(body) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
function send(res, status, obj) {
  res.writeHead(status, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
  res.end(JSON.stringify(obj));
}

/**
 * @param {object} deps
 * @param {object} deps.registry Registry (add/remove/get/pubkeys)
 * @param {string} deps.vapidPublicKey
 * @param {(r:object)=>boolean} deps.verify verifyRegistration
 * @param {(pubkey:string)=>void} deps.onRegister called after a successful register (e.g. watch it)
 * @returns {import('node:http').Server}
 */
export function createServer({ registry, vapidPublicKey, verify, onRegister }) {
  return httpCreateServer(async (req, res) => {
    try {
      if (req.method === 'OPTIONS') {
        res.writeHead(204, {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET,POST,OPTIONS',
          'access-control-allow-headers': 'content-type',
        });
        return res.end();
      }
      if (req.method === 'GET' && req.url === '/vapidPublicKey') {
        return send(res, 200, { key: vapidPublicKey });
      }
      if (req.method === 'POST' && req.url === '/register') {
        const { pubkey, subscription, sig } = await readJson(req);
        if (!pubkey || !subscription?.endpoint || !sig) return send(res, 400, { error: 'bad request' });
        if (!verify({ pubkey, action: 'register', endpoint: subscription.endpoint, sig })) return send(res, 401, { error: 'bad signature' });
        await registry.add(pubkey, subscription);
        onRegister(pubkey);
        return send(res, 200, { ok: true });
      }
      if (req.method === 'POST' && req.url === '/unregister') {
        const { pubkey, endpoint, sig } = await readJson(req);
        if (!pubkey || !endpoint || !sig) return send(res, 400, { error: 'bad request' });
        if (!verify({ pubkey, action: 'unregister', endpoint, sig })) return send(res, 401, { error: 'bad signature' });
        await registry.remove(pubkey, endpoint);
        return send(res, 200, { ok: true });
      }
      return send(res, 404, { error: 'not found' });
    } catch (e) {
      return send(res, 500, { error: String(e?.message || e) });
    }
  });
}
