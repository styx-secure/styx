// Flegias preview (synthetic data only)
import { schnorr } from '@noble/curves/secp256k1';
import { bytesToHex } from '../../src/utils.js';
export function generateSecretKey() { return schnorr.utils.randomPrivateKey(); }
export function createPreviewPorts({ secretKey, recorder = () => {} }) {
  const store = new Map();
  const record = (port, method, args) => recorder(port, method, copy(args));
  return {
    storage: {
      put(value) { record('storage','put',[value]); store.set(value.deliveryId,value); return true; },
      get(id) { record('storage','get',[id]); return store.get(id) ?? null; },
      update(id,value) { record('storage','update',[id,value]); if (!store.has(id)) return false; store.set(id,value); return true; },
      remove(id) { record('storage','remove',[id]); return store.delete(id); },
      list() { record('storage','list',[]); return [...store.values()]; }
    },
    session: {
      seal(args) { record('session','seal',[args]); return { ciphertext: args.plaintext.slice() }; },
      open(args) { record('session','open',[args]); return { plaintext: args.ciphertext.slice() }; }
    },
    identity: {
      getPublicKey() { record('identity','getPublicKey',[]); return bytesToHex(schnorr.getPublicKey(secretKey)); },
      sign(args) { record('identity','sign',[args]); return schnorr.sign(args.digest,secretKey); }
    }
  };
}

// Copy recorder arguments using ECMAScript values only; no host cloning API.
function copy(value) {
  if (value instanceof Uint8Array) return value.slice();
  if (Array.isArray(value)) return value.map(copy);
  if (value !== null && typeof value === 'object') {
    const result = {};
    for (const key of Object.keys(value)) result[key] = copy(value[key]);
    return result;
  }
  return value;
}
