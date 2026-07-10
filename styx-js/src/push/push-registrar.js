// push-registrar.js — client side of Web Push. Subscribes via the browser
// pushManager, signs the registration with the Nostr identity (via the injected
// `sign` callback so the secret stays inside StyxChat), and registers with the
// bridge. Opt-in: with no bridgeUrl it does nothing and the app is unaffected.

/** Decode a URL-safe base64 VAPID key into the bytes pushManager wants. */
export function urlBase64ToUint8Array(base64) {
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const b64 = (base64 + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

export class PushRegistrar {
  /**
   * @param {object} deps
   * @param {string} deps.bridgeUrl base URL of the push bridge ('' → disabled)
   * @param {string} deps.pubkey our hex Nostr pubkey
   * @param {(action:string, endpoint:string)=>Promise<string>} deps.sign schnorr signer
   * @param {typeof fetch} deps.fetchImpl
   * @param {PushManager} deps.pushManager
   */
  constructor({ bridgeUrl, pubkey, sign, fetchImpl, pushManager }) {
    this._bridgeUrl = bridgeUrl;
    this._pubkey = pubkey;
    this._sign = sign;
    this._fetch = fetchImpl;
    this._pm = pushManager;
  }

  /** @returns {Promise<boolean>} whether a registration was sent + accepted. */
  async enable() {
    if (!this._bridgeUrl) return false; // opt-in: no bridge configured
    try {
      const keyRes = await this._fetch(`${this._bridgeUrl}/vapidPublicKey`);
      const { key } = await keyRes.json();
      const sub = await this._pm.subscribe({
        userVisibleOnly: true,
        applicationServerKey: urlBase64ToUint8Array(key),
      });
      const json = sub.toJSON();
      const sig = await this._sign('register', json.endpoint);
      const res = await this._fetch(`${this._bridgeUrl}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ pubkey: this._pubkey, subscription: json, sig }),
      });
      return !!res.ok;
    } catch (e) {
      console.debug('push registration failed', e);
      return false;
    }
  }
}
