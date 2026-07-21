// vault-kdf-loader.js — verified loader of the styx-kdf-wasm artifact for the
// vault worker (Blocco 3, PR-3; vault spec §9/§7.1 discipline). Pure module
// with injectable dependencies: no Worker API, no storage.
//
// The ONLY thing the page may influence is WHERE the deployment serves the
// frozen artifact (a same-origin *.wasm path). The JavaScript glue is
// imported STATICALLY by the worker entry — never from a URL received in a
// message, never via blob:/data:/eval — and the WASM is initialized
// exclusively from bytes that already passed the exact size and SHA-256
// digest checks below, followed by an internal synthetic KAT whose output
// never leaves the worker.

import { VaultWorkerError, VaultWorkerErrorCodes as Codes } from './vault-worker-errors.js';

/** Frozen digest of pkg/styx_kdf_wasm_bg.wasm (PR-1, PROVENANCE.md). */
export const KDF_WASM_SHA256 = 'ad67202689c58d5e7b7a0b845d7b9d7253ecc04542f8921804c11d62942ae8f5';
/** Exact artifact size in bytes (PR-1, PROVENANCE.md). */
export const KDF_WASM_BYTES = 42082;
/**
 * The only pathname the loader accepts: the canonical vendored location,
 * optionally under a deployment prefix. Binds the URL to the ONE artifact
 * this build was reviewed against.
 */
export const KDF_WASM_PATH_SUFFIX = '/vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm';
export const MAX_WASM_URL_LENGTH = 1024;

// Internal synthetic KAT (cross-validated 'absolute-min-bounds' anchor from
// the frozen KDF vectors: RustCrypto == hash-wasm across engines, PR-1).
// TEST-ONLY inputs; minimal cost so INIT stays fast. The output is compared
// and zeroized — it is NEVER part of any response.
const KAT_PASSWORD = Object.freeze([107]);
const KAT_SALT = Object.freeze([0, 1, 2, 3, 4, 5, 6, 7]);
const KAT_PARAMS = Object.freeze({ mKib: 1024, t: 1, p: 1, outLen: 16 });
const KAT_HEX = '7a6ebb2e8257e4c8ea88b5d3bf7c5a95';

const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');

const initError = (message, reason) => new VaultWorkerError(
  Codes.BAD_REQUEST, message, { phase: 'init', reason },
);

/**
 * Fail-closed validation of the INIT wasm URL (vault spec §9; mandate §10):
 * bounded same-origin string, https: (http: only for loopback test hosts),
 * no credentials, no query, no fragment, no backslash, no `..` segment, no
 * encoded slash, pathname bound to the canonical KDF artifact location.
 * @returns {URL} @throws {VaultWorkerError} BAD_REQUEST
 */
export function validateKdfWasmUrl(rawUrl, origin) {
  if (typeof rawUrl !== 'string' || rawUrl.length === 0 || rawUrl.length > MAX_WASM_URL_LENGTH) {
    throw initError('wasm url must be a bounded string', 'bad-url-shape');
  }
  if (/[\s\\]/.test(rawUrl)) throw initError('wasm url contains forbidden characters', 'bad-url-chars');
  if (/%2f|%5c/i.test(rawUrl)) throw initError('encoded slashes are not allowed in the wasm url', 'encoded-slash');
  // Checked on the RAW input: the URL parser normalizes %2E%2E into `..`
  // BEFORE pathname checks could see it, so traversal is rejected up front.
  if (/\.\./.test(rawUrl) || /%2e/i.test(rawUrl)) {
    throw initError('dot segments are not allowed in the wasm url', 'dot-dot');
  }
  let url;
  try {
    url = new URL(rawUrl, origin);
  } catch {
    throw initError('wasm url does not parse', 'unparsable-url');
  }
  if (url.origin !== new URL(origin).origin) {
    throw initError('wasm url must be same-origin', 'cross-origin');
  }
  const loopback = url.hostname === '127.0.0.1' || url.hostname === 'localhost' || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw initError('wasm url protocol not allowed', 'bad-protocol');
  }
  if (url.username !== '' || url.password !== '') throw initError('wasm url must carry no credentials', 'credentials');
  if (url.search !== '') throw initError('wasm url must carry no query', 'query');
  if (url.hash !== '') throw initError('wasm url must carry no fragment', 'fragment');
  if (url.pathname.split('/').includes('..')) throw initError('wasm url must not traverse', 'dot-dot');
  if (url.pathname !== KDF_WASM_PATH_SUFFIX && !url.pathname.endsWith(KDF_WASM_PATH_SUFFIX)) {
    throw initError('wasm url does not point at the KDF artifact', 'wrong-artifact-path');
  }
  return url;
}

/**
 * Create the loader with injected dependencies (production values come from
 * the worker entry and are frozen there; tests inject fakes).
 *
 * @param {object} deps
 * @param {string} deps.origin the worker's own origin (self.location.origin)
 * @param {typeof fetch} deps.fetchImpl
 * @param {SubtleCrypto} deps.subtleImpl
 * @param {(module: {module: BufferSource}) => unknown} deps.initSyncImpl the
 *   statically imported styx_kdf_wasm glue initSync
 * @param {(pw: Uint8Array, salt: Uint8Array, m: number, t: number, p: number, out: number) => Uint8Array} deps.deriveImpl
 *   the statically imported argon2id_derive export
 */
export function createVaultKdfLoader({
  origin, fetchImpl, subtleImpl, initSyncImpl, deriveImpl,
}) {
  let loaded = false;

  /**
   * Verified load sequence (mandate §10): validate URL → same-origin fetch
   * with redirects DENIED → bounded read → exact size → SHA-256 → frozen
   * digest → initSync(verifiedBytes) → internal synthetic KAT → zeroize.
   * @param {string} rawUrl from the INIT payload
   * @returns {Promise<{wasmBytes: number, digestVerified: true, katVerified: true}>}
   * @throws {VaultWorkerError}
   */
  async function load(rawUrl) {
    const url = validateKdfWasmUrl(rawUrl, origin);

    let response;
    try {
      response = await fetchImpl(url.href, { redirect: 'error', credentials: 'omit', cache: 'no-store' });
    } catch {
      throw initError('wasm fetch failed', 'fetch-failed');
    }
    if (!response || response.ok !== true) throw initError('wasm fetch returned a non-ok status', 'fetch-not-ok');

    // Bounded read: never accumulate more than the expected size + 1 probe byte.
    let bytes;
    if (response.body && typeof response.body.getReader === 'function') {
      const reader = response.body.getReader();
      const buf = new Uint8Array(KDF_WASM_BYTES + 1);
      let offset = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (offset + value.byteLength > buf.byteLength) {
          await reader.cancel().catch(() => {});
          buf.fill(0);
          throw initError('wasm response exceeds the expected size', 'oversized-artifact');
        }
        buf.set(value, offset);
        offset += value.byteLength;
      }
      bytes = buf.subarray(0, offset);
    } else {
      const raw = new Uint8Array(await response.arrayBuffer());
      if (raw.byteLength > KDF_WASM_BYTES) throw initError('wasm response exceeds the expected size', 'oversized-artifact');
      bytes = raw;
    }
    if (bytes.byteLength !== KDF_WASM_BYTES) {
      bytes.fill(0);
      throw initError('wasm artifact size mismatch', 'size-mismatch');
    }

    const digest = toHex(new Uint8Array(await subtleImpl.digest('SHA-256', bytes)));
    if (digest !== KDF_WASM_SHA256) {
      bytes.fill(0);
      throw initError('wasm artifact digest mismatch', 'digest-mismatch');
    }

    // Only VERIFIED bytes ever reach the WASM engine.
    try {
      initSyncImpl({ module: bytes });
    } catch {
      throw initError('wasm initialization failed', 'init-failed');
    }

    // Internal synthetic KAT: the engine must produce the cross-validated
    // anchor before the worker may report READY. Output never leaves here.
    const pw = new Uint8Array(KAT_PASSWORD);
    const salt = new Uint8Array(KAT_SALT);
    let out;
    try {
      out = deriveImpl(pw, salt, KAT_PARAMS.mKib, KAT_PARAMS.t, KAT_PARAMS.p, KAT_PARAMS.outLen);
    } catch {
      throw initError('internal KAT execution failed', 'kat-failed');
    } finally {
      pw.fill(0);
      salt.fill(0);
    }
    const katOk = out instanceof Uint8Array && toHex(out) === KAT_HEX;
    if (out instanceof Uint8Array) out.fill(0);
    if (!katOk) throw initError('internal KAT mismatch', 'kat-mismatch');

    loaded = true;
    return { wasmBytes: KDF_WASM_BYTES, digestVerified: true, katVerified: true };
  }

  return Object.freeze({ load, isLoaded: () => loaded });
}
