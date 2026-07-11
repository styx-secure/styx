// static-server.mjs — a dependency-free static file server for the built PWA.
// Serves the production `dist/` over HTTP for a Cloudflare tunnel to front with
// HTTPS. No npm dependencies, so it starts reliably at boot (systemd) without
// touching the network. Correct MIME types (application/wasm is load-critical
// for the MLS engine) and an SPA fallback to index.html.
import { createServer } from 'node:http';
import { readFile, stat, realpath } from 'node:fs/promises';
import { join, normalize, extname, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT_RAW = process.env.STYX_DIST
  ? normalize(process.env.STYX_DIST)
  : fileURLToPath(new URL('./dist', import.meta.url));
// Canonical root: symlinks are resolved once so per-request realpath checks can
// reject any file that escapes it (a symlink inside dist/ pointing outside).
const ROOT = await realpath(ROOT_RAW).catch(() => ROOT_RAW);
const HOST = process.env.STYX_HOST || '127.0.0.1';
const PORT = Number(process.env.STYX_PORT || 8090);

// Hardening headers chosen to NOT break the app: no default-src/script-src (WASM
// needs 'wasm-unsafe-eval' and this is only verifiable in a real browser), only
// directives that don't govern script/style/wasm/connect. A full script/style
// CSP should be added after browser verification.
const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'content-security-policy': "object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
};

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8',
  '.wasm': 'application/wasm',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

const BAD_ENCODING = Symbol('bad-encoding');

/**
 * Resolve a URL path to an absolute path inside ROOT (textual check).
 * @returns {string|null|typeof BAD_ENCODING} absolute path, null if it escapes
 *   ROOT, or BAD_ENCODING if the percent-encoding is malformed.
 */
function resolvePath(urlPath) {
  let decoded;
  try {
    decoded = decodeURIComponent(urlPath.split('?')[0]);
  } catch {
    return BAD_ENCODING; // malformed %xx → 400, not a 500
  }
  const rel = normalize(decoded).replace(/^(\.\.[/\\])+/, '');
  const abs = join(ROOT, rel);
  // Trailing separator so a sibling like `<root>-secret` cannot pass the prefix.
  return abs === ROOT || abs.startsWith(ROOT + sep) ? abs : null;
}

/**
 * Confirm a path is a regular file that, after resolving symlinks, still lives
 * inside ROOT — so a symlink planted in dist/ cannot serve an outside file.
 * @returns {Promise<string|null>} the canonical path, or null.
 */
async function readable(path) {
  try {
    const s = await stat(path);
    if (!s.isFile()) return null;
    const real = await realpath(path);
    return real === ROOT || real.startsWith(ROOT + sep) ? real : null;
  } catch {
    return null;
  }
}

const server = createServer(async (req, res) => {
  try {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { ...SECURITY_HEADERS, allow: 'GET, HEAD' });
      res.end();
      return;
    }
    const target = resolvePath(req.url === '/' ? '/index.html' : req.url);
    if (target === BAD_ENCODING) { res.writeHead(400, SECURITY_HEADERS); res.end('Bad request'); return; }
    if (!target) { res.writeHead(403, SECURITY_HEADERS); res.end('Forbidden'); return; }

    let file = await readable(target);
    // SPA fallback: unknown non-asset path → index.html (client-side app shell).
    if (!file && !extname(target)) file = await readable(join(ROOT, 'index.html'));
    if (!file) { res.writeHead(404, SECURITY_HEADERS); res.end('Not found'); return; }

    const ext = extname(file).toLowerCase();
    const type = MIME[ext] || 'application/octet-stream';
    // The service worker and app shell must revalidate so updates ship; hashed
    // assets under /assets/ are immutable and can be cached hard.
    const immutable = /\/assets\//.test(file) && ext !== '.html';
    const cache = immutable
      ? 'public, max-age=31536000, immutable'
      : 'no-cache';

    const body = await readFile(file);
    res.writeHead(200, {
      ...SECURITY_HEADERS,
      'content-type': type,
      'content-length': body.length,
      'cache-control': cache,
    });
    res.end(req.method === 'HEAD' ? undefined : body);
  } catch (err) {
    res.writeHead(500, SECURITY_HEADERS);
    res.end('Internal error');
    process.stderr.write(`[static-server] ${err?.stack || err}\n`);
  }
});

server.listen(PORT, HOST, () => {
  process.stdout.write(`[static-server] serving ${ROOT} at http://${HOST}:${PORT}\n`);
});
