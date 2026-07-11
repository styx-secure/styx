// static-server.mjs — a dependency-free static file server for the built PWA.
// Serves the production `dist/` over HTTP for a Cloudflare tunnel to front with
// HTTPS. No npm dependencies, so it starts reliably at boot (systemd) without
// touching the network. Correct MIME types (application/wasm is load-critical
// for the MLS engine) and an SPA fallback to index.html.
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { join, normalize, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = process.env.STYX_DIST
  ? normalize(process.env.STYX_DIST)
  : fileURLToPath(new URL('./dist', import.meta.url));
const HOST = process.env.STYX_HOST || '127.0.0.1';
const PORT = Number(process.env.STYX_PORT || 8090);

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

/** Resolve a URL path to a file inside ROOT, or null if it escapes ROOT. */
function resolvePath(urlPath) {
  const decoded = decodeURIComponent(urlPath.split('?')[0]);
  const rel = normalize(decoded).replace(/^(\.\.[/\\])+/, '');
  const abs = join(ROOT, rel);
  return abs.startsWith(ROOT) ? abs : null;
}

async function readable(path) {
  try {
    const s = await stat(path);
    return s.isFile() ? path : null;
  } catch {
    return null;
  }
}

const server = createServer(async (req, res) => {
  try {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' });
      res.end();
      return;
    }
    let target = resolvePath(req.url === '/' ? '/index.html' : req.url);
    if (!target) { res.writeHead(403); res.end('Forbidden'); return; }

    let file = await readable(target);
    // SPA fallback: unknown non-asset path → index.html (client-side app shell).
    if (!file && !extname(target)) file = await readable(join(ROOT, 'index.html'));
    if (!file) { res.writeHead(404); res.end('Not found'); return; }

    const ext = extname(file).toLowerCase();
    const type = MIME[ext] || 'application/octet-stream';
    // The service worker and app shell must revalidate so updates ship; hashed
    // assets under /assets/ are immutable and can be cached hard.
    const immutable = /\/assets\//.test(file) && ext !== '.html';
    const cache = immutable
      ? 'public, max-age=31536000, immutable'
      : 'no-cache';

    const body = await readFile(file);
    res.writeHead(200, { 'content-type': type, 'content-length': body.length, 'cache-control': cache });
    res.end(req.method === 'HEAD' ? undefined : body);
  } catch (err) {
    res.writeHead(500);
    res.end('Internal error');
    process.stderr.write(`[static-server] ${err?.stack || err}\n`);
  }
});

server.listen(PORT, HOST, () => {
  process.stdout.write(`[static-server] serving ${ROOT} at http://${HOST}:${PORT}\n`);
});
