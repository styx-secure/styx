// identicon.js — deterministic 5×5 symmetric identicon + short-key helper (UI only).
// These are frontend concerns, kept out of the StyxChat core contract.

function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Abbreviate a public key: `abcd1234…wxyz`. */
export function shortKey(pubkey) {
  const s = String(pubkey || '');
  return s.length <= 14 ? s : s.slice(0, 8) + '…' + s.slice(-6);
}

/** Deterministic identicon as an SVG data-URI, seeded by the pubkey. */
export function identicon(pubkey) {
  const seed = fnv1a(String(pubkey || 'anon'));
  const rnd = mulberry32(seed);
  const hue = seed % 360;
  const fg = `hsl(${hue} 58% 52%)`;
  const bg = `hsl(${hue} 30% 94%)`;
  const N = 5;
  const s = 20;
  const grid = [];
  for (let x = 0; x < 3; x++) {
    grid[x] = [];
    for (let y = 0; y < N; y++) grid[x][y] = rnd() > 0.5;
  }
  let rects = '';
  for (let x = 0; x < N; x++) {
    const sx = x < 3 ? x : N - 1 - x;
    for (let y = 0; y < N; y++) {
      if (grid[sx][y]) rects += `<rect x="${x * s}" y="${y * s}" width="${s}" height="${s}"/>`;
    }
  }
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">` +
    `<rect width="100" height="100" fill="${bg}"/><g fill="${fg}">${rects}</g></svg>`;
  return 'data:image/svg+xml,' + encodeURIComponent(svg);
}
