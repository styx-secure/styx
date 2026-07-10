// scripts/gen-icons.mjs — rasterize the app logo into the PNG icons the manifest
// and iOS home screen need. Run once (npm run gen:icons); PNGs are committed.
import sharp from 'sharp';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const pub = (p) => fileURLToPath(new URL(`../public/${p}`, import.meta.url));
const svg = readFileSync(pub('icon.svg'));

// Maskable icon: same art on a full-bleed square (no rounded corners) so the
// platform mask can apply its own shape without clipping the glyph.
const maskableSvg = Buffer.from(`
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <rect width="512" height="512" fill="#0b8a60"/>
  <path d="M170 190c52-34 130-34 182 0" fill="none" stroke="#ffffff" stroke-width="26" stroke-linecap="round"/>
  <path d="M170 256c52 34 130 34 182 0" fill="none" stroke="#ffffff" stroke-width="26" stroke-linecap="round"/>
  <path d="M170 322c52-34 130-34 182 0" fill="none" stroke="#ffffff" stroke-width="26" stroke-linecap="round"/>
</svg>`);

async function main() {
  await sharp(svg).resize(192, 192).png().toFile(pub('pwa-192.png'));
  await sharp(svg).resize(512, 512).png().toFile(pub('pwa-512.png'));
  await sharp(svg).resize(180, 180).png().toFile(pub('apple-touch-icon.png'));
  await sharp(maskableSvg).resize(512, 512).png().toFile(pub('pwa-maskable-512.png'));
  console.log('icons written to public/');
}
main().catch((e) => { console.error(e); process.exit(1); });
