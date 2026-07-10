// test/pwa-manifest.test.js — the web app manifest must carry the fields a
// browser needs to consider the app installable.
import { describe, test, expect } from '@jest/globals';
import { manifest } from '../pwa.config.js';

describe('PWA manifest', () => {
  test('has the required installability fields', () => {
    expect(manifest.name).toBeTruthy();
    expect(manifest.short_name).toBeTruthy();
    expect(manifest.start_url).toBe('/');
    expect(manifest.display).toBe('standalone');
    expect(manifest.theme_color).toMatch(/^#/);
    expect(manifest.background_color).toMatch(/^#/);
  });

  test('declares 192px and 512px png icons plus a maskable one', () => {
    const sizes = manifest.icons.map((i) => i.sizes);
    expect(sizes).toContain('192x192');
    expect(sizes).toContain('512x512');
    expect(manifest.icons.some((i) => i.purpose === 'maskable')).toBe(true);
    expect(manifest.icons.every((i) => i.type === 'image/png')).toBe(true);
  });
});
