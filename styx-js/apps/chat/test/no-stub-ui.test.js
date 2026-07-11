// test/no-stub-ui.test.js
// Non-functional features must not be exposed with the real library.
import { describe, test, expect } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

describe('no stub UI with the real lib', () => {
  test('ContactRow no longer renders a presence dot (mock-only data)', () => {
    expect(read('../src/components/ContactRow.jsx')).not.toMatch(/className=["'`]presence/);
  });

  test('the remote-pairing tab is gated behind the demo flag', () => {
    const src = read('../src/components/PairingModal.jsx');
    // The tab and RemoteTab render must be guarded by REMOTE_PAIRING (demo-only).
    expect(src).toMatch(/REMOTE_PAIRING\s*&&/);
    expect(src).toMatch(/import\.meta\.env\s*&&\s*import\.meta\.env\.VITE_DEMO === '1'/);
  });
});
