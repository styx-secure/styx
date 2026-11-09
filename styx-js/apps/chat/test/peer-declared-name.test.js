// test/peer-declared-name.test.js — the conversation header shows the alias
// chosen on this device; the name the peer declares for itself is shown apart,
// only when it differs, and never with the verified mark. (The app's JSX is not
// transformed under jest; these checks read the sources, like no-stub-ui.test.js.)
import { describe, test, expect } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const read = (rel) => readFileSync(fileURLToPath(new URL(rel, import.meta.url)), 'utf8');

describe('peer-declared name in the conversation header', () => {
  const src = read('../src/components/ConversationView.jsx');
  const header = src.slice(src.indexOf('<div className="cv-header">'), src.indexOf('<div className="cv-msgs'));

  test('the alias line shows only the local alias', () => {
    expect(header).toMatch(/<div className="alias">\{contact\.alias\}<\/div>/);
  });

  test('the declared name has its own line, shown only when it differs from the alias', () => {
    expect(header).toMatch(
      /\{contact\.peerAlias && contact\.peerAlias !== contact\.alias && \(\s*<div className="status" data-testid="peer-declared-name"[^>]*>\s*si presenta come «\{contact\.peerAlias\}»\s*<\/div>\s*\)\}/,
    );
  });

  test('the verified mark never refers to the declared name', () => {
    const badge = header.slice(header.indexOf('data-testid="safety-badge"'));
    expect(badge).toMatch(/\{contact\.verified\s*\?/);
    expect(badge).not.toMatch(/peerAlias/);
    expect(header.match(/peerAlias/g)).toHaveLength(3);
  });
});
