// test/install-hint.test.js — which install hint to show, if any. Pure logic so
// it is testable without a DOM (and without importing React under Jest).
import { describe, test, expect } from '@jest/globals';
import { installHintKind } from '../src/lib/install-hint.js';

describe('installHintKind', () => {
  test('no hint when already installed (standalone)', () => {
    expect(installHintKind({ standalone: true, isIOS: true, deferredPrompt: null })).toBe('none');
    expect(installHintKind({ standalone: true, isIOS: false, deferredPrompt: {} })).toBe('none');
  });

  test('iOS Safari (not standalone) gets the add-to-home hint', () => {
    expect(installHintKind({ standalone: false, isIOS: true, deferredPrompt: null })).toBe('ios');
  });

  test('Android with a captured install prompt gets the install button', () => {
    expect(installHintKind({ standalone: false, isIOS: false, deferredPrompt: {} })).toBe('android');
  });

  test('non-iOS without a captured prompt shows nothing', () => {
    expect(installHintKind({ standalone: false, isIOS: false, deferredPrompt: null })).toBe('none');
  });
});
