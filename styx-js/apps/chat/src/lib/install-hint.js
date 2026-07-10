// install-hint.js — pure decision for which install hint to show. No React,
// no DOM: unit-testable under Jest and imported by the InstallHint component.

/** @returns {'none'|'ios'|'android'} */
export function installHintKind({ standalone, isIOS, deferredPrompt }) {
  if (standalone) return 'none';
  if (isIOS) return 'ios';
  if (deferredPrompt) return 'android';
  return 'none';
}

export function isIOSDevice() {
  if (typeof navigator === 'undefined') return false;
  return /iphone|ipad|ipod/i.test(navigator.userAgent);
}

export function isStandalone() {
  if (typeof window === 'undefined') return false;
  return window.matchMedia?.('(display-mode: standalone)').matches
    || window.navigator.standalone === true;
}
