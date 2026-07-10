// test/notify.test.js — the local notifier decides whether to raise a browser
// notification, using injected deps so it is testable without a DOM.
import { describe, test, expect, jest } from '@jest/globals';
import { createNotifier } from '../src/lib/notify.js';

function harness({ permission = 'granted', visible = false, t = 1000 } = {}) {
  const shown = [];
  let now = t;
  const notifier = createNotifier({
    getPermission: () => permission,
    isPageVisible: () => visible,
    show: (n) => shown.push(n),
    now: () => now,
    coalesceMs: 4000,
  });
  return { notifier, shown, advance: (ms) => { now += ms; } };
}

describe('createNotifier', () => {
  test('shows a generic notification when hidden and permission granted', () => {
    const { notifier, shown } = harness({ visible: false, permission: 'granted' });
    expect(notifier.notifyIncoming()).toBe(true);
    expect(shown).toHaveLength(1);
    expect(shown[0].body).toBe('Hai un nuovo messaggio');
    expect(shown[0].title).toBe('Styx Chat');
  });

  test('stays silent when the page is visible (foreground)', () => {
    const { notifier, shown } = harness({ visible: true });
    expect(notifier.notifyIncoming()).toBe(false);
    expect(shown).toHaveLength(0);
  });

  test('stays silent when permission is not granted', () => {
    const { notifier, shown } = harness({ permission: 'default' });
    expect(notifier.notifyIncoming()).toBe(false);
    expect(shown).toHaveLength(0);
  });

  test('coalesces a burst into one notification within the window', () => {
    const { notifier, shown, advance } = harness({ visible: false });
    expect(notifier.notifyIncoming()).toBe(true);
    advance(1000);
    expect(notifier.notifyIncoming()).toBe(false); // within 4s window
    advance(4000);
    expect(notifier.notifyIncoming()).toBe(true);  // window elapsed
    expect(shown).toHaveLength(2);
  });
});
