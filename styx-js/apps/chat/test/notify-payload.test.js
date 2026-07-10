// test/notify-payload.test.js — the notification shown (locally AND on a push)
// is the single generic payload; it must never carry content or a sender.
import { describe, test, expect } from '@jest/globals';
import { NOTIFICATION } from '../src/lib/notify.js';

describe('NOTIFICATION payload', () => {
  test('is the generic, content-free notification', () => {
    expect(NOTIFICATION).toEqual({ title: 'Styx Chat', body: 'Hai un nuovo messaggio', tag: 'styx-new' });
  });
});
