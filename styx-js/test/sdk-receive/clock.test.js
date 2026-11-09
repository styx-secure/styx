// M3-RECEIVE-2 follow-up: the test clock of helpers.js. The outcome of the
// receive tests must not depend on how long a real adapter write takes: the
// clock stands still while a port call is in progress, and timers fire in the
// order of their due times on that clock. Every check below waits for an event
// or reads the clock while it is held, never for a real-time window.
import { describe, test, expect } from '@jest/globals';
import { fastClock, holdClock, heldPorts, sleep, until } from './helpers.js';

/** A promise and the function that settles it. */
function gate() {
  let open;
  const promise = new Promise((resolve) => { open = resolve; });
  return { promise, open };
}

describe('the test clock (helpers.js fastClock)', () => {
  test('is the closed clock port of C-SDK section 8.4: now, setTimer, clearTimer and nothing else', () => {
    const clock = fastClock();
    expect(Reflect.ownKeys(clock).sort()).toEqual(['clearTimer', 'now', 'setTimer']);
  });

  test('while held, its time stands still and none of its timers fires; released, the timer fires', async () => {
    const clock = fastClock(50);
    const release = holdClock(clock);
    const before = clock.now();
    const fired = [];
    clock.setTimer(() => fired.push('t'), 0);
    await sleep(50); // host time passes; the held clock does not
    expect(clock.now()).toBe(before);
    expect(fired).toEqual([]);
    release();
    expect(await until(() => fired.length === 1)).toBe(true);
  });

  test('holds nest: the clock runs again only after the last release; a second release is a no-op', async () => {
    const clock = fastClock(50);
    const first = holdClock(clock);
    const second = holdClock(clock);
    const fired = [];
    clock.setTimer(() => fired.push('t'), 0);
    first();
    first();
    const at = clock.now();
    await sleep(20);
    expect(clock.now()).toBe(at);
    expect(fired).toEqual([]);
    second();
    expect(await until(() => fired.length === 1)).toBe(true);
  });

  test('timers fire in the order of their due times, ties in arming order; a cleared timer never fires', async () => {
    const clock = fastClock(50);
    const release = holdClock(clock);
    const fired = [];
    clock.setTimer(() => fired.push('c'), 3000);
    clock.setTimer(() => fired.push('a'), 1000);
    const cleared = clock.setTimer(() => fired.push('x'), 2000);
    clock.setTimer(() => fired.push('b'), 1000);
    clock.setTimer(() => fired.push('d'), 3000);
    clock.clearTimer(cleared);
    release();
    expect(await until(() => fired.length === 4)).toBe(true);
    expect(fired).toEqual(['a', 'b', 'c', 'd']);
  });

  test('a hold taken by a timer callback stops the rest of that round until it is released', async () => {
    const clock = fastClock(50);
    const outer = holdClock(clock);
    const fired = [];
    let inner = null;
    clock.setTimer(() => { fired.push('first'); inner = holdClock(clock); }, 1000);
    clock.setTimer(() => fired.push('second'), 1000);
    outer();
    expect(await until(() => fired.length >= 1)).toBe(true);
    await sleep(50);
    expect(fired).toEqual(['first']);
    inner();
    expect(await until(() => fired.length === 2)).toBe(true);
    expect(fired).toEqual(['first', 'second']);
  });

  test('a timer cleared by an earlier callback of the same round never fires', async () => {
    const clock = fastClock(50);
    const release = holdClock(clock);
    const fired = [];
    let second = null;
    clock.setTimer(() => { fired.push('first'); clock.clearTimer(second); }, 1000);
    second = clock.setTimer(() => fired.push('second'), 1000);
    clock.setTimer(() => fired.push('third'), 1000);
    release();
    expect(await until(() => fired.length === 2)).toBe(true);
    await sleep(50);
    expect(fired).toEqual(['first', 'third']);
  });

  test('a timer fires only once its due time has passed on the clock', async () => {
    const clock = fastClock(50);
    const armed = clock.now();
    const seen = [];
    clock.setTimer(() => seen.push(clock.now()), 500);
    expect(await until(() => seen.length === 1)).toBe(true);
    expect(seen[0] - armed).toBeGreaterThanOrEqual(500);
  });
});

describe('the ports handed to the SDK (helpers.js heldPorts)', () => {
  test('hold the clock for the whole of an asynchronous call, however long it lasts on the host', async () => {
    const clock = fastClock(50);
    const write = gate();
    const fired = [];
    let started = null;
    const ports = heldPorts({ receiveState: { stage: () => { started = clock.now(); return write.promise; } } }, clock);
    clock.setTimer(() => fired.push('periodic'), 0);
    const call = ports.receiveState.stage(); // the clock is held from here: `started` is its reading
    await sleep(50); // a slow real write
    expect(clock.now()).toBe(started);
    expect(fired).toEqual([]);
    write.open('done');
    expect(await call).toBe('done');
    expect(await until(() => fired.length === 1)).toBe(true);
  });

  test('release the clock when a call rejects or throws, and pass the failure through unchanged', async () => {
    const clock = fastClock(50);
    const failure = new Error('transient');
    const ports = heldPorts({
      session: { openCandidate: () => Promise.reject(failure), isKnownSender: () => { throw failure; } },
    }, clock);
    await expect(ports.session.openCandidate()).rejects.toBe(failure);
    expect(() => ports.session.isKnownSender()).toThrow(failure);
    const fired = [];
    clock.setTimer(() => fired.push('t'), 0);
    expect(await until(() => fired.length === 1)).toBe(true);
  });

  test('return the value the port returned, a thenable function included, and hold the clock until it settles', async () => {
    const clock = fastClock(50);
    let settle = null;
    const thenable = Object.assign(() => undefined, { then: (resolve) => { settle = resolve; } });
    const ports = heldPorts({ session: { openCandidate: () => thenable } }, clock);
    expect(ports.session.openCandidate()).toBe(thenable);
    const fired = [];
    clock.setTimer(() => fired.push('t'), 0);
    expect(await until(() => settle !== null)).toBe(true);
    await sleep(50);
    expect(fired).toEqual([]);
    settle('done');
    expect(await until(() => fired.length === 1)).toBe(true);
  });

  test('release the clock when reading the then of a returned value throws, and return that value unchanged', async () => {
    const clock = fastClock(50);
    const hostile = {};
    Object.defineProperty(hostile, 'then', { get() { throw new Error('no then'); } });
    const ports = heldPorts({ session: { openCandidate: () => hostile } }, clock);
    expect(ports.session.openCandidate()).toBe(hostile);
    const fired = [];
    clock.setTimer(() => fired.push('t'), 0);
    expect(await until(() => fired.length === 1)).toBe(true);
  });

  test('keep synchronous results and the arguments as they are, and non-function members untouched', () => {
    const clock = fastClock(50);
    const seen = [];
    const ports = heldPorts({ identity: { getPublicKey: (...args) => { seen.push(args); return 'key'; }, tag: 7 } }, clock);
    expect(ports.identity.getPublicKey(1, 2)).toBe('key');
    expect(seen).toEqual([[1, 2]]);
    expect(ports.identity.tag).toBe(7);
  });

  test('refuse a port that is not a plain object (its prototype methods would be lost)', () => {
    class Port { stage() { return true; } }
    expect(() => heldPorts({ receiveState: new Port() }, fastClock())).toThrow('plain object');
  });
});
