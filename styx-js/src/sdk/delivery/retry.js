/**
 * I-RETRY -- retransmission backoff schedule of the M3 early-lane delivery
 * layer (C-DLV section 4.3), with injected clock and randomness.
 *
 * This module is SDK-internal (C-DLV section 9) and holds no state: every
 * export is a pure function over values and ports its caller supplies. It
 * imports nothing, opens no socket and reads no clock or random source of its
 * own; the clock port and the random port of C-SDK section 8.4 reach it as
 * arguments, so a test can drive the schedule with exactly the values it
 * wants.
 *
 * Nothing a caller supplies escapes as a throw except the deliberate
 * `TypeError` API-misuse signal this contract fixes for `attempts`,
 * `maxAttempts`, `deadlineAt`, `n` and `u`. Every read of an injected port
 * happens inside a guarded path, so a port that is absent, is not a function,
 * throws when read or throws when called is an internal fault of the item
 * (`E_SDK_INTERNAL`), never a value that reaches the caller as an exception.
 *
 * The schedule is the one C-DLV section 4.3 fixes, and this module adds no
 * bound, no jitter rule and no code:
 *
 *   base(n)      = min(1000 * 2^(n-1), 30000)                  milliseconds
 *   delay(n, u)  = floor(base(n) / 2) + floor(u * base(n) / 2^33)
 *
 * with `n` the number of the attempt that just ended and `u` one
 * `random.nextUint32()` value in [0, 2^32). So delay(n, u) lies in
 * [base(n) / 2, base(n)): 500-999 ms after attempt 1, 1 000-1 999 ms after
 * attempt 2, 2 000-3 999 ms after attempt 3, 4 000-7 999 ms after attempt 4,
 * 8 000-15 999 ms after attempt 5, and 15 000-29 999 ms after attempts 6 to 9.
 */

/** Backoff base of C-DLV section 3: 1 000 ms. */
export const BACKOFF_BASE_MS = 1000;

/** Backoff cap of C-DLV section 3: 30 000 ms. */
export const BACKOFF_CAP_MS = 30000;

/** The size of the closed draw range of `random.nextUint32()`: 2^32. */
const DRAW_RANGE = 2 ** 32;

/** The divisor of the jitter term of `delay(n, u)`: 2^33. */
const JITTER_DIVISOR = 2 ** 33;

/**
 * A clock reading of C-SDK section 8.4 is a finite number of milliseconds and
 * C-DLV section 6.1 states that "the clock domain is not narrowed": a finite
 * value is a valid reading whether it is negative or not an integer, so only a
 * value that is not a finite number is invalid. C-DLV section 6.1's
 * negative / not-a-safe-integer rule concerns `created_at` when an event
 * structure is built, not the validity of a clock reading.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isValidClockValue(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

/**
 * A draw of C-SDK section 8.4 is an integer in [0, 2^32).
 *
 * @param {unknown} value
 * @returns {boolean}
 */
function isValidDraw(value) {
  return Number.isInteger(value) && value >= 0 && value < DRAW_RANGE;
}

/**
 * The closed result of C-DLV section 4.5 and C-SDK section 8.4 for an internal
 * fault, an invalid clock reading and an invalid draw: the item moves to its
 * applicable terminal failed state with `lastCode: 'E_SDK_INTERNAL'`.
 *
 * @returns {{ action: 'FAIL', lastCode: 'E_SDK_INTERNAL' }}
 */
function internalFault() {
  return Object.freeze({ action: 'FAIL', lastCode: 'E_SDK_INTERNAL' });
}

/**
 * Read and call one method of an injected port.
 *
 * The property read and the call both happen here, inside the guarded path of
 * the caller, so that a port that is absent, a method that is not a function,
 * a getter that throws and a method that throws all raise in the same place
 * and are mapped to `E_SDK_INTERNAL` by the caller. Reading the method only
 * where section 4.3 reads it is what keeps an exhausted item from touching a
 * port at all. No value a caller supplied reaches the caller as a throw
 * (C-SDK section 8.4).
 *
 * @param {unknown} port
 * @param {string} name
 * @returns {unknown}
 */
function callPortMethod(port, name) {
  const method = port[name];
  if (typeof method !== 'function') {
    throw new TypeError(`port method ${name} is not a function`);
  }
  return method.call(port);
}

/**
 * `base(n)` of C-DLV section 4.3: the backoff base of the attempt after
 * attempt `n`, `min(1000 * 2^(n-1), 30000)` milliseconds.
 *
 * `n` is the number of the attempt that just ended. The delivery layer calls
 * this only with the integer in `[1, maxAttempts]` it keeps itself, so any
 * other value is a misuse of this API, not a delivery outcome, and throws a
 * `TypeError`. Section 4.3 gives `attempts` no invalid value and no code.
 *
 * @param {number} n
 * @returns {number} base(n) in milliseconds
 */
export function backoffBaseMs(n) {
  if (!Number.isSafeInteger(n) || n < 1) {
    throw new TypeError('backoffBaseMs: attempt must be a positive safe integer');
  }
  return Math.min(BACKOFF_BASE_MS * 2 ** (n - 1), BACKOFF_CAP_MS);
}

/**
 * `delay(n, u)` of C-DLV section 4.3: the retry delay after the attempt
 * numbered `n`, from one injected draw `u`:
 *
 *   floor(base(n) / 2) + floor(u * base(n) / 2^33)  milliseconds
 *
 * The result lies in `[base(n) / 2, base(n))`. `u` is one
 * `random.nextUint32()` value in `[0, 2^32)`; a value outside that range is
 * an invalid random value and is reported by {@link planRetry} as
 * `E_SDK_INTERNAL`, so this function's domain is a valid draw and any other
 * value throws a `TypeError` rather than returning a number the schedule does
 * not define.
 *
 * @param {number} n the number of the attempt that just ended
 * @param {number} u one draw in [0, 2^32)
 * @returns {number} delay(n, u) in milliseconds
 */
export function retryDelayMs(n, u) {
  if (!Number.isSafeInteger(n) || n < 1) {
    throw new TypeError('retryDelayMs: attempt must be a positive safe integer');
  }
  if (!isValidDraw(u)) {
    throw new TypeError('retryDelayMs: draw must be an integer in [0, 2^32)');
  }
  const base = backoffBaseMs(n);
  return Math.floor(base / 2) + Math.floor((u * base) / JITTER_DIVISOR);
}

/**
 * The retry-or-fail decision of C-DLV section 4.3, taken after the attempt
 * numbered `attempts` has ended without an acceptance.
 *
 * `attempts` and `maxAttempts` are the delivery layer's own values: the
 * integer count of the attempt that just ended and the configured finite
 * bound of section 3 (`1..10`). `deadlineAt` is the item's deadline, the
 * clock reading of section 4.2 step 4 plus `deadlineMs`; C-SDK section 6.2
 * fixes its domain as a finite number, so a fractional deadline is lawful and
 * is not rejected. Those three are internal values with no invalid value in
 * the ratified text, so a misuse of them - including a `deadlineAt` that is
 * not a finite number - throws a `TypeError`; that is an API misuse signal,
 * not a delivery outcome, and no code is invented for it. The `deadlineAt`
 * check happens only where section 4.3 first uses the deadline, so an
 * exhausted item still fails with `lastCode: null` and without a draw.
 *
 * `clock` and `random` are the injected ports of C-SDK section 8.4, read
 * exactly where section 4.3 reads them and only there: `random.nextUint32()`
 * when a draw is needed and `clock.now()` for the deadline comparison. Each
 * read happens inside its own guarded path, so a port that is absent, a method
 * that is not a function, a getter that throws and a method that calls back a
 * throw are all `E_SDK_INTERNAL` (C-DLV section 4.5, C-SDK section 8.4); that
 * result is recorded for the item exactly as an internal fault is. Because no
 * port is read before the exhaustion decision, an exhausted item fails with
 * `lastCode: null` even when both ports are absent.
 *
 * The decision, in the order of section 4.3:
 *
 *   1. `attempts === maxAttempts`: the attempts are exhausted, so the item
 *      fails with `lastCode: null` and no random value is drawn;
 *   2. otherwise one draw `u` is taken and `delay(attempts, u)` computed;
 *   3. if `clock.now() + delay >= deadlineAt`, the item fails at once with
 *      `lastCode: null`;
 *   4. otherwise the item returns to `QUEUED` and the next attempt is armed
 *      on the clock port after `delayMs`.
 *
 * @param {{ attempts: number, maxAttempts: number, clock: { now: () => number },
 *           deadlineAt: number, random: { nextUint32: () => number } }} input
 * @returns {{ action: 'RETRY', delayMs: number } |
 *           { action: 'FAIL', lastCode: null | 'E_SDK_INTERNAL' }}
 */
export function planRetry({ attempts, maxAttempts, clock, deadlineAt, random }) {
  if (!Number.isSafeInteger(attempts) || attempts < 1) {
    throw new TypeError('planRetry: attempts must be a positive safe integer');
  }
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1) {
    throw new TypeError('planRetry: maxAttempts must be a positive safe integer');
  }
  if (attempts > maxAttempts) {
    throw new TypeError('planRetry: attempts must not exceed maxAttempts');
  }

  // (1) Exhaustion, decided first and exactly as section 4.3 states it: no
  // attempt remains, so the item fails with `lastCode: null` and without a
  // draw. No port is read on this path, so even an exhausted item whose ports
  // are absent, are not functions or throw when read fails as section 4.3
  // says instead of raising.
  if (attempts === maxAttempts) {
    return Object.freeze({ action: 'FAIL', lastCode: null });
  }

  // (2) One draw and the delay of section 4.3. The method is read here, inside
  // the guard: a missing, non-function or throwing `nextUint32` is an internal
  // fault of the item.
  let draw;
  try {
    draw = callPortMethod(random, 'nextUint32');
  } catch {
    return internalFault();
  }
  if (!isValidDraw(draw)) {
    return internalFault();
  }
  const delayMs = retryDelayMs(attempts, draw);

  // (3) The deadline comparison, on the injected clock. The method is read
  // inside this guard for the same reason as the draw above.
  let now;
  try {
    now = callPortMethod(clock, 'now');
  } catch {
    return internalFault();
  }
  if (!isValidClockValue(now)) {
    return internalFault();
  }

  // The deadline is a finite number (C-SDK section 6.2); a fractional value is
  // lawful, and anything else is a caller misuse.
  if (typeof deadlineAt !== 'number' || !Number.isFinite(deadlineAt)) {
    throw new TypeError('planRetry: deadlineAt must be a finite number');
  }

  if (now + delayMs >= deadlineAt) {
    return Object.freeze({ action: 'FAIL', lastCode: null });
  }

  // (4) The item returns to QUEUED and the next attempt is armed after delayMs.
  return Object.freeze({ action: 'RETRY', delayMs });
}
