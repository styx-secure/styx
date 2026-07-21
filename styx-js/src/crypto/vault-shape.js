// vault-shape.js — the single strict-shape gate for untrusted vault format
// objects (Blocco 3, PR-2; review F6). Pure module, zero dependencies.
//
// Object.keys() sees only ENUMERABLE STRING properties, so a hostile object
// could smuggle Symbol keys, non-enumerable extras, or — worst — define a
// REQUIRED field as a non-enumerable accessor that gets invoked (with side
// effects or untyped exceptions) when validation reads it. This helper closes
// that class: it enumerates Reflect.ownKeys, accepts exclusively enumerable
// plain DATA properties from a closed allowlist, and returns a snapshot built
// from the property descriptors — accessors are rejected WITHOUT ever being
// invoked, and callers never re-read the original object.

/**
 * Validate the shape of an untrusted object and snapshot it.
 *
 * Rules (all fail-closed via `invalid`, the caller's typed-error factory):
 * - plain object only: not null/array, prototype Object.prototype or null;
 * - every own key (Reflect.ownKeys): a string, inside `allowedKeys`, backed
 *   by an ENUMERABLE DATA descriptor (`value` present, no `get`/`set`);
 * - Symbol properties rejected outright;
 * - every `allowedKeys` entry required (missing → invalid).
 *
 * @param {unknown} raw untrusted input
 * @param {readonly string[]} allowedKeys closed field list (all required
 *   unless `requiredKeys` narrows it)
 * @param {(message: string, details?: object) => Error} invalid factory for
 *   the caller's typed error (VAULT_WRAPPER_INVALID / VAULT_RECORD_INVALID)
 * @param {{requiredKeys?: readonly string[]}} [options] pass
 *   `{requiredKeys: []}` for all-optional shapes (e.g. error details, review
 *   W6) — the allowlist and descriptor discipline stay identical
 * @returns {object} fresh plain object with the values extracted from the
 *   descriptors — the caller must validate and use ONLY this snapshot
 */
export function snapshotStrictPlainObject(raw, allowedKeys, invalid, { requiredKeys = allowedKeys } = {}) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw invalid('value must be a plain object');
  }
  const proto = Object.getPrototypeOf(raw);
  if (proto !== Object.prototype && proto !== null) {
    throw invalid('value must not carry a custom prototype');
  }
  const snapshot = {};
  for (const key of Reflect.ownKeys(raw)) {
    if (typeof key !== 'string') {
      throw invalid('symbol properties are not allowed');
    }
    if (!allowedKeys.includes(key)) {
      // slice: attacker-chosen names must fit the closed error-details shape
      throw invalid('unknown field', { field: key.slice(0, 64) });
    }
    const desc = Object.getOwnPropertyDescriptor(raw, key);
    // Descriptor-based: an accessor is rejected WITHOUT invoking it.
    if (desc === undefined || !Object.hasOwn(desc, 'value') || desc.get !== undefined || desc.set !== undefined) {
      throw invalid('fields must be plain data properties', { field: key });
    }
    if (desc.enumerable !== true) {
      throw invalid('fields must be enumerable', { field: key });
    }
    snapshot[key] = desc.value;
  }
  for (const key of requiredKeys) {
    if (!Object.hasOwn(snapshot, key)) throw invalid('missing field', { field: key });
  }
  return snapshot;
}
