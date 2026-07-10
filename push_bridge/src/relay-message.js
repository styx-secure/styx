// relay-message.js — pure decision over one raw relay frame: is this a new,
// stored (kind 1059) event addressed to a pubkey we watch? Returns the recipient
// and event id to notify, or null. Kept side-effect-free (except marking `seen`)
// so it is trivially unit-testable without any sockets.
const STORED_KIND = 1059; // messages + invites (welcomes); ephemeral 20000 is never notified

/**
 * @param {any} data raw relay message array, e.g. ['EVENT', subId, event]
 * @param {Set<string>} seen event ids already processed (mutated: the id is added)
 * @param {Set<string>} watched pubkeys we have registrations for
 * @returns {{pubkey:string, eventId:string}|null}
 */
export function handleRelayMessage(data, seen, watched) {
  if (!Array.isArray(data) || data[0] !== 'EVENT') return null;
  const ev = data[2];
  if (!ev || ev.kind !== STORED_KIND || !ev.id) return null;
  if (seen.has(ev.id)) return null;
  const recipient = (ev.tags || []).find((t) => t[0] === 'p' && watched.has(t[1]));
  if (!recipient) return null;
  seen.add(ev.id);
  if (seen.size > 5000) seen.clear(); // bound memory on a long-running bridge
  return { pubkey: recipient[1], eventId: ev.id };
}
