// Flegias preview (synthetic data only)
import { SDK_INTERFACE_VERSION, createStyxClient, SdkEventKind, DeliveryState } from '../../src/sdk/index.js';
import { utf8Encode } from '../../src/utils.js';
// The caller registers the returned client before awaiting any operation.
export function runHandler({ relays, ports, recorder, caseNumber, sender, wait }) {
  const faults = []; const events = []; const results = []; let sends = 0;
  let replyId; let received = false;
  const result = (r) => { recorder('result', r); results.push(r); if (r.ok !== true) throw new Error('handler SDK result not ok'); return r.value; };
  const client = result(createStyxClient({ interfaceVersion: SDK_INTERFACE_VERSION, relays, ports }));
  // Client objects contain methods; capture the creation envelope without cloning its value.
  const opening = utf8Encode(`Flegias preview (synthetic data only): synthetic case ${caseNumber} opening text.`);
  const reply = utf8Encode(`Flegias preview (synthetic data only): synthetic reply to case ${caseNumber}.`);
  const listening = client.onEvent(async (event) => {
    try {
      recorder('event', { ...event, ...(event.payload instanceof Uint8Array ? { payload: event.payload.slice() } : {}) }); events.push(event);
      if (!Object.values(SdkEventKind).includes(event.kind)) throw new Error('unknown handler event');
      if (event.kind === SdkEventKind.DELIVERY_STATE_CHANGED && !Object.values(DeliveryState).includes(event.state)) throw new Error('unknown delivery state');
      if (event.kind === SdkEventKind.INBOUND_DISCARDED) throw new Error('handler discarded inbound');
      if (event.kind !== SdkEventKind.MESSAGE_RECEIVED) return;
      if (event.sender !== sender || !equal(event.payload,opening)) throw new Error('unexpected handler message');
      if (received) return;
      received = true; sends++;
      replyId = result(await client.send({ recipient: event.sender, payload: reply })).deliveryId;
    } catch (error) { faults.push(error); }
  }).then(result);
  return {
    client, faults, events, results, get sends() { return sends; }, get replyId() { return replyId; },
    start: async () => { await listening; return result(await client.start()); },
    completed: async () => wait(async () => {
      if (faults.length) throw faults[0];
      if (!replyId) return false;
      const d = result(await client.getDelivery({ deliveryId: replyId }));
      if (!Object.values(DeliveryState).includes(d.state)) throw new Error('unknown reply state');
      if (d.terminal && d.state !== DeliveryState.RELAY_ACCEPTED) throw new Error('reply terminal failure');
      return d.state === DeliveryState.RELAY_ACCEPTED && d;
    }),
    shutdown: async () => result(await client.shutdown())
  };
}
function equal(a,b) { return a.length === b.length && a.every((v,i) => v === b[i]); }
