// Flegias preview (synthetic data only)
import { SDK_INTERFACE_VERSION, createStyxClient, SdkEventKind, DeliveryState } from '../../src/sdk/index.js';
import { utf8Encode, bytesToHex } from '../../src/utils.js';
function create({ relays, ports, wait, onMessage = () => {} }) {
  const faults = []; const events = []; const results = [];
  const value = r => { results.push(r); if (r.ok !== true) throw new Error('reporter SDK result not ok'); return r.value; };
  const client = value(createStyxClient({ interfaceVersion: SDK_INTERFACE_VERSION, relays, ports }));
  const listening = client.onEvent(event => {
    try {
      events.push(event);
      if (!Object.values(SdkEventKind).includes(event.kind)) throw new Error('unknown reporter event');
      if (event.kind === SdkEventKind.DELIVERY_STATE_CHANGED && !Object.values(DeliveryState).includes(event.state)) throw new Error('unknown reporter delivery state');
      if (event.kind === SdkEventKind.INBOUND_DISCARDED) throw new Error('reporter discarded inbound');
      if (event.kind === SdkEventKind.MESSAGE_RECEIVED) onMessage(event);
    } catch (error) { faults.push(error); }
  }).then(value);
  return {
    client, events, results, faults,
    start: async () => { await listening; return value(await client.start()); },
    send: async (recipient,payload) => {
      const id = value(await client.send({ recipient,payload })).deliveryId;
      return wait(async () => {
        if (faults.length) throw faults[0];
        const d = value(await client.getDelivery({ deliveryId: id }));
        if (!Object.values(DeliveryState).includes(d.state)) throw new Error('unknown outbound state');
        if (d.terminal && d.state !== DeliveryState.RELAY_ACCEPTED) throw new Error('outbound terminal failure');
        return d.state === DeliveryState.RELAY_ACCEPTED && d;
      });
    },
    shutdown: async () => value(await client.shutdown())
  };
}
export function runCaseReporter({ relays, ports, handler, caseNumber, wait }) {
  const expected = utf8Encode(`Flegias preview (synthetic data only): synthetic reply to case ${caseNumber}.`);
  let replies = 0;
  const run = create({ relays, ports, wait, onMessage: event => {
    if (event.sender !== handler || event.payload.length !== expected.length || !event.payload.every((v,i) => v === expected[i])) throw new Error('unexpected case reply');
    replies++;
  }});
  return { ...run, open: () => run.send(handler,utf8Encode(`Flegias preview (synthetic data only): synthetic case ${caseNumber} opening text.`)),
    receive: () => wait(() => { if (run.faults.length) throw run.faults[0]; return replies > 0; }), get replies() { return replies; } };
}
export function runOutsideReporter({ relays, ports, bystander, token, caseNumber, wait }) {
  const run = create({ relays, ports, wait, onMessage: () => { throw new Error('unexpected outside inbound'); } });
  return { ...run, publish: () => run.send(bystander,utf8Encode(`Flegias preview (synthetic data only): synthetic outside message ${caseNumber} ${bytesToHex(token)}`)) };
}
