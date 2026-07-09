// test/transport/broadcast-channel-transport.test.js
import { describe, test, expect, afterEach } from '@jest/globals';
import { BroadcastChannelTransport } from '../../src/transport/broadcast-channel-transport.js';

const tick = () => new Promise((r) => setTimeout(r, 10));
const open = [];
function make(pubkey, channel) {
  const t = new BroadcastChannelTransport(pubkey, { channelName: channel });
  open.push(t);
  return t;
}
afterEach(() => { open.splice(0).forEach((t) => t.close()); });

describe('BroadcastChannelTransport', () => {
  test('delivers a message addressed to a specific peer', async () => {
    const ch = 'styx-test-1';
    const alice = make('alice', ch);
    const bob = make('bob', ch);
    const received = [];
    bob.onMessage((from, bytes) => received.push({ from, text: new TextDecoder().decode(bytes) }));

    await alice.send('bob', new TextEncoder().encode('ciao'));
    await tick();

    expect(received).toEqual([{ from: 'alice', text: 'ciao' }]);
  });

  test('does not deliver to peers other than the addressee', async () => {
    const ch = 'styx-test-2';
    const alice = make('alice', ch);
    make('bob', ch);
    const carol = make('carol', ch);
    const carolGot = [];
    carol.onMessage((from, b) => carolGot.push(from));

    await alice.send('bob', new TextEncoder().encode('x'));
    await tick();

    expect(carolGot).toHaveLength(0);
  });

  test('does not echo a message back to the sender', async () => {
    const ch = 'styx-test-3';
    const alice = make('alice', ch);
    const aliceGot = [];
    alice.onMessage((from) => aliceGot.push(from));

    await alice.send('alice', new TextEncoder().encode('self'));
    await tick();

    expect(aliceGot).toHaveLength(0);
  });
});
