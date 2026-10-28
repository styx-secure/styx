import { describe, test, expect } from '@jest/globals';
import { rig, identity, waitFor, assertSixHandles, settle, sleep, assertWirePublication, assertDedupCounts, assertReceiptBoundary, assertAcceptanceDistinct, assertFrozen, assertItem, assertDeliveryTimeline } from './loopback-harness.js';

describe('T-RELAY O-SCEN3 real composed client', () => {
  test('lostAtShutdownThenNewClient / shutdownLostThenNewClient: six identities after LOST before STOPPED', async () => {
    const h = rig();
    try {
      await h.addRelay({ mode: 'neverAnswering' }); await h.addRelay({ mode: 'neverAnswering' });
      const m = h.member(); expect((await h.start(m)).value.connectedRelays).toBe(2);
      expect(h.manual.now).toBe(12000);
      const ids = []; const recipient = identity().publicKey;
      for (let i = 0; i < 2; i += 1) {
        const sent = await m.client.send({ recipient, payload: new Uint8Array([i + 1]) });
        expect(sent.ok).toBe(true); ids.push(sent.value.deliveryId);
      }
      await waitFor(() => h.relays.every((r) => r.published().length === 2), 'both publications');
      await h.manual.to(20000);
      const handles = [...h.manual.timers.keys()];
      expect(handles).toHaveLength(6);
      expect([...h.manual.timers.values()].map((t) => t.at).sort((a, b) => a - b)).toEqual([21000, 22000, 24000, 24000, 132000, 132000]);
      const baseline = h.relays.map((r) => r.reqs().length);
      const shutdown = m.client.shutdown();
      for (const handle of handles) h.manual.captured.get(handle).callback();
      const result = await shutdown; expect(result).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 2 } });
      assertSixHandles(h.trace, handles);
      await h.manual.to(20010);
      const frozen = await Promise.all(ids.map((id) => h.snapshot(m, id)));
      for (let i = 0; i < ids.length; i += 1) {
        assertItem(frozen[i], { id: ids[i], recipient, state: 'LOST_ON_SHUTDOWN', outcomes: ['PENDING', 'PENDING'] });
        assertDeliveryTimeline(h.trace, ids[i], [[12000, 'IN_FLIGHT'], [20000, 'LOST_ON_SHUTDOWN']]);
      }
      expect(frozen.map((s) => s.state)).toEqual(['LOST_ON_SHUTDOWN', 'LOST_ON_SHUTDOWN']);
      expect(frozen.map((s) => s.relayOutcomes.map((o) => o.outcome))).toEqual([['PENDING', 'PENDING'], ['PENDING', 'PENDING']]);
      await h.manual.to(20100);
      const fresh = h.member(); await h.listen(fresh); const freshStart = fresh.client.start();
      await waitFor(() => h.relays.every((r, i) => r.reqs().length === baseline[i] + 1), 'fresh independent subscriptions');
      for (const at of [22000, 24000]) {
        await h.manual.to(at);
        for (const handle of handles) h.manual.captured.get(handle).callback();
        expect(h.relays.map((r, i) => r.reqs().length - baseline[i])).toEqual([1, 1]);
        expect(await Promise.all(ids.map((id) => h.snapshot(m, id)))).toEqual(frozen);
        expect(handles.every((handle) => !h.manual.timers.has(handle))).toBe(true);
      }
      await h.manual.to(32100); expect((await freshStart).ok).toBe(true);
      expect(h.relays.map((r, i) => r.reqs().length - baseline[i])).toEqual([1, 1]);
      expect([...h.manual.timers.values()].some((t) => t.at === 42100)).toBe(true);
      await h.manual.to(32110);
      for (const id of ids) expect(await fresh.client.getDelivery({ deliveryId: id })).toEqual({ ok: false, code: 'E_SDK_UNKNOWN_DELIVERY' });
      await h.manual.to(36010); expect(await Promise.all(ids.map((id) => h.snapshot(m, id)))).toEqual(frozen);
      await h.manual.to(36020);
      expect(await m.client.send({ recipient: identity().publicKey, payload: new Uint8Array([9]) })).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
      expect(h.trace.filter((r) => r.type === 'event' && r.event.kind === 'DELIVERY_STATE_CHANGED' && r.at > 20000)).toEqual([]);
      await settle();
    } finally { await h.stop(); }
  });

  test('hungRelayAlongsideNormal: exact acceptance, timeout, shutdown timeline', async () => {
    const h = rig(); try {
      await h.addRelay({ mode: 'neverAnswering' }); const normal = await h.addRelay({ holdFrames: true });
      const m = h.member({ delivery: { receiptMode: 'RECIPIENT_RECEIPT' } }); await h.start(m);
      const recipient = identity().publicKey;
      const sent = await m.client.send({ recipient, payload: new Uint8Array([1]) });
      const id = sent.value.deliveryId;
      await waitFor(() => normal.queued.some((q) => q.frame[0] === 'OK'), 'normal OK held');
      await h.manual.to(12050); normal.release();
      await waitFor(() => m.events.some((e) => e.state === 'RELAY_ACCEPTED_AWAITING_RECEIPT'), 'receipt mode acceptance');
      expect((await h.snapshot(m, id)).relayOutcomes.map((r) => r.outcome)).toEqual(['PENDING', 'ACCEPTED']);
      await h.manual.to(24010);
      expect(await h.snapshot(m, id)).toMatchObject({
        state: 'RELAY_ACCEPTED_AWAITING_RECEIPT', terminal: false, attempts: 1, createdAt: 12000, deadlineAt: 132000, lastCode: null,
        relayOutcomes: [{ relayIndex: 0, outcome: 'TIMED_OUT' }, { relayIndex: 1, outcome: 'ACCEPTED' }] });
      await h.manual.to(24020); expect((await m.client.shutdown()).value.lost).toBe(1);
      expect(m.events.filter((e) => e.deliveryId === id).map((e) => e.state)).toEqual(['IN_FLIGHT', 'RELAY_ACCEPTED_AWAITING_RECEIPT', 'LOST_ON_SHUTDOWN']);
      await h.manual.to(24030); expect(await m.client.start()).toEqual({ ok: false, code: 'E_SDK_CLIENT_STOPPED' });
      assertItem(await h.snapshot(m, id), { id, recipient, state: 'LOST_ON_SHUTDOWN', outcomes: ['TIMED_OUT', 'ACCEPTED'] });
      assertDeliveryTimeline(h.trace, id, [[12000, 'IN_FLIGHT'], [12050, 'RELAY_ACCEPTED_AWAITING_RECEIPT'], [24020, 'LOST_ON_SHUTDOWN']]);
      expect(m.draws).toEqual([]);
    } finally { await h.stop(); }
  });

  test('twoHungRelaysExhaustion: five attempts, four exact draws, immutable late OK', async () => {
    const h = rig(); try {
      await h.addRelay({ mode: 'neverAnswering' }); await h.addRelay({ mode: 'neverAnswering' });
      const draws = [4294967295, 2147483648, 4294967295, 0]; const m = h.member({ randomValues: draws }); await h.start(m);
      const recipient = identity().publicKey;
      const sent = await m.client.send({ recipient, payload: new Uint8Array([2]) }); const id = sent.value.deliveryId;
      for (const [index, at] of [12000, 24999, 38499, 54498, 70498].entries()) {
        await h.manual.to(at); await waitFor(() => h.relays.every((r) => r.published().length === index + 1), `attempt ${index + 1}`);
        const s = await h.snapshot(m, id); expect(s.attempts).toBe(index + 1); expect(s.state).toBe('IN_FLIGHT');
        expect(s.relayOutcomes.map((r) => r.outcome)).toEqual(['PENDING', 'PENDING']);
        await h.manual.to(at + 12000);
        const ended = await h.snapshot(m, id);
        expect(ended.state).toBe(index === 4 ? 'FAILED_NOT_ACCEPTED' : 'QUEUED');
        expect(ended.relayOutcomes.map((r) => r.outcome)).toEqual(['TIMED_OUT', 'TIMED_OUT']);
      }
      await h.manual.to(82508); const frozen = await h.snapshot(m, id);
      expect(frozen).toMatchObject({ state: 'FAILED_NOT_ACCEPTED', terminal: true, attempts: 5, createdAt: 12000, deadlineAt: 132000, lastCode: null });
      expect(m.draws).toEqual(draws);
      for (const r of h.relays) {
        const e = r.published()[0].frame[1]; expect(r.published().every((p) => JSON.stringify(p.frame[1]) === JSON.stringify(e))).toBe(true);
        r.sendRaw([...r.sockets][0], ['OK', e.id, true, 'late']);
      }
      await settle();
      assertItem(frozen, { id, recipient, state: 'FAILED_NOT_ACCEPTED', attempts: 5, outcomes: ['TIMED_OUT', 'TIMED_OUT'] });
      assertDeliveryTimeline(h.trace, id, [[12000, 'IN_FLIGHT'], [24000, 'QUEUED'], [24999, 'IN_FLIGHT'], [36999, 'QUEUED'], [38499, 'IN_FLIGHT'], [50499, 'QUEUED'], [54498, 'IN_FLIGHT'], [66498, 'QUEUED'], [70498, 'IN_FLIGHT'], [82498, 'FAILED_NOT_ACCEPTED']]);
      await h.manual.to(82518); expect(await m.client.shutdown()).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
      await h.manual.to(132010); expect(await h.snapshot(m, id)).toEqual(frozen);
      expect(h.relays.map((r) => r.published().length)).toEqual([5, 5]);
    } finally { await h.stop(); }
  });

  test.each([
    ['receiptBeforeDeadline', 60000, 61000, 61100, 61105, 61200, 'RECIPIENT_RECEIPT_RECEIVED', 'timer-first'],
    ['receiptAfterDeadline', 133000, 134000, 134100, 134105, 135000, 'FAILED_NO_RECEIPT', 'timer-first'],
    ['receiptExactlyAtDeadline', 121000, 122000, 122100, 122105, 132000, 'FAILED_NO_RECEIPT', 'timer-first'],
    ['receiptExactlyAtDeadline', 121000, 122000, 122100, 122105, 132000, 'FAILED_NO_RECEIPT', 'frame-first'],
    ['receiptInLastAttempt timely', 60000, 61000, 61100, 61105, 61200, 'RECIPIENT_RECEIPT_RECEIVED', 'timer-first', 1],
    ['receiptInLastAttempt missing', 133000, 134000, 134100, 134105, 135000, 'FAILED_NO_RECEIPT', 'timer-first', 1],
  ])('%s / offlineRecipient (start=%s, opens=%s/%s, message=%s, receipt=%s, terminal=%s, order=%s)', async (name, startAt, open0, open1, messageAt, receiptAt, terminal, order, maxAttempts = 5) => {
    const h = rig(); try {
      const a = await h.addRelay({ holdFrames: true }); const b = await h.addRelay({ holdFrames: true });
      const recipientId = identity(); const sender = h.member({ delivery: { receiptMode: 'RECIPIENT_RECEIPT', maxAttempts } }); await h.start(sender);
      const sent = await sender.client.send({ recipient: recipientId.publicKey, payload: new Uint8Array([8]) }); const id = sent.value.deliveryId;
      await waitFor(() => h.relays.every((r) => r.queued.some((q) => q.frame[0] === 'OK')), 'both sender OK');
      await h.manual.to(12050); a.release((f) => f[0] === 'OK');
      await waitFor(() => sender.events.some((e) => e.state === 'RELAY_ACCEPTED_AWAITING_RECEIPT'), 'acceptance distinct from receipt');
      await h.manual.to(12060); b.release((f) => f[0] === 'OK');
      await waitFor(async () => (await h.snapshot(sender, id)).relayOutcomes.every((r) => r.outcome === 'ACCEPTED'), 'both real OK processed before advancing the injected clock');
      await waitFor(() => a.events.size === 1 && b.events.size === 1, 'message stored while recipient absent');
      expect(h.members).toHaveLength(1);
      assertAcceptanceDistinct(await h.snapshot(sender, id));
      h.relays.forEach((r, relayIndex) => assertWirePublication({ relayIndex, row: r.published()[0] }, r.published()[0].frame[1].id, relayIndex));
      await h.manual.to(startAt);
      // Hold the real upgrades of only the subsequently created recipient.
      a.setHoldUpgrade(true); b.setHoldUpgrade(true);
      const recipient = h.member({ identity: recipientId }); await h.listen(recipient); const starting = recipient.client.start();
      await waitFor(() => a.upgrades.length && b.upgrades.length, 'recipient held real upgrades');
      await h.manual.to(open0); a.releaseUpgrade();
      await waitFor(() => a.queued.some((q) => q.frame[0] === 'EVENT' && q.frame[2].kind === 4741), 'offline replay0');
      await h.manual.to(open1); b.releaseUpgrade();
      await waitFor(() => b.queued.some((q) => q.frame[0] === 'EVENT' && q.frame[2].kind === 4741), 'offline replay1');
      await h.manual.to(messageAt); a.release((f) => f[0] === 'EVENT' && f[2].kind === 4741);
      await waitFor(() => h.relays.every((r) => r.published().some((p) => p.frame[1].kind === 4742)), 'real recipient signed and published receipt');
      const secondAt = messageAt + 145;
      const secondCopy = async () => {
        await h.manual.to(secondAt); b.release((f) => f[0] === 'EVENT' && f[2].kind === 4741); await settle();
      };
      if (secondAt < receiptAt) await secondCopy();
      expect(recipient.session.calls.filter((c) => c === 'open')).toHaveLength(1);
      expect(recipient.events.filter((e) => e.kind === 'MESSAGE_RECEIVED')).toHaveLength(1);
      for (const r of h.relays) expect(r.published().filter((p) => p.frame[1].kind === 4742)).toHaveLength(1);
      const isReceipt = (f) => f[0] === 'EVENT' && f[2].kind === 4742;
      expect(h.relays.every((r) => !r.history.some((x) => x.type === 'out' && isReceipt(x.frame ?? [])))).toBe(true);
      if (order === 'frame-first') h.manual.setNow(receiptAt); else await h.manual.to(receiptAt);
      a.release(isReceipt);
      if (name !== 'receiptBeforeDeadline') b.release(isReceipt);
      await waitFor(() => sender.events.some((e) => e.state === terminal), 'receipt deadline terminal');
      if (order === 'frame-first') await h.manual.to(receiptAt);
      const frozen = await h.snapshot(sender, id);
      assertReceiptBoundary({ at: receiptAt, deadline: 132000, successful: frozen.state === 'RECIPIENT_RECEIPT_RECEIVED' });
      if (secondAt > receiptAt) await secondCopy();
      if (name === 'receiptBeforeDeadline') { await h.manual.to(61260); b.release(isReceipt); await sleep(2); }
      expect(frozen).toMatchObject({ state: terminal, terminal: true, attempts: 1, createdAt: 12000, deadlineAt: 132000, lastCode: null });
      await h.manual.to(startAt + 12000); expect((await starting).ok).toBe(true);
      const readAt = name === 'receiptBeforeDeadline' ? 72010 : name === 'receiptExactlyAtDeadline' ? 133010 : 146010;
      await h.manual.to(readAt);
      assertItem(await h.snapshot(sender, id), { id, recipient: recipientId.publicKey, state: terminal, outcomes: ['ACCEPTED', 'ACCEPTED'] });
      assertDeliveryTimeline(h.trace, id, [[12000, 'IN_FLIGHT'], [12050, 'RELAY_ACCEPTED_AWAITING_RECEIPT'], [terminal === 'RECIPIENT_RECEIPT_RECEIVED' ? receiptAt : 132000, terminal]]);
      expect(h.trace.filter((r) => r.type === 'event' && r.event.kind === 'MESSAGE_RECEIVED').map((r) => r.at)).toEqual([messageAt]);
      for (const r of h.relays) r.release(isReceipt);
      await h.manual.to(name === 'receiptBeforeDeadline' ? 72020 : readAt);
      expect(await sender.client.shutdown()).toEqual({ ok: true, value: { clientState: 'STOPPED', lost: 0 } });
      await h.manual.to(Math.max(146010, h.manual.now)); await settle();
      assertFrozen(await h.snapshot(sender, id), frozen);
      expect(sender.events.filter((e) => e.deliveryId === id && e.terminal)).toHaveLength(1);
      expect(sender.draws).toEqual([]);
    } finally { await h.stop(); }
  });

  test.each(['relayLossAndReplacement', 'outboundDuplicateAccepted'])('%s: real loss, replacement, no same-attempt republish', async (name) => {
    const h = rig(); try {
      const delayed = await h.addRelay({ holdFrames: true });
      const dropped = await h.addRelay({ holdFrames: true });
      // Preserve scenario relay ordering for the duplicate-acceptance variant.
      if (name === 'outboundDuplicateAccepted') h.relays.reverse();
      const m = h.member({ randomValues: [0, 4294967295] }); await h.start(m);
      const recipient = identity().publicKey;
      const sent = await m.client.send({ recipient, payload: new Uint8Array([3]) }); const id = sent.value.deliveryId;
      await waitFor(() => h.relays.every((r) => r.published().length === 1), 'attempt1 stored on both');
      if (name === 'outboundDuplicateAccepted') delayed.setMode('neverAnswering');
      await h.manual.to(12050); [...dropped.sockets][0].close();
      await waitFor(() => dropped.sockets.size === 0, 'real old connection closed');
      dropped.queued.splice(0); dropped.setMode(name === 'relayLossAndReplacement' ? 'neverAnswering' : 'normal');
      await h.manual.to(13000);
      expect((await h.snapshot(m, id)).relayOutcomes[name === 'outboundDuplicateAccepted' ? 0 : 1].outcome).toBe('UNREACHABLE');
      await h.manual.to(13500); await waitFor(() => dropped.connections === 2 && dropped.reqs().length === 2, 'replacement opened');
      expect(dropped.published()).toHaveLength(1);
      await h.manual.to(24000); expect((await h.snapshot(m, id)).state).toBe('QUEUED');
      await h.manual.to(24999); await waitFor(() => h.relays.every((r) => r.published().length === 2), 'attempt2 publishes');
      expect(dropped.published()[1].connection).not.toBe(dropped.published()[0].connection);
      expect(dropped.published()[1].frame).toEqual(dropped.published()[0].frame);
      await h.manual.to(name === 'relayLossAndReplacement' ? 32000 : 25099);
      let released = false; const accepted = name === 'relayLossAndReplacement' ? delayed : dropped;
      accepted.release((f) => { if (f[0] !== 'OK' || released) return false; released = true; return true; });
      await waitFor(() => m.events.some((e) => e.state === 'RELAY_ACCEPTED'), 'late or duplicate OK accepts current attempt');
      if (name === 'outboundDuplicateAccepted') expect(accepted.history.filter((r) => r.type === 'out' && r.frame?.[0] === 'OK')[0].frame[3]).toMatch(/^duplicate:/);
      await h.manual.to(36999); const frozen = await h.snapshot(m, id);
      expect(frozen).toMatchObject({ state: 'RELAY_ACCEPTED', terminal: true, attempts: 2, createdAt: 12000, deadlineAt: 132000, lastCode: null });
      expect(frozen.relayOutcomes.map((r) => r.outcome)).toEqual(['ACCEPTED', 'TIMED_OUT']);
      assertItem(frozen, { id, recipient, state: 'RELAY_ACCEPTED', attempts: 2, outcomes: ['ACCEPTED', 'TIMED_OUT'] });
      assertDeliveryTimeline(h.trace, id, [[12000, 'IN_FLIGHT'], [24000, 'QUEUED'], [24999, 'IN_FLIGHT'], [name === 'relayLossAndReplacement' ? 32000 : 25099, 'RELAY_ACCEPTED']]);
      expect(m.draws).toEqual([0, 4294967295]);
      const socket = [...accepted.sockets][0]; const event = accepted.published()[0].frame[1];
      accepted.sendRaw(socket, ['OK', event.id, true, 'duplicate: again']); await settle();
      expect(await h.snapshot(m, id)).toEqual(frozen);
      expect(m.events.filter((e) => e.state === 'RELAY_ACCEPTED')).toHaveLength(1);
      await h.manual.to(37009); expect((await m.client.shutdown()).value.lost).toBe(0);
    } finally { await h.stop(); }
  });

  test('inboundDuplicateReordered: reversed replay, cross-relay copies, one open/message/receipt per id', async () => {
    const h = rig(); try {
      const a = await h.addRelay({ holdFrames: true }); const b = await h.addRelay({ holdFrames: true, duplicate: true, reverse: true });
      const receiverId = identity(); const sender = h.member({ delivery: { receiptMode: 'RECIPIENT_RECEIPT' } }); await h.start(sender);
      const ids = [];
      for (const byte of [1, 2]) {
        const result = await sender.client.send({ recipient: receiverId.publicKey, payload: new Uint8Array([byte]) }); ids.push(result.value.deliveryId);
      }
      await waitFor(() => h.relays.every((r) => r.published().length === 2), 'two distinct messages stored');
      const events = a.published().map((p) => p.frame[1]); expect(events[0].id).not.toBe(events[1].id);
      await h.manual.to(12050); a.release((f) => f[0] === 'OK'); await sleep(2);
      await h.manual.to(12060); b.release((f) => f[0] === 'OK'); await sleep(2);
      await h.manual.to(20000); a.setHoldUpgrade(true); b.setHoldUpgrade(true);
      const recipient = h.member({ identity: receiverId }); await h.listen(recipient); const starting = recipient.client.start();
      await waitFor(() => a.upgrades.length && b.upgrades.length, 'recipient held real upgrades');
      await h.manual.to(21000); b.releaseUpgrade(); await waitFor(() => b.queued.filter((q) => q.frame[0] === 'EVENT').length === 4, 'reverse duplicate replay');
      expect(b.queued.filter((q) => q.frame[0] === 'EVENT').map((q) => q.frame[2].id)).toEqual([events[1].id, events[1].id, events[0].id, events[0].id]);
      await h.manual.to(21100); a.releaseUpgrade(); await waitFor(() => a.queued.filter((q) => q.frame[0] === 'EVENT').length === 2, 'normal replay');
      const one = (r, predicate) => { let used = false; r.release((f) => { if (used || !predicate(f)) return false; used = true; return true; }); expect(used).toBe(true); };
      for (const [i, at] of [21105, 21115, 21125, 21135].entries()) {
        await h.manual.to(at); one(b, (f) => f[0] === 'EVENT' && f[2].kind === 4741);
        await waitFor(() => recipient.events.filter((e) => e.kind === 'MESSAGE_RECEIVED').length === (i < 2 ? 1 : 2), 'ordered inbound processing');
      }
      await waitFor(() => h.relays.every((r) => r.published().filter((p) => p.frame[1].kind === 4742).length === 2), 'two actual receipts per relay');
      const receipt = (original) => (f) => f[0] === 'EVENT' && f[2].kind === 4742 && f[2].tags.some((t) => t[0] === 'e' && t[1] === original.id);
      for (const [at, original] of [[21200, events[1]], [21210, events[1]], [21220, events[0]], [21230, events[0]]]) {
        await h.manual.to(at); one(b, receipt(original)); await sleep(2);
        if (at === 21200) {
          await h.manual.to(21205); a.release((f) => f[0] === 'EVENT' && f[2].kind === 4741); await sleep(2);
        }
      }
      await h.manual.to(21305); a.release((f) => f[0] === 'EVENT' && f[2].kind === 4742);
      await waitFor(() => sender.events.filter((e) => e.state === 'RECIPIENT_RECEIPT_RECEIVED').length === 2, 'both receipts accepted');
      expect(recipient.session.calls.filter((c) => c === 'open')).toHaveLength(2);
      expect(recipient.events.filter((e) => e.kind === 'MESSAGE_RECEIVED').map((e) => [...e.payload])).toEqual([[2], [1]]);
      assertDedupCounts({ opens: recipient.session.calls.filter((c) => c === 'open').length,
        messages: recipient.events.filter((e) => e.kind === 'MESSAGE_RECEIVED').length,
        receipts: recipient.identity.calls.filter((c) => c === 'sign').length, unique: 2 });
      expect(sender.events.filter((e) => e.terminal).map((e) => e.deliveryId)).toEqual([ids[1], ids[0]]);
      await h.manual.to(32000); expect((await starting).ok).toBe(true);
      await h.manual.to(32010);
      for (let i = 0; i < ids.length; i += 1) {
        assertItem(await h.snapshot(sender, ids[i]), { id: ids[i], recipient: receiverId.publicKey, state: 'RECIPIENT_RECEIPT_RECEIVED', outcomes: ['ACCEPTED', 'ACCEPTED'] });
        assertDeliveryTimeline(h.trace, ids[i], [[12000, 'IN_FLIGHT'], [12050, 'RELAY_ACCEPTED_AWAITING_RECEIPT'], [i === 0 ? 21220 : 21200, 'RECIPIENT_RECEIPT_RECEIVED']]);
      }
      expect(recipient.events.filter((e) => e.kind === 'INBOUND_DISCARDED')).toEqual([]);
      for (const id of ids) expect(await recipient.client.getDelivery({ deliveryId: id })).toEqual({ ok: false, code: 'E_SDK_UNKNOWN_DELIVERY' });
      expect((await Promise.all(ids.map((id) => h.snapshot(sender, id)))).map((s) => s.state)).toEqual(['RECIPIENT_RECEIPT_RECEIVED', 'RECIPIENT_RECEIPT_RECEIVED']);
    } finally { await h.stop(); }
  });

  test('nonEmptyStoreRefused: two real stopped records, zero new connections and no catch-up timer', async () => {
    const h = rig(); try {
      await h.addRelay({ mode: 'neverAnswering' }); await h.addRelay({ mode: 'neverAnswering' });
      const old = h.member(); await h.start(old); const recipient = identity().publicKey;
      for (const byte of [4, 5]) expect((await old.client.send({ recipient, payload: new Uint8Array([byte]) })).ok).toBe(true);
      await waitFor(() => h.relays.every((r) => r.published().length === 2), 'both old items published');
      expect((await old.client.shutdown()).value.lost).toBe(2); expect(old.storage.records.size).toBe(2);
      const connections = h.relays.map((r) => r.connections); h.manual.setNow(0);
      const refused = h.member({ storage: old.storage }); await h.listen(refused);
      const starting = refused.client.start(); await h.manual.to(5); await h.manual.to(10);
      expect(await starting).toEqual({ ok: false, code: 'E_SDK_STORAGE_NOT_EMPTY' });
      expect(h.relays.map((r) => r.connections)).toEqual(connections); expect(h.manual.timers.size).toBe(0);
      expect(refused.events).toEqual([]);
    } finally { await h.stop(); }
  });
});
