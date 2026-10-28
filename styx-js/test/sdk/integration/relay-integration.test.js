import { describe, test, expect } from '@jest/globals';
import { rig, identity, waitFor, deferred, settle, sleep, eventId, assertNoForbiddenPublish, probe } from './loopback-harness.js';

async function send(h, m) {
  const result = await m.client.send({ recipient: identity().publicKey, payload: new Uint8Array([7, 9]) });
  expect(result.ok).toBe(true); await settle(); return result.value.deliveryId;
}
async function withRig(fn) { const h = rig(); try { await fn(h); } finally { await h.stop(); } }

describe('T-RELAY real two-relay integration', () => {
  test('hungRelay: a silent first relay cannot delay normal acceptance', async () => withRig(async (h) => {
    const silent = await h.addRelay({ mode: 'neverAnswering' }); const normal = await h.addRelay();
    const m = h.member({ delivery: { receiptMode: 'RELAY_ACCEPTANCE_ONLY' } });
    expect((await h.start(m)).value.connectedRelays).toBe(2); const id = await send(h, m);
    await waitFor(() => m.events.some((e) => e.state === 'RELAY_ACCEPTED'), 'normal acceptance');
    expect(h.manual.now).toBe(12000); expect(normal.published()).toHaveLength(1); expect(silent.published()).toHaveLength(1);
    expect((await h.snapshot(m, id)).relayOutcomes.map((x) => x.outcome)).toEqual(['PENDING', 'ACCEPTED']);
    await h.manual.to(24000);
    expect((await h.snapshot(m, id)).relayOutcomes.map((x) => x.outcome)).toEqual(['TIMED_OUT', 'ACCEPTED']);
    expect((await h.snapshot(m, id)).attempts).toBe(1); expect(m.draws).toEqual([]);
  }));

  test('clockAheadOfHost: late open excluded from successful start then usable', async () => withRig(async (h) => {
    const late = await h.addRelay({ holdUpgrade: true }); await h.addRelay({ mode: 'rejectAll' });
    const m = h.member({ delivery: { receiptMode: 'RELAY_ACCEPTANCE_ONLY' } });
    expect(await h.start(m, { held: [0] })).toEqual({ ok: true, value: { clientState: 'RUNNING', connectedRelays: 1 } });
    late.releaseUpgrade(); await waitFor(() => late.reqs().length === 1, 'late real open subscription');
    const id = await send(h, m); await waitFor(() => m.events.some((e) => e.state === 'RELAY_ACCEPTED'), 'late connection usable');
    expect((await h.snapshot(m, id)).relayOutcomes[0].outcome).toBe('ACCEPTED');
  }));

  test('clockAheadOfHost: late open disposed after failed start once settled', async () => withRig(async (h) => {
    const a = await h.addRelay({ holdUpgrade: true }); const b = await h.addRelay({ holdUpgrade: true });
    const m = h.member(); const starting = h.start(m, { held: [0, 1] });
    await waitFor(() => h.manual.now === 12000, 'injected connection phase expired');
    a.releaseUpgrade(); b.releaseUpgrade();
    expect(await starting).toEqual({ ok: false, code: 'E_SDK_NO_RELAY_AVAILABLE' });
    await waitFor(() => a.connections === 1 && b.connections === 1, 'both late opens');
    await waitFor(() => a.sockets.size === 0 && b.sockets.size === 0, 'failed-start sockets disposed');
    expect(h.manual.timers.size).toBe(0); expect(a.published()).toHaveLength(0); expect(b.published()).toHaveLength(0);
  }));

  test('stalledHandshake: real unanswered TCP upgrade beside normal relay times out independently', async () => withRig(async (h) => {
    await h.addRelay({ mode: 'stalledHandshake' }); await h.addRelay();
    const m = h.member({ delivery: { receiptMode: 'RELAY_ACCEPTANCE_ONLY' } });
    expect((await h.start(m, { held: [0] })).value.connectedRelays).toBe(1);
    const id = await send(h, m); await waitFor(() => m.events.some((e) => e.state === 'RELAY_ACCEPTED'), 'normal relay immediate send');
    await h.manual.to(24000);
    expect((await h.snapshot(m, id)).relayOutcomes.map((x) => x.outcome)).toEqual(['TIMED_OUT', 'ACCEPTED']);
  }), 20000);

  test.each(['acceptance', 'cancel'])('lateOpenAfterAcceptanceOrCancel: no forbidden publication after %s', async (end) => withRig(async (h) => {
    const late = await h.addRelay({ holdUpgrade: true }); await h.addRelay({ mode: end === 'cancel' ? 'neverAnswering' : 'normal' });
    const m = h.member({ delivery: { receiptMode: 'RELAY_ACCEPTANCE_ONLY' } }); await h.start(m, { held: [0] });
    const id = await send(h, m);
    if (end === 'cancel') expect((await m.client.cancel({ deliveryId: id })).ok).toBe(true);
    else await waitFor(() => m.events.some((e) => e.state === 'RELAY_ACCEPTED'), 'accepted before late open');
    late.releaseUpgrade(); await waitFor(() => late.reqs().length === 1, 'late open');
    await sleep(20); assertNoForbiddenPublish(late.published());
    expect((await h.snapshot(m, id)).state).toBe(end === 'cancel' ? 'CANCELLED' : 'RELAY_ACCEPTED');
  }));

  test('signingFailureFirstAttempt: no relay timeout after sign rejects', async () => withRig(async (h) => {
    await h.addRelay(); await h.addRelay(); const idPort = identity(); idPort.port.sign = () => { throw new Error('injected signing failure'); };
    const m = h.member({ identity: idPort }); await h.start(m); const id = await send(h, m);
    await waitFor(() => m.events.some((e) => e.state === 'FAILED_NOT_ACCEPTED'), 'sign failure terminal');
    const state = await h.snapshot(m, id); expect(state.lastCode).toBe('E_SDK_IDENTITY_FAILED');
    expect(state.relayOutcomes.map((x) => x.outcome)).toEqual(['PENDING', 'PENDING']);
    expect(h.relays.map((r) => r.published().length)).toEqual([0, 0]);
  }));

  test.each([-1, (Number.MAX_SAFE_INTEGER + 1) * 1000])('signingFailureFirstAttempt: invalid created_at clock %s', async (time) => withRig(async (h) => {
    await h.addRelay(); await h.addRelay();
    const m = h.member(); await h.start(m);
    await m.client.onEvent((event) => { if (event.state === 'IN_FLIGHT') h.manual.setNow(time); });
    const id = await send(h, m);
    await waitFor(() => m.events.some((e) => e.state === 'FAILED_NOT_ACCEPTED'), 'invalid clock terminal');
    const s = await h.snapshot(m, id); expect(s.lastCode).toBe('E_SDK_INTERNAL');
    expect(s.createdAt).toBe(12000); expect(s.attempts).toBe(1);
    expect(s.relayOutcomes.map((x) => x.outcome)).toEqual(['PENDING', 'PENDING']);
    h.manual.setNow(12000);
  }));

  test('cancelDuringRetryWait: in-progress successful cancel blocks due retry', async () => withRig(async (h) => {
    await h.addRelay({ mode: 'neverAnswering' }); await h.addRelay({ mode: 'neverAnswering' });
    const m = h.member({ randomValues: [0] }); await h.start(m); const id = await send(h, m);
    await waitFor(() => h.relays.every((r) => r.published().length === 1), 'attempt1');
    await h.manual.to(24000); expect((await h.snapshot(m, id)).state).toBe('QUEUED');
    const gate = deferred(); let held = false;
    m.storage.control.update = (key, record, apply) => {
      if (record.state !== 'CANCELLED') return apply();
      held = true; return gate.promise.then(apply);
    };
    const cancelled = m.client.cancel({ deliveryId: id });
    await waitFor(() => held, 'cancel write reached real storage port'); await h.manual.to(24500);
    expect(h.relays.map((r) => r.published().length)).toEqual([1, 1]);
    gate.resolve(); expect((await cancelled).ok).toBe(true);
    expect((await h.snapshot(m, id)).state).toBe('CANCELLED');
  }));

  test('shutdownDuringAttempt: call freezes outcomes even when attempt callbacks run', async () => withRig(async (h) => {
    await h.addRelay({ mode: 'neverAnswering' }); await h.addRelay({ mode: 'neverAnswering' });
    const m = h.member(); await h.start(m); const id = await send(h, m);
    await waitFor(() => h.relays.every((r) => r.published().length === 1), 'both EVENT');
    const callbacks = [...h.manual.timers.values()]; const stopped = m.client.shutdown();
    for (const t of callbacks) t.callback(); await stopped;
    const frozen = await h.snapshot(m, id); expect(frozen.state).toBe('LOST_ON_SHUTDOWN');
    expect(frozen.relayOutcomes.map((x) => x.outcome)).toEqual(['PENDING', 'PENDING']);
    await h.manual.to(24000); expect(await h.snapshot(m, id)).toEqual(frozen);
    expect(h.relays.map((r) => r.published().length)).toEqual([1, 1]);
  }));

  test('correct-id invalid signature reaches SDK and is rejected before session.open', async () => withRig(async (h) => {
    const a = await h.addRelay({ holdFrames: true }); await h.addRelay({ mode: 'neverAnswering' });
    const recipient = h.member(); await h.start(recipient); a.release();
    const sender = h.member({ delivery: { receiptMode: 'RELAY_ACCEPTANCE_ONLY' } }); await h.start(sender);
    const sent = await sender.client.send({ recipient: recipient.identity.publicKey, payload: new Uint8Array([91]) }); expect(sent.ok).toBe(true);
    await waitFor(() => a.queued.some((q) => q.frame[0] === 'EVENT' && q.frame[2].kind === 4741), 'held real outbound message');
    const q = a.queued.find((x) => x.frame[0] === 'EVENT' && x.frame[2].kind === 4741);
    const invalid = { ...q.frame[2], sig: '00'.repeat(64) }; expect(eventId(invalid)).toBe(invalid.id);
    a.sendRaw(q.socket, ['EVENT', q.frame[1], invalid]);
    await waitFor(() => recipient.events.some((e) => e.kind === 'INBOUND_DISCARDED'), 'signature discarded');
    expect(recipient.session.calls.filter((c) => c === 'open')).toHaveLength(0);
    a.release((frame) => frame[0] === 'EVENT');
    await waitFor(() => recipient.events.some((e) => e.kind === 'MESSAGE_RECEIVED'), 'valid original accepted');
    expect(recipient.session.calls.filter((c) => c === 'open')).toHaveLength(1);
  }));

  test('cancelDuringRetryWait: failed storage write releases the deferred real retry', async () => withRig(async (h) => {
    await h.addRelay({ mode: 'neverAnswering' }); await h.addRelay({ mode: 'neverAnswering' });
    const m = h.member({ randomValues: [0] }); await h.start(m); const id = await send(h, m);
    await waitFor(() => h.relays.every((r) => r.published().length === 1), 'first publication'); await h.manual.to(24000);
    const gate = deferred(); let entered = false;
    m.storage.control.update = (key, record, apply) => {
      if (record.state !== 'CANCELLED') return apply(); entered = true; return gate.promise.then(() => false);
    };
    const cancelling = m.client.cancel({ deliveryId: id }); await waitFor(() => entered, 'held cancel write');
    await h.manual.to(24500); expect(h.relays.map((r) => r.published().length)).toEqual([1, 1]);
    gate.resolve(); expect(await cancelling).toEqual({ ok: false, code: 'E_SDK_STORAGE_FAILED' });
    await waitFor(() => h.relays.every((r) => r.published().length === 2), 'deferred retry resumes after failure');
    expect((await h.snapshot(m, id)).attempts).toBe(2);
  }));

  test('lateCloseAfterReplacement: old real closing socket retained until replacement opens', async () => withRig(async (h) => {
    const a = await h.addRelay({ holdFrames: true }); await h.addRelay({ mode: 'neverAnswering' });
    const m = h.member({ randomValues: [0] }); await h.start(m); const id = await send(h, m);
    await waitFor(() => a.published().length === 1, 'publish before loss');
    const old = [...a.sockets][0]; old._socket.pause(); old.close();
    await sleep(20); await h.manual.to(13000); await h.manual.to(13500);
    await waitFor(() => a.connections === 2, 'real replacement opens while old server close is retained');
    expect(a.sockets.has(old)).toBe(true); expect(a.sockets.size).toBe(2);
    expect(a.published()).toHaveLength(1);
    expect((await h.snapshot(m, id)).relayOutcomes[0].outcome).toBe('UNREACHABLE');
    old._socket.resume(); await waitFor(() => !a.sockets.has(old), 'late old close released');
    expect((await m.client.shutdown()).ok).toBe(true);
    await waitFor(() => h.relays.every((r) => !r.sockets.size && !r.tcp.size), 'old and replacement both disposed');
  }));

  test('connectionFailsDuringAttempt: pending real upgrade aborts during publication', async () => withRig(async (h) => {
    const broken = await h.addRelay({ holdUpgrade: true }); await h.addRelay({ mode: 'neverAnswering' });
    const m = h.member({ randomValues: [0] }); await h.start(m, { held: [0] }); const id = await send(h, m);
    await waitFor(() => h.relays[1].published().length === 1, 'attempt already publishing');
    for (const socket of broken.tcp) socket.destroy();
    broken.setHoldUpgrade(false);
    await waitFor(() => broken.tcp.size === 0 && m.draws.length === 1, 'real upgrade error settled and replacement scheduled');
    await h.manual.to(24000);
    await waitFor(() => broken.connections === 1, 'replacement upgrade can settle before disposal');
    expect((await h.snapshot(m, id)).relayOutcomes[0].outcome).toBe('TIMED_OUT');
  }));

  test('harness controls: wrong-id rejected, correct-id bad signature relayed, conjunctive filters and CLOSE', async () => withRig(async (h) => {
    const a = await h.addRelay(); await h.addRelay(); const m = h.member(); await h.start(m); await send(h, m);
    await waitFor(() => a.published().length === 1, 'genuine signed SDK event'); const event = a.published()[0].frame[1];
    const control = await probe(a.url);
    try {
      const wrong = { ...event, id: 'f'.repeat(64) }; control.send(['EVENT', wrong]);
      await waitFor(() => control.frames.some((f) => f[0] === 'OK' && f[1] === wrong.id), 'wrong-id reply');
      expect(control.frames.find((f) => f[0] === 'OK' && f[1] === wrong.id)[2]).toBe(false); expect(a.events.has(wrong.id)).toBe(false);
      control.send(['EVENT', { ...event, sig: '00'.repeat(64) }]);
      await waitFor(() => control.frames.some((f) => f[0] === 'OK' && f[1] === event.id), 'id-only harness accepts bad signature');
      expect(control.frames.find((f) => f[0] === 'OK' && f[1] === event.id)[2]).toBe(true);
      const target = event.tags.find((t) => t[0] === 'p')[1];
      const correct = { ids: [event.id], kinds: [4741], '#p': [target] };
      for (const [index, bad] of [{ ids: [wrong.id] }, { kinds: [4742] }, { '#p': [identity().publicKey] }].entries()) {
        const sub = `bad-${index}`; control.send(['REQ', sub, { ...correct, ...bad }]);
        await waitFor(() => control.frames.some((f) => f[0] === 'EOSE' && f[1] === sub), 'filter EOSE barrier');
        expect(control.frames.filter((f) => f[0] === 'EVENT' && f[1] === sub)).toHaveLength(0);
        control.send(['CLOSE', sub]);
      }
      control.send(['REQ', 'match', correct]);
      await waitFor(() => control.frames.some((f) => f[0] === 'EOSE' && f[1] === 'match'), 'matching EOSE');
      expect(control.frames.filter((f) => f[0] === 'EVENT' && f[1] === 'match')).toHaveLength(1);
      control.send(['CLOSE', 'match']);
      await waitFor(() => [...a.subscriptions.values()].every((s) => !s.has('match') && ![...s.keys()].some((key) => key.startsWith('bad-'))), 'CLOSE removes real subscription');
    } finally { await control.close(); }
  }));

  test('harness modes: reject all EVENT and host delay every frame', async () => withRig(async (h) => {
    const rejected = await h.addRelay({ mode: 'rejectAll' }); const delayed = await h.addRelay({ delayMs: 20 });
    const m = h.member(); await h.start(m); const id = await send(h, m);
    await waitFor(() => m.events.some((e) => e.state === 'RELAY_ACCEPTED'), 'delayed normal acceptance');
    expect((await h.snapshot(m, id)).relayOutcomes.map((r) => r.outcome)).toEqual(['REJECTED', 'ACCEPTED']);
    expect(rejected.events.size).toBe(0); expect(delayed.events.size).toBe(1);
    const c = await probe(delayed.url); try {
      const at = Date.now(); c.send(['REQ', 'delay-proof', { ids: [] }]);
      await waitFor(() => c.frames.some((f) => f[0] === 'EOSE' && f[1] === 'delay-proof'), 'delayed EOSE');
      expect(Date.now() - at).toBeGreaterThanOrEqual(15);
    } finally { await c.close(); }
  }));

  test('harness dropAfterFrames counts EVENT, not REQ, and stores before closing without OK', async () => withRig(async (h) => {
    const dropped = await h.addRelay({ mode: 'dropAfterFrames', dropAfter: 1 }); await h.addRelay({ mode: 'neverAnswering' });
    const m = h.member({ randomValues: [0] }); await h.start(m); expect(dropped.reqs()).toHaveLength(1);
    const id = await send(h, m); await waitFor(() => dropped.sockets.size === 0, 'drop after EVENT');
    expect(dropped.published()).toHaveLength(1); expect(dropped.events.size).toBe(1);
    expect(dropped.history.filter((r) => r.type === 'out' && r.frame?.[0] === 'OK')).toHaveLength(0);
    await h.manual.to(13000); expect((await h.snapshot(m, id)).relayOutcomes[0].outcome).toBe('UNREACHABLE');
  }));
});
