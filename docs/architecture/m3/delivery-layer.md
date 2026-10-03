# M3 early-lane delivery-layer contract

Status: normative candidate for card `C-DLV` of the M3 early lane. It is experimental and versioned with the SDK, and it makes no stability promise to third parties. Dependent implementation stays blocked until the owner hash-ratifies the SHA-256 of this exact file and every other `beforeImplementation` gate of the M3 scope record is met.

## 1. Scope and boundaries

This document fixes the delivery layer behind the public SDK interface: outbound queue states and their timing, retransmission and backoff bounds, receipts and acknowledgements, duplicate handling, parallel multi-relay publish and subscribe with per-relay timeouts, per-relay outcome reporting, the process-lifetime limit, the SDK-internal non-normative on-wire structures, and the requirements for the loopback relay test harness that card `T-RELAY` builds. **MUST**, **MUST NOT** and **REJECT** are normative.

It is authorized by the owner act in Issue #400 §2(b) and implements card `C-DLV` of the M3 scope record (#400 comment `5950987413`). It sits behind the ratified public SDK interface `docs/architecture/m3/sdk-interface.md` (card `C-SDK`, SHA-256 `47f75d6cd0bd3d542fd699f99144da6ccd9d6965908e5d1f4b2c1dfd976a9a11`, ratified in #400 comment `5960945402` and merged into `m3/integration`). That document is called "the interface" below, and its section numbers are cited as "interface §n".

This document fixes the values and rules that the interface assigns to `C-DLV` (its record field `ownedByCDlv`), plus internal delivery parameters that serve them (the inbound pending bound and the relay supervision interval, internal implementation limits that change no public bound, no guarantee and no item of `cDlvMayNotChange`), and nothing that the interface reserves to itself (`cDlvMayNotChange`). It does not add, remove or rename any entry point, configuration field, method, result code, delivery state, transition, per-relay outcome, public SDK event kind or field, port method, outer bound or allowed import of the interface (its record field `cDlvMayNotChange`). Where this document and the interface could be read differently, the interface wins, and the difference is a defect of this document.

It is not protocol authority. It selects no Styx protocol semantic, no Marmot or Nostr envelope standard, and no normative wire or persisted format. It introduces no cryptographic construction: it uses only SHA-256 digests and BIP-340 Schnorr signatures over Nostr event ids, the construction that the existing transport code already uses to sign Nostr events. It obtains every signature from the injected identity port and verifies signatures only on inbound structures, with `schnorr.verify` as interface §9 allows.

## 2. Outer bounds

The outer bounds of #400 §2(b), restated in interface §2, bind every rule below:

1. Every outbound item has a finite attempt count (`maxAttempts`, at most 10) and a finite deadline (`deadlineMs`, at most 600 000 ms). When either is exhausted without the item's success state, the item reaches a terminal failed state. There is no unbounded retransmission.
2. No exactly-once, ordering or cross-restart guarantee. The duplicate suppression of §8 is a bounded, best-effort, per-process measure and is not an exactly-once claim.
3. Relay acceptance (`RELAY_ACCEPTED`, `RELAY_ACCEPTED_AWAITING_RECEIPT`, per-relay `ACCEPTED`) and recipient receipt (`RECIPIENT_RECEIPT_RECEIVED`) are distinct. A valid receipt establishes only that a structure signed with the recipient identity's key acknowledged this message's event id (§7.3). A conforming recipient SDK sends a receipt only after it opened the message and emitted `MESSAGE_RECEIVED` (§7.2), but the sender cannot verify that. Neither relay acceptance nor a receipt proves that a person read the message.
4. Process lifetime only. Every queue, timer, window and record of this document lives in the memory of one client in one process. On an explicit, orderly `shutdown()` every non-terminal item is reported as `LOST_ON_SHUTDOWN`. After a crash or abrupt termination nothing is reported and nothing is recovered; no claim is made for that case.
5. No normative wire format. The structures of §6 are SDK-internal, experimental and versioned with the interface version string. They are not a Styx protocol semantic and not a Nostr standard.
6. Relay URLs reach the delivery layer only from `config.relays`. No module contains a relay URL literal, a default relay list or a fallback relay. In this interface version every configured relay host is a loopback IP literal (interface §4.1).

## 3. Parameters, bounds and defaults

Every value below is a positive safe integer. A configured value outside its bounds REJECTs at `createStyxClient` with `E_SDK_INVALID_CONFIG` (interface §4.1). An absent `delivery` field takes its default.

| Parameter | Minimum | Maximum | Default | Notes |
| --- | --- | --- | --- | --- |
| `maxAttempts` | 1 | 10 | 5 | Publication attempts per item (§4.3). |
| `deadlineMs` | 30 000 | 600 000 | 120 000 | From the admission clock reading (§4.4). The minimum equals the maximum of `perRelayTimeoutMs`, so no combination of in-bound values needs a cross-field rule. |
| `perRelayTimeoutMs` | 11 000 | 30 000 | 12 000 | Per relay, per attempt (§5.3); also the `start()` connection-phase bound, and at least twice the port-call timeout. The minimum exceeds `RelayPool`'s fixed 10 000 ms host-timer connection timeout, so the host-time bound of §5.2 on waiting for connection attempts never exceeds one per-relay timeout of host time. |

`receiptMode` defaults to `RELAY_ACCEPTANCE_ONLY`, the mode that claims less.

Fixed values (not configurable in this version):

| Value | Fixed at | Meaning |
| --- | --- | --- |
| Port-call timeout | `floor(perRelayTimeoutMs / 2)` of the client's effective value (5 500 ms to 15 000 ms; 6 000 ms by default) | Enforced with the host `setTimeout`, never with the clock port (interface §8). Two sequential port calls together never exceed `perRelayTimeoutMs`, which never exceeds `deadlineMs` (§4.4). |
| Payload maximum | 65 536 bytes | `send` with a larger `payload` returns `E_SDK_PAYLOAD_TOO_LARGE`. |
| Queue bound | 256 non-terminal items per client | A `send` that would exceed it returns `E_SDK_QUEUE_FULL`. |
| Terminal processing slack | 1 000 ms | §4.4. |
| Backoff base | 1 000 ms | §4.3. |
| Backoff cap | 30 000 ms | §4.3. |
| Inbound duplicate window | 4 096 event ids per client | §8. |
| Inbound pending bound | 1 024 frames per client | §7.1. |
| Relay supervision interval | 1 000 ms | §5.2. |
| Reconnect interval | the backoff schedule of §4.3, by consecutive failures of that relay, capped at 30 000 ms | §5.2. |

The SDK does not inspect the size of a ciphertext or a plaintext that the session port returns (interface §8.2). Relays may refuse large events; such a refusal is an ordinary relay outcome (§5.3).

## 4. Outbound queue

### 4.1 Queue states

The delivery layer has no internal queue state of its own. Each internal queue state is exactly one state of the interface's closed `DeliveryState` enumeration (interface §6.1), and every transition below is one of the interface's allowed transitions:

| Interface state | Queue meaning in this layer |
| --- | --- |
| `QUEUED` | Item stored; waiting for its first attempt or for a scheduled retry. |
| `IN_FLIGHT` | One attempt in progress (§4.3): building or signing the event (first attempt only), or waiting for per-relay outcomes. |
| `RELAY_ACCEPTED_AWAITING_RECEIPT` | `RECIPIENT_RECEIPT` mode, at least one relay acknowledged; waiting for a valid receipt (§7.3). No further publication. |
| `RELAY_ACCEPTED` | `RELAY_ACCEPTANCE_ONLY` mode, at least one relay acknowledged. Terminal success. |
| `RECIPIENT_RECEIPT_RECEIVED` | Valid receipt accepted (§7.3). Terminal success. |
| `FAILED_NOT_ACCEPTED` | Terminal: attempts exhausted, next attempt would start at or after the deadline, deadline reached, or a fault, all before any acceptance was recorded for the item. After this state is recorded, `OK` frames for the item are ignored and the only remaining relay-outcome change is `PENDING` → `TIMED_OUT` at the attempt timeout (§5.3), so no relay becomes `ACCEPTED` after the item failed. |
| `FAILED_NO_RECEIPT` | Terminal: acceptance recorded in `RECIPIENT_RECEIPT` mode, then the deadline was reached without a valid receipt, or a fault occurred. |
| `CANCELLED` | Terminal: `cancel` (§4.6). |
| `LOST_ON_SHUTDOWN` | Terminal: non-terminal at an orderly `shutdown()`. |

### 4.2 Admission (`send`)

`send` runs, in this order, and stops at the first failure with the interface code shown; no item exists after a failure (interface §5.2):

1. argument validation (`E_SDK_INVALID_ARGUMENT`, `E_SDK_PAYLOAD_TOO_LARGE`);
2. queue bound (`E_SDK_QUEUE_FULL`), counting non-terminal items and admissions still in progress, so concurrent `send` calls cannot exceed it;
3. `session.seal({ recipient, plaintext })`, bounded by the port-call timeout; a return other than `{ ciphertext }` with a non-empty `Uint8Array` is a malformed value (`E_SDK_SESSION_FAILED`, subject to §4.5);
4. reading the clock: `createdAt = clock.now()` and `deadlineAt = createdAt + deadlineMs`; an invalid clock value is `E_SDK_INTERNAL` (interface §8.4). In the same synchronous step the SDK arms the item's deadline timer on the clock port (`deadlineMs`) and its host `setTimeout` backstop (`deadlineMs + 1000`) of §4.4;
5. `storage.put(record)` with the record of §6.4, bounded by the port-call timeout (`E_SDK_STORAGE_FAILED`). If `put` fails after it may have written, the SDK calls `remove` once. If that removal also fails, `send` resolves `E_SDK_STORAGE_FAILED` and the residual-item rule of interface §5.2 applies: the SDK records the item in its in-memory view directly as `FAILED_NOT_ACCEPTED` with `lastCode: 'E_SDK_STORAGE_FAILED'`, emits that one terminal `DELIVERY_STATE_CHANGED` event, and never publishes it. On every failure at step 5 the timers of step 4 are cleared.

If `shutdown()` is called before step 5 has issued `put`, `send` stops at its next step boundary (after the port call in progress settles or times out), releases its queue reservation, creates no item and resolves `E_SDK_CLIENT_STOPPED`. Once `put` has been issued, `send` completes step 5.

`deliveryId` is the string `d` followed by the decimal value of a per-client counter that starts at 1 and increases by one for every admission that reaches step 5. It is opaque, never reused within the client, never derived from the payload, the recipient or a caller value, and never appears on the wire.

On success the item is `QUEUED` with `attempts = 0` and every per-relay outcome `PENDING`, and `send` resolves `{ deliveryId, state: 'QUEUED' }`. Admission itself is not a transition and emits no event. If `shutdown()` was called while `put` was in progress, the item takes `QUEUED` → `LOST_ON_SHUTDOWN` at once (§4.6); this takes precedence over the deadline. It applies only to an item that `put` admitted: if `put` fails and the one `remove` also fails, the residual-item rule of interface §5.2 (step 5 above) takes precedence over `shutdown()`, and that item is reported only as `FAILED_NOT_ACCEPTED` with `lastCode: 'E_SDK_STORAGE_FAILED'`. Otherwise, if either deadline timer fired while `put` was in progress, the item takes `QUEUED` → `FAILED_NOT_ACCEPTED` at once with `lastCode: null` (one event). Otherwise the first attempt is scheduled with `queueMicrotask`, not with the clock port, so it starts without waiting for an injected timer.

### 4.3 Attempts, retransmission and backoff

- An attempt starts by moving the item `QUEUED` → `IN_FLIGHT` and incrementing `attempts`. `attempts` never exceeds `maxAttempts`.
- On the first attempt only, the SDK builds the outbound message event of §6.2 and obtains its signature from `identity.sign({ digest })`, bounded by the port-call timeout. A return other than a 64-byte `Uint8Array` is a malformed value and moves the item to `FAILED_NOT_ACCEPTED` with `lastCode: 'E_SDK_IDENTITY_FAILED'` (subject to §4.5). The SDK does not verify its own outbound signature (interface §8.3 and §9 allow `schnorr.verify` for inbound structures only); a signature that relays refuse yields `REJECTED` outcomes. The signed event is kept with the item. Every retransmission republishes exactly these bytes, so retransmissions carry the same event id and never call `seal` or `sign` again.
- The attempt timeout is armed when the attempt starts publishing: on the first attempt, after `identity.sign` has returned a valid signature; on later attempts, when the attempt starts. No attempt timeout runs while the signing call is in progress, so no attempt can time out or be retried before its event is signed, whatever the clock port does; the signing call is bounded on host time by the port-call timeout (interface §8), and the deadline (§4.4) keeps running. If the deadline, `cancel` or `shutdown()` makes the item terminal while signing is in progress, the signing continuation does nothing further (§4.5) and its signature is discarded. If signing fails, the item becomes terminal as above: no relay was published to and no attempt timeout was armed, so no relay outcome of that attempt is set and none becomes `TIMED_OUT`; every entry keeps `PENDING`, the value every entry has from admission until a relay outcome is set, and here means only that the event was never published.
- The attempt publishes the signed event in parallel to every configured relay (§5.3). Its publication phase ends at the first of: one relay reports `ACCEPTED`; every relay has a non-`PENDING` outcome for this attempt; the attempt timeout of `perRelayTimeoutMs`, armed when publishing starts, has elapsed, measured on the clock port with a host `setTimeout` backstop of the same delay (every relay still `PENDING` becomes `TIMED_OUT`). Without an acceptance, the attempt ends with its publication phase. An acceptance never clears the attempt timeout: the relays still `PENDING` keep settling and become `TIMED_OUT` when it elapses (§5.3), in every mode.
- If the publication phase ended with an acceptance, the item moves to `RELAY_ACCEPTED` (mode `RELAY_ACCEPTANCE_ONLY`) or `RELAY_ACCEPTED_AWAITING_RECEIPT` (mode `RECIPIENT_RECEIPT`). No retransmission ever happens after an acceptance is recorded: the accepting attempt is the item's last, whatever the value of `attempts`, and no further attempt can start.
- In `RECIPIENT_RECEIPT` mode an attempt that records an acceptance is the item's last attempt, and it does not end at the acceptance: its publication phase ends there (the item moves `IN_FLIGHT` → `RELAY_ACCEPTED_AWAITING_RECEIPT` and nothing is published again), and the attempt itself ends only at a valid receipt (`RECIPIENT_RECEIPT_RECEIVED`), at the deadline (`FAILED_NO_RECEIPT`, §4.4), at a fault (`FAILED_NO_RECEIPT`, §4.5), at `cancel` or at `shutdown()`. The attempt sequence therefore ends when that accepted attempt ends, whatever the number of attempts left under `maxAttempts` (interface §6.1 defines `FAILED_NO_RECEIPT` as the terminal state for no valid receipt by the deadline or an unrecoverable fault after acknowledgement), and every way it ends without the success state is a terminal failed state, as interface §2.1 requires: there is no moment at which the attempts are exhausted and the item is neither successful nor terminal. With `maxAttempts` 1, the single attempt either ends without acceptance (`FAILED_NOT_ACCEPTED`) or is accepted and ends at the receipt, the deadline, a fault, `cancel` or `shutdown()`. This matches interface §6.1, which defines `FAILED_NO_RECEIPT` as "no valid recipient receipt arrived by the deadline, or an unrecoverable fault after acknowledgement" and `FAILED_NOT_ACCEPTED` as exhaustion "before any relay acknowledgement", and adds that an item that reached `RELAY_ACCEPTED_AWAITING_RECEIPT` never later reports `FAILED_NOT_ACCEPTED`. In `RELAY_ACCEPTANCE_ONLY` mode the acceptance is the success state and ends the attempt.
- Otherwise, with `n = attempts` (the number of the attempt that just ended), the retry delay is computed by the pure function

  `base(n) = min(1000 × 2^(n−1), 30000)` ms and `delay(n, u) = floor(base(n) / 2) + floor(u × base(n) / 2^33)`,

  where `u` is one `random.nextUint32()` value in `[0, 2^32)`. So `delay(n)` lies in `[base(n)/2, base(n))`: 500–999 ms after attempt 1, 1 000–1 999 ms after attempt 2, 2 000–3 999 ms after attempt 3, 4 000–7 999 ms after attempt 4, 8 000–15 999 ms after attempt 5, and 15 000–29 999 ms after attempts 6 to 9. An invalid random value is `E_SDK_INTERNAL` and moves the item to `FAILED_NOT_ACCEPTED`.
- If `attempts = maxAttempts`, the item moves at once to `FAILED_NOT_ACCEPTED` with `lastCode: null`, without drawing a random value. Otherwise the SDK draws `u`, computes `delay`, and if `clock.now() + delay ≥ deadlineAt` the item moves at once to `FAILED_NOT_ACCEPTED` with `lastCode: null`; else it moves `IN_FLIGHT` → `QUEUED` and the next attempt is armed on the clock port after `delay`.
- Worked example with the defaults (`maxAttempts` 5, `perRelayTimeoutMs` 12 000, `deadlineMs` 120 000) and two relays that never answer, when the clock port's timers fire at their scheduled delays: each attempt publishes for 12 000 ms, and the four retry delays are at most 999 + 1 999 + 3 999 + 7 999 = 14 996 ms, so the fifth attempt ends no later than 5 × 12 000 + 14 996 = 74 996 ms after the first attempt starts publishing. Signing before the first publication adds at most 6 000 ms, and admission before it (`seal` and `put`, each at most 6 000 ms) at most 12 000 ms, so the item is `FAILED_NOT_ACCEPTED` no later than 92 996 ms after `send` is called, well before its 120 000 ms deadline. Retry delays use only the clock port (§4.5); when its timers do not fire, the unconditional bound is the deadline backstop of §4.4: the item is terminal no later than `deadlineMs` + 1 000 ms (121 000 ms by default) of host time after the admission clock reading.

### 4.4 Deadline

At `deadlineAt` (measured on the clock port), a non-terminal item moves to `FAILED_NOT_ACCEPTED` from `QUEUED` or `IN_FLIGHT`, or to `FAILED_NO_RECEIPT` from `RELAY_ACCEPTED_AWAITING_RECEIPT`, with `lastCode: null`. An attempt in progress at the deadline is abandoned; later relay frames for it never change the item's state (§5.3).

As interface §6.1 requires, the SDK also arms a host `setTimeout` of `deadlineMs + 1000` ms (the terminal processing slack) in the same synchronous step as the clock reading that sets `createdAt` (§4.2 step 4). The backstop applies the same deadline transition; whichever of the two fires first acts, and the other is cleared. The admission steps after that reading are `put` and, only after a failed `put`, one `remove`; each is bounded by the port-call timeout, so together they take at most `perRelayTimeoutMs` ≤ `deadlineMs` of host time, and a residual item of interface §5.2 is also reported before the backstop. Every item therefore reaches a terminal state no later than `deadlineMs + 1000` ms of host time after that clock reading, even if the clock port's timers never fire.

Deadline check before success. Immediately before it records a transition into `RELAY_ACCEPTED`, `RELAY_ACCEPTED_AWAITING_RECEIPT` or `RECIPIENT_RECEIPT_RECEIVED`, or starts an attempt, the SDK reads `clock.now()`. At or after `deadlineAt` it applies the deadline transition above instead, so no success state and no attempt is ever recorded at or after the deadline.

### 4.5 Timers, faults and unknown values

- Retry delays, the deadline, the attempt timeout, the `start()` connection phase and relay supervision are armed with `clock.setTimer` and cleared with `clock.clearTimer`. The deadline (§4.4), the attempt timeout (§4.3) and the `start()` connection phase (§5.2) also have a host `setTimeout` backstop; whichever fires first acts, and the other is cleared. Port-call timeouts use only the host `setTimeout`.
- A storage write that fails during background processing (§6.4) does not undo the transition just recorded. If the item is still non-terminal, it moves at once to its applicable terminal failed state with `lastCode: 'E_SDK_STORAGE_FAILED'`: `FAILED_NOT_ACCEPTED` from `QUEUED` or `IN_FLIGHT`, `FAILED_NO_RECEIPT` from `RELAY_ACCEPTED_AWAITING_RECEIPT`. A failed write of a terminal state changes nothing. An `update` that returns `false` (interface §8.1: the record is absent) is a failed write under this rule. A `remove` that undoes a failed admission succeeds when it returns `true` or `false` (interface §8.1: `false` means the record is absent, so the absence the cleanup needs holds): the method keeps its original failure result, and no residual item and no event exist. Only a `remove` that fails, throws, times out or returns a malformed value leaves a possible residual item, which follows the residual-item rule of interface §5.2 (§4.2).
- An internal fault, or a clock or random value that is invalid, moves a non-terminal item to its applicable terminal failed state (same mapping) with `lastCode: 'E_SDK_INTERNAL'`.
- Unknown values follow interface §5.3 exactly and take precedence over any other code. A code, state or outcome name outside the closed sets of the interface that a lane module of §9 yields, or that a port return carries in a `code`, `state` or `outcome` property, is `E_SDK_UNKNOWN_CODE`: in a method result it is `{ ok: false, code: 'E_SDK_UNKNOWN_CODE' }`, a non-terminal item moves to its applicable terminal failed state with `lastCode: 'E_SDK_UNKNOWN_CODE'`, and during inbound processing it emits `INBOUND_DISCARDED` with `E_SDK_UNKNOWN_CODE`. Any other port return that is not the exact success shape of interface §8 is a malformed value of that port. Values from relays are not lane-module values; a relay frame that is malformed or unexpected is ignored as §5.3, §5.4 and §7.1 specify, which can only lead to `TIMED_OUT`, never to acceptance.
- `lastCode` is `null` for exhaustion, deadline, `CANCELLED` and `LOST_ON_SHUTDOWN`, and otherwise one of `E_SDK_STORAGE_FAILED`, `E_SDK_IDENTITY_FAILED`, `E_SDK_INTERNAL` or `E_SDK_UNKNOWN_CODE`. A success state always has `lastCode: null`.

### 4.6 Retention, continuations, cancel and shutdown

- The SDK's in-memory view of its items is authoritative for snapshots, events and decisions; the storage port mirrors it (§6.4) and is not read back while the client runs. `getDelivery` reads only the in-memory view.
- Every item, terminal ones included, is retained for the client's lifetime, so `getDelivery` returns every item's final state, also in `STOPPED` (interface §4.2). When an item becomes terminal, the SDK drops its ciphertext and signed event from memory.
- **Continuations.** After `shutdown()` has been called, no asynchronous step starts new delivery work: it records no transition other than those of `shutdown()` itself, publishes nothing and calls no further port except the `put` completion and `remove` of a `send` already past step 4 (§4.2) and the bounded cleanup of §4.6 and §5.5. Before that, each kind of step checks its own condition when it resumes:
  - a deadline callback (clock or host) acts if its item is still non-terminal, whatever attempts happened since it was armed;
  - an attempt-timeout callback acts on the relay outcomes of its attempt as §5.3 states, whatever the item's state; an `OK` frame acts on them except once the item is `FAILED_NOT_ACCEPTED`, `CANCELLED` or `LOST_ON_SHUTDOWN` (§5.3); either changes the item's state only while the item is `IN_FLIGHT` in that same attempt;
  - a port-call continuation of an attempt (`sign`), a retry timer and the first-attempt microtask act only if the item is still in the state and attempt they started from; otherwise they do nothing further;
  - a `send` or `cancel` continuation follows §4.2 and the `cancel` rule below.
  A terminal item never starts an attempt, publishes or calls a port again, except the write of its own terminal record.
- **`cancel`.** An unknown id returns `E_SDK_UNKNOWN_DELIVERY`; a terminal item returns `E_SDK_DELIVERY_TERMINAL` unchanged. Otherwise the SDK calls `storage.update` with the item's record in state `CANCELLED`, bounded by the port-call timeout. From the call on, no new attempt of the item starts (interface §4.2: `cancel` stops further attempts); a retry that falls due while the write is in progress waits for it. The attempt in progress, its relay outcomes, its acceptance and the deadline continue meanwhile. If the write fails, the failed `cancel` changes nothing: the item keeps whatever state the attempt in progress, the deadline or `shutdown()` gave it, and a retry that fell due meanwhile starts at once, unless the deadline rule of §4.3 applies. If the write succeeds and the item is still non-terminal, the SDK records `CANCELLED` (allowed from every non-terminal state), emits the event and resolves success. If the item became terminal meanwhile, `cancel` resolves `E_SDK_DELIVERY_TERMINAL` and the SDK writes the item's actual terminal record (a failure is ignored), except after `shutdown()` was called: then the `LOST_ON_SHUTDOWN` write of §4.6 step (4) is the item's only further write. If the write fails, `cancel` resolves `E_SDK_STORAGE_FAILED` and the item is unchanged (interface §5.2); the stored record may then differ from the in-memory view, which is never read back. A `cancel` for an item whose cancel write is still in progress resolves with that write's result. A `cancel` still in progress when `shutdown()` is called resolves `E_SDK_CLIENT_STOPPED` once its write has settled, whatever that write returned, and records nothing; the `LOST_ON_SHUTDOWN` write of step (4) is the item's only further write. Relay frames that arrive after cancellation never change the item's state (§5.3). A copy already handed to a relay is not recalled.
- **`shutdown()`** follows interface §4.2 in this order: (1) synchronously at the call, the client stops admitting calls: for call admission it behaves as `STOPPED` from the call on, so every state-changing method called before `shutdown()` resolves returns `E_SDK_CLIENT_STOPPED`, while `getDelivery` and `onEvent` stay allowed as interface §4.2 allows them in `STOPPED` (interface §4.2 does not define calls made while `shutdown()` is in progress; this document fixes the fail-closed `STOPPED` behaviour for them, and `CLIENT_STATE_CHANGED` with `STOPPED` is emitted in step (5)), the inbound frame queue of §7.1 is dropped so no queued frame is parsed or opened afterwards, no new attempt, retry, reconnection or receipt starts, relay frames received afterwards are ignored, and every admitted non-terminal item takes the transition to `LOST_ON_SHUTDOWN` with `lastCode: null` in the in-memory view, so no item's terminal state waits for the steps below; in the same synchronous step every relay outcome is frozen at its current value, and every delivery timer callback that runs afterwards (attempt timeout and its host backstop, retry, deadline and its host backstop, relay supervision, reconnection) does nothing, so the item states and relay outcomes cannot change in the steps below; the port-call timeouts and the `start()` connection-phase timer with its host backstop stay active until the calls they bound have settled, so every port call and every `start()` in progress still settles within its bound and `shutdown()` always reaches its cleanup; the timer handles themselves are cleared in step (4), after the events of step (3), in the order interface §4.2 gives; (2) it waits until every `start()` and `send` call already in progress has resolved. A `start()` in progress stops at its next step boundary (after the port call in progress settles or times out), starts no further port call or connection, closes what it opened as a failed `start()` does (§5.5) and resolves `E_SDK_CLIENT_STOPPED`. A `send` in progress follows §4.2: before `put` it resolves `E_SDK_CLIENT_STOPPED` with no item; after `put` was issued it completes `put` (and, after a failed `put`, the one `remove`), and an item it admits resolves success as §4.2 states and takes `QUEUED` → `LOST_ON_SHUTDOWN` at once; (3) it delivers the `LOST_ON_SHUTDOWN` events to the listeners registered before the call; (4) it waits until every port call still in progress has settled or timed out, issues the storage writes of the `LOST_ON_SHUTDOWN` records in parallel (failures ignored, each bounded by the port-call timeout), clears every clock and host timer it armed, and closes every relay connection as §5.5 specifies; (5) it emits `CLIENT_STATE_CHANGED` with `STOPPED`, removes every listener registered before the call, releases its ports, transports and timers, keeps an immutable terminal snapshot of each item, and resolves `{ clientState: 'STOPPED', lost }`, where `lost` counts the items of steps (1) and (2). Storage, listener and internal faults never prevent these effects.

## 5. Parallel multi-relay publish and subscribe

### 5.1 One `RelayPool` per relay, replaced after loss

The delivery layer uses `RelayPool` from `styx-js/src/transport/nostr-transport.js`, unchanged, as interface §9 allows, and no other transport export. At any time it holds **at most one current `RelayPool` per configured relay**, each constructed with a one-element URL list (a relay has no current pool between the retirement of its pool and the preparation of the next one, §5.2), so that every publication, subscription, timeout and outcome is per relay and no relay's state can delay another's.

A relay's pool is never reconnected. After its connection is lost or its connection attempt fails, it is retired and replaced by a new pool (§5.2). `RelayPool` handles the close of a socket by deleting that URL's entry from its own connection map; replacing the pool confines a late close of an old socket to the retired pool, so it cannot remove a newer socket from the map that `dispose()` closes.

Each pool is prepared, before it connects, in this order: the SDK calls its `disconnectAll()`, which on a pool with no connection only clears the pool's own automatic-reconnect flag, so the pool never schedules a reconnection timer of its own; it calls `subscribe(subscriptionId, filter)` (§5.4), which `RelayPool` stores and sends when the connection opens; and it attaches one listener to the pool's `messages` emitter. The SDK never calls `reconnect()`, `addRelay()`, `removeRelay()` or `publishAndVerify()`, and never reads or writes a property whose name starts with `_`.

### 5.2 Connection, supervision and reconnection

- `start()` runs in this order: `storage.list()`, whose result is checked in this order: a value that is not an array is a malformed value (`E_SDK_STORAGE_FAILED`); then, before any shape check, an element that is a plain object and has a value outside a closed set of the interface in any closed slot it carries (its `state`, interface §6.1; its `receiptMode`, interface §4.1; its `lastCode`, which is `null` or a result code of interface §5.2; or the `outcome` of any `relayOutcomes` entry, interface §6.3) is `E_SDK_UNKNOWN_CODE` (interface §5.3), whatever its other fields; then an element that is not a plain object with exactly the field names of the record of §6.4 is a malformed value (`E_SDK_STORAGE_FAILED`); these checks run before the emptiness rule; any other non-empty array is `E_SDK_STORAGE_NOT_EMPTY`; only an empty array lets `start()` continue; `identity.getPublicKey()` (anything other than a lowercase 64-hex string is `E_SDK_IDENTITY_FAILED`), cached for the client's lifetime; preparing one pool per relay (§5.1); the connection phase. Each port call is bounded by the port-call timeout.
- The connection phase calls `connectAll()` on every pool in parallel. A pool's connection attempt is in progress until its `connectAll()` promise settles; in the existing code it resolves with the number of relays connected and does not reject, and the SDK treats a resolution with `0` or a rejection alike as a failed connection of that relay, handled as below. The phase ends `perRelayTimeoutMs` after it begins, measured on the clock port with a host `setTimeout` backstop of the same delay; interface §4.2 requires it to end no later than that, and this document fixes the end at that bound, also when every attempt has settled earlier, so that `connectedRelays` is always counted at the same point. A pool counts as connected when its `healthCheck()` reports the relay connected. The phase end and `RelayPool`'s own timeout run on different clocks: the phase ends on the clock port (or its host backstop), which interface §8.4 lets advance independently of host time, while `RelayPool` settles each connection attempt with its own fixed 10 000 ms host timer. So a connection attempt can still be in progress when the phase ends, and the SDK keeps tracking it until its `connectAll()` promise settles (at most 10 000 ms of host time after it began, whatever the clock port does). Such a late connection never joins the completed phase: it does not count in `connectedRelays` and does not change the result of `start()`. If `start()` succeeded, the pool stays the relay's current pool; when its attempt settles connected, the relay is connected from then on and the supervision rules below apply; when it settles without a connection, the relay takes the replacement path below. If `start()` fails, the pool is disposed when its attempt has settled, as the next item states.
- `start()` succeeds when at least one pool is connected at the end of the phase, and on success it emits `CLIENT_STATE_CHANGED` with `RUNNING` and resolves at that moment, so `connectedRelays` is the number connected when it resolves (interface §4.2), counted at the phase end. If none is, `start()` returns `E_SDK_NO_RELAY_AVAILABLE`. The connection phase ends at `perRelayTimeoutMs` on the clock port, with its host backstop (interface §4.2); that bound is unaffected by the cleanup below. The cleanup that interface §4.2 requires before a failed `start()` resolves has its own host-time bound: before any failed `start()` resolves, it waits until every connection attempt it began has settled, because `RelayPool` exposes a socket only once it opens and the SDK cannot close a socket that is still connecting (`dispose()` would miss it, and it could open afterwards). `RelayPool` settles each attempt with its own fixed 10 000 ms host timer, and the attempts begin when the phase begins, so this wait ends no later than 10 000 ms of host time after the phase began, which is less than one per-relay timeout of host time (§3), whatever the clock port does. A failed `start()` therefore never waits longer than one per-relay timeout of host time on a relay that hangs (interface §4.2). It then calls `dispose()` on every pool, clears every timer and discards the cached public key, so no connection, subscription, timer or cached key survives and a later `start()` begins from scratch.
- While the client is `RUNNING`, the SDK reads every current pool's `healthCheck()` every relay supervision interval (1 000 ms, on the clock port) and whenever `publish` returns `0`. A pool that is not connected and has no connection attempt in progress is retired at once with `dispose()`. After the relay's k-th consecutive failed or lost connection, its new pool is prepared (§5.1) and connected with `connectAll()` after `delay(k, u)` of §4.3 (500 ms to 29 999 ms). If `random.nextUint32()` returns an invalid value here, that is `E_SDK_INTERNAL` for this reconnection delay (interface §8.4), but no item and no method result depends on it, so the code has no surface: no item changes state, the SDK uses the largest delay of that step, `base(k) − 1` ms, for this reconnection try, and draws again for the next one. A successful connection resets k. Connection tries are not outbound items and have no attempt count; they stop at `shutdown()`. Reconnection is best effort and makes no claim when the clock port's timers do not fire.

### 5.3 Publish and per-relay outcomes

- For each attempt and each relay, the SDK sets that relay's outcome to `PENDING`, unless it is already `ACCEPTED` for this item, and calls `publish(event)` on that relay's current pool, if it has one. `publish` returns `0` when the pool has no open connection; a relay with no current pool is handled as if `publish` had returned `0`, without a call. Then:
  - the relay stays `PENDING`, whatever the reason (a stalled WebSocket handshake, a refused connection, a lost connection waiting for its replacement, or a connection attempt that settled before `start()` ended). `RelayPool` reports a refused connection and its own 10 000 ms timeout of a stalled handshake alike, as a resolution of `connectAll()` with `0`, so the SDK cannot tell a hung relay from an unreachable one before publication and treats both as hanging;
  - if a connection to that relay opens before the attempt timeout, the relay is still `PENDING` in this attempt, the client is still `RUNNING`, the item is still `IN_FLIGHT` in this same attempt and its deadline has not passed, the SDK calls `publish(event)` on it once and the outcome follows the rules below; otherwise it publishes nothing on it;
  - a relay still `PENDING` at the attempt timeout becomes `TIMED_OUT`, as for any relay that hangs (interface §6.3).
- `UNREACHABLE` is set only for a relay on which `publish` returned `1` in this attempt and whose connection was then lost (its pool's `healthCheck()` no longer reports it connected, read at the next relay supervision interval or `publish` of §5.2) before any matching `OK` frame. A relay that keeps its connection open and never answers is `TIMED_OUT`, never `UNREACHABLE`. A relay that is `UNREACHABLE` in an attempt stays so for that attempt, and the SDK does not publish on its replacement connection until the next attempt, which publishes the same event again.
- Otherwise the relay's outcome is set by the first matching NIP-01 `OK` frame from that relay's current pool: `["OK", <event id>, true, <string>]` sets `ACCEPTED` (a message starting `duplicate:` counts, since the relay holds the same event); `["OK", <event id>, false, <string>]` sets `REJECTED`. A frame matches when its event id is the item's event id and that relay is `PENDING` in the item's latest attempt; any other `OK` frame is ignored. Because every attempt publishes the identical event, an `OK` frame cannot be attributed to a particular attempt: an answer to an earlier attempt that arrives while the relay is `PENDING` in a later attempt counts for the later attempt, which is sound because it concerns the same event. This includes a late `OK false`: `REJECTED` in a later attempt means that the relay refused these exact bytes at least once, not necessarily in that attempt; it never produces an acceptance, and the item can still be accepted by another relay or a later attempt. At the attempt timeout, every relay still `PENDING` in that attempt becomes `TIMED_OUT`.
- Every relay's outcome settles at its own answer or at the attempt timeout, whichever comes first. A relay that hangs, never answers or accepts the socket but never responds is `TIMED_OUT` at the attempt timeout and never delays the outcome of any other relay, the acceptance of the item, or any other item.
- `ACCEPTED` is sticky for an item: once a relay accepted it, later attempts do not reset or republish to that relay, but no later attempt can happen anyway (§4.3).
- `relayOutcomes` in a snapshot holds, per configured relay in `config.relays` order, the outcome of the latest attempt for that relay. Every entry is `PENDING` at admission. The entries of an attempt keep settling by the rules above until its attempt timeout fires; once the item is `FAILED_NOT_ACCEPTED` or `CANCELLED`, `OK` frames for it are ignored and the only remaining change is `PENDING` → `TIMED_OUT` at the attempt timeout, so such an item never shows a relay `ACCEPTED` that it did not record before its terminal state (interface §6.1 defines `FAILED_NOT_ACCEPTED` as reached before any relay acknowledgement); in the other terminal states except `LOST_ON_SHUTDOWN` (a success state or `FAILED_NO_RECEIPT`) an acceptance was already recorded, and `OK` frames keep settling the other relays' entries until the attempt timeout, so a hung relay is always reported as `TIMED_OUT` after its per-relay timeout (interface §6.3); then they stay unchanged. Each `getDelivery` call returns a fresh frozen snapshot, and a snapshot already returned never changes; this settling is the only difference that later snapshots of a terminal item can show, and it never changes `state`, `terminal` or `lastCode`. An item that becomes terminal before its first publication phase begins, so that no attempt timeout was ever armed for it (a first-attempt signing failure, a deadline, `cancel` or fault reached before the first publication phase, or a residual item after a failed `put` and a failed cleanup), keeps every entry `PENDING`, which then means only that its publication never began. Once a publication phase has begun, its attempt timeout stays armed whatever `publish` returned (a `publish` that returns `0` sends nothing but still leaves the relay `PENDING`), and the entries still `PENDING` become `TIMED_OUT` when it elapses, also if the item became terminal meanwhile. Apart from that case, the single exception is `shutdown()`, which interface §4.2 requires to clear every timer: it freezes every relay outcome synchronously at the call (§4.6 step 1), and entries of an attempt still in progress at the call keep `PENDING`. That relay's per-relay timeout has then not elapsed while the client ran, so interface §6.3 (`TIMED_OUT` after the per-relay timeout) has not yet applied to it; `PENDING` means only that the client stopped first. This is not a change to interface §6.3: that rule applies once a relay's per-relay timeout has elapsed, which did not happen while the client ran, and the timer clearing that interface §4.2 requires at `shutdown()` makes any later settling impossible. The snapshot is immutable from then on.
- Relay outcomes never change an item's state except the first `ACCEPTED` of an item in `IN_FLIGHT`, as §4.3 states.
- An `OK` frame that arrives after its relay's outcome for the latest attempt has settled (for example after `TIMED_OUT`) is ignored. A relay acknowledgement counts only when the SDK records it; an ignored late acknowledgement is not recorded. The next attempt, if any, republishes the same event, and a relay that already holds it may answer again (`duplicate:` counts as `ACCEPTED`) or not, in which case §5.3 applies as to any publication. If no attempt follows, the item can end in `FAILED_NOT_ACCEPTED`, which interface §6.1 defines as not meaning that no relay received the bytes.

### 5.4 Subscribe

`start()` registers one subscription on every pool before it connects (§5.1), so `RelayPool` sends the `REQ` when each connection opens, including on replacement pools. It uses one `subscriptionId` per client (the letter `s` followed by 32 lowercase hexadecimal digits from `randomBytes`) and the filter `{ "kinds": [4741, 4742], "#p": [<own public key>] }`. The filter has no `since` and no `limit`: a relay may replay events stored before this client started, including from earlier process lifetimes. That replay is a possibility, not a guarantee, and §8 treats it as a duplicate source. Frames from each pool are handled independently as they arrive; no relay waits for another. A frame that is not a JSON array, is not `EVENT`, `OK`, `EOSE`, `NOTICE` or `CLOSED`, or, for an `EVENT`, `EOSE` or `CLOSED` frame, names another subscription is ignored; `OK` frames are matched by event id (§5.3).

### 5.5 Closing

At `shutdown()` and before a failed `start()` resolves, the SDK waits until every connection attempt of every current pool has settled (at most `RelayPool`'s fixed 10 000 ms connection timeout, enforced by its host timer and shorter than the minimum `perRelayTimeoutMs`; a `shutdown()` that interrupts a `start()` waits for that `start()` first, and the two waits overlap because they concern the same connection attempts), then calls `dispose()` on every current pool; retired pools were disposed when they were retired. `dispose()` calls `close()` on the pool's socket, drops the pool's reference to it and removes its listeners.

In this document a relay connection is closed when the SDK has started the WebSocket closing handshake on it with `close()`, holds no reference to it, and can neither send on it nor receive from it. This is the strongest closure that the unchanged `RelayPool` lets the SDK establish, since `RelayPool` exposes no socket and no close-completion signal. The closing handshake then completes in the WebSocket implementation, which bounds it on its own (the `ws` implementation, for example, destroys the underlying socket after its fixed closing timeout when a relay does not answer the handshake). No claim is made about the time the handshake takes. Because each pool's automatic reconnection was cleared before it connected (§5.1), no pool opens a new connection afterwards. `shutdown()` therefore resolves within the host time of the `start()` or `send` calls already in progress (each bounded as §5.2 and §4.2 state; a `send` past `put` takes at most two port-call timeouts, for `put` and the one `remove`), plus the step-(4) wait for port calls in progress and the parallel `LOST_ON_SHUTDOWN` writes (one port-call timeout each), plus 10 000 ms for connection attempts to settle; in total at most four port-call timeouts plus 10 000 ms of host time beyond a `start()` in progress.

## 6. SDK-internal on-wire and record structures (non-normative)

Everything in this section is SDK-internal, experimental and tied to the interface version string `styx-m3-sdk/0.1.0-experimental`. It is not a Styx protocol semantic, not a Nostr standard and not a persisted format; a later version may change it without migration. It uses the event shape that Nostr relays already accept, as the existing transport code does, and selects no new semantic. In this interface version it only ever reaches loopback relays.

### 6.1 Event shape and id

Every structure is a NIP-01-shaped event object with exactly the keys `id`, `pubkey`, `created_at`, `kind`, `tags`, `content`, `sig`, where:

- `pubkey` is the signer's lowercase 64-hex public key from `identity.getPublicKey()`;
- `created_at` is `floor(clock.now() / 1000)` at signing. Interface §8.4 allows any finite clock value; when that value is negative or `floor(clock.now() / 1000)` is not a safe integer, the structure cannot be built: for a message event the item moves to `FAILED_NOT_ACCEPTED` with `lastCode: 'E_SDK_INTERNAL'` (§4.5), and for a receipt no receipt is sent. The clock domain is not narrowed; only such structures are not built;
- `id` is the lowercase hex of `sha256(utf8Encode(JSON.stringify([0, pubkey, created_at, kind, tags, content])))`;
- `sig` is the lowercase hex of the 64-byte value returned by `identity.sign({ digest })` with `digest` = the 32 bytes of `id`. Inbound structures are accepted only if BIP-340 `schnorr.verify(hexToBytes(sig), hexToBytes(id), hexToBytes(pubkey))` succeeds (§7.1).

### 6.2 Message event (kind 4741)

| Field | Value |
| --- | --- |
| `kind` | `4741` |
| `tags` | exactly, in this order: `["p", <recipient>]`, `["v", "styx-m3-sdk/0.1.0-experimental"]`, `["n", <32 lowercase hex digits from randomBytes(16)>]`, and, only in `RECIPIENT_RECEIPT` mode, `["r", "1"]` as a fourth tag |
| `content` | `bytesToBase64(ciphertext)`, where `ciphertext` is the non-empty `seal` result |

The `n` tag makes two items distinct events even when they have identical recipient, ciphertext and `created_at` second. The SDK keeps every event id it assigned in the client; if a newly built id equals one of them, it draws a new `n` tag, at most three times, and then moves the item to `FAILED_NOT_ACCEPTED` with `lastCode: 'E_SDK_INTERNAL'`. No two items of a client share an event id. The event id is the message identifier for receipts and duplicate handling. The `r` tag asks the recipient for a receipt.

### 6.3 Receipt event (kind 4742)

| Field | Value |
| --- | --- |
| `pubkey` | the recipient's public key (the receipt's signer) |
| `kind` | `4742` |
| `tags` | exactly, in this order: `["p", <original sender pubkey>]`, `["e", <original message event id>]`, `["v", "styx-m3-sdk/0.1.0-experimental"]`, `["n", <32 lowercase hex digits from randomBytes(16)>]` |
| `content` | the empty string |

A receipt carries no payload, plaintext, ciphertext or reading claim.

### 6.4 Item record

The record that the SDK hands to the storage port (`put`, `update`; `remove` receives only the `deliveryId` string, interface §8.1) is a frozen plain object with exactly the fields `deliveryId`, `recipient`, `receiptMode`, `state`, `attempts`, `createdAt`, `deadlineAt`, `lastCode`, `relayOutcomes`, `ciphertext` (a copy of the sealed bytes; `null` once the item is terminal) and `event` (`null` until the first attempt signs it, then the signed event of §6.2; `null` again once the item is terminal). The record is opaque to the port and is not a persisted format. The SDK calls `list` only in `start()` (the emptiness check), `put` once at admission, `update` after every recorded transition (the `LOST_ON_SHUTDOWN` transitions, recorded at the `shutdown()` call, are written in its step (4)) and for a `cancel` (§4.6), and `remove` only to undo a failed admission (§4.2); it does not call `get` in this version. Writes for one item are issued in the order its transitions are recorded, except the `cancel` write.

## 7. Receipts and acknowledgements

### 7.1 Inbound processing

Inbound `EVENT` frames for the client's subscription are queued per client and processed one at a time, in arrival order across all relays. `RelayPool` decodes every WebSocket message with `JSON.parse` before it emits it, so frames reach the SDK already decoded and this document places no bound on that decoding. At most 1 024 decoded `EVENT` frames wait; a frame that arrives when the bound is full is dropped before any SDK validation and before any session-port call. The bound is per client, not per relay: a relay that floods frames can cause frames from other relays, receipts included, to be dropped. This document makes no claim about inbound delivery under such load. Each queued frame's event is validated in this order, and the first failure emits `INBOUND_DISCARDED` with `E_SDK_INBOUND_INVALID` (interface §4.3, §5.2):

1. a plain object with exactly the seven keys of §6.1, where `id` is 64 and `sig` is 128 lowercase hexadecimal digits, `pubkey` is 64 lowercase hexadecimal digits, `created_at` is a non-negative safe integer, `kind` is a safe integer, `tags` is an array of arrays of strings, and `content` is a string;
2. `kind` is `4741` or `4742`;
3. the tags are exactly the closed tag list of §6.2 or §6.3 for that kind, with every value in the form given there: a kind-4741 event is valid with exactly its three fixed tags, or with exactly those three followed by `["r", "1"]` as the fourth tag, and any other `r` value, position or count is `E_SDK_INBOUND_INVALID`; the `p` tag equals the client's own public key; the `v` tag equals the interface version string (any other version is not interpreted, interface §3); for kind `4742` the `e` tag is 64 lowercase hexadecimal digits and `content` is the empty string;
4. `id` equals the recomputed id of §6.1;
5. `schnorr.verify(hexToBytes(sig), hexToBytes(id), hexToBytes(pubkey))` succeeds.

Then the duplicate check of §8 runs; a duplicate is dropped without an event. A frame dropped because the pending bound is full, a duplicate, and a valid receipt that matches no item (§7.3) are not structures that failed parsing, version, signature or `open`, so they emit nothing (interface §4.3 requires `INBOUND_DISCARDED` only for those failures). Inbound delivery carries no guarantee; a relay may deliver a dropped event again.

### 7.2 Message events

A valid kind-4741 event's `content` is decoded with `base64ToBytes`; a decoding failure or an empty result is `E_SDK_INBOUND_INVALID`. The bytes are passed to `session.open({ sender: pubkey, ciphertext })`, bounded by the port-call timeout. A failure, or a return other than `{ plaintext }` with a `Uint8Array`, emits `INBOUND_DISCARDED` with `E_SDK_SESSION_FAILED` (subject to §4.5). On success the SDK emits `MESSAGE_RECEIVED` with `sender` = `pubkey` and a fresh copy of the plaintext.

If the event carries the `r` tag, the SDK then publishes one receipt (§6.3) for it: it signs the receipt through `identity.sign` (bounded by the port-call timeout; a return other than a 64-byte `Uint8Array` means no receipt) and calls `publish` once on every connected current pool. A receipt is sent at most once per message event id while that id is in the duplicate window. Receipt publication is best effort: no retry, no outcome tracking, no event to the recipient's caller. A signing failure or an unconnected relay means no receipt; the sender then reports `FAILED_NO_RECEIPT` at its deadline, which interface §6.1 defines as not meaning that the recipient did not receive the message.

### 7.3 Receipt events (acknowledgements)

A kind-4742 event that passed every check of §7.1 (including its `p` tag equal to this client's public key) is accepted as the receipt of an outbound item only when all of these hold: its `e` tag is the event id of a non-terminal item of this client in `RECIPIENT_RECEIPT` mode, its `pubkey` equals that item's `recipient`, the item has not already taken a receipt, and `clock.now()` is before the item's `deadlineAt` (otherwise the deadline transition of §4.4 applies at once). Otherwise the receipt is ignored without an event. An accepted receipt:

- moves an item in `RELAY_ACCEPTED_AWAITING_RECEIPT` to `RECIPIENT_RECEIPT_RECEIVED`;
- for an item still in `QUEUED` or `IN_FLIGHT` (the recipient answered before any relay acknowledgement reached this client), is held on the item and causes no transition. Acceptance is still recorded only through `IN_FLIGHT` → `RELAY_ACCEPTED_AWAITING_RECEIPT` when a relay reports `ACCEPTED` (§4.3); the item then moves at once to `RECIPIENT_RECEIPT_RECEIVED`, two transitions with two events. If the item becomes terminal without an acceptance, the held receipt is discarded. A held receipt never creates or substitutes for a relay acceptance.

Relay acknowledgement (§5.3) and recipient receipt are recorded separately and never inferred from each other.

## 8. Duplicate handling

- **Outbound.** Retransmissions republish the identical signed event with the same event id. A relay may answer a repeated event with `OK true "duplicate: …"`, which counts as `ACCEPTED` (§5.3), or with any other answer or none, which §5.3 handles like any first publication. No claim is made about how many copies a relay stores. A recipient may receive the same event from several relays or more than once from one relay, which §8 treats as duplicates.
- **Inbound.** Each client remembers the ids of the last 4 096 valid inbound events (messages and receipts), first in, first out; an id enters the window when its event passes the checks of §7.1, before `session.open`, so a re-delivered copy of an event whose `open` failed is dropped as a duplicate. An event whose id is in the window is dropped without an event and without a second receipt. An event older than the window, or replayed to a new client or a later process, may be emitted again. No exactly-once claim follows.
- **Ordering.** Inbound events are emitted in the order this client processes them, which need not match sending order.

## 9. Delivery modules and imports

The delivery layer is split over the implementation cards of the scope record. Exact export names are fixed by each card's contract, consistently with these responsibilities. These modules are SDK-internal and are not part of the public surface.

| Card | File | Responsibility in this document |
| --- | --- | --- |
| `I-RETRY` | `styx-js/src/sdk/delivery/retry.js` | the pure `delay(n, u)` schedule and the retry-or-fail decision of §4.3, with injected clock and random values |
| `I-RELAY` | `styx-js/src/sdk/delivery/relay-pool.js` | one current `RelayPool` per relay, §5.1 to §5.5, per-relay outcomes and timeouts |
| `I-QUEUE` | `styx-js/src/sdk/delivery/outbox.js` | the item lifecycle of §4, building the outbound message event of §6.2, the record of §6.4 behind the storage port, retention |
| `I-ACK` | `styx-js/src/sdk/delivery/receipts.js` | the common structure rules of §6.1 as applied to inbound events, the receipt of §6.3, inbound validation of §7, receipts and duplicate handling of §8 |
| `I-SDK` | `styx-js/src/sdk/index.js`, `styx-js/src/sdk/client.js` | assembly behind the interface |

Imports stay inside interface §9, which is unchanged. The delivery modules need only this subset; each implementation card contract enumerates its own exact list from it:

- `styx-js/src/sdk/**` lane modules present at the importing card's base or in its own allowlist, as interface §9 allows;
- `styx-js/src/transport/nostr-transport.js`: `RelayPool` only;
- `styx-js/src/utils.js`: `bytesToHex`, `hexToBytes`, `utf8Encode`, `bytesToBase64`, `base64ToBytes`, `randomBytes`;
- `@noble/hashes/sha256`: `sha256`;
- `@noble/curves/secp256k1`: `schnorr`, for `schnorr.verify` of inbound structures only in `styx-js/src/sdk/**`;
- runtime globals of interface §9, among them `WebSocket` (used only inside `RelayPool`), `setTimeout`, `clearTimeout` and `queueMicrotask`.

No delivery module imports `styx-js/src/storage/**`, `styx-js/src/crypto/**`, `styx-js/src/config/**`, `styx-js/apps/**`, any other transport export (including `NostrTransport`, `OutboxWorker`, `TransportFailover`, `WebRTCTransport`, `BroadcastChannelTransport` and `NostrChatTransport`) or any new dependency.

## 10. Loopback relay test harness requirements (`T-RELAY`)

`C-DLV` writes no harness code. `T-RELAY` builds the harness inside its own allowlist `styx-js/test/sdk/integration/**`, from existing dependencies only, and the harness MUST meet these requirements:

- It is built with `WebSocketServer` from the existing `ws` development dependency and runs inside the Jest process. Before creating a client, the test process installs the `WebSocket` implementation of `ws` as the runtime global, because `RelayPool` uses the global `WebSocket` and Node 18 does not provide it (interface §9). No new dependency, container image, compose file or file outside `styx-js/test/sdk/integration/**`; the existing `styx-js/docker-compose*.yml` relay infrastructure is not used.
- Every relay listens on a loopback IP literal (`127.0.0.1` or `::1`) on an ephemeral port chosen by the operating system, and every relay URL in the tests is built from that address and port. No test contains a non-loopback `ws:` or `wss:` URL.
- It implements the NIP-01 subset this layer uses: `EVENT` (store and answer `OK` with the event id), `REQ` with `kinds`, `#p` and `ids` filters (replay stored matches, then `EOSE`, then forward live matches), and `CLOSE`. In its default mode it recomputes the event id with `sha256` from `@noble/hashes/sha256` and answers `OK false` when it differs. It does not verify signatures. This is a design choice of the harness, not a restriction of interface §9: a relay that accepts events with a wrong signature lets the tests show that the SDK's own inbound verification rejects them. Inbound signature verification is exercised through the SDK itself, with events signed by test identity ports, including events with a wrong signature.
- It offers at least these per-relay behaviours, each selectable per relay instance: normal; never answering (accepts the connection and never sends any frame); rejecting (`OK false` for every event); dropping the connection after a configurable number of frames; delaying every frame by a configurable time; delivering every matching event twice; and delivering stored events in reverse order.
- The integration tests run at least two independent relays at once and cover at least these scenarios, named as in the record of §12: `hungRelay`, a never-answering relay next to a normal one (the normal relay's outcome and the item's acceptance arrive within one per-relay timeout); `clockAheadOfHost`, an injected clock advanced past the connection phase while a connection attempt is still in progress on the host, with the late connection not counted in the result of `start()`, disposed after a failed `start()` once it settles, and used as the relay connection after a successful one; `stalledHandshake`, a relay whose WebSocket handshake never completes (a `ws` `WebSocketServer` with `noServer: true` behind a `node:http` or `node:net` listener on loopback that accepts the TCP connection and never answers the upgrade), reported `TIMED_OUT`, including when it is configured next to a normal relay at `start()` and an item is sent at once after `start()` resolves; `connectionFailsDuringAttempt`, a connection attempt that fails, or reaches `RelayPool`'s 10 000 ms timeout, during an attempt, reported `TIMED_OUT`; `connectionLostAfterPublish`, a relay that drops its connection after receiving the event and before answering, reported `UNREACHABLE`; `lateOpenAfterAcceptanceOrCancel`, a connection that opens during an attempt after the item was accepted by another relay or cancelled, with no publication on it; `signingFailureFirstAttempt`, a signing failure on the first attempt, with every relay outcome left `PENDING` and none `TIMED_OUT`, and a clock value whose `created_at` is negative or not a safe integer, with `FAILED_NOT_ACCEPTED` and `E_SDK_INTERNAL`; `receiptInLastAttempt`, `maxAttempts` 1 in `RECIPIENT_RECEIPT` mode, with the item accepted in its only attempt and then reaching `RECIPIENT_RECEIPT_RECEIVED` when the receipt arrives before the deadline, and `FAILED_NO_RECEIPT` at the deadline otherwise; `cancelDuringRetryWait`, a `cancel` whose write is in progress when a retry falls due, with no new attempt before the write settles, and the same with a failing write, after which the retry starts; `shutdownDuringAttempt`, `shutdown()` during an attempt whose timeout is about to fire, with every outcome frozen at the call; `relayLossAndReplacement`, relay loss during an attempt after publication, reported `UNREACHABLE` for that attempt with no publication on the replacement connection in it, followed by publication on the replacement connection in the next attempt; `offlineRecipient`, an offline recipient (the recipient starts after the sender's acceptance and still receives the stored message, and the sender reports `FAILED_NO_RECEIPT` or `RECIPIENT_RECEIPT_RECEIVED` according to the timing); `duplicateAndReordered`, duplicate and reordered delivery; `shutdownLostThenNewClient`, an orderly `shutdown()` with pending items reported as `LOST_ON_SHUTDOWN`, followed by a new client with a new empty store that does not see them; `lateCloseAfterReplacement`, an old socket's close that arrives after its replacement connection opened, with no open connection left after `shutdown()` resolves.
- Every test closes every relay server and client socket it opened, and asserts that the SDK leaves no open connection after `shutdown()` resolves, including when an old socket's close arrives after its replacement connection opened.

Unit tests of `I-RELAY` and `I-ACK` that need a relay build their own within their own allowlisted test file under the same requirements; no shared test-helper file exists outside a card's allowlist.

## 11. Non-claims and gates

The delivery layer is experimental, internal to the repository, not audited, not a product and not authorized for sensitive use. It claims no exactly-once delivery, ordering, cross-restart reliability, durable persistence, payload confidentiality beyond the injected session port, identity hiding, unlinkability, padding, timing protection, onion routing or metadata protection. Relays and network observers see public keys, the `p`, `e`, `v`, `n` and `r` tags, timing, sizes and network metadata; a receipt also tells the sender's relays that a holder of the recipient's key answered. Relay acceptance and recipient receipt are distinct, and neither proves that a person read a message. Because every item is retained for the client's lifetime, the client's memory grows with the number of items sent; a long-running caller creates a new client to release it.

These statements stay in force verbatim:

- "Styx is under active development and has **not** completed an independent security audit. Do not use current builds for sensitive, high-risk, or life-critical use."
- "C0.3 remains `NO-GO` for implementation alignment, demo, product, and sensitive use."

Implementation of this contract (`I-RETRY`, `I-RELAY`, `I-QUEUE`, `I-ACK`, `I-SDK`, `T-RELAY`) starts only after every `beforeImplementation` gate of the M3 scope record holds, including the owner hash-ratification of this exact file and of `O-SCEN3`, and their merge into `m3/integration`. `O-SCEN3` is written by a model vendor different from the author vendor of this document.

## 12. Machine-readable normative record

The JSON below is normative and closed. Prose clarifies but does not widen it. Duplicate keys are invalid.

<!-- styx-m3-delivery-layer-json:v1:start -->
```json
{
  "schema": "styx-m3-delivery-layer/v1",
  "closed": true,
  "card": "C-DLV",
  "sdkInterfaceVersion": "styx-m3-sdk/0.1.0-experimental",
  "sdkInterfaceDoc": { "path": "docs/architecture/m3/sdk-interface.md", "sha256": "47f75d6cd0bd3d542fd699f99144da6ccd9d6965908e5d1f4b2c1dfd976a9a11" },
  "publicSurfaceChanged": false,
  "parameters": {
    "maxAttempts": { "min": 1, "max": 10, "default": 5 },
    "deadlineMs": { "min": 30000, "max": 600000, "default": 120000 },
    "perRelayTimeoutMs": { "min": 11000, "max": 30000, "default": 12000 },
    "receiptModeDefault": "RELAY_ACCEPTANCE_ONLY"
  },
  "fixed": {
    "portCallTimeoutMs": "floor(perRelayTimeoutMs / 2)",
    "portCallTimer": "host",
    "payloadMaxBytes": 65536,
    "queueBoundNonTerminal": 256,
    "terminalSlackMs": 1000,
    "inboundDuplicateWindow": 4096,
    "inboundPendingBound": 1024,
    "relaySupervisionMs": 1000
  },
  "backoff": {
    "baseMs": 1000,
    "capMs": 30000,
    "formula": "base(n)=min(1000*2^(n-1),30000); delay(n,u)=floor(base(n)/2)+floor(u*base(n)/2^33); u=random.nextUint32()",
    "retryAfterAcceptance": false,
    "failWhen": ["attempts == maxAttempts", "clock.now() + delay >= deadlineAt"],
    "afterAcceptance": "no further attempt; in RECIPIENT_RECEIPT the accepted attempt is the last and ends only at receipt, deadline, fault, cancel or shutdown"
  },
  "deadline": { "from": "createdAt", "clock": "clock port", "hostBackstopMs": "deadlineMs + terminalSlackMs", "backstopArmedAt": "admission clock reading", "checkedBeforeSuccessOrAttempt": true, "fromNonAccepted": "FAILED_NOT_ACCEPTED", "fromAwaitingReceipt": "FAILED_NO_RECEIPT" },
  "hostBackstops": ["deadline", "attemptTimeout", "startConnectionPhase", "portCall"],
  "attemptTimerArmedAt": "publication start (after the first signature)",
  "lifecycle": {
    "deliveryId": "d + per-client decimal counter",
    "retention": "every item for the client lifetime",
    "continuationRecheck": true,
    "cancelWritesBeforeCommit": true,
    "uniqueEventIds": "per client, at most 3 n-tag redraws, then E_SDK_INTERNAL",
    "shutdownLostAtCall": true,
    "shutdownWaitsForCallsInProgress": true,
    "shutdownKeepsActive": ["portCall", "startConnectionPhase"],
    "afterShutdownCall": { "start": "E_SDK_CLIENT_STOPPED", "send": "E_SDK_CLIENT_STOPPED", "getDelivery": "unchanged (interface 4.2)", "cancel": "E_SDK_CLIENT_STOPPED", "onEvent": "unchanged (interface 4.2)", "shutdown": "E_SDK_CLIENT_STOPPED" },
    "callsInProgressAtShutdown": { "startBeforeCompletion": "E_SDK_CLIENT_STOPPED", "sendBeforePut": "E_SDK_CLIENT_STOPPED", "sendAfterPut": "completes; admitted item LOST_ON_SHUTDOWN", "cancel": "E_SDK_CLIENT_STOPPED after its write settles" },
    "connectionClosed": "close() started, no reference held, no send or receive"
  },
  "queueStates": ["QUEUED", "IN_FLIGHT", "RELAY_ACCEPTED_AWAITING_RECEIPT", "RELAY_ACCEPTED", "RECIPIENT_RECEIPT_RECEIVED", "FAILED_NOT_ACCEPTED", "FAILED_NO_RECEIPT", "CANCELLED", "LOST_ON_SHUTDOWN"],
  "transitionsUsed": {
    "QUEUED": ["IN_FLIGHT", "CANCELLED", "FAILED_NOT_ACCEPTED", "LOST_ON_SHUTDOWN"],
    "IN_FLIGHT": ["QUEUED", "RELAY_ACCEPTED_AWAITING_RECEIPT", "RELAY_ACCEPTED", "FAILED_NOT_ACCEPTED", "CANCELLED", "LOST_ON_SHUTDOWN"],
    "RELAY_ACCEPTED_AWAITING_RECEIPT": ["RECIPIENT_RECEIPT_RECEIVED", "FAILED_NO_RECEIPT", "CANCELLED", "LOST_ON_SHUTDOWN"],
    "RELAY_ACCEPTED": [],
    "RECIPIENT_RECEIPT_RECEIVED": [],
    "FAILED_NOT_ACCEPTED": [],
    "FAILED_NO_RECEIPT": [],
    "CANCELLED": [],
    "LOST_ON_SHUTDOWN": []
  },
  "lastCodes": [null, "E_SDK_STORAGE_FAILED", "E_SDK_IDENTITY_FAILED", "E_SDK_INTERNAL", "E_SDK_UNKNOWN_CODE"],
  "codesUsed": ["E_SDK_INVALID_ARGUMENT", "E_SDK_PAYLOAD_TOO_LARGE", "E_SDK_QUEUE_FULL", "E_SDK_SESSION_FAILED", "E_SDK_STORAGE_FAILED", "E_SDK_IDENTITY_FAILED", "E_SDK_NO_RELAY_AVAILABLE", "E_SDK_STORAGE_NOT_EMPTY", "E_SDK_UNKNOWN_DELIVERY", "E_SDK_DELIVERY_TERMINAL", "E_SDK_CLIENT_STOPPED", "E_SDK_INBOUND_INVALID", "E_SDK_INTERNAL", "E_SDK_UNKNOWN_CODE", "E_SDK_INVALID_CONFIG"],
  "relays": {
    "poolPerRelay": true,
    "poolReplacedAfterLoss": true,
    "autoReconnectClearedVia": "disconnectAll before connectAll",
    "subscribeBeforeConnect": true,
    "transportCalls": ["constructor", "disconnectAll", "subscribe", "messages", "connectAll", "healthCheck", "publish", "dispose"],
    "transportCallsNever": ["reconnect", "addRelay", "removeRelay", "publishAndVerify", "underscorePrefixedProperties"],
    "startPhaseMs": "perRelayTimeoutMs",
    "reconnectInterval": "delay(k,u) by consecutive failures of that relay",
    "closeWaitsForConnectSettleMs": 10000,
    "lateConnection": "tracked until connectAll settles (host time); never counts in connectedRelays; after a successful start it becomes the relay connection, after a failed start it is disposed once settled"
  },
  "relayOutcomeRules": {
    "outcomes": ["PENDING", "ACCEPTED", "REJECTED", "TIMED_OUT", "UNREACHABLE"],
    "publishReturnedZero": "PENDING",
    "publishAfterOpen": "once, only while RUNNING, IN_FLIGHT in the same attempt and before the deadline",
    "connectionLostAfterPublish": "UNREACHABLE",
    "okTrue": "ACCEPTED",
    "okFalse": "REJECTED",
    "noOkWithinPerRelayTimeout": "TIMED_OUT",
    "acceptedSticky": true,
    "okMatchedBy": "event id and relay, while that relay is PENDING in the latest attempt",
    "okAttributedToAttempt": false,
    "okAfterSettleIgnored": true,
    "settleWindow": "until the attempt timeout, also after the item is terminal (after FAILED_NOT_ACCEPTED or CANCELLED only PENDING -> TIMED_OUT, OK frames ignored); only shutdown freezes PENDING; an item that becomes terminal before its first publication phase begins (no attempt timeout ever armed: first-attempt signing failure, deadline, cancel or fault before it, failed put with failed cleanup) keeps every entry PENDING; once a publication phase has begun, its attempt timeout stays armed even if every publish returned 0",
    "hungRelayBlocksOthers": false
  },
  "wire": {
    "normative": false,
    "versionTag": "styx-m3-sdk/0.1.0-experimental",
    "eventKeys": ["id", "pubkey", "created_at", "kind", "tags", "content", "sig"],
    "id": "sha256(utf8(JSON.stringify([0,pubkey,created_at,kind,tags,content])))",
    "signature": "identity.sign over id (BIP-340); verified on inbound structures only",
    "outboundSelfVerify": false,
    "message": { "kind": 4741, "tags": ["p", "v", "n"], "optionalTag": "r", "content": "base64(ciphertext)" },
    "receipt": { "kind": 4742, "tags": ["p", "e", "v", "n"], "content": "" },
    "subscriptionFilter": { "kinds": [4741, 4742], "pTag": "own public key", "since": false, "limit": false },
    "sizeInspected": false
  },
  "record": {
    "fields": ["deliveryId", "recipient", "receiptMode", "state", "attempts", "createdAt", "deadlineAt", "lastCode", "relayOutcomes", "ciphertext", "event"],
    "persistedFormat": false,
    "authoritative": "in-memory view",
    "storageCalls": { "put": "admission", "update": "after every recorded transition and for cancel", "remove": "undo a failed admission", "list": "start emptiness check", "get": "never" }
  },
  "receipts": {
    "requestedBy": "r tag in RECIPIENT_RECEIPT mode",
    "sentAfter": "successful open and MESSAGE_RECEIVED",
    "sentAtMostOncePerEventIdInWindow": true,
    "retry": false,
    "acceptedWhen": ["every inbound check of section 7.1, including p tag equal to own public key", "e tag is a non-terminal RECIPIENT_RECEIPT item", "pubkey equals item recipient", "first receipt for the item", "clock.now() < deadlineAt"],
    "earlyReceiptHeldUntilAcceptance": true,
    "receiptImpliesRelayAcceptance": false,
    "receiptProvesOpening": false,
    "receiptProvesReading": false
  },
  "duplicates": {
    "outboundSameEventOnRetransmit": true,
    "inboundWindow": 4096,
    "inboundDuplicateEmits": "nothing",
    "exactlyOnce": false,
    "ordering": false
  },
  "outerBounds": {
    "finiteAttemptsAndDeadline": true,
    "exactlyOnce": false,
    "ordering": false,
    "crossRestart": false,
    "relayAcceptanceDistinctFromReceipt": true,
    "receiptProvesReading": false,
    "processLifetimeOnly": true,
    "orderlyShutdownReportsLost": true,
    "crashReportsNothing": true,
    "normativeWireFormat": false,
    "relayUrlsInjectedOnly": true
  },
  "modules": {
    "I-RETRY": ["styx-js/src/sdk/delivery/retry.js"],
    "I-RELAY": ["styx-js/src/sdk/delivery/relay-pool.js"],
    "I-QUEUE": ["styx-js/src/sdk/delivery/outbox.js"],
    "I-ACK": ["styx-js/src/sdk/delivery/receipts.js"],
    "I-SDK": ["styx-js/src/sdk/index.js", "styx-js/src/sdk/client.js"]
  },
  "imports": {
    "lane": "styx-js/src/sdk/** modules present at the importing card base or in its own allowlist",
    "transport": { "styx-js/src/transport/nostr-transport.js": ["RelayPool"] },
    "utils": ["bytesToHex", "hexToBytes", "utf8Encode", "bytesToBase64", "base64ToBytes", "randomBytes"],
    "packages": { "@noble/hashes/sha256": ["sha256"], "@noble/curves/secp256k1": ["schnorr"] },
    "srcSchnorrUse": "verify only, inbound",
    "noImport": ["styx-js/src/storage/**", "styx-js/src/crypto/**", "styx-js/src/config/**", "styx-js/apps/**"],
    "forbiddenTransportExports": ["NostrTransport", "OutboxWorker", "TransportFailover", "WebRTCTransport", "BroadcastChannelTransport", "NostrChatTransport"],
    "newDependency": false,
    "withinSdkInterfaceSection9": true
  },
  "harness": {
    "card": "T-RELAY",
    "path": "styx-js/test/sdk/integration/**",
    "builtFrom": "ws WebSocketServer",
    "nodeWebSocketGlobal": "ws WebSocket installed as global before client creation",
    "hosts": ["127.0.0.1", "::1"],
    "port": "ephemeral",
    "newDependency": false,
    "dockerCompose": false,
    "nip01Subset": ["EVENT", "OK", "REQ", "EOSE", "CLOSE"],
    "behaviours": ["normal", "neverAnswering", "rejecting", "dropAfterFrames", "delayFrames", "duplicateDelivery", "reverseOrder"],
    "minRelays": 2,
    "signatureVerification": false,
    "scenarios": ["hungRelay", "clockAheadOfHost", "stalledHandshake", "connectionFailsDuringAttempt", "connectionLostAfterPublish", "lateOpenAfterAcceptanceOrCancel", "signingFailureFirstAttempt", "receiptInLastAttempt", "cancelDuringRetryWait", "shutdownDuringAttempt", "relayLossAndReplacement", "offlineRecipient", "duplicateAndReordered", "shutdownLostThenNewClient", "lateCloseAfterReplacement"],
    "cDlvWritesHarnessCode": false
  }
}
```
<!-- styx-m3-delivery-layer-json:v1:end -->

## 13. Conformance

Conforming implementations and tests of the cards in §9 demonstrate at least: a failed `put` followed by a cleanup `remove` that returns `false`, with the original `send` failure result and no residual item or event; a `RECIPIENT_RECEIPT` item accepted by one relay while another hangs, with the hung relay `TIMED_OUT` at the attempt timeout; an injected clock advanced past `perRelayTimeoutMs` while a valid first signing call is still pending within its host port-call timeout, with no attempt timeout, retry or `TIMED_OUT` before the signature and the attempt then publishing the signed event; `shutdown()` with a never-settling `put`, a never-settling `sign` and a never-settling cleanup `update`, each resolved by its host port-call timeout, with `shutdown()` resolving; every parameter bound and default of §3, including rejection of each out-of-bound value with `E_SDK_INVALID_CONFIG`; the exact `delay(n, u)` values for `u = 0` and `u = 2^32 − 1` at every `n` from 1 to 9; no attempt beyond `maxAttempts` and no attempt starting at or after `deadlineAt`; unknown `code`, `state` and `outcome` values from a port, in a method result, an item and inbound processing; a stalled handshake reported `TIMED_OUT`; the deadline, attempt-timeout and `start()` backstops with a clock whose timers never fire, including a slow `put` followed by a slow `remove`; no success state or attempt recorded at or after `deadlineAt`, including for a late receipt; the port-call timeout equal to `floor(perRelayTimeoutMs / 2)`; one event for an item whose deadline passed during `put`; a hung relay reported `TIMED_OUT` also after the item became terminal by success, `cancel`, deadline or fault; identical event bytes across retransmissions; per-relay outcomes for each `OK true`, `OK false`, no answer and unconnected case; a never-answering relay that does not delay another relay's `ACCEPTED`; no `RelayPool` reconnection timer after a dropped connection; pool replacement after loss with no open socket left after `shutdown()` when an old socket's close arrives late; `cancel` with a failing and with a slow storage write; `shutdown()` during a `send`, a signing call and a `start()` in progress, with every admitted item reported `LOST_ON_SHUTDOWN` at the call and no publication or port call other than cleanup after it; inbound rejection of each validation step of §7.1; duplicate suppression within the window; a receipt that arrives before relay acceptance; no transition outside `transitionsUsed`; and no open connection, subscription or timer after `shutdown()`.

A conforming validator of the record in §12 rejects: an unknown or missing field; a duplicate key; a bound that is not finite or a default outside its bounds; a `maxAttempts` maximum above 10 or a `deadlineMs` maximum above 600 000; a `deadlineMs` minimum below the `perRelayTimeoutMs` maximum; a transition not allowed by the interface; a code or last code outside the interface's closed set; a relay outcome outside the interface's list; retransmission after acceptance; a receipt that implies relay acceptance, opening or reading; outbound self-verification; a normative wire format; an import outside interface §9; and any `outerBounds` value different from the one above.

## 14. Authority and ratification

This contract implements card `C-DLV` of the M3 scope record (Issue #400 comment `5950987413`) under the owner act in Issue #400, on base `m3/integration` at `12e6570fa2588999c30d33203f0e8f687a46448c`, which contains the ratified `C-SDK` document. Its only file is `docs/architecture/m3/delivery-layer.md`.

The final file SHA-256 must be owner hash-ratified by a `styx-m3-ratification:v1` comment on #400 that names the author model vendor and the reviewer model vendor. Any byte change voids that ratification. Removing this file fully rolls back `C-DLV`; no code, dependency or persisted bytes are introduced.
