# M3 early-lane public SDK interface contract

Status: normative candidate for card `C-SDK` of the M3 early lane. It is experimental and versioned, and it makes no stability promise to third parties. Dependent implementation stays blocked until the owner hash-ratifies the SHA-256 of this exact file and every other `beforeImplementation` gate of the M3 scope record is met.

## 1. Scope and boundaries

This document defines the public JavaScript interface of the early-lane SDK: its entry points, its closed result and error codes, its delivery-state enumeration, the ports through which storage, session and signing/identity capabilities are injected, its versioning, and the exact imports allowed to the modules that implement it. **MUST**, **MUST NOT** and **REJECT** are normative.

It is a JavaScript runtime-profile API under Section 9 item 5 of `docs/protocol/protocol-hardening-plan.md`, authorized by the owner act in Issue #400 §2(a). It is not the item-2 language-neutral application-core interface, it is not the M2 internal session adapter API (`docs/architecture/m2/adapter-contract.md` on `m2/integration`), and it is not protocol authority. Nothing here selects a Styx protocol semantic, a Marmot or Nostr envelope standard, or a normative wire or persisted format.

The interface is consumed only inside the repository: by lane tests, by the synthetic-only preview once that is separately authorized, and by later lane cards. `styx-js/package.json` and its `exports` map are not changed, so the SDK is not a published package entry point. `styx-js/src/index.js` does not re-export it.

Delivery behaviour behind this interface (queue transitions, retransmission and backoff bounds, receipts and acknowledgements, duplicate handling, per-relay timeouts and the meaning of each per-relay outcome) is fixed by the separate delivery-layer contract `C-DLV` (`docs/architecture/m3/delivery-layer.md`). `C-DLV` MUST NOT add, remove or rename an entry point, configuration field, method, result code, delivery state, transition, per-relay outcome, public SDK event kind or public SDK event field (§7), port method, outer bound or allowed import defined here; any such change needs a new hash-ratified version of this document. This boundary covers only the public SDK surface seen by a consumer. SDK-internal structures behind it (on-wire message identifiers, receipts, acknowledgements, Nostr event kinds and tags, and the fields of internal records) are owned entirely by `C-DLV` and are not frozen here; the public §7 events are SDK callback objects, not on-wire event kinds.

## 2. Outer bounds inherited from #400

These bounds are part of the interface. No value, state or event defined here claims more than they allow.

1. **Finite attempts and deadline.** Every outbound item has a finite attempt count and a finite deadline. When either is exhausted without the item's success state, the item reaches a terminal failed state. There is no unbounded retransmission.
2. **No exactly-once, ordering or cross-restart guarantee.** A message may be received zero, one or more times, and in any order relative to other messages. Nothing persists or resumes across process restarts.
3. **Relay acceptance is not recipient receipt.** `RELAY_ACCEPTED` and `RELAY_ACCEPTED_AWAITING_RECEIPT` mean only that at least one relay acknowledged the publication. `RECIPIENT_RECEIPT_RECEIVED` means only that a receipt attributed to the recipient identity was received and validated as `C-DLV` specifies. Neither proves that a person read the message.
4. **Process lifetime only.** Delivery guarantees hold only within one process lifetime. On an explicit, orderly `shutdown()`, every non-terminal item is reported as `LOST_ON_SHUTDOWN`. After a crash or abrupt termination nothing is reported and nothing is recovered; no claim is made for that case.
5. **No normative wire format.** Any on-wire structure the SDK produces or consumes (message identifier, receipt, acknowledgement, event kind or tag) is SDK-internal, experimental and versioned with `sdkInterfaceVersion`. It is not normative. Using the allowed transport exports with the event formats they already produce selects no new semantic.
6. **Relay URLs are injected only.** Relay endpoints reach the SDK only through `config.relays`. No module under `styx-js/src/sdk/**` contains a relay URL literal, a default relay list or a fallback relay.

The SDK makes no confidentiality, integrity, authenticity, identity-hiding, unlinkability, padding, timing or metadata-protection claim of its own. Payload protection is exactly what the injected session port provides, and the SDK does not inspect or attest it. Relays and network observers see public keys, timing, sizes and network metadata.

## 3. Versioning

- The exact interface version string is `styx-m3-sdk/0.1.0-experimental`. It is exported as the constant `SDK_INTERFACE_VERSION`.
- `createStyxClient(config)` requires `config.interfaceVersion` to equal that string exactly (byte-for-byte, case-sensitive). Any other value, including a missing one, returns `E_SDK_UNSUPPORTED_VERSION` and creates no client. There is no negotiation, range, downgrade or fallback.
- The version is experimental. It carries no stability, compatibility or deprecation promise to third parties before a later owner act. Any change to an entry point, field, code, state, event kind, port method, bound inherited from §2 or allowed import requires a new hash-ratified version of this document with a new version string.
- SDK-internal on-wire structures carry or are keyed by this version string as `C-DLV` specifies; an inbound structure from any other version is not interpreted: it emits `INBOUND_DISCARDED` with `E_SDK_INBOUND_INVALID` and nothing else.

## 4. Entry points

The single public module is `styx-js/src/sdk/index.js` (card `I-SDK`). It exports exactly these names and nothing else:

| Export | Kind | Purpose |
| --- | --- | --- |
| `SDK_INTERFACE_VERSION` | frozen string constant | §3. |
| `SdkResultCode` | frozen object, code → code | The closed set of §5. |
| `DeliveryState` | frozen object, state → state | The closed set of §6. |
| `RelayOutcome` | frozen object, outcome → outcome | The closed set of §6.3. |
| `ClientState` | frozen object, state → state | `CREATED`, `RUNNING`, `STOPPED`. |
| `SdkEventKind` | frozen object, kind → kind | The closed set of §7. |
| `isKnownResultCode(code)` | pure predicate | Returns the boolean `true` only for a member of `SdkResultCode` and `false` for every other value. It is the only export that returns no result envelope, and it never throws. |
| `createStyxClient(config)` | function | §4.1. |

`styx-js/src/sdk/client.js` holds the client implementation and is not imported by consumers directly.

### 4.1 `createStyxClient(config)`

Synchronous. Returns a result envelope (§5.1) for every input value, including `undefined`, `null` and non-objects (which return `E_SDK_INVALID_CONFIG`); it never throws. On success `value` is a client object in state `CREATED`; nothing is connected, scheduled or stored yet.

`config` is a closed plain object. Unknown fields REJECT with `E_SDK_INVALID_CONFIG`.

| Field | Required | Type and rule |
| --- | --- | --- |
| `interfaceVersion` | yes | exactly `SDK_INTERFACE_VERSION` (§3). |
| `relays` | yes | array of 1 to 16 distinct strings, each a syntactically valid absolute `ws:` or `wss:` URL with no userinfo and no fragment. Order is preserved; no entry is added, removed or reordered by the SDK. In this interface version every relay host must be a loopback IP address literal (an IPv4 address in the loopback block or the IPv6 loopback address); any other host, including a host name, REJECTs with `E_SDK_INVALID_CONFIG`, so the SDK of this version cannot connect to a public or remote relay. Lifting this restriction is a deployment decision that needs a later owner act and a new version of this document. |
| `ports` | yes | closed object `{ storage, session, identity }`; each is required and must expose every method of §8 as a function. |
| `clock` | no | closed object `{ now, setTimer, clearTimer }` (§8.4). Absent means the built-in `Date.now`, `setTimeout` and `clearTimeout`. |
| `random` | no | closed object `{ nextUint32 }` (§8.4). Absent means the built-in `crypto.getRandomValues`. |
| `delivery` | no | closed object `{ maxAttempts, deadlineMs, perRelayTimeoutMs, receiptMode }`. Each numeric field, when present, is a positive safe integer within the bounds `C-DLV` fixes; `receiptMode` is `RECIPIENT_RECEIPT` or `RELAY_ACCEPTANCE_ONLY`. An absent field takes the finite default `C-DLV` fixes. `Infinity`, `NaN`, `0`, negatives, non-integers and out-of-bound values REJECT. |

Validation is total and happens before any side effect. The first failing rule determines the code: `E_SDK_UNSUPPORTED_VERSION`, then `E_SDK_INVALID_CONFIG` for every other field. No partially constructed client is ever returned.

### 4.2 Client methods

Every method below is asynchronous and **always resolves** to a result envelope (§5.1); it never rejects and never throws, including for invalid arguments, port failures and internal faults. Every argument object is closed; unknown fields REJECT with `E_SDK_INVALID_ARGUMENT`.

| Method | Allowed client state | Success `value` | Effect |
| --- | --- | --- | --- |
| `start()` | `CREATED` | `{ clientState: 'RUNNING', connectedRelays }` | Checks that the storage port holds no item (otherwise `E_SDK_STORAGE_NOT_EMPTY`), connects to the configured relays as `C-DLV` specifies, and subscribes for inbound messages and receipts addressed to the identity port's public key. Its relay-connection phase ends no later than one per-relay timeout after it begins (measured by the clock port of §8, with the same host-`setTimeout` backstop that §8 uses for port calls, so a clock whose timers never fire cannot extend it) and never waits longer on a relay that hangs; port calls made by `start()` are bounded separately as §8 specifies, and a port call that does not settle within that bound is that port's failure. It succeeds when at least one relay has connected by the end of the connection phase, and `connectedRelays` is the number connected when it resolves. If none connects within the per-relay timeout, returns `E_SDK_NO_RELAY_AVAILABLE`. Every failed `start()` called in `CREATED`, whatever its code, leaves the client in `CREATED` with no open relay connection, subscription or timer and no cached public key; the SDK closes anything it opened before resolving, and a later `start()` begins from scratch. |
| `send({ recipient, payload })` | `RUNNING` | `{ deliveryId, state: 'QUEUED' }` | Validates, seals `payload` through the session port, stores one outbound item through the storage port, and schedules delivery. Returns before any network attempt completes. |
| `getDelivery({ deliveryId })` | `RUNNING`, `STOPPED` | a delivery snapshot (§6.2) | Read-only. Unknown id returns `E_SDK_UNKNOWN_DELIVERY`. |
| `cancel({ deliveryId })` | `RUNNING` | `{ deliveryId, state: 'CANCELLED' }` | Moves a non-terminal item to `CANCELLED` and stops further attempts. A publication already handed to a relay is not recalled. A terminal item returns `E_SDK_DELIVERY_TERMINAL` and is unchanged. |
| `onEvent(listener)` | any | `{ unsubscribe }` | Registers a function listener for §7 events. Like every method here, `onEvent` resolves to a result envelope; on success its `value` is a frozen object with exactly one property, `unsubscribe`, a function that takes no argument, is synchronous and idempotent, returns `undefined` and never throws. Calling it removes the listener; it is the only synchronous function the SDK hands back. |
| `shutdown()` | `CREATED`, `RUNNING` | `{ clientState: 'STOPPED', lost }` | Orderly stop, unconditional once called in an allowed state: stops scheduling, moves every non-terminal item to `LOST_ON_SHUTDOWN` and emits its event to the listeners registered before the call, delivering those events before it removes the listeners, closes subscriptions and relay connections, and clears every timer. `lost` is the number of items so reported. After it resolves, the client is `STOPPED`, and the SDK has called `clearTimer` for every timer handle it holds, closed every subscription and relay connection it opened, removed every listener registered before the call, and released its ports, transports and timers; it keeps an immutable terminal snapshot of each of its items so that `getDelivery` in `STOPPED` returns the item's final state (for example `LOST_ON_SHUTDOWN`); it makes no claim about an injected clock that ignores `clearTimer`. A storage port failure, a listener fault or an internal fault during shutdown never prevents these effects: lost reporting uses the SDK's own in-memory view of its items, and the method still resolves success. This is a departure from the no-change-on-failure rule, listed in §5.2. A second call returns `E_SDK_CLIENT_STOPPED`. |

A call in a client state not listed returns: `E_SDK_NOT_STARTED` in `CREATED`, `E_SDK_ALREADY_STARTED` for `start()` in `RUNNING`, and `E_SDK_CLIENT_STOPPED` in `STOPPED`. A `STOPPED` client never restarts; a new client is created instead, and it does not see the old client's items.

`send` argument rules:

- `recipient` is the recipient identity's public key as a lowercase 64-character hexadecimal string (the form the identity port of §8.3 returns). Anything else REJECTs with `E_SDK_INVALID_ARGUMENT`.
- `payload` is a `Uint8Array` of 1 byte up to the maximum `C-DLV` fixes. An empty or non-`Uint8Array` payload REJECTs with `E_SDK_INVALID_ARGUMENT`; an oversize one with `E_SDK_PAYLOAD_TOO_LARGE`. The SDK copies the bytes before it resolves; later mutation by the caller has no effect.
- `deliveryId` is assigned by the SDK, is unique within the client, and is an opaque string. It carries no meaning outside the process and is never derived from the payload, the recipient or a caller-supplied value.

### 4.3 Inbound messages

Inbound application messages are delivered only through `MESSAGE_RECEIVED` events (§7). The SDK passes the inbound ciphertext to the session port's `open` method and emits the event only when `open` returns success. An inbound structure that fails parsing, version checks, signature verification or `open` emits no `MESSAGE_RECEIVED`; it emits `INBOUND_DISCARDED` with one of the three inbound discard codes of §5.2 and no payload, sender, or content-derived field. Duplicate inbound messages may be emitted more than once unless `C-DLV` suppresses them within the process lifetime; the interface makes no exactly-once claim.

## 5. Result envelope and codes

### 5.1 Envelope

`createStyxClient` and every client method of §4.2 return exactly one of these frozen, closed objects (`isKnownResultCode` is the single exception, §4):

- success: `{ ok: true, value }`;
- failure: `{ ok: false, code }`, where `code` is a member of `SdkResultCode`.

Nothing else is returned. A failure carries no message text, stack, upstream error, secret, plaintext, key, relay URL, path or host detail.

### 5.2 Closed code set

| Code | Meaning |
| --- | --- |
| `E_SDK_UNSUPPORTED_VERSION` | `config.interfaceVersion` is not exactly `SDK_INTERFACE_VERSION`. |
| `E_SDK_INVALID_CONFIG` | Any other configuration rule of §4.1 failed. |
| `E_SDK_INVALID_ARGUMENT` | A method argument is missing, of the wrong type, malformed, or has an unknown field. |
| `E_SDK_PAYLOAD_TOO_LARGE` | `payload` exceeds the `C-DLV` maximum. |
| `E_SDK_NOT_STARTED` | The method needs `RUNNING` and the client is `CREATED`. |
| `E_SDK_ALREADY_STARTED` | `start()` on a `RUNNING` client. |
| `E_SDK_CLIENT_STOPPED` | Any state-changing call, or a second `shutdown()`, on a `STOPPED` client. |
| `E_SDK_STORAGE_NOT_EMPTY` | `start()` found an item already present in the storage port. |
| `E_SDK_NO_RELAY_AVAILABLE` | `start()` connected to no relay. |
| `E_SDK_QUEUE_FULL` | `send` would exceed the in-memory queue bound `C-DLV` fixes. |
| `E_SDK_UNKNOWN_DELIVERY` | No item with that `deliveryId` exists in this client. |
| `E_SDK_DELIVERY_TERMINAL` | `cancel` on an item already in a terminal state. |
| `E_SDK_STORAGE_FAILED` | A storage port call failed, threw, timed out or returned a malformed value. |
| `E_SDK_SESSION_FAILED` | A session port call failed, threw, timed out or returned a malformed value. |
| `E_SDK_IDENTITY_FAILED` | An identity port call failed, threw, timed out or returned a malformed value. |
| `E_SDK_INBOUND_INVALID` | (`INBOUND_DISCARDED` only) An inbound structure failed parsing, version or signature checks. |
| `E_SDK_INTERNAL` | An internal fault with no more specific code. |
| `E_SDK_UNKNOWN_CODE` | A component or port produced a code or state outside the closed sets of this document. |

`E_SDK_INBOUND_INVALID`, `E_SDK_SESSION_FAILED` and `E_SDK_UNKNOWN_CODE` are the only codes that appear in `INBOUND_DISCARDED`: the first for parsing, version and signature failures, the second for a failed `open`, the third when a lane component or the session port yields a value outside the closed sets (§5.3). `E_SDK_INBOUND_INVALID` never appears in a method result.

When a method other than `shutdown()` fails, it makes no change visible to the caller as a usable item: an item is either fully created (stored, with its `deliveryId` returned) or not created as a deliverable item. If a storage write may have happened before a later step failed, the SDK removes the item before resolving; if that removal itself fails, the method resolves `E_SDK_STORAGE_FAILED`, and the residual item, if present, is never sent and is reported through events as `FAILED_NOT_ACCEPTED`. These are the only two departures from no-change-on-failure: this residual-item rule and the unconditional `shutdown()` of §4.2.

### 5.3 Unknown codes and states fail closed

- **Inside the SDK.** A code, state or outcome produced by a lane component or a port that is not a member of the closed sets here is never forwarded as is. In a result of a client method of §4.2 it becomes `{ ok: false, code: 'E_SDK_UNKNOWN_CODE' }`; `createStyxClient` calls no port or lane component, and any internal fault there returns `E_SDK_INVALID_CONFIG`, never success. For a non-terminal outbound item it moves the item to `FAILED_NOT_ACCEPTED` (if no relay acceptance was recorded) or, in `RECIPIENT_RECEIPT` mode after a relay acceptance was recorded, to `FAILED_NO_RECEIPT`, with `lastCode: 'E_SDK_UNKNOWN_CODE'`, and stops further attempts. A terminal item, including `RELAY_ACCEPTED` in `RELAY_ACCEPTANCE_ONLY` mode (where relay acceptance is itself terminal), is never changed by an unknown value. It never yields `ok: true`, a success state or a success event; the only success that can coexist with an unknown value is the unconditional `shutdown()` result, which reports the affected item as `LOST_ON_SHUTDOWN`, never as delivered.
- **In consumers.** A consumer MUST treat as failure any envelope whose `ok` is not exactly the boolean `true`, any `code` for which `isKnownResultCode` is `false`, any delivery state not in §6 and any event kind not in §7. A consumer MUST NOT infer success, acceptance or receipt from an unknown value.
- Unknown is never mapped to a weaker failure, retried as success, or ignored.

## 6. Delivery states

### 6.1 Closed state enumeration

| State | Terminal | Meaning | Does NOT mean |
| --- | --- | --- | --- |
| `QUEUED` | no | Stored in the in-memory queue; no attempt in progress. | Any network activity. |
| `IN_FLIGHT` | no | A publication attempt to the configured relays is in progress. | That any relay received it. |
| `RELAY_ACCEPTED_AWAITING_RECEIPT` | no | At least one relay acknowledged the publication; `receiptMode` is `RECIPIENT_RECEIPT` and no valid recipient receipt has arrived yet. | Recipient receipt; storage by every relay. |
| `RELAY_ACCEPTED` | yes | At least one relay acknowledged the publication; `receiptMode` is `RELAY_ACCEPTANCE_ONLY`. Success state of that mode. | Recipient receipt or reading. |
| `RECIPIENT_RECEIPT_RECEIVED` | yes | A receipt for this item, attributed to the recipient identity and validated as `C-DLV` specifies, was received. Success state of `RECIPIENT_RECEIPT` mode. | That a person read the message. |
| `FAILED_NOT_ACCEPTED` | yes | Attempts or deadline exhausted, or an unrecoverable fault, before any relay acknowledgement. | That no relay or recipient got the bytes. |
| `FAILED_NO_RECEIPT` | yes | At least one relay acknowledged, but no valid recipient receipt arrived by the deadline (`RECIPIENT_RECEIPT` mode), or an unrecoverable fault after acknowledgement. | That the recipient did not receive the message. |
| `CANCELLED` | yes | Cancelled by the caller before reaching another terminal state. | That an already published copy was withdrawn. |
| `LOST_ON_SHUTDOWN` | yes | Non-terminal at an orderly `shutdown()`. | Anything about whether a copy reached a relay or recipient. |

Allowed transitions (`C-DLV` fixes when each is taken, never adds one). The "outbound queue states" that the scope record assigns to `C-DLV` are its internal queue states; each maps onto exactly one state of this closed public enumeration, and `C-DLV` times them but cannot extend or rename this enumeration:

- `QUEUED` → `IN_FLIGHT`, `CANCELLED`, `FAILED_NOT_ACCEPTED`, `LOST_ON_SHUTDOWN`;
- `IN_FLIGHT` → `QUEUED` (retry scheduled), `RELAY_ACCEPTED_AWAITING_RECEIPT`, `RELAY_ACCEPTED`, `FAILED_NOT_ACCEPTED`, `CANCELLED`, `LOST_ON_SHUTDOWN`;
- `RELAY_ACCEPTED_AWAITING_RECEIPT` → `RECIPIENT_RECEIPT_RECEIVED`, `FAILED_NO_RECEIPT`, `CANCELLED`, `LOST_ON_SHUTDOWN`;
- every terminal state → none.

In `RECIPIENT_RECEIPT` mode, `RELAY_ACCEPTED` is unreachable. In `RELAY_ACCEPTANCE_ONLY` mode, `RELAY_ACCEPTED_AWAITING_RECEIPT`, `RECIPIENT_RECEIPT_RECEIVED` and `FAILED_NO_RECEIPT` are unreachable. A once-recorded relay acknowledgement is never forgotten: an item that reached `RELAY_ACCEPTED_AWAITING_RECEIPT` never later reports `FAILED_NOT_ACCEPTED`. Every item reaches exactly one terminal state, and it does so no later than its deadline plus the bounded processing slack `C-DLV` fixes, unless the process ends first. The deadline is measured by the clock port (§8.4); the SDK also arms a host `setTimeout` backstop for it, as §8 does for port calls, so a clock whose timers never fire cannot keep an item non-terminal past that bound.

### 6.2 Delivery snapshot

`getDelivery` returns a frozen, closed object:

| Field | Type |
| --- | --- |
| `deliveryId` | string |
| `recipient` | lowercase 64-hex string, as passed to `send` |
| `state` | member of `DeliveryState` |
| `terminal` | boolean, exactly as in §6.1 |
| `attempts` | non-negative integer, never above `maxAttempts` |
| `createdAt` | number from `clock.now()` |
| `deadlineAt` | number from `clock.now()`; finite |
| `lastCode` | `null` or a member of `SdkResultCode` |
| `relayOutcomes` | frozen array, one entry per configured relay in `config.relays` order: `{ relayIndex, outcome }` |

A snapshot contains no payload, ciphertext, secret key material or relay URL; the recipient's public key is its only key-related field. Relays are identified by their index in `config.relays`.

### 6.3 Per-relay outcome enumeration

`RelayOutcome` is closed: `PENDING`, `ACCEPTED`, `REJECTED`, `TIMED_OUT`, `UNREACHABLE`. `C-DLV` fixes when each is set and how it combines across attempts. A relay that hangs is reported as `TIMED_OUT` after its per-relay timeout and never delays the outcome of any other relay. `ACCEPTED` means only that this relay acknowledged the publication.

## 7. Events

`SdkEventKind` is closed. Every event is a frozen, closed object `{ kind, ...fields }`:

| Kind | Fields |
| --- | --- |
| `CLIENT_STATE_CHANGED` | `clientState` |
| `DELIVERY_STATE_CHANGED` | `deliveryId`, `state`, `terminal`, `lastCode` |
| `MESSAGE_RECEIVED` | `sender` (lowercase 64-hex public key the inbound structure was verified against), `payload` (a fresh `Uint8Array` returned by the session port's `open`) |
| `INBOUND_DISCARDED` | `code` (`E_SDK_INBOUND_INVALID`, `E_SDK_SESSION_FAILED` or `E_SDK_UNKNOWN_CODE`) |

Rules:

- Listeners are called asynchronously, after the state change they report is recorded, in registration order. An exception thrown or a promise rejected by a listener is caught and ignored; it never changes delivery, state or other listeners.
- `DELIVERY_STATE_CHANGED` is emitted once per transition, and the terminal transition of an item is emitted exactly once while the client lives. Events are not replayed to listeners registered later.
- `MESSAGE_RECEIVED` carries no relay URL, transport identifier, timing or raw transport event. It may be emitted more than once for the same message (§2 bound 2 and §4.3).

## 8. Injected ports

All ports are caller-supplied objects. The SDK calls them only through the methods below, treats every return value as untrusted, and validates its shape. Every storage, session and identity port method may be synchronous or return a promise. A port call that throws, rejects, returns a malformed value, or does not settle within the port-call timeout is a failure of that port (`E_SDK_STORAGE_FAILED`, `E_SDK_SESSION_FAILED` or `E_SDK_IDENTITY_FAILED`). The port-call timeout is always finite: `C-DLV` fixes its value, which never exceeds the client's `delivery.perRelayTimeoutMs`, and the SDK enforces it with the host's own `setTimeout`, not with the injected clock port, so neither a port that never settles nor a clock whose timers never fire can hold a method open past that bound. Clock and random port methods (§8.4) are called synchronously; a promise or other non-synchronous return from them is an invalid value. The SDK never reads a port's other properties, never wraps or replaces a port, and never serialises a port object.

No port may be backed, inside the lane, by `styx-js/src/storage/**`, `styx-js/src/crypto/**`, `styx-js/src/config/**`, `styx-js/apps/**` or the M2 session adapter. Lane code does not import those paths (§9). Wiring the SDK to the M2 adapter or to durable storage is a separate owner act; until then any such wiring is unsupported and carries no claim.

### 8.1 Storage port (`ports.storage`)

The outbound queue lives in memory behind this port in the early lane. The lane's implementation (card `I-QUEUE`) is an in-memory store; there is no durable implementation.

| Method | Input | Success return |
| --- | --- | --- |
| `put(record)` | an SDK-internal outbound record | `true` |
| `get(deliveryId)` | string | the record, or `null` |
| `update(deliveryId, record)` | string, record | `true`; `false` if absent |
| `remove(deliveryId)` | string | `true`; `false` if absent |
| `list()` | — | array of records |

Records are opaque to the port and SDK-internal; their fields are fixed by `C-DLV` and are not a persisted format. The port stores and returns them without interpretation. Holding a record in the port is not a delivery guarantee. Even if a caller injects a store that outlives the process, the SDK makes no cross-restart claim: `start()` REJECTs a non-empty store with `E_SDK_STORAGE_NOT_EMPTY` and never resumes, replays or re-sends a stored item.

### 8.2 Session port (`ports.session`)

| Method | Input | Success return |
| --- | --- | --- |
| `seal({ recipient, plaintext })` | lowercase 64-hex string, `Uint8Array` | `{ ciphertext }`, a non-empty `Uint8Array` |
| `open({ sender, ciphertext })` | lowercase 64-hex string, `Uint8Array` | `{ plaintext }`, a `Uint8Array` |

The SDK seals every outbound payload once in `send` and stores only the sealed bytes; retransmissions reuse those bytes and never call `seal` again. The SDK never inspects ciphertext. A session port that returns its input unchanged is allowed in tests; then no payload confidentiality exists, and the SDK claims none in any case. The early lane provides no session-backed encryption through the M2 adapter.

### 8.3 Signing and identity port (`ports.identity`)

| Method | Input | Success return |
| --- | --- | --- |
| `getPublicKey()` | — | lowercase 64-hex string |
| `sign({ digest })` | 32-byte `Uint8Array` | 64-byte `Uint8Array` signature over `digest` |

- Secret key material never crosses this interface. The SDK never receives, stores, logs, derives or exports a secret key, and it never constructs a transport object that requires one. `NostrTransport` is not imported by the lane: it signs internally with a secret key it is given and, without one, emits an all-zero signature that relays are expected to reject, so it is not usable with this port. The delivery layer instead builds each SDK-internal outbound event, computes its digest, obtains the signature from `identity.sign`, and publishes the signed event through `RelayPool`.
- The SDK calls `getPublicKey()` once in `start()` and uses that value for the client's lifetime. A different value later is not observed.
- The SDK does not verify the meaning of a signature beyond what `C-DLV` specifies for inbound structures. `sign` is used only for SDK-internal outbound structures of this version.
- The identity is whatever the caller injects. It is not a Milestone 4 per-case identity or return capability.

### 8.4 Clock and randomness

| Port | Methods |
| --- | --- |
| `clock` | `now()` → finite number of milliseconds; `setTimer(callback, delayMs)` → opaque handle; `clearTimer(handle)` |
| `random` | `nextUint32()` → integer in `[0, 2^32)` |

They exist so that timing and backoff jitter are deterministic in tests. They are not security inputs; `deliveryId` generation is not required to use them. A clock or random function that throws or returns an invalid value is `E_SDK_INTERNAL` for the affected operation and moves an affected item to its applicable terminal failed state.

## 9. Exact allowed imports

This section is the upper bound for every lane module under `styx-js/src/sdk/**` and every lane test under `styx-js/test/sdk/**`, except the preview tests under `styx-js/test/sdk/flegias-preview/**` and the preview files under `styx-js/examples/flegias-preview/**`. The preview's imports are fixed by its own contract within the scope record's `importRule` (which also lets preview files import other preview files and Node and browser built-ins); this document neither widens nor narrows them. Each card contract enumerates its own exact subset; nothing outside this table may be imported, and dynamic `import()` and `require()` of any specifier outside it are forbidden as well.

| Specifier (resolved path) | Imported names | Allowed in | Purpose |
| --- | --- | --- | --- |
| `styx-js/src/sdk/**` lane modules present at the importing card's base or in its own allowlist | any of their exports | `src/sdk`, `test/sdk` | composition |
| `styx-js/src/utils.js` (unchanged) | a subset of its existing exports, only: `EventEmitter`, `uuidv4`, `bytesToHex`, `hexToBytes`, `utf8Encode`, `utf8Decode`, `randomBytes`, `constantTimeEqual`, `concatBytes`, `bytesToBase64`, `base64ToBytes`, `secureZero` (its other exports, `uint32BE` and `readUint32BE`, are not allowed) | `src/sdk`, `test/sdk` | helpers |
| `styx-js/src/transport/transport-interface.js` (unchanged) | `TransportInterface`, `TransportState`, `TransportMessage` | `src/sdk`, `test/sdk` | existing transport types |
| `styx-js/src/transport/nostr-transport.js` (unchanged) | `RelayPool` | `src/sdk`, `test/sdk` | existing relay access; signed events are published with `RelayPool.publish` or `RelayPool.publishAndVerify` (§8.3) |
| `@noble/hashes/sha256` (declared runtime dependency) | `sha256` | `src/sdk`, `test/sdk` | digest of SDK-internal structures, outbound and inbound (including the digest checked by inbound signature verification) |
| `@noble/curves/secp256k1` (declared runtime dependency) | `schnorr` | `src/sdk` for `schnorr.verify` only; `test/sdk` also for key generation and signing inside test identity ports | inbound signature check; test keys |
| `@jest/globals` (declared development dependency) | `describe`, `test`, `it`, `expect`, `beforeAll`, `beforeEach`, `afterAll`, `afterEach`, `jest` | `test/sdk` only | test runner |
| `ws` (declared development dependency) | `WebSocket`, `WebSocketServer` | `test/sdk` only | loopback relays started inside the test and a `WebSocket` implementation for Node |
| Node built-ins `node:assert`, `node:events`, `node:net`, `node:http`, `node:timers`, `node:timers/promises`, `node:crypto` | any | `test/sdk` only | test harness |
| Web/runtime globals `WebSocket`, `crypto.getRandomValues`, `setTimeout`, `clearTimeout`, `Date`, `TextEncoder`, `TextDecoder`, `Uint8Array`, `Promise`, `queueMicrotask` | — | `src/sdk`, `test/sdk` | runtime |

Rules:

- Modules under `styx-js/src/sdk/**` import no `node:` built-in. They run unchanged in a browser, and in Node only when the host provides a global `WebSocket` (Node 18 does not); a test that needs `WebSocket` in Node supplies it from `ws`.
- No module or test imports `styx-js/src/storage/**`, `styx-js/src/crypto/**`, `styx-js/src/config/**`, `styx-js/apps/**`, any other file under `styx-js/src/transport/**`, or any other export of the two allowed transport files, including `OutboxWorker`, `TransportFailover`, `WebRTCTransport`, `BroadcastChannelTransport` and `NostrChatTransport`.
- Test files may import test files in their own card's allowlist. No shared test-helper file exists outside a card's allowlist.
- No new runtime or development dependency, lockfile change, vendored WASM change, pin change or ciphersuite change is allowed. `styx-js/package.json` is not changed.
- Lane tests connect only to loopback relays they start inside the test. Lane code, tests and examples contain no non-loopback `ws://` or `wss://` URL, and no module under `styx-js/src/sdk/**` contains any relay URL literal.

## 10. Non-claims and gates

The SDK is experimental, internal to the repository, not audited, not a product and not authorized for sensitive use. It claims no exactly-once delivery, ordering, cross-restart reliability, durable persistence, payload confidentiality beyond the injected session port, identity hiding, unlinkability, padding, timing protection, onion routing or metadata protection. Relay acceptance and recipient receipt are distinct, and neither proves that a person read a message.

These statements stay in force verbatim:

- "Styx is under active development and has **not** completed an independent security audit. Do not use current builds for sensitive, high-risk, or life-critical use."
- "C0.3 remains `NO-GO` for implementation alignment, demo, product, and sensitive use."

Implementation of this interface (`I-SDK`) starts only after every `beforeImplementation` gate of the M3 scope record holds, including the owner hash-ratification of this exact file, of `C-DLV` and of `O-SCEN3`, and their merge into `m3/integration`.

## 11. Machine-readable normative record

The JSON below is normative and closed. Prose clarifies but does not widen it. Duplicate keys are invalid.

<!-- styx-m3-sdk-interface-json:v1:start -->
```json
{
  "schema": "styx-m3-sdk-interface/v1",
  "closed": true,
  "sdkInterfaceVersion": "styx-m3-sdk/0.1.0-experimental",
  "stability": "experimental-no-stability-promise",
  "publicModule": "styx-js/src/sdk/index.js",
  "implementationModule": "styx-js/src/sdk/client.js",
  "packageJsonChanged": false,
  "exports": [
    "SDK_INTERFACE_VERSION",
    "SdkResultCode",
    "DeliveryState",
    "RelayOutcome",
    "ClientState",
    "SdkEventKind",
    "isKnownResultCode",
    "createStyxClient"
  ],
  "config": {
    "required": ["interfaceVersion", "relays", "ports"],
    "optional": ["clock", "random", "delivery"],
    "relays": { "minItems": 1, "maxItems": 16, "distinct": true, "schemes": ["ws:", "wss:"], "userinfo": false, "fragment": false, "defaultList": false, "hosts": "loopbackIpLiteralOnly" },
    "ports": ["storage", "session", "identity"],
    "delivery": {
      "fields": ["maxAttempts", "deadlineMs", "perRelayTimeoutMs", "receiptMode"],
      "numericRule": "positive safe integer within C-DLV bounds; absent means C-DLV finite default",
      "receiptMode": ["RECIPIENT_RECEIPT", "RELAY_ACCEPTANCE_ONLY"]
    },
    "unknownField": "E_SDK_INVALID_CONFIG"
  },
  "clientStates": ["CREATED", "RUNNING", "STOPPED"],
  "methods": {
    "start": { "allowedIn": ["CREATED"], "codes": ["E_SDK_ALREADY_STARTED", "E_SDK_CLIENT_STOPPED", "E_SDK_STORAGE_NOT_EMPTY", "E_SDK_NO_RELAY_AVAILABLE", "E_SDK_STORAGE_FAILED", "E_SDK_IDENTITY_FAILED", "E_SDK_INTERNAL", "E_SDK_UNKNOWN_CODE"] },
    "send": { "allowedIn": ["RUNNING"], "codes": ["E_SDK_NOT_STARTED", "E_SDK_CLIENT_STOPPED", "E_SDK_INVALID_ARGUMENT", "E_SDK_PAYLOAD_TOO_LARGE", "E_SDK_QUEUE_FULL", "E_SDK_STORAGE_FAILED", "E_SDK_SESSION_FAILED", "E_SDK_INTERNAL", "E_SDK_UNKNOWN_CODE"] },
    "getDelivery": { "allowedIn": ["RUNNING", "STOPPED"], "codes": ["E_SDK_NOT_STARTED", "E_SDK_INVALID_ARGUMENT", "E_SDK_UNKNOWN_DELIVERY", "E_SDK_STORAGE_FAILED", "E_SDK_INTERNAL", "E_SDK_UNKNOWN_CODE"] },
    "cancel": { "allowedIn": ["RUNNING"], "codes": ["E_SDK_NOT_STARTED", "E_SDK_CLIENT_STOPPED", "E_SDK_INVALID_ARGUMENT", "E_SDK_UNKNOWN_DELIVERY", "E_SDK_DELIVERY_TERMINAL", "E_SDK_STORAGE_FAILED", "E_SDK_INTERNAL", "E_SDK_UNKNOWN_CODE"] },
    "onEvent": { "allowedIn": ["CREATED", "RUNNING", "STOPPED"], "codes": ["E_SDK_INVALID_ARGUMENT", "E_SDK_INTERNAL", "E_SDK_UNKNOWN_CODE"] },
    "shutdown": { "allowedIn": ["CREATED", "RUNNING"], "codes": ["E_SDK_CLIENT_STOPPED"] }
  },
  "createStyxClientCodes": ["E_SDK_UNSUPPORTED_VERSION", "E_SDK_INVALID_CONFIG"],
  "resultEnvelope": { "success": ["ok", "value"], "failure": ["ok", "code"], "neverRejects": true, "neverThrows": true },
  "resultCodes": [
    "E_SDK_UNSUPPORTED_VERSION",
    "E_SDK_INVALID_CONFIG",
    "E_SDK_INVALID_ARGUMENT",
    "E_SDK_PAYLOAD_TOO_LARGE",
    "E_SDK_NOT_STARTED",
    "E_SDK_ALREADY_STARTED",
    "E_SDK_CLIENT_STOPPED",
    "E_SDK_STORAGE_NOT_EMPTY",
    "E_SDK_NO_RELAY_AVAILABLE",
    "E_SDK_QUEUE_FULL",
    "E_SDK_UNKNOWN_DELIVERY",
    "E_SDK_DELIVERY_TERMINAL",
    "E_SDK_STORAGE_FAILED",
    "E_SDK_SESSION_FAILED",
    "E_SDK_IDENTITY_FAILED",
    "E_SDK_INBOUND_INVALID",
    "E_SDK_INTERNAL",
    "E_SDK_UNKNOWN_CODE"
  ],
  "inboundDiscardCodes": ["E_SDK_INBOUND_INVALID", "E_SDK_SESSION_FAILED", "E_SDK_UNKNOWN_CODE"],
  "unknownValuePolicy": {
    "methodResult": "E_SDK_UNKNOWN_CODE",
    "appliesTo": "nonTerminalOutboundItems",
    "terminalItemsUnchanged": true,
    "outboundItemBeforeAcceptance": "FAILED_NOT_ACCEPTED",
    "outboundItemAfterAcceptance": "FAILED_NO_RECEIPT",
    "afterAcceptanceMode": "RECIPIENT_RECEIPT",
    "consumer": "treat as failure; never infer success, acceptance or receipt"
  },
  "deliveryStates": {
    "QUEUED": { "terminal": false },
    "IN_FLIGHT": { "terminal": false },
    "RELAY_ACCEPTED_AWAITING_RECEIPT": { "terminal": false },
    "RELAY_ACCEPTED": { "terminal": true, "success": true, "mode": "RELAY_ACCEPTANCE_ONLY" },
    "RECIPIENT_RECEIPT_RECEIVED": { "terminal": true, "success": true, "mode": "RECIPIENT_RECEIPT" },
    "FAILED_NOT_ACCEPTED": { "terminal": true, "success": false },
    "FAILED_NO_RECEIPT": { "terminal": true, "success": false, "mode": "RECIPIENT_RECEIPT" },
    "CANCELLED": { "terminal": true, "success": false },
    "LOST_ON_SHUTDOWN": { "terminal": true, "success": false }
  },
  "transitions": {
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
  "snapshotFields": ["deliveryId", "recipient", "state", "terminal", "attempts", "createdAt", "deadlineAt", "lastCode", "relayOutcomes"],
  "relayOutcomes": ["PENDING", "ACCEPTED", "REJECTED", "TIMED_OUT", "UNREACHABLE"],
  "events": {
    "CLIENT_STATE_CHANGED": ["clientState"],
    "DELIVERY_STATE_CHANGED": ["deliveryId", "state", "terminal", "lastCode"],
    "MESSAGE_RECEIVED": ["sender", "payload"],
    "INBOUND_DISCARDED": ["code"]
  },
  "ports": {
    "storage": ["put", "get", "update", "remove", "list"],
    "session": ["seal", "open"],
    "identity": ["getPublicKey", "sign"],
    "clock": ["now", "setTimer", "clearTimer"],
    "random": ["nextUint32"]
  },
  "portFailureCodes": { "storage": "E_SDK_STORAGE_FAILED", "session": "E_SDK_SESSION_FAILED", "identity": "E_SDK_IDENTITY_FAILED", "clock": "E_SDK_INTERNAL", "random": "E_SDK_INTERNAL" },
  "secretKeyMaterialCrossesInterface": false,
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
  "imports": {
    "lane": "styx-js/src/sdk/** modules present at the importing card base or in its own allowlist",
    "utils": { "path": "styx-js/src/utils.js", "names": ["EventEmitter", "uuidv4", "bytesToHex", "hexToBytes", "utf8Encode", "utf8Decode", "randomBytes", "constantTimeEqual", "concatBytes", "bytesToBase64", "base64ToBytes", "secureZero"] },
    "transport": {
      "styx-js/src/transport/transport-interface.js": ["TransportInterface", "TransportState", "TransportMessage"],
      "styx-js/src/transport/nostr-transport.js": ["RelayPool"]
    },
    "packages": {
      "@noble/hashes/sha256": { "names": ["sha256"], "allowedIn": ["src", "test"] },
      "@noble/curves/secp256k1": { "names": ["schnorr"], "allowedIn": ["src", "test"], "srcUse": "verify only" },
      "@jest/globals": { "names": ["describe", "test", "it", "expect", "beforeAll", "beforeEach", "afterAll", "afterEach", "jest"], "allowedIn": ["test"] },
      "ws": { "names": ["WebSocket", "WebSocketServer"], "allowedIn": ["test"] }
    },
    "nodeBuiltinsTestOnly": ["node:assert", "node:events", "node:net", "node:http", "node:timers", "node:timers/promises", "node:crypto"],
    "noImport": ["styx-js/src/storage/**", "styx-js/src/crypto/**", "styx-js/src/config/**", "styx-js/apps/**"],
    "forbiddenTransportExports": ["OutboxWorker", "TransportFailover", "WebRTCTransport", "BroadcastChannelTransport", "NostrChatTransport"],
    "newDependency": false
  },
  "network": { "laneTestRelays": "loopback only, started inside the test", "relayUrlLiteralInSrcSdk": false },
  "ownedByCDlv": ["queue transitions timing", "retransmission and backoff bounds", "maxAttempts, deadlineMs, perRelayTimeoutMs bounds and defaults", "payload maximum", "queue bound", "port call timeout value (finite, at most perRelayTimeoutMs, enforced by the host timer)", "receipt structure and validation", "duplicate handling", "per-relay outcome rules", "SDK-internal record and on-wire structures, including message identifiers, receipts, acknowledgements, Nostr event kinds and tags", "terminal processing slack"],
  "cDlvMayNotChange": ["exports", "config fields", "methods", "result codes", "delivery states", "transitions", "relay outcomes", "public SDK event kinds and fields (section 7)", "port methods", "outer bounds", "imports"]
}
```
<!-- styx-m3-sdk-interface-json:v1:end -->

## 12. Conformance

A conforming implementation (card `I-SDK`) and its tests demonstrate at least: every code of `resultCodes` is reachable or is shown unreachable by construction for that method; every method returns the envelope and never rejects or throws; unknown codes, states and outcomes from a stubbed component or port fail closed as in §5.3; every delivery state and allowed transition is exercised and no other transition occurs; `shutdown()` reports every non-terminal item as `LOST_ON_SHUTDOWN` and leaves no timer, connection or listener active; a hung relay does not delay the per-relay outcome of another relay; `start()` rejects a non-empty storage port; no secret key material is passed to the SDK; and the static import check of §9 passes for every lane file.

A conforming validator of the record in §11 rejects: an unknown or missing field; a duplicate key; a code, state, outcome, event kind or port method outside the closed lists; a state without `terminal`; a transition from a terminal state; a transition target outside `deliveryStates`; a method code outside `resultCodes`; a method missing from `methods`; and any `outerBounds` value different from the one above. A conforming implementation never returns, from a method, a code outside that method's own `codes` list in the record; such a return is a conformance failure, not merely a validator concern.

## 13. Authority and ratification

This contract implements card `C-SDK` of the M3 scope record (Issue #400 comment `5950987413`) under the owner act in Issue #400, on base `m3/integration` at `e0fe27ae1b02ad35d80fa70cbb0f2ac64fbf812a`. Its only file is `docs/architecture/m3/sdk-interface.md`.

The final file SHA-256 must be owner hash-ratified by a `styx-m3-ratification:v1` comment on #400 before `C-DLV` relies on it as ratified and before any dependent implementation. Any byte change voids that ratification. Removing this file fully rolls back `C-SDK`; no code, dependency or persisted bytes are introduced.
