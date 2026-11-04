# M3 early-lane public SDK interface contract

Status: normative candidate for card `C-SDK` of the M3 early lane. It is experimental and versioned, and it makes no stability promise to third parties. Dependent implementation stays blocked until the owner hash-ratifies the SHA-256 of this exact file and every other `beforeImplementation` gate of the M3 scope record is met.

## 1. Scope and boundaries

This document defines the public JavaScript interface of the early-lane SDK: its entry points, its closed result and error codes, its delivery-state enumeration, the ports through which storage, session and signing/identity capabilities are injected, its versioning, and the exact imports allowed to the modules that implement it. **MUST**, **MUST NOT** and **REJECT** are normative.

It is a JavaScript runtime-profile API under Section 9 item 5 of `docs/protocol/protocol-hardening-plan.md`, authorized by the owner act in Issue #400 §2(a). It is not the item-2 language-neutral application-core interface, it is not the M2 internal session adapter API (`docs/architecture/m2/adapter-contract.md` on `m2/integration`), and it is not protocol authority. Nothing here selects a Styx protocol semantic, a Marmot or Nostr envelope standard, or a normative wire or persisted format.

The interface is consumed only inside the repository: by lane tests, by the synthetic-only preview once that is separately authorized, and by later lane cards. `styx-js/package.json` and its `exports` map are not changed, so the SDK is not a published package entry point. `styx-js/src/index.js` does not re-export it.

Delivery behaviour behind this interface (queue transitions, retransmission and backoff bounds, receipts and acknowledgements, duplicate handling, per-relay timeouts and the meaning of each per-relay outcome) is fixed by the separate delivery-layer contract `C-DLV` (`docs/architecture/m3/delivery-layer.md`). `C-DLV` MUST NOT add, remove or rename an entry point, configuration field, method, result code, delivery state, transition, per-relay outcome, public SDK event kind or public SDK event field (§7), port method, outer bound or allowed import defined here; any such change needs a new hash-ratified version of this document. This boundary covers only the public SDK surface seen by a consumer. SDK-internal structures behind it (on-wire message identifiers, receipts, acknowledgements, Nostr event kinds and tags, and the fields of internal records) are owned entirely by `C-DLV` and are not frozen here; the public §7 events are SDK callback objects, not on-wire event kinds.

M3-INVITE #525 adds caller-port invitation orchestration only. The identity port, not the SDK, constructs and reverses the NIP-59 layers (kind 13 seal and kind 1059 wrap, NIP-44 v2); the session port supplies every MLS operation. Experimental kinds 4743 and 4744 are SDK-internal and versioned, not Marmot kinds or compatibility. The SDK implements neither construction. The single real-engine test exception of §8 does not authorize product wiring.

## 2. Outer bounds inherited from #400

These bounds are part of the interface. No value, state or event defined here claims more than they allow.

1. **Finite attempts and deadline.** Every outbound item has a finite attempt count and a finite deadline. When either is exhausted without the item's success state, the item reaches a terminal failed state. There is no unbounded retransmission.
2. **No exactly-once, ordering or cross-restart guarantee.** A message may be received zero, one or more times, and in any order relative to other messages. Nothing persists or resumes across process restarts. This is the default and stays in force without `ports.receiveState`. The only exception is the conditional durable-receive exception of §8.5: with `ports.receiveState` configured, every admitted inbound kind-4741 event whose `stage` has completed durably stays recoverable locally across stop, restart and crash; no event id whose outcome was durably committed is passed to MLS processing again (an attempt that was not committed may be repeated on the previous authoritative state, in the same run or after restart); and every committed application result is redelivered until it is acknowledged. Before `stage` completes, recovery still depends on the relays. The exception rests on caller semantics the SDK cannot verify (§8.2, §8.5), resumes no outbound item, and adds no completeness, global ordering or exactly-once claim for application effects.
3. **Relay acceptance is not recipient receipt.** `RELAY_ACCEPTED` and `RELAY_ACCEPTED_AWAITING_RECEIPT` mean only that at least one relay acknowledged the publication. `RECIPIENT_RECEIPT_RECEIVED` means only that a receipt attributed to the recipient identity was received and validated as `C-DLV` specifies. Neither proves that a person read the message.
4. **Process lifetime only.** Delivery guarantees hold only within one process lifetime. On an explicit, orderly `shutdown()`, every non-terminal item is reported as `LOST_ON_SHUTDOWN`. After a crash or abrupt termination nothing is reported and nothing is recovered; no claim is made for that case. The sole exception is the inbound receive state recovered under the conditional durable-receive exception of bound 2.
5. **No normative wire format.** Any on-wire structure the SDK produces or consumes (message identifier, receipt, acknowledgement, event kind or tag) is SDK-internal, experimental and versioned with `sdkWireVersion`, independently of `sdkInterfaceVersion`. It is not normative. Using the allowed transport exports with the event formats they already produce selects no new semantic.
6. **Relay URLs are injected only.** Relay endpoints reach the SDK only through `config.relays`. No module under `styx-js/src/sdk/**` contains a relay URL literal, a relay host name, a default relay list or a fallback relay. Hosts are limited by §4.1 and reach the SDK only through caller configuration.

The SDK makes no confidentiality, integrity, authenticity, identity-hiding, unlinkability, padding, timing or metadata-protection claim of its own. Payload protection is exactly what the injected session port provides, and the SDK does not inspect or attest it. Relays and network observers see public keys, timing, sizes and network metadata.

## 3. Versioning

- The exact interface version string is `styx-m3-sdk/0.4.0-experimental`. It is exported as the constant `SDK_INTERFACE_VERSION`. It replaces `styx-m3-sdk/0.3.1-experimental` (M3-RECEIVE-1, #556 and #557); a configuration carrying the older string returns `E_SDK_UNSUPPORTED_VERSION`.
- Independently, `SDK_WIRE_VERSION` is `styx-m3-sdk/0.3.0-experimental`, exported by `wire-version.js` and re-exported by the public module. It alone is written/checked in every `v` tag of kinds 4741, 4742, 4743 and the 4744 Welcome rumor. Kinds 1059 and 13 are unchanged and carry no new `v` tag. This preserves the existing experimental 0.3.0 wire; it is not a protocol interoperability claim. Interface 0.4.0 changes no kind, tag, field, content or bound on the wire.
- `createStyxClient(config)` requires `config.interfaceVersion` to equal that string exactly (byte-for-byte, case-sensitive). Any other value, including a missing one, returns `E_SDK_UNSUPPORTED_VERSION` and creates no client. There is no negotiation, range, downgrade or fallback.
- The version is experimental. It carries no stability, compatibility or deprecation promise to third parties before a later owner act. Any change to an entry point, field, code, state, event kind, port method, bound inherited from §2 or allowed import requires a new hash-ratified version of this document with a new version string.
- SDK-internal on-wire structures carry or are keyed by `SDK_WIRE_VERSION`, not `SDK_INTERFACE_VERSION`, as `C-DLV` specifies; an inbound delivery structure from any other wire version is not interpreted: it emits `INBOUND_DISCARDED` with `E_SDK_INBOUND_INVALID` and nothing else. Invitation candidates on their independent subscriptions are instead ignored without an event (§4.2).

## 4. Entry points

The single public module is `styx-js/src/sdk/index.js` (card `I-SDK`). It exports exactly these names and nothing else:

| Export | Kind | Purpose |
| --- | --- | --- |
| `SDK_INTERFACE_VERSION` | frozen string constant | §3. |
| `SDK_WIRE_VERSION` | frozen string constant | Independent experimental wire tag value (§3). |
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
| `relays` | yes | array of 1 to 16 distinct strings. Each is either a syntactically valid absolute `ws:` or `wss:` URL with no userinfo and no fragment whose host is a loopback IP literal (IPv4 in the loopback block or the IPv6 loopback address), under the unchanged I-SDK RFC 3986 loopback rule; or an allowlisted remote URL under the rule below. Order and every accepted string are preserved unchanged; nothing is added, removed, normalised or reordered. Every other value REJECTs with `E_SDK_INVALID_CONFIG`. |
| `publicRelayHosts` | no | array of 1 to 16 pairwise distinct host-name strings under the exact ASCII rule below. Absent means no remote relay is allowed; present `undefined` is invalid. |
| `ports` | yes | closed object `{ storage, session, identity, receiveState? }`; `storage`, `session` and `identity` are required and must expose their required methods of §8 as functions. The optional invitation group comprises all five session/identity methods of §8.2–§8.3 or none; any partial or non-function group REJECTs with `E_SDK_INVALID_CONFIG`. Without the group, every invitation method returns `E_SDK_NOT_CONFIGURED` in `RUNNING` without calling a port. The optional `receiveState` port (§8.5) is an object or function exposing all seven methods of §8.5 as functions, and when it is present the session port must also expose `openCandidate` and `isKnownSender` (§8.2) as functions; a `receiveState` that is `null` or a primitive, or that lacks any of its seven methods as a function, REJECTs with `E_SDK_INVALID_CONFIG`, as does a missing session method. |
| `receive` | no | allowed only with `ports.receiveState`; otherwise `E_SDK_INVALID_CONFIG`. A closed plain object whose optional fields are positive safe integers at most their maximum: `maxPending` (default 4 096, maximum 65 536), `maxUnacknowledged` (default 4 096, maximum 65 536), `maxSeen` (default 1 048 576, maximum 16 777 216), `maxStoredBytes` (default 268 435 456, maximum 4 294 967 296). An absent field takes its default; an unknown field, `0`, a negative, non-integer or out-of-bound value REJECTs with `E_SDK_INVALID_CONFIG`. The quotas apply as §8.5 states. |
| `clock` | no | closed object `{ now, setTimer, clearTimer }` (§8.4). Absent means the built-in `Date.now`, `setTimeout` and `clearTimeout`. |
| `random` | no | closed object `{ nextUint32 }` (§8.4). Absent means the built-in `crypto.getRandomValues`. |
| `delivery` | no | closed object `{ maxAttempts, deadlineMs, perRelayTimeoutMs, receiptMode }`. Each numeric field, when present, is a positive safe integer within the bounds `C-DLV` fixes; `receiptMode` is `RECIPIENT_RECEIPT` or `RELAY_ACCEPTANCE_ONLY`. An absent field takes the finite default `C-DLV` fixes. `Infinity`, `NaN`, `0`, negatives, non-integers and out-of-bound values REJECT. |

The `publicRelayHosts` host-name rule is: 1–253 characters, at least two labels separated by single dots, no leading or trailing dot; each label has 1–63 characters from lowercase ASCII `a`–`z`, `0`–`9` and `-`, neither starting nor ending with `-`. The last label matches neither `^[0-9]+$` nor `^0x[0-9a-f]*$` (no WHATWG ends-in-a-number IPv4 reading; `0xzz` remains a label). Uppercase, non-ASCII, `%`, `_`, `:` and every other character REJECT; nothing is normalised. Internationalised names use their ASCII `xn--` form.

A remote relay URL requires scheme `wss`, compared case-insensitively (RFC 3986 §3.1), an authority consisting of exactly an RFC 3986 reg-name host whose ASCII-lowercased form equals a `publicRelayHosts` entry byte for byte, an empty path or exactly `/`, and no query or fragment. No userinfo or colon is allowed in that authority: an empty port, explicit `:443` and every other explicit port REJECT; default 443 (RFC 6455) is used. Non-loopback `ws:` and non-loopback IP literals always REJECT. Loopback parsing is unchanged, including its existing path, query and port rules. The lifting is authorized only by the public relays act #317 comments `6316724633` and `6316738209`, adopted by current scope replacement4 #400/6426737491 and M3-PUBLIC-RELAYS #522 approval #400/6489853937; it is not a DNS, TLS or deployment assurance.

Validation is total and happens before any side effect. The first failing rule determines the code: `E_SDK_UNSUPPORTED_VERSION`, then `E_SDK_INVALID_CONFIG` for every other field. No partially constructed client is ever returned.

### 4.2 Client methods

Every method below is asynchronous and **always resolves** to a result envelope (§5.1); it never rejects and never throws, including for invalid arguments, port failures and internal faults. Every argument object is closed; unknown fields REJECT with `E_SDK_INVALID_ARGUMENT`.

| Method | Allowed client state | Success `value` | Effect |
| --- | --- | --- | --- |
| `start()` | `CREATED` | `{ clientState: 'RUNNING', connectedRelays }` | Checks that the storage port holds no item (otherwise `E_SDK_STORAGE_NOT_EMPTY`), connects to the configured relays as `C-DLV` specifies, and subscribes for inbound messages and receipts addressed to the identity port's public key. Its relay-connection phase ends no later than one per-relay timeout after it begins (measured by the clock port of §8, with the same host-`setTimeout` backstop that §8 uses for port calls, so a clock whose timers never fire cannot extend it) and never waits longer on a relay that hangs; port calls made by `start()` are bounded separately as §8 specifies, and a port call that does not settle within that bound is that port's failure. It succeeds when at least one relay has connected by the end of the connection phase, and `connectedRelays` is the number connected when it resolves. If none connects within the per-relay timeout, returns `E_SDK_NO_RELAY_AVAILABLE`. With `ports.receiveState`, after `getPublicKey()` and before any relay connection, `start()` calls `load` once and then runs the recovery pass of §8.5; a failed, timed-out or malformed `load` returns `E_SDK_RECEIVE_STATE_FAILED`, an incompatible snapshot `E_SDK_RECEIVE_STATE_INCOMPATIBLE`, an out-of-set value `E_SDK_UNKNOWN_CODE`, and a recovery pass that leaves the receive state paused or frozen `E_SDK_RECEIVE_STATE_FAILED`; nothing is reset or deleted in either case. Every failed `start()` called in `CREATED`, whatever its code, leaves the client in `CREATED` with no open relay connection, subscription or timer and no cached public key; the SDK closes anything it opened before resolving, and a later `start()` begins from scratch. |
| `send({ recipient, payload })` | `RUNNING` | `{ deliveryId, state: 'QUEUED' }` | Validates, seals `payload` through the session port, stores one outbound item through the storage port, and schedules delivery. Returns before any network attempt completes. |
| `getDelivery({ deliveryId })` | `RUNNING`, `STOPPED` | a delivery snapshot (§6.2) | Read-only. Unknown id returns `E_SDK_UNKNOWN_DELIVERY`. |
| `cancel({ deliveryId })` | `RUNNING` | `{ deliveryId, state: 'CANCELLED' }` | Moves a non-terminal item to `CANCELLED` and stops further attempts. A publication already handed to a relay is not recalled. A terminal item returns `E_SDK_DELIVERY_TERMINAL` and is unchanged. |
| `onEvent(listener)` | any | `{ unsubscribe }` | Registers a function listener for §7 events. Like every method here, `onEvent` resolves to a result envelope; on success its `value` is a frozen object with exactly one property, `unsubscribe`, a function that takes no argument, is synchronous and idempotent, returns `undefined` and never throws. Calling it removes the listener for future reservations; an already-reserved in-flight message retains its audience under §7. It is the only synchronous function the SDK hands back. |
| `shutdown()` | `CREATED`, `RUNNING` | `{ clientState: 'STOPPED', lost }` | Orderly stop, unconditional once called in an allowed state: stops scheduling, moves every non-terminal item to `LOST_ON_SHUTDOWN` and emits its event to the listeners registered before the call, delivering those events before it removes the listeners, closes subscriptions and relay connections, and clears every timer. `lost` is the number of items so reported. After it resolves, the client is `STOPPED`, and the SDK has called `clearTimer` for every timer handle it holds, closed every subscription and relay connection it opened, removed every listener registered before the call, and released its ports, transports and timers; it keeps an immutable terminal snapshot of each of its items so that `getDelivery` in `STOPPED` returns the item's final state (for example `LOST_ON_SHUTDOWN`); it makes no claim about an injected clock that ignores `clearTimer`. A storage port failure, a listener fault or an internal fault during shutdown never prevents these effects: lost reporting uses the SDK's own in-memory view of its items, and the method still resolves success. This is a departure from the no-change-on-failure rule, listed in §5.2. A second call returns `E_SDK_CLIENT_STOPPED`. |

| `publishKeyPackage()` | `RUNNING` | `{ keyPackageEventId, acceptedRelays }` | Create and sign a kind-4743 KeyPackage, publish on an independent relay set and remember its id for this client's lifetime. |
| `invite({ invitee })` | `RUNNING` | `{ keyPackageEventId, welcomeEventId, acceptedRelays }` | Fetch valid kind-4743 events of the named invitee, choose newest `created_at` and lowest id on a tie, call `startSession`, delegate wrap construction, and publish the wrap unchanged. |
| `acceptInvite({ inviter, keyPackageEventId })` | `RUNNING` | `{ inviter }` | Wait on an independent kind-1059 subscription addressed to the own key. Ignore failing candidates, require the explicitly named inviter, and pass the first acceptable Welcome to `joinSession`. |
| `acknowledgeMessage({ eventId })` | `RUNNING`; in `CREATED` only during a `start()` whose `load` succeeded | `{ eventId }` | Acknowledges one application result of the receive state (§8.5): removes its payload from the active durable state through `ack` and ends its redelivery. |

`acknowledgeMessage` rules: `eventId` is 64 lowercase hex digits in a closed argument object (else `E_SDK_INVALID_ARGUMENT`). Once `shutdown()` has been called it returns `E_SDK_CLIENT_STOPPED`; in `CREATED` before a successful `load` it returns `E_SDK_NOT_STARTED`; without `ports.receiveState` it returns `E_SDK_NOT_CONFIGURED` and calls no port. It succeeds for a `READY` id only after at least one reserved listener has been invoked with that entry in the current run (§7.1), through one `ack` write; and, idempotently without a write, for an id already acknowledged. A `READY` id not yet invoked in this run, an unknown id and a rejected id (present only in `seen`) return `E_SDK_UNKNOWN_MESSAGE`. While the receive state is paused or frozen, or when the `ack` write fails, it returns `E_SDK_RECEIVE_STATE_FAILED` (a failed `ack` freezes the receive state, §8.5). Concurrent calls for one id share one write. It is bounded by five port-call timeouts of host time; an internal fault or that bound is `E_SDK_INTERNAL`, and an out-of-set code from the receive state is `E_SDK_UNKNOWN_CODE` (§5.3). An acknowledgement in progress at `shutdown()` completes or fails within that bound.

With `ports.receiveState`, while the receive state is paused or frozen (§8.5), `send`, `publishKeyPackage`, `invite` and `acceptInvite` return `E_SDK_RECEIVE_STATE_FAILED` before any storage, provider or network mutation: `send` after the client-state check, both before and after reading its argument; the invitation methods after the client-state and `E_SDK_NOT_CONFIGURED` checks and before argument validation. Calls already in progress are checked by the caller's coordinator (§8.2).

A call in a client state not listed returns: `E_SDK_NOT_STARTED` in `CREATED`, `E_SDK_ALREADY_STARTED` for `start()` in `RUNNING`, and `E_SDK_CLIENT_STOPPED` in `STOPPED`. A `STOPPED` client never restarts; a new client is created instead, and it does not see the old client's items.

`send` argument rules:

- `recipient` is the recipient identity's public key as a lowercase 64-character hexadecimal string (the form the identity port of §8.3 returns). Anything else REJECTs with `E_SDK_INVALID_ARGUMENT`.
- `payload` is a `Uint8Array` of 1 byte up to the maximum `C-DLV` fixes. An empty or non-`Uint8Array` payload REJECTs with `E_SDK_INVALID_ARGUMENT`; an oversize one with `E_SDK_PAYLOAD_TOO_LARGE`. The SDK copies the bytes before it resolves; later mutation by the caller has no effect.
- `deliveryId` is assigned by the SDK, is unique within the client, and is an opaque string. It carries no meaning outside the process and is never derived from the payload, the recipient or a caller-supplied value.

Invitation argument objects are closed. `invitee` and `inviter` are lowercase 64-hex keys different from the own key. `keyPackageEventId` is 64 lowercase hex digits and identifies a KeyPackage successfully published by this client during its lifetime; otherwise `E_SDK_INVALID_ARGUMENT`. `acceptedRelays` is a frozen ascending array of exactly the `config.relays` indices that answered `OK true` during publication; it attests no peer receipt.

Each invocation owns its relay set, subscription id, connection, fetch/wait and publication phases, and disposes it before resolving; it never changes the delivery relay set. The fetch waits for every connected relay's `EOSE` or at most `perRelayTimeoutMs`. Publication ends at the first acceptance or the C-DLV §5.3 attempt timeout, at most `perRelayTimeoutMs`. `acceptInvite` admits a deadline of `deadlineMs`, checks it immediately before each `joinSession`, and a called `joinSession` decides its result. Clock waits have host `setTimeout` backstops of the same delay (deadline: `deadlineMs + 1000`); port calls use the host port-call timeout. Host bounds: publication/invite ≤ two port-call timeouts + three `perRelayTimeoutMs` + 10 000 ms; accept ≤ `deadlineMs + 1000` + two port-call timeouts + 10 000 ms.

Invalid KeyPackages or wraps, other versions, a wrong seal signer or rumor pubkey, and an `unwrapGift` that throws, rejects, times out or returns malformed/out-of-set data are ignored without any event; waiting continues. A failing `startSession` or `joinSession` is `E_SDK_SESSION_FAILED`; malformed wrap construction is `E_SDK_IDENTITY_FAILED` and nothing is published. There is no rollback of caller state: failed join may consume a KeyPackage while the inviter retains its session; retry needs fresh engines, ports and clients on both sides.

At the synchronous `shutdown()` call every invocation is marked stopped and its relay set frozen. Every wait ends at its next frame or timer callback; no new port call begins, and an in-progress result is discarded when it settles. A late successful join can leave an unreported caller session. Shutdown step (2) does not wait for invitations. After all `LOST_ON_SHUTDOWN` events, step (4) disposes invitation sets concurrently with delivery disposal, each method resolves `E_SDK_CLIENT_STOPPED`, then shutdown resolves. Freezing does not shorten an invitation connection phase; the prior shutdown bound grows by at most one `perRelayTimeoutMs` plus one port-call timeout.

### 4.3 Inbound messages

Inbound application messages are delivered only through `MESSAGE_RECEIVED` events (§7). The SDK passes the inbound ciphertext to the session port's `open` method and emits the event only when `open` returns success. An inbound structure that fails parsing, version checks, signature verification or `open` emits no `MESSAGE_RECEIVED`; it emits `INBOUND_DISCARDED` with one of the three inbound discard codes of §5.2 and no payload, sender, or content-derived field. Duplicate inbound messages may be emitted more than once unless `C-DLV` suppresses them within the process lifetime; the interface makes no exactly-once claim.

With `ports.receiveState`, kind-4741 messages follow §8.5 instead: the session port's `open` is not called for them; an admitted event is staged durably, opened with `openCandidate` and committed, and only a committed application result is emitted as `MESSAGE_RECEIVED` (§7.1), redelivered until `acknowledgeMessage`. A committed rejection emits `INBOUND_DISCARDED` with `E_SDK_SESSION_FAILED` once and is never emitted as a message. Delivery stays at least once; the application de-duplicates by `eventId`.

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

| `E_SDK_NOT_CONFIGURED` | Invitation port group is absent. |

| `E_SDK_PUBLISH_NOT_ACCEPTED` | No relay acknowledged the invitation publication. |

| `E_SDK_KEYPACKAGE_NOT_FOUND` | Fetch found no valid KeyPackage of the invitee. |

| `E_SDK_INVITE_TIMEOUT` | No acceptable Welcome before the wait deadline. |

| `E_SDK_RECEIVE_STATE_FAILED` | The receive-state port failed, threw, timed out or returned a malformed value, or the receive state is paused or frozen (§8.5). |
| `E_SDK_RECEIVE_STATE_INCOMPATIBLE` | `load` reported, or returned, a snapshot of another identity, scope or schema, or one the caller found inconsistent (§8.5). |
| `E_SDK_RECEIVE_STATE_CONFLICT` | (receive-state port and `RECEIVE_STATE_FAILED` only) A write named a revision other than the current one. |
| `E_SDK_RECEIVE_STATE_CAPACITY` | (receive-state port only) A `commit` was refused for capacity and wrote nothing. |
| `E_SDK_UNKNOWN_MESSAGE` | `acknowledgeMessage` named no acknowledgeable application result (§4.2). |

`E_SDK_INBOUND_INVALID`, `E_SDK_SESSION_FAILED` and `E_SDK_UNKNOWN_CODE` are the only codes that appear in `INBOUND_DISCARDED`: the first for parsing, version and signature failures, the second for a failed `open`, the third when a lane component or the session port yields a value outside the closed sets (§5.3). `E_SDK_INBOUND_INVALID` never appears in a method result.

When a method other than `shutdown()` fails, it makes no change visible to the caller as a usable item: an item is either fully created (stored, with its `deliveryId` returned) or not created as a deliverable item. If a storage write may have happened before a later step failed, the SDK removes the item before resolving; if that removal itself fails, the method resolves `E_SDK_STORAGE_FAILED`, and the residual item, if present, is never sent and is reported through events as `FAILED_NOT_ACCEPTED`. For delivery items these are the only two departures from no-change-on-failure: this residual-item rule and the unconditional `shutdown()` of §4.2. Invitation methods create no delivery item and cannot roll back caller session state or a published event (§4.2). The four invitation codes occur only in invitation method results, never in `INBOUND_DISCARDED`. The five codes added by M3-RECEIVE-1 (the last five rows above) never appear in `INBOUND_DISCARDED`; `E_SDK_RECEIVE_STATE_CONFLICT` and `E_SDK_RECEIVE_STATE_CAPACITY` are never returned by a method.

### 5.3 Unknown codes and states fail closed

- **Inside the SDK.** A code, state or outcome produced by a lane component or a port that is not a member of the closed sets here is never forwarded as is. In a result of a client method of §4.2 it becomes `{ ok: false, code: 'E_SDK_UNKNOWN_CODE' }`; `createStyxClient` calls no port or lane component, and any internal fault there returns `E_SDK_INVALID_CONFIG`, never success. For a non-terminal outbound item it moves the item to `FAILED_NOT_ACCEPTED` (if no relay acceptance was recorded) or, in `RECIPIENT_RECEIPT` mode after a relay acceptance was recorded, to `FAILED_NO_RECEIPT`, with `lastCode: 'E_SDK_UNKNOWN_CODE'`, and stops further attempts. A terminal item, including `RELAY_ACCEPTED` in `RELAY_ACCEPTANCE_ONLY` mode (where relay acceptance is itself terminal), is never changed by an unknown value. It never yields `ok: true`, a success state or a success event; the only success that can coexist with an unknown value is the unconditional `shutdown()` result, which reports the affected item as `LOST_ON_SHUTDOWN`, never as delivered.
- **In consumers.** A consumer MUST treat as failure any envelope whose `ok` is not exactly the boolean `true`, any `code` for which `isKnownResultCode` is `false`, any delivery state not in §6 and any event kind not in §7. A consumer MUST NOT infer success, acceptance or receipt from an unknown value.
- Unknown is never mapped to a weaker failure, retried as success, or ignored.
- **Unchanged lane modules.** The outbound queue and the 0.3.1 inbound path read the closed `code` slots of the values they inspect themselves against the code set of interface 0.3.1, so one of the five codes added in 0.4.0 found there reads as unknown (`E_SDK_UNKNOWN_CODE`), a stricter reading. Every other closed `code` slot the client reads uses the set of §5.2.

### 5.4 Method → code table

A method never returns a code outside its row (§12). `E_SDK_RECEIVE_STATE_FAILED`, `E_SDK_RECEIVE_STATE_INCOMPATIBLE` and `E_SDK_UNKNOWN_MESSAGE` are returned only with `ports.receiveState`; without it, `acknowledgeMessage` returns `E_SDK_NOT_CONFIGURED` once started.

| Method | Codes |
| --- | --- |
| `createStyxClient` | `E_SDK_UNSUPPORTED_VERSION`, `E_SDK_INVALID_CONFIG` |
| `start` | `E_SDK_ALREADY_STARTED`, `E_SDK_CLIENT_STOPPED`, `E_SDK_STORAGE_NOT_EMPTY`, `E_SDK_NO_RELAY_AVAILABLE`, `E_SDK_STORAGE_FAILED`, `E_SDK_IDENTITY_FAILED`, `E_SDK_INTERNAL`, `E_SDK_UNKNOWN_CODE`, `E_SDK_RECEIVE_STATE_FAILED`, `E_SDK_RECEIVE_STATE_INCOMPATIBLE` |
| `send` | `E_SDK_NOT_STARTED`, `E_SDK_CLIENT_STOPPED`, `E_SDK_INVALID_ARGUMENT`, `E_SDK_PAYLOAD_TOO_LARGE`, `E_SDK_QUEUE_FULL`, `E_SDK_STORAGE_FAILED`, `E_SDK_SESSION_FAILED`, `E_SDK_INTERNAL`, `E_SDK_UNKNOWN_CODE`, `E_SDK_RECEIVE_STATE_FAILED` |
| `getDelivery` | `E_SDK_NOT_STARTED`, `E_SDK_INVALID_ARGUMENT`, `E_SDK_UNKNOWN_DELIVERY`, `E_SDK_STORAGE_FAILED`, `E_SDK_INTERNAL`, `E_SDK_UNKNOWN_CODE` |
| `cancel` | `E_SDK_NOT_STARTED`, `E_SDK_CLIENT_STOPPED`, `E_SDK_INVALID_ARGUMENT`, `E_SDK_UNKNOWN_DELIVERY`, `E_SDK_DELIVERY_TERMINAL`, `E_SDK_STORAGE_FAILED`, `E_SDK_INTERNAL`, `E_SDK_UNKNOWN_CODE` |
| `onEvent` | `E_SDK_INVALID_ARGUMENT`, `E_SDK_INTERNAL`, `E_SDK_UNKNOWN_CODE` |
| `shutdown` | `E_SDK_CLIENT_STOPPED` |
| `publishKeyPackage` | `E_SDK_NOT_STARTED`, `E_SDK_CLIENT_STOPPED`, `E_SDK_NOT_CONFIGURED`, `E_SDK_NO_RELAY_AVAILABLE`, `E_SDK_INTERNAL`, `E_SDK_UNKNOWN_CODE`, `E_SDK_SESSION_FAILED`, `E_SDK_IDENTITY_FAILED`, `E_SDK_PUBLISH_NOT_ACCEPTED`, `E_SDK_RECEIVE_STATE_FAILED` |
| `invite` | `E_SDK_NOT_STARTED`, `E_SDK_CLIENT_STOPPED`, `E_SDK_NOT_CONFIGURED`, `E_SDK_NO_RELAY_AVAILABLE`, `E_SDK_INTERNAL`, `E_SDK_UNKNOWN_CODE`, `E_SDK_INVALID_ARGUMENT`, `E_SDK_KEYPACKAGE_NOT_FOUND`, `E_SDK_SESSION_FAILED`, `E_SDK_IDENTITY_FAILED`, `E_SDK_PUBLISH_NOT_ACCEPTED`, `E_SDK_RECEIVE_STATE_FAILED` |
| `acceptInvite` | `E_SDK_NOT_STARTED`, `E_SDK_CLIENT_STOPPED`, `E_SDK_NOT_CONFIGURED`, `E_SDK_NO_RELAY_AVAILABLE`, `E_SDK_INTERNAL`, `E_SDK_UNKNOWN_CODE`, `E_SDK_INVALID_ARGUMENT`, `E_SDK_SESSION_FAILED`, `E_SDK_INVITE_TIMEOUT`, `E_SDK_RECEIVE_STATE_FAILED` |
| `acknowledgeMessage` | `E_SDK_NOT_STARTED`, `E_SDK_CLIENT_STOPPED`, `E_SDK_NOT_CONFIGURED`, `E_SDK_INVALID_ARGUMENT`, `E_SDK_UNKNOWN_MESSAGE`, `E_SDK_RECEIVE_STATE_FAILED`, `E_SDK_INTERNAL`, `E_SDK_UNKNOWN_CODE` |

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
| `MESSAGE_RECEIVED` | `sender` (lowercase 64-hex public key the inbound structure was verified against), `payload` (a fresh `Uint8Array` returned by the session port's `open`, or with `ports.receiveState` a fresh copy of the committed plaintext), `eventId` (the 64 lowercase hex event id of the inbound kind-4741 event, with or without `ports.receiveState`) |
| `INBOUND_DISCARDED` | `code` (`E_SDK_INBOUND_INVALID`, `E_SDK_SESSION_FAILED` or `E_SDK_UNKNOWN_CODE`) |
| `RECEIVE_STATE_CAPACITY` | `scope` (the scope literal of §8.5) |
| `RECEIVE_STATE_FAILED` | `code` (`E_SDK_RECEIVE_STATE_FAILED`, `E_SDK_RECEIVE_STATE_CONFLICT` or `E_SDK_UNKNOWN_CODE`) |
| `RECEIVE_STATE_CLOCK_SKEW` | `scope` (the scope literal of §8.5), `relay` (the exact string of `config.relays` concerned) |

Rules:

- Listeners are called asynchronously, after the state change they report is recorded, in registration order. An exception thrown or a promise rejected by a listener is caught and ignored; it never changes delivery, state or other listeners.
- `DELIVERY_STATE_CHANGED` is emitted once per transition, and the terminal transition of an item is emitted exactly once while the client lives. Already emitted events are not replayed to later listeners.
- For `MESSAGE_RECEIVED`, before starting `session.open` the SDK reserves the currently live `onEvent` registrations. With none, the validated event waits as ciphertext under C-DLV's shared 1 024-entry volatile bound; no open, processed-id insertion or receipt occurs. A newly registered listener wakes this queue. All callbacks qualify, including callbacks ignoring that event kind. Admitted messages are opened in local arrival order; no sender/global ordering claim follows.
- Unsubscribing the last listener pauses future opens. A callback reserved for an already-started open remains eligible for that one delivery after unsubscribe or the start of shutdown; no later registration receives that message. Each reserved callback receives its own payload copy asynchronously in registration order. Its invocation, including a throw/rejected promise, authorizes a requested receipt; callback completion/processing/reading is not awaited or attested. Shutdown starts no new open, drops unopened ciphertext, and settles that already-reserved delivery within the existing host-time bounds before disposal. No replay or recovery survives restart.
- `MESSAGE_RECEIVED` carries no relay URL, transport identifier, timing or raw transport event. It may be emitted more than once for the same message (§2 bound 2 and §4.3).
- The three `RECEIVE_STATE_*` kinds occur only with `ports.receiveState` (§8.5) and are delivered like ordinary events. `RECEIVE_STATE_CAPACITY` is emitted once per crossing of a quota; `RECEIVE_STATE_FAILED` once per entry into the paused or frozen condition from the normal one; `RECEIVE_STATE_CLOCK_SKEW` at most once per relay per run. None of them is emitted after `shutdown()` has been called.

The third and fourth rules above (reservation before `session.open`; unsubscription, shutdown and no recovery after restart) describe the path without `ports.receiveState`. With it, kind-4741 messages are emitted under §7.1 instead; `INBOUND_DISCARDED` keeps its three codes.

### 7.1 Emission with `ports.receiveState`

- Only a committed application result (a `READY` entry, §8.5) is emitted, never before its durable `commit` or a `resolve` reporting `committed`, and no ciphertext waits for an audience: admission, staging, opening and committing proceed without a listener.
- A `READY` entry is dispatched when it can reserve the `onEvent` registrations live at that moment, as one reserved delivery with a fresh payload copy per callback in registration order. Without a live registration it stays `READY`; a new registration wakes emission of every unacknowledged `READY` entry. At most one dispatch per entry is scheduled or in flight; further wakeups for it are coalesced.
- `READY` entries are emitted in commit order (loaded entries first, in `load` order): after `load` in `start()` (before the first relay connection), at commit, at each new registration, and by a redelivery pass every 60 000 ms on the clock port while `RUNNING`. Redelivery continues during the run and after restart until `acknowledgeMessage` succeeds for the entry; listener invocation, return, throw or rejection is not acknowledgement.
- The entry is read once when its dispatch runs: an entry acknowledged since the dispatch was scheduled invokes no callback; otherwise it is marked invoked for the current run immediately before its reserved callbacks are called, so a callback may acknowledge it. The invocation, including a throw or rejected promise, makes a requested receipt due (§8.5).
- From the synchronous `shutdown()` call no new dispatch is scheduled; a dispatch already scheduled settles within the existing drain bound. Unacknowledged entries stay `READY` in the receive state.

## 8. Injected ports

All ports are caller-supplied objects. The SDK calls them only through the methods below, treats every return value as untrusted, and validates its shape. Every storage, session, identity and receive-state port method may be synchronous or return a promise. A port call that throws, rejects, returns a malformed value, or does not settle within the port-call timeout is a failure of that port (`E_SDK_STORAGE_FAILED`, `E_SDK_SESSION_FAILED`, `E_SDK_IDENTITY_FAILED` or, for the receive-state port of §8.5, `E_SDK_RECEIVE_STATE_FAILED`; a failure of `openCandidate` or `isKnownSender` follows §8.5). The port-call timeout is always finite: `C-DLV` fixes its value, which never exceeds the client's `delivery.perRelayTimeoutMs`, and the SDK enforces it with the host's own `setTimeout`, not with the injected clock port, so neither a port that never settles nor a clock whose timers never fire can hold a method open past that bound. Clock and random port methods (§8.4) are called synchronously; a promise or other non-synchronous return from them is an invalid value. The SDK never reads a port's other properties, never wraps or replaces a port, and never serialises a port object.

No port may be backed, inside the lane, by `styx-js/src/storage/**`, `styx-js/src/crypto/**`, `styx-js/src/config/**`, `styx-js/apps/**` or the M2 session adapter. Lane code does not import those paths (§9). Wiring the SDK to the M2 adapter or to durable storage is a separate owner act; until then any such wiring is unsupported and carries no claim. Durable receive state behind the optional caller-injected port of §8.5 is the one authorized exception to the latter (M3-RECEIVE-1 scope extension #400/6629916795, shared source #556); the caller implements it, and no lane module backs it. The sole M3-INVITE exception is the unchanged `MlsEngine` and vendored WASM used by `styx-js/test/sdk-mls/invite-mls.test.js`, under #317/6316724633; no product module or other test inherits it.

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

Optional invitation session methods, present exactly when both optional identity methods are present:

| Method | Input | Success return |
| --- | --- | --- |
| `createKeyPackage()` | — | `Uint8Array`, 1–65 536 bytes |
| `startSession({ peer, keyPackage })` | lowercase peer key; KeyPackage bytes | closed `{ welcome, ratchetTree }`, each `Uint8Array`, 1–262 144 bytes |
| `joinSession({ peer, welcome, ratchetTree })` | lowercase peer key and bounded bytes | `true` |

The caller MUST bind the KeyPackage credential to `peer`, create exactly a two-member session in `startSession`, and fail without creation for a wrong credential or existing peer session. `joinSession` MUST fail for a different other member or an existing peer session, else bind the group to `peer`; it may consume local KeyPackage state even on failure. Subsequent `seal`/`open` for that peer use that group. These are caller semantics, not properties the SDK verifies. A size violation is the corresponding session-port failure.

Receive session methods, required exactly when `ports.receiveState` is present (§4.1, §8.5) and called only for kind-4741 events:

| Method | Input | Success return |
| --- | --- | --- |
| `openCandidate({ sender, ciphertext })` | lowercase 64-hex string, non-empty `Uint8Array` | closed `{ receiveOutcome, ticket, plaintext? }`: `receiveOutcome` is `application`, `retry` or `reject` (its own closed set, never a `RelayOutcome`); `plaintext`, a `Uint8Array`, is present exactly for `application`; `ticket` is present, opaque, and passed unchanged to `commit` |
| `isKnownSender({ sender })` | lowercase 64-hex string | boolean |

`reject` is only for a positively classified permanent rejection, at least: a ciphertext that is not an MLS application `PrivateMessage`, and an application message that yields no peer plaintext. Every other failure, including a binding error of an established session and every engine exception, is `retry`. `isKnownSender` is `true` only when the caller holds a durable peer binding for `sender`. A throw, rejection, timeout or malformed return of either method is neither `retry` nor `false` as a value: for `openCandidate` the entry stays `PENDING` as for `retry`; for `isKnownSender` the event is not staged and the relay's cursor barrier fails (§8.5). An out-of-set value also emits `INBOUND_DISCARDED` with `E_SDK_UNKNOWN_CODE`.

Caller semantics with `ports.receiveState` (normative, not checked by the SDK): one exclusive coordinator per MLS provider, shared by every port that uses it, serialises `openCandidate`, `commit`, `resolve` and candidate installation with every other provider mutation (`seal`, `createKeyPackage`, `startSession`, `joinSession`), and checks calls already in progress immediately before each provider mutation while the receive state is frozen (§8.5); no operation observes an uncommitted candidate; a ticket records the provider generation it was made from; after `commit` succeeds or `resolve` returns `committed` the candidate becomes authoritative; after a failed commit or `aborted` the authoritative state is the one immediately before the candidate was prepared, including every mutation already completed under the coordinator, never an older receive checkpoint; a `retry` or `reject` candidate never replaces the authoritative state, and a failed or timed-out `openCandidate` is discarded or rolled back before any other provider mutation resumes; a late result after a timeout never reactivates an abandoned candidate. The caller makes each provider mutation recoverable before its effect leaves the process (for `seal`, before returning the ciphertext, which the SDK stores and publishes only after its `put`) and coordinates that checkpoint with receive commits; this covers MLS state only, with no outbox resume and no recovery of interrupted invitations. A new session is added to the caller's peer bindings before it is used for reception. Both a candidate-copy and a restore strategy are allowed under this exclusion. The caller may record its own peer-binding changes in the unit that `commit` makes durable; their form is not part of this interface.

### 8.3 Signing and identity port (`ports.identity`)

| Method | Input | Success return |
| --- | --- | --- |
| `getPublicKey()` | — | lowercase 64-hex string |
| `sign({ digest })` | 32-byte `Uint8Array` | 64-byte `Uint8Array` signature over `digest` |

- Secret key material never crosses this interface. The SDK never receives, stores, logs, derives or exports a secret key, and it never constructs a transport object that requires one. `NostrTransport` is not imported by the lane: it signs internally with a secret key it is given and, without one, emits an all-zero signature that relays are expected to reject, so it is not usable with this port. The delivery layer instead builds each SDK-internal outbound event, computes its digest, obtains the signature from `identity.sign`, and publishes the signed event through `RelayPool`.
- The SDK calls `getPublicKey()` once in `start()` and uses that value for the client's lifetime. A different value later is not observed.
- The SDK does not verify the meaning of a signature beyond what `C-DLV` specifies for inbound structures. `sign` is used only for SDK-internal outbound structures of this version.
- The identity is whatever the caller injects. It is not a Milestone 4 per-case identity or return capability.

Optional identity invitation methods, all-or-none with the three session methods:

| Method | Input | Success return |
| --- | --- | --- |
| `giftWrap({ rumor, recipient })` | closed unsigned rumor and lowercase recipient key | event object |
| `unwrapGift({ event })` | received gift-wrap event | closed `{ rumor, sealSigner }` |

The caller MUST implement a kind-1059 NIP-59 wrap for `recipient`, a kind-13 seal signed by its identity key, a fresh wrapping key and NIP-44 v2, and reverse that construction with the authenticated seal signer. The SDK receives no secret key and implements none of those cryptographic operations. Before publication it checks only the wrap shape, kind, exact `p` tag and content bound, without outbound signature self-verification. It checks inbound id and signature before unwrapping. A malformed or oversize `giftWrap` return is `E_SDK_IDENTITY_FAILED`; `unwrapGift` failures only ignore that candidate. Cleartext test wrapping provides no confidentiality.

### 8.4 Clock and randomness

| Port | Methods |
| --- | --- |
| `clock` | `now()` → finite number of milliseconds; `setTimer(callback, delayMs)` → opaque handle; `clearTimer(handle)` |
| `random` | `nextUint32()` → integer in `[0, 2^32)` |

They exist so that timing and backoff jitter are deterministic in tests. They are not security inputs; `deliveryId` generation is not required to use them. A clock or random function that throws or returns an invalid value is `E_SDK_INTERNAL` for the affected operation and moves an affected item to its applicable terminal failed state.

### 8.5 Receive-state port (`ports.receiveState`)

Optional (§4.1): all seven methods or none, and with it the receive session methods of §8.2. Without it nothing in this section applies and the client behaves as interface 0.3.1 plus `eventId`, `acknowledgeMessage` (`E_SDK_NOT_CONFIGURED`) and the enlarged closed sets; the default of §2 bound 2 holds. With it, the **conditional durable-receive exception** of §2 bound 2 applies: every admitted inbound kind-4741 event whose `stage` has completed durably stays recoverable locally across stop, restart and crash; no event id whose outcome was durably committed is passed to `openCandidate` again; every committed application result is redelivered until it is acknowledged. The exception holds only under the caller semantics of §8.2 and this section, which the SDK cannot verify; it covers kind 4741 only and never an outbound item.

The scope literal is `styx-m3-delivery/4741/wire-0.3.0`; the only snapshot schema is `styx-m3-receive-state/v1`. Every call is bounded by the port-call timeout and its return validated; the SDK issues at most one write at a time, in issue order. Each of the five write methods carries a fresh `operationId` (32 lowercase hex digits from `randomBytes(16)`, never reused within the client) and `revision`, the last revision the SDK adopted; `resolve` generates none.

| Method | Input | Success return |
| --- | --- | --- |
| `load({ identity, scope })` | own public key, scope literal | closed snapshot `{ schema, identity, scope, revision, storedBytes, cursors, pending, ready, acknowledged, receiptsDue, seen }` |
| `stage({ operationId, revision, event })` | `event` = `{ eventId, sender, ciphertext, receiptRequested }` | `{ revision, storedBytes }` |
| `commit({ operationId, revision, eventId, ticket, result })` | `result` = `{ type: 'application', sender, payload, receiptDue }` or `{ type: 'rejected' }` | `{ revision, storedBytes }` |
| `ack({ operationId, revision, eventId })` | id of a `READY` entry | `{ revision, storedBytes }` |
| `receiptDone({ operationId, revision, eventId })` | id of a receipt obligation | `{ revision, storedBytes }` |
| `commitCursor({ operationId, revision, relay, generation, syncedUntil })` | exact `config.relays` string, pool number of `C-DLV` §5.4, whole seconds | `{ revision, storedBytes }` |
| `resolve({ operationId })` | the `operationId` of an earlier `commit` whose result is uncertain | `{ status: 'committed', revision, storedBytes, result }` or `{ status: 'aborted', revision, storedBytes? }` |

A method may instead return a closed `{ code }`: `load` with `E_SDK_RECEIVE_STATE_FAILED` or `E_SDK_RECEIVE_STATE_INCOMPATIBLE`; `stage`, `ack`, `receiptDone` and `commitCursor` with `E_SDK_RECEIVE_STATE_FAILED` or `E_SDK_RECEIVE_STATE_CONFLICT`; `commit` with those two or `E_SDK_RECEIVE_STATE_CAPACITY`; `resolve` with `E_SDK_RECEIVE_STATE_FAILED`. Every `revision` and `storedBytes` is a non-negative safe integer; the SDK adopts those of each success. A write return that is neither its success shape nor one of its codes (a throw, rejection, timeout, malformed value or another code) is an uncertain result: the write may or may not have taken effect. A value outside a closed set of this document in a closed slot is `E_SDK_UNKNOWN_CODE` (§5.3).

Port semantics (caller requirements): `load` is called once in each `start()`, before any relay connection; before it returns, the caller restores its MLS checkpoint and peer bindings. It returns `E_SDK_RECEIVE_STATE_INCOMPATIBLE` for another identity, scope or unknown schema, or a snapshot it finds semantically inconsistent (for example a peer binding whose session cannot be loaded). A missing snapshot is a valid empty state (`revision` 0, empty arrays) only if the caller says so explicitly. `stage` makes a durable `PENDING` entry keyed by event id, idempotent per id. `commit` makes durable, atomically as one unit, the session state bound to `ticket` (including any peer-binding change the caller made under the candidate), the entry's new state (`READY` for an application result, `REJECTED` otherwise), its receipt obligation and the seen mark; `E_SDK_RECEIVE_STATE_CAPACITY` guarantees that nothing was written. `ack` atomically removes the payload from the active state and from every later `load`, keeps the seen mark and adds the id to `acknowledged`. `receiptDone` removes the receipt obligation. `commitCursor` records a cursor that has passed the complete barrier of `C-DLV` §5.4; it may be lower than the stored value only in the clock-skew case. `resolve` is read-only and repeatable and answers only for the named `commit`: `committed` carries exactly that commit's closed `result`, `aborted` is returned only when that commit can no longer take effect, and the caller retains the resolution at least until the next successful `load`. A write against a revision other than the current one returns `E_SDK_RECEIVE_STATE_CONFLICT`. One client owns one receive state; a second writer is unsupported. `storedBytes` is the logical size of the active durable receive state (pending ciphertext, ready payloads, receipt, seen and acknowledged records, cursors, MLS checkpoint and peer-binding data), not a physical file or journal size.

Snapshot records are closed plain objects with own data properties, in genuine arrays: `pending` `{ eventId, sender, ciphertext, receiptRequested }` in stage order; `ready` `{ eventId, sender, payload, receiptDue }` in commit order; `receiptsDue` `{ eventId, sender }`; `cursors` `{ relay, syncedUntil }`; `seen`, the ids of every durable kind-4741 entry in any state (`PENDING`, `READY`, acknowledged, `REJECTED`); `acknowledged`, the ids of acknowledged application results only. The SDK checks: `schema`, `identity` and `scope` exactly (else `E_SDK_RECEIVE_STATE_INCOMPATIBLE`); `seen` holds distinct 64-hex ids; `pending`, `ready` and `acknowledged` are disjoint subsets of `seen` without repetition; senders are 64-hex; `ciphertext` is a non-empty and `payload` any `Uint8Array`; flags are booleans; each `receiptsDue` entry names either a `READY` entry with `receiptDue` true and the same sender, or an acknowledged id; `cursors` relay strings are distinct and `syncedUntil` is a non-negative safe integer. Any other violation is `E_SDK_RECEIVE_STATE_FAILED`. A cursor of a relay no longer in `config.relays` is ignored; a new relay starts without one.

Quotas (`config.receive`, §4.1) count the entries returned by `load` plus later writes. New admission stops while `PENDING` entries reach `maxPending`, `READY` entries reach `maxUnacknowledged`, `seen` reaches `maxSeen`, the latest adopted `storedBytes` reaches `maxStoredBytes`, or after a `commit` refused for capacity until the next successful `commit` or `ack`. The write that crosses a limit completes; nothing is deleted; `RECEIVE_STATE_CAPACITY` is emitted once per crossing and again only after the state has dropped below every limit. Reaching `maxSeen` is persistent saturation: no caller compaction may drop tombstones still required.

Fail-stop. Any definite refusal or uncertain result of `stage`, `ack`, `receiptDone` or `commitCursor`, and a `commit` refused with `E_SDK_RECEIVE_STATE_FAILED` or `E_SDK_RECEIVE_STATE_CONFLICT`, freezes the receive state for the rest of the client's lifetime; recovery needs `shutdown()` and a new client whose `start()` completes a successful `load`. An uncertain `commit` pauses it: `resolve` is called at once and then at every periodic pass of `C-DLV` §7.4; `committed` adopts the revision and applies the committed result, `aborted` adopts the revision and leaves the entry `PENDING`, and either returns to the normal condition; a failed `resolve` keeps it paused. A `commit` refused with `E_SDK_RECEIVE_STATE_CAPACITY` neither pauses nor freezes: the entry stays `PENDING` and the quota rule applies. While paused or frozen, nothing is admitted or opened, no cursor is committed, no receipt publication starts, `acknowledgeMessage` returns `E_SDK_RECEIVE_STATE_FAILED`, and `send`, `publishKeyPackage`, `invite` and `acceptInvite` return it before any storage, provider or network mutation (§4.2). `RECEIVE_STATE_FAILED` reports each entry into the condition once. Nothing ever falls back to the path without the port.

The inbound flow is fixed by `C-DLV` §5.4 and §7.4: kind 4741 only, de-duplicated against the durable `seen` set; admission requires `isKnownSender` `true` and no quota reached, and an event not admitted is neither staged nor opened, emitted, receipted or remembered; then `stage`, `openCandidate` and, for `application` or `reject`, `commit`; `retry` leaves the entry `PENDING` for a later bounded retry. A recovery pass in `start()`, after `load` and before the first relay connection, opens every loaded `PENDING` entry once in stage order. A receipt obligation is committed with an application result whose event requested one, published only after a reserved listener was invoked with the entry (§7.1), at most once per run, and removed by `receiptDone` after the first observed `OK true`; opening a message again to build a receipt is forbidden. Kind 4742 keeps its existing path. At `shutdown()` admission stops at the synchronous call, no new candidate or commit starts, a commit already issued completes and the next `load` shows its outcome, every uncommitted entry stays `PENDING`, and the open unit, the write chain and a receipt in progress are awaited within the existing settle bound of two port-call timeouts before relay disposal (a unit not settled by then stays `PENDING`).

At rest (caller requirement): the port holds ciphertext, plaintext until `ack`, MLS state, peer bindings and receive metadata, all of which the caller encrypts at rest. At `ack` the payload leaves the active state and every later `load`; physical erasure from journals, snapshots, backups or media is not claimed unless an atomic compaction has completed, and no secure-erase guarantee is given.

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

The one test `styx-js/test/sdk-mls/invite-mls.test.js` additionally imports only the exact names granted by #317/6316724633 and #525: Jest lifecycle/test names; `MlsEngine` from the unchanged engine; `readFileSync` from `node:fs` solely for immutable WASM; `WebSocket`/`WebSocketServer`, `schnorr`, `sha256`, allowed utils and the SDK entry point. It owns its loopback harness. No other file gains crypto or filesystem access. `invite.js` uses only the contract's exact relay/retry, utils, sha256 and verify-only Schnorr imports.

Rules:

- Modules under `styx-js/src/sdk/**` import no `node:` built-in. They run unchanged in a browser, and in Node only when the host provides a global `WebSocket` (Node 18 does not); a test that needs `WebSocket` in Node supplies it from `ws`.
- No module or test imports `styx-js/src/storage/**`, `styx-js/src/crypto/**`, `styx-js/src/config/**`, `styx-js/apps/**`, any other file under `styx-js/src/transport/**`, or any other export of the two allowed transport files, including `OutboxWorker`, `TransportFailover`, `WebRTCTransport`, `BroadcastChannelTransport` and `NostrChatTransport`.
- Test files may import test files in their own card's allowlist. No shared test-helper file exists outside a card's allowlist.
- No new runtime or development dependency, lockfile change, vendored WASM change, pin change or ciphersuite change is allowed. `styx-js/package.json` is not changed.
- Lane tests connect only to loopback relays they start inside the test; preview and examples stay loopback-only. A non-loopback relay test string, using an RFC 6761 `.test` or `.invalid` host or a non-loopback IP literal, may appear only when assembled at run time from its parts and is never connected to. No module under `styx-js/src/sdk/**` contains a relay URL literal, relay host name, default list or fallback relay; callers alone supply hosts and endpoints under §4.1.

## 10. Non-claims and gates

The SDK is experimental, internal to the repository, not audited, not a product and not authorized for sensitive use. Third-party relays see public keys, the `p`, `e`, `v`, `n` and `r` tags, timing, sizes and the client network address; they may store, refuse or drop events. A listed host may resolve to any address, including private or loopback; no DNS policy or TLS pinning is provided, and host WebSocket TLS validation is not attested. It claims no exactly-once delivery, ordering, cross-restart reliability, durable persistence, payload confidentiality beyond the injected session port, identity hiding, unlinkability, padding, timing protection, onion routing or metadata protection. With `ports.receiveState`, the conditional durable-receive exception of §2 bound 2 and §8.5 is the only cross-restart claim; it rests on caller semantics the SDK cannot verify, and it claims no completeness, no global ordering and no exactly-once application effect. Relay acceptance and recipient receipt are distinct, and neither proves that a person read a message.

These statements stay in force verbatim:

- "Styx is under active development and has **not** completed an independent security audit. Do not use current builds for sensitive, high-risk, or life-critical use."
- "C0.3 remains `NO-GO` for implementation alignment, demo, product, and sensitive use."

Implementation of this interface (`I-SDK`) starts only after every `beforeImplementation` gate of the M3 scope record holds, including the owner hash-ratification of this exact file, of `C-DLV` and of `O-SCEN3`, and their merge into `m3/integration`.

Invitation metadata is also public: relays see KeyPackage publishers, the invitee key in `p`, sizes and timing. What the gift wrap hides is wholly a property of the injected port, not an SDK assurance. There is no Marmot compatibility or implicit migration; no service for organizations, deployment or sensitive-use permission follows.

## 11. Machine-readable normative record

The JSON below is normative and closed. Prose clarifies but does not widen it. Duplicate keys are invalid.

<!-- styx-m3-sdk-interface-json:v1:start -->
```json
{
  "schema": "styx-m3-sdk-interface/v1",
  "closed": true,
  "sdkInterfaceVersion": "styx-m3-sdk/0.4.0-experimental",
  "sdkWireVersion": "styx-m3-sdk/0.3.0-experimental",
  "messageAdmission": {
    "requiresListenerBeforeOpen": true,
    "waiting": "bounded volatile ciphertext only",
    "wake": "onEvent registration",
    "lastUnsubscribe": "pause future opens; reserved in-flight delivery stays eligible",
    "receiptAfter": "actual invocation, not callback completion",
    "shutdown": "drop unopened ciphertext; settle reserved in-flight delivery under existing bounds",
    "appliesTo": "kind 4741 without ports.receiveState; with it see receiveState.emission"
  },
  "stability": "experimental-no-stability-promise",
  "publicModule": "styx-js/src/sdk/index.js",
  "implementationModule": "styx-js/src/sdk/client.js",
  "packageJsonChanged": false,
  "exports": [
    "SDK_INTERFACE_VERSION",
    "SDK_WIRE_VERSION",
    "SdkResultCode",
    "DeliveryState",
    "RelayOutcome",
    "ClientState",
    "SdkEventKind",
    "isKnownResultCode",
    "createStyxClient"
  ],
  "config": {
    "required": [
      "interfaceVersion",
      "relays",
      "ports"
    ],
    "optional": [
      "clock",
      "random",
      "delivery",
      "publicRelayHosts",
      "receive"
    ],
    "relays": {
      "minItems": 1,
      "maxItems": 16,
      "distinct": true,
      "schemes": [
        "ws:",
        "wss:"
      ],
      "userinfo": false,
      "fragment": false,
      "defaultList": false,
      "hosts": "loopbackIpLiteralOrAllowlistedWssHost"
    },
    "publicRelayHosts": {
      "type": "array",
      "minItems": 1,
      "maxItems": 16,
      "distinct": true,
      "absent": "no remote relay",
      "hostMinLength": 1,
      "hostMaxLength": 253,
      "minLabels": 2,
      "labelMinLength": 1,
      "labelMaxLength": 63,
      "characters": "lowercase ASCII a-z, 0-9, hyphen; single-dot separators",
      "labelEdgeHyphen": false,
      "leadingOrTrailingDot": false,
      "lastLabelReject": [
        "^[0-9]+$",
        "^0x[0-9a-f]*$"
      ],
      "normalise": false,
      "remoteUrl": {
        "scheme": "wss (case-insensitive)",
        "hostMatch": "ASCII-lowercased reg-name equals allowlist entry byte for byte",
        "userinfo": false,
        "explicitPort": false,
        "defaultPort": 443,
        "paths": [
          "",
          "/"
        ],
        "query": false,
        "fragment": false,
        "acceptedStringUnchanged": true
      }
    },
    "ports": [
      "storage",
      "session",
      "identity"
    ],
    "optionalPorts": [
      "receiveState"
    ],
    "delivery": {
      "fields": [
        "maxAttempts",
        "deadlineMs",
        "perRelayTimeoutMs",
        "receiptMode"
      ],
      "numericRule": "positive safe integer within C-DLV bounds; absent means C-DLV finite default",
      "receiptMode": [
        "RECIPIENT_RECEIPT",
        "RELAY_ACCEPTANCE_ONLY"
      ]
    },
    "receive": {
      "requires": "ports.receiveState",
      "fields": [
        "maxPending",
        "maxUnacknowledged",
        "maxSeen",
        "maxStoredBytes"
      ],
      "numericRule": "positive safe integer at most max; absent means default",
      "limits": {
        "maxPending": {
          "default": 4096,
          "max": 65536
        },
        "maxUnacknowledged": {
          "default": 4096,
          "max": 65536
        },
        "maxSeen": {
          "default": 1048576,
          "max": 16777216
        },
        "maxStoredBytes": {
          "default": 268435456,
          "max": 4294967296
        }
      },
      "withoutReceiveState": "E_SDK_INVALID_CONFIG"
    },
    "unknownField": "E_SDK_INVALID_CONFIG"
  },
  "clientStates": [
    "CREATED",
    "RUNNING",
    "STOPPED"
  ],
  "methods": {
    "start": {
      "allowedIn": [
        "CREATED"
      ],
      "codes": [
        "E_SDK_ALREADY_STARTED",
        "E_SDK_CLIENT_STOPPED",
        "E_SDK_STORAGE_NOT_EMPTY",
        "E_SDK_NO_RELAY_AVAILABLE",
        "E_SDK_STORAGE_FAILED",
        "E_SDK_IDENTITY_FAILED",
        "E_SDK_INTERNAL",
        "E_SDK_UNKNOWN_CODE",
        "E_SDK_RECEIVE_STATE_FAILED",
        "E_SDK_RECEIVE_STATE_INCOMPATIBLE"
      ]
    },
    "send": {
      "allowedIn": [
        "RUNNING"
      ],
      "codes": [
        "E_SDK_NOT_STARTED",
        "E_SDK_CLIENT_STOPPED",
        "E_SDK_INVALID_ARGUMENT",
        "E_SDK_PAYLOAD_TOO_LARGE",
        "E_SDK_QUEUE_FULL",
        "E_SDK_STORAGE_FAILED",
        "E_SDK_SESSION_FAILED",
        "E_SDK_INTERNAL",
        "E_SDK_UNKNOWN_CODE",
        "E_SDK_RECEIVE_STATE_FAILED"
      ]
    },
    "getDelivery": {
      "allowedIn": [
        "RUNNING",
        "STOPPED"
      ],
      "codes": [
        "E_SDK_NOT_STARTED",
        "E_SDK_INVALID_ARGUMENT",
        "E_SDK_UNKNOWN_DELIVERY",
        "E_SDK_STORAGE_FAILED",
        "E_SDK_INTERNAL",
        "E_SDK_UNKNOWN_CODE"
      ]
    },
    "cancel": {
      "allowedIn": [
        "RUNNING"
      ],
      "codes": [
        "E_SDK_NOT_STARTED",
        "E_SDK_CLIENT_STOPPED",
        "E_SDK_INVALID_ARGUMENT",
        "E_SDK_UNKNOWN_DELIVERY",
        "E_SDK_DELIVERY_TERMINAL",
        "E_SDK_STORAGE_FAILED",
        "E_SDK_INTERNAL",
        "E_SDK_UNKNOWN_CODE"
      ]
    },
    "onEvent": {
      "allowedIn": [
        "CREATED",
        "RUNNING",
        "STOPPED"
      ],
      "codes": [
        "E_SDK_INVALID_ARGUMENT",
        "E_SDK_INTERNAL",
        "E_SDK_UNKNOWN_CODE"
      ]
    },
    "shutdown": {
      "allowedIn": [
        "CREATED",
        "RUNNING"
      ],
      "codes": [
        "E_SDK_CLIENT_STOPPED"
      ]
    },
    "publishKeyPackage": {
      "allowedIn": [
        "RUNNING"
      ],
      "codes": [
        "E_SDK_NOT_STARTED",
        "E_SDK_CLIENT_STOPPED",
        "E_SDK_NOT_CONFIGURED",
        "E_SDK_NO_RELAY_AVAILABLE",
        "E_SDK_INTERNAL",
        "E_SDK_UNKNOWN_CODE",
        "E_SDK_SESSION_FAILED",
        "E_SDK_IDENTITY_FAILED",
        "E_SDK_PUBLISH_NOT_ACCEPTED",
        "E_SDK_RECEIVE_STATE_FAILED"
      ]
    },
    "invite": {
      "allowedIn": [
        "RUNNING"
      ],
      "codes": [
        "E_SDK_NOT_STARTED",
        "E_SDK_CLIENT_STOPPED",
        "E_SDK_NOT_CONFIGURED",
        "E_SDK_NO_RELAY_AVAILABLE",
        "E_SDK_INTERNAL",
        "E_SDK_UNKNOWN_CODE",
        "E_SDK_INVALID_ARGUMENT",
        "E_SDK_KEYPACKAGE_NOT_FOUND",
        "E_SDK_SESSION_FAILED",
        "E_SDK_IDENTITY_FAILED",
        "E_SDK_PUBLISH_NOT_ACCEPTED",
        "E_SDK_RECEIVE_STATE_FAILED"
      ]
    },
    "acceptInvite": {
      "allowedIn": [
        "RUNNING"
      ],
      "codes": [
        "E_SDK_NOT_STARTED",
        "E_SDK_CLIENT_STOPPED",
        "E_SDK_NOT_CONFIGURED",
        "E_SDK_NO_RELAY_AVAILABLE",
        "E_SDK_INTERNAL",
        "E_SDK_UNKNOWN_CODE",
        "E_SDK_INVALID_ARGUMENT",
        "E_SDK_SESSION_FAILED",
        "E_SDK_INVITE_TIMEOUT",
        "E_SDK_RECEIVE_STATE_FAILED"
      ]
    },
    "acknowledgeMessage": {
      "allowedIn": [
        "RUNNING"
      ],
      "alsoAllowedDuringStartAfterLoad": true,
      "codes": [
        "E_SDK_NOT_STARTED",
        "E_SDK_CLIENT_STOPPED",
        "E_SDK_NOT_CONFIGURED",
        "E_SDK_INVALID_ARGUMENT",
        "E_SDK_UNKNOWN_MESSAGE",
        "E_SDK_RECEIVE_STATE_FAILED",
        "E_SDK_INTERNAL",
        "E_SDK_UNKNOWN_CODE"
      ]
    }
  },
  "createStyxClientCodes": [
    "E_SDK_UNSUPPORTED_VERSION",
    "E_SDK_INVALID_CONFIG"
  ],
  "resultEnvelope": {
    "success": [
      "ok",
      "value"
    ],
    "failure": [
      "ok",
      "code"
    ],
    "neverRejects": true,
    "neverThrows": true
  },
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
    "E_SDK_UNKNOWN_CODE",
    "E_SDK_NOT_CONFIGURED",
    "E_SDK_PUBLISH_NOT_ACCEPTED",
    "E_SDK_KEYPACKAGE_NOT_FOUND",
    "E_SDK_INVITE_TIMEOUT",
    "E_SDK_RECEIVE_STATE_FAILED",
    "E_SDK_RECEIVE_STATE_INCOMPATIBLE",
    "E_SDK_RECEIVE_STATE_CONFLICT",
    "E_SDK_RECEIVE_STATE_CAPACITY",
    "E_SDK_UNKNOWN_MESSAGE"
  ],
  "inboundDiscardCodes": [
    "E_SDK_INBOUND_INVALID",
    "E_SDK_SESSION_FAILED",
    "E_SDK_UNKNOWN_CODE"
  ],
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
    "QUEUED": {
      "terminal": false
    },
    "IN_FLIGHT": {
      "terminal": false
    },
    "RELAY_ACCEPTED_AWAITING_RECEIPT": {
      "terminal": false
    },
    "RELAY_ACCEPTED": {
      "terminal": true,
      "success": true,
      "mode": "RELAY_ACCEPTANCE_ONLY"
    },
    "RECIPIENT_RECEIPT_RECEIVED": {
      "terminal": true,
      "success": true,
      "mode": "RECIPIENT_RECEIPT"
    },
    "FAILED_NOT_ACCEPTED": {
      "terminal": true,
      "success": false
    },
    "FAILED_NO_RECEIPT": {
      "terminal": true,
      "success": false,
      "mode": "RECIPIENT_RECEIPT"
    },
    "CANCELLED": {
      "terminal": true,
      "success": false
    },
    "LOST_ON_SHUTDOWN": {
      "terminal": true,
      "success": false
    }
  },
  "transitions": {
    "QUEUED": [
      "IN_FLIGHT",
      "CANCELLED",
      "FAILED_NOT_ACCEPTED",
      "LOST_ON_SHUTDOWN"
    ],
    "IN_FLIGHT": [
      "QUEUED",
      "RELAY_ACCEPTED_AWAITING_RECEIPT",
      "RELAY_ACCEPTED",
      "FAILED_NOT_ACCEPTED",
      "CANCELLED",
      "LOST_ON_SHUTDOWN"
    ],
    "RELAY_ACCEPTED_AWAITING_RECEIPT": [
      "RECIPIENT_RECEIPT_RECEIVED",
      "FAILED_NO_RECEIPT",
      "CANCELLED",
      "LOST_ON_SHUTDOWN"
    ],
    "RELAY_ACCEPTED": [],
    "RECIPIENT_RECEIPT_RECEIVED": [],
    "FAILED_NOT_ACCEPTED": [],
    "FAILED_NO_RECEIPT": [],
    "CANCELLED": [],
    "LOST_ON_SHUTDOWN": []
  },
  "snapshotFields": [
    "deliveryId",
    "recipient",
    "state",
    "terminal",
    "attempts",
    "createdAt",
    "deadlineAt",
    "lastCode",
    "relayOutcomes"
  ],
  "relayOutcomes": [
    "PENDING",
    "ACCEPTED",
    "REJECTED",
    "TIMED_OUT",
    "UNREACHABLE"
  ],
  "events": {
    "CLIENT_STATE_CHANGED": [
      "clientState"
    ],
    "DELIVERY_STATE_CHANGED": [
      "deliveryId",
      "state",
      "terminal",
      "lastCode"
    ],
    "MESSAGE_RECEIVED": [
      "sender",
      "payload",
      "eventId"
    ],
    "INBOUND_DISCARDED": [
      "code"
    ],
    "RECEIVE_STATE_CAPACITY": [
      "scope"
    ],
    "RECEIVE_STATE_FAILED": [
      "code"
    ],
    "RECEIVE_STATE_CLOCK_SKEW": [
      "scope",
      "relay"
    ]
  },
  "ports": {
    "storage": [
      "put",
      "get",
      "update",
      "remove",
      "list"
    ],
    "session": [
      "seal",
      "open"
    ],
    "identity": [
      "getPublicKey",
      "sign"
    ],
    "clock": [
      "now",
      "setTimer",
      "clearTimer"
    ],
    "random": [
      "nextUint32"
    ],
    "receiveState": [
      "load",
      "stage",
      "commit",
      "ack",
      "receiptDone",
      "commitCursor",
      "resolve"
    ]
  },
  "portFailureCodes": {
    "storage": "E_SDK_STORAGE_FAILED",
    "session": "E_SDK_SESSION_FAILED",
    "identity": "E_SDK_IDENTITY_FAILED",
    "receiveState": "E_SDK_RECEIVE_STATE_FAILED",
    "clock": "E_SDK_INTERNAL",
    "random": "E_SDK_INTERNAL"
  },
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
    "utils": {
      "path": "styx-js/src/utils.js",
      "names": [
        "EventEmitter",
        "uuidv4",
        "bytesToHex",
        "hexToBytes",
        "utf8Encode",
        "utf8Decode",
        "randomBytes",
        "constantTimeEqual",
        "concatBytes",
        "bytesToBase64",
        "base64ToBytes",
        "secureZero"
      ]
    },
    "transport": {
      "styx-js/src/transport/transport-interface.js": [
        "TransportInterface",
        "TransportState",
        "TransportMessage"
      ],
      "styx-js/src/transport/nostr-transport.js": [
        "RelayPool"
      ]
    },
    "packages": {
      "@noble/hashes/sha256": {
        "names": [
          "sha256"
        ],
        "allowedIn": [
          "src",
          "test"
        ]
      },
      "@noble/curves/secp256k1": {
        "names": [
          "schnorr"
        ],
        "allowedIn": [
          "src",
          "test"
        ],
        "srcUse": "verify only"
      },
      "@jest/globals": {
        "names": [
          "describe",
          "test",
          "it",
          "expect",
          "beforeAll",
          "beforeEach",
          "afterAll",
          "afterEach",
          "jest"
        ],
        "allowedIn": [
          "test"
        ]
      },
      "ws": {
        "names": [
          "WebSocket",
          "WebSocketServer"
        ],
        "allowedIn": [
          "test"
        ]
      }
    },
    "nodeBuiltinsTestOnly": [
      "node:assert",
      "node:events",
      "node:net",
      "node:http",
      "node:timers",
      "node:timers/promises",
      "node:crypto"
    ],
    "noImport": [
      "styx-js/src/storage/**",
      "styx-js/src/crypto/**",
      "styx-js/src/config/**",
      "styx-js/apps/**"
    ],
    "forbiddenTransportExports": [
      "OutboxWorker",
      "TransportFailover",
      "WebRTCTransport",
      "BroadcastChannelTransport",
      "NostrChatTransport"
    ],
    "newDependency": false
  },
  "network": {
    "laneTestRelays": "loopback only, started inside the test",
    "relayUrlLiteralInSrcSdk": false
  },
  "ownedByCDlv": [
    "queue transitions timing",
    "retransmission and backoff bounds",
    "maxAttempts, deadlineMs, perRelayTimeoutMs bounds and defaults",
    "payload maximum",
    "queue bound",
    "port call timeout value (finite, at most perRelayTimeoutMs, enforced by the host timer)",
    "receipt structure and validation",
    "duplicate handling",
    "per-relay outcome rules",
    "SDK-internal record and on-wire structures, including message identifiers, receipts, acknowledgements, Nostr event kinds and tags",
    "terminal processing slack",
    "durable receive flow, retry budget and passes, per-pool subscription ids, cursor barrier and clock-skew rule (C-DLV 5.4, 7.4)"
  ],
  "cDlvMayNotChange": [
    "exports",
    "config fields",
    "methods",
    "result codes",
    "delivery states",
    "transitions",
    "relay outcomes",
    "public SDK event kinds and fields (section 7)",
    "port methods",
    "outer bounds",
    "imports"
  ],
  "optionalInvitationPorts": {
    "allOrNone": true,
    "session": [
      "createKeyPackage",
      "startSession",
      "joinSession"
    ],
    "identity": [
      "giftWrap",
      "unwrapGift"
    ],
    "absent": "E_SDK_NOT_CONFIGURED",
    "partial": "E_SDK_INVALID_CONFIG",
    "callerSemantics": "section 8.2 and 8.3; SDK implements no MLS or gift-wrap cryptography",
    "sourceTestException": "styx-js/test/sdk-mls/invite-mls.test.js only, owner #317/6316724633"
  },
  "invitation": {
    "argumentsClosed": true,
    "acceptedRelays": "frozen ascending accepting config.relays indices",
    "relaySets": "independent and disposed before resolution",
    "newCodesInbound": false,
    "failedCandidateEmits": false,
    "shutdown": "section 4.2, disposal in step 4 after LOST_ON_SHUTDOWN",
    "retry": "fresh engines, ports and clients on both sides after session failure"
  },
  "receiveState": {
    "optional": true,
    "allOrNone": true,
    "methods": [
      "load",
      "stage",
      "commit",
      "ack",
      "receiptDone",
      "commitCursor",
      "resolve"
    ],
    "requiredSessionMethods": [
      "openCandidate",
      "isKnownSender"
    ],
    "partialOrMissingSessionMethod": "E_SDK_INVALID_CONFIG",
    "absent": "0.3.1 behaviour plus eventId, acknowledgeMessage E_SDK_NOT_CONFIGURED and the enlarged closed sets; H17 stays declared",
    "conditionalDurableReceiveException": {
      "requires": "ports.receiveState and the caller semantics of sections 8.2 and 8.5",
      "kinds": [
        4741
      ],
      "stagedEventRecoverableAcrossRestartAndCrash": true,
      "committedIdOpenedAgain": false,
      "redeliveredUntilAcknowledged": true,
      "beforeStage": "relay-dependent",
      "outboundResume": false,
      "completeness": false,
      "globalOrdering": false,
      "exactlyOnceApplicationEffect": false,
      "verifiedBySdk": false
    },
    "scope": "styx-m3-delivery/4741/wire-0.3.0",
    "schema": "styx-m3-receive-state/v1",
    "operationId": "32 lowercase hex from randomBytes(16), fresh per write, never reused within the client; none for resolve",
    "writesSerialized": true,
    "portCallTimeout": "each call",
    "snapshotFields": [
      "schema",
      "identity",
      "scope",
      "revision",
      "storedBytes",
      "cursors",
      "pending",
      "ready",
      "acknowledged",
      "receiptsDue",
      "seen"
    ],
    "records": {
      "pending": [
        "eventId",
        "sender",
        "ciphertext",
        "receiptRequested"
      ],
      "ready": [
        "eventId",
        "sender",
        "payload",
        "receiptDue"
      ],
      "receiptsDue": [
        "eventId",
        "sender"
      ],
      "cursors": [
        "relay",
        "syncedUntil"
      ],
      "seen": "event ids of every durable kind-4741 entry in any state",
      "acknowledged": "event ids of acknowledged application results only"
    },
    "disjointSubsetsOfSeen": [
      "pending",
      "ready",
      "acknowledged"
    ],
    "commitResults": {
      "application": [
        "type",
        "sender",
        "payload",
        "receiptDue"
      ],
      "rejected": [
        "type"
      ]
    },
    "writeSuccess": [
      "revision",
      "storedBytes"
    ],
    "resolveResults": {
      "committed": [
        "status",
        "revision",
        "storedBytes",
        "result"
      ],
      "aborted": [
        "status",
        "revision"
      ],
      "abortedOptional": [
        "storedBytes"
      ]
    },
    "portCodes": {
      "load": [
        "E_SDK_RECEIVE_STATE_FAILED",
        "E_SDK_RECEIVE_STATE_INCOMPATIBLE"
      ],
      "stage": [
        "E_SDK_RECEIVE_STATE_FAILED",
        "E_SDK_RECEIVE_STATE_CONFLICT"
      ],
      "commit": [
        "E_SDK_RECEIVE_STATE_FAILED",
        "E_SDK_RECEIVE_STATE_CONFLICT",
        "E_SDK_RECEIVE_STATE_CAPACITY"
      ],
      "ack": [
        "E_SDK_RECEIVE_STATE_FAILED",
        "E_SDK_RECEIVE_STATE_CONFLICT"
      ],
      "receiptDone": [
        "E_SDK_RECEIVE_STATE_FAILED",
        "E_SDK_RECEIVE_STATE_CONFLICT"
      ],
      "commitCursor": [
        "E_SDK_RECEIVE_STATE_FAILED",
        "E_SDK_RECEIVE_STATE_CONFLICT"
      ],
      "resolve": [
        "E_SDK_RECEIVE_STATE_FAILED"
      ]
    },
    "uncertainWrite": "throw, rejection, timeout, malformed value or code outside the method set",
    "openCandidate": {
      "fields": [
        "receiveOutcome",
        "ticket",
        "plaintext"
      ],
      "receiveOutcome": [
        "application",
        "retry",
        "reject"
      ],
      "plaintextExactlyFor": "application",
      "ticket": "present, opaque, passed unchanged to commit",
      "failure": "entry stays PENDING, as retry"
    },
    "isKnownSender": {
      "returns": "boolean",
      "false": "not admitted; not staged, opened, emitted, receipted or remembered",
      "failure": "not staged; barrier failure"
    },
    "quotas": {
      "counts": "entries returned by load plus later writes",
      "reached": "new admission stops; crossing write completes; nothing deleted",
      "event": "RECEIVE_STATE_CAPACITY once per crossing",
      "commitCapacityRefusal": "entry stays PENDING; admission stops until the next successful commit or ack",
      "maxSeenSaturationPersistent": true
    },
    "failStop": {
      "frozenBy": "any definite refusal or uncertain result of stage, ack, receiptDone or commitCursor; commit refused with E_SDK_RECEIVE_STATE_FAILED or E_SDK_RECEIVE_STATE_CONFLICT",
      "frozenUntil": "shutdown and a new client whose start completes a successful load",
      "pausedBy": "uncertain commit",
      "pausedUntil": "resolve committed or aborted; failed resolve keeps paused",
      "blocked": [
        "admission",
        "open",
        "cursor commit",
        "receipt publication",
        "acknowledgeMessage",
        "send",
        "publishKeyPackage",
        "invite",
        "acceptInvite"
      ],
      "methodCode": "E_SDK_RECEIVE_STATE_FAILED",
      "event": "RECEIVE_STATE_FAILED once per entry into the condition",
      "fallbackToPathWithoutPort": false
    },
    "acknowledgeMessage": {
      "success": [
        "eventId"
      ],
      "readyRequiresInvocationInCurrentRun": true,
      "alreadyAcknowledged": "success without a write",
      "unknownNotInvokedOrRejected": "E_SDK_UNKNOWN_MESSAGE",
      "hostBound": "5 * port-call timeout"
    },
    "emission": {
      "only": "committed application results (READY)",
      "waitsForListenerBeforeOpen": false,
      "order": "commit order, loaded entries first",
      "wake": [
        "load in start",
        "commit",
        "onEvent registration",
        "redelivery pass"
      ],
      "redeliveryIntervalMs": 60000,
      "oneDispatchPerEntry": true,
      "acknowledgedBeforeDispatchInvokesNothing": true,
      "invocationIsAcknowledgement": false
    },
    "receipts": "obligation committed with the application result; published after a reserved listener invocation or acknowledgement, at most once per run, receiptDone after first OK true; never reopened",
    "inboundDiscardedCodes": [
      "E_SDK_INBOUND_INVALID",
      "E_SDK_SESSION_FAILED",
      "E_SDK_UNKNOWN_CODE"
    ],
    "atRest": "caller encrypts ciphertext, plaintext until ack, MLS state, peer bindings and metadata; physical erasure not claimed",
    "callerSemantics": "section 8.2 coordinator and section 8.5; not checked by the SDK"
  }
}
```
<!-- styx-m3-sdk-interface-json:v1:end -->

## 12. Conformance

A conforming implementation (card `I-SDK`) and its tests demonstrate at least: every code of `resultCodes` is reachable or is shown unreachable by construction for that method; every method returns the envelope and never rejects or throws; unknown codes, states and outcomes from a stubbed component or port fail closed as in §5.3; every delivery state and allowed transition is exercised and no other transition occurs; `shutdown()` reports every non-terminal item as `LOST_ON_SHUTDOWN` and leaves no timer, connection or listener active; a hung relay does not delay the per-relay outcome of another relay; `start()` rejects a non-empty storage port; no secret key material is passed to the SDK; and the static import check of §9 passes for every lane file.

A conforming validator of the record in §11 rejects: an unknown or missing field; a duplicate key; a code, state, outcome, event kind or port method outside the closed lists; a state without `terminal`; a transition from a terminal state; a transition target outside `deliveryStates`; a method code outside `resultCodes`; a method missing from `methods`; and any `outerBounds` value different from the one above. A conforming implementation never returns, from a method, a code outside that method's own `codes` list in the record; such a return is a conformance failure, not merely a validator concern.

M3-INVITE conformance additionally covers every wire refusal and Model B call in #525, all five-or-none port members, nine client members/22 result codes (ten and 27 since interface 0.4.0), old-version rejection, exact accepted indices and newest/tie selection, host-time bounds with faulty clocks, shutdown order with pending delivery and invitation work, and the single real-engine flow with equal exported secrets, seal/open, rejected credential/Welcome and fresh-state retry. The cleartext test identity port proves no confidentiality.

## 13. Authority and ratification

This contract implements card `C-SDK` of the M3 scope record (Issue #400 comment `5950987413`) under the owner act in Issue #400, on base `m3/integration` at `e0fe27ae1b02ad35d80fa70cbb0f2ac64fbf812a`. Its only file is `docs/architecture/m3/sdk-interface.md`.

M3-PUBLIC-RELAYS #522 produces version 0.2.0 under #400/6489853937 and the cited public relays act. The historical 0.1.0 ratification is not a ratification of these new bytes; the new C-SDK and C-DLV hashes remain output candidates pending a separately marked owner output ratification. Historical O-SCEN3 and C-PREV pins are unchanged.

The final file SHA-256 must be owner hash-ratified by a `styx-m3-ratification:v1` comment on #400 before `C-DLV` relies on it as ratified and before any dependent implementation. Any byte change voids that ratification. Removing this file fully rolls back `C-SDK`; no code, dependency or persisted bytes are introduced.

M3-INVITE #525 amends only the enumerated sections under #400/6544668029, scope replacement 5 #400/6544596450 and the existing #317/6316724633 act. The version-0.2.0 predecessor is integrated and ratified by #400/6544441411. These version-0.3.0 bytes remain output candidates until separately exact-head hash-ratified; historical O-SCEN3/C-PREV citations remain unchanged.

M3-RECEIVE-1 (contract #557, shared normative source #556) amends only §2, §3, §4, §5, §7, §8, §10 (the non-claim qualifier), §11 and this section, under the scope extension #400/6629916795 and its exact-contract approval; version 0.4.0 replaces 0.3.1. The §9 import exceptions for the reference adapter and its tests are not part of it. These bytes remain output candidates until separately exact-head hash-ratified.
