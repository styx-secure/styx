# M3 early-lane delivery scenarios — candidate normative set

Card `O-SCEN3`, M3 early lane. This directory is the deliverable of the scope record `O-SCEN3`: a scenario set
for the M3 delivery layer, authored by a model vendor different from the author of C-DLV, derived **only** from
the two ratified documents.

Sources, both read at the exact base `f14a8d54cbe5e62c844a9db12bf78f62a4858267` of `m3/integration`:

| Document | Path | SHA-256 |
| --- | --- | --- |
| C-SDK | `docs/architecture/m3/sdk-interface.md` | `47f75d6cd0bd3d542fd699f99144da6ccd9d6965908e5d1f4b2c1dfd976a9a11` |
| C-DLV | `docs/architecture/m3/delivery-layer.md` | `9ffd2accd7bf715d87728bc484669b70501d10c198707f15c4ce12b3935cf1b8` |

Every scenario cites those documents by section and takes every parameter, bound, state name, code and
behaviour name from them. Nothing here is a new protocol, a new wire format, or a claim wider than the two
documents.

## 1. What each file is

Each file is one record: a fenced `json` block between the markers `<!-- styx-m3-scenario:v1:start -->` and
`<!-- styx-m3-scenario:v1:end -->`, followed by prose. The JSON is the record; the prose explains it and
carries the **Clauses.** paragraph. Identifiers are camel case, state names are the closed enumeration of
C-SDK §6.1, per-relay outcomes the closed enumeration of C-SDK §6.3, and codes the closed set of C-SDK §5.2.

The record object is **closed**: a file declares exactly the keys `schema`, `closed`, `scenarioId`,
`purposeItem`, `title`, `harnessScenarios`, `contracts`, `clauses`, `nonClaims` and `timelines`. A timeline
declares exactly `id`, `harness`, `config`, `preconditions`, `clauses`, `events`, `expectedTransitions`,
`expectedItemStates`, `expectedRelayStates`, `expectedMethodResults`, `expectedEvents` and `notEmitted`, plus
two optional keys: `harnessNote` (a sentence that states how far the C-DLV §12 description of this timeline's
`harness` name differs from what the timeline runs) and `expectedPortCalls` (a list of
`{ at, port, call, count }` objects, each asserting that the injected port `port` received `count` calls of
`call` at the event instant `at` — the timelines use it for the timer handles an orderly shutdown clears). An
event declares `at`, `actor`, `event`, `detail`, `timing` and `checks`, plus the optional structured keys
`relayAnswer`, `clock`, `transitions` and `anchor` (the instant a connection phase began, see §1.2). A relay
declares `index`, `host`, `port`, `behaviours` and `role`, plus `holdMs` when it selects `delayFrames` and
`replacement` when a later connection of that relay behaves differently from its first. Only the keys that the
checker knows are allowed, and every key the checker requires must be present, so a reader can tell a missing
rule from an unknown one.

### 1.1 `purposeItem`

One of the five items of the scope record `O-SCEN3`: `hungRelay`, `relayLoss`, `duplicateAndReordered`,
`offlineRecipient`, `queueRestartLost`. `harnessScenarios` names the C-DLV §12 harness scenarios a file
exercises, and each timeline names, in its `harness` key, the one harness scenario it runs. The file's
`harnessScenarios` is exactly the set of the `harness` values of its timelines, and every name is a member of
the closed `harness.scenarios` list of the C-DLV record (§12).

### 1.2 Timings

`timing.kind` is a closed set. `deltaFromPrevious` means the event happens `valueMs` **milliseconds after the
previous event of the same timeline**, on the injected clock port of C-SDK §8.4; the checker recomputes that
sum, so a timeline's `at` values and its deltas cannot drift apart. The other kinds carry their own meaning
and are checked against the configured parameters:

| `kind` | `valueMs` | Checked against |
| --- | --- | --- |
| `portCall` | the bound of the port call (for the orderly stop, the bound of each port write of C-DLV §4.6 step (4)) | `portCallTimeoutMs`, which C-DLV §3 fixes as `floor(perRelayTimeoutMs / 2)` |
| `connectionPhase` | the length of the connection phase | `perRelayTimeoutMs` (C-DLV §5.2) |
| `attemptTimeout` | the publication timeout of one attempt, measured from the instant the attempt's publication began (an accepted receipt-mode attempt can outlive it, C-DLV §4.3, §5.3) | `perRelayTimeoutMs` (C-DLV §3, §4.3) |
| `retryDelay` | the delay of the retry after the attempt in `attempt` | `delay(n, u)` with the injected draw of that attempt (C-DLV §4.3) |
| `reconnectDelay` | the delay before the pool invokes `connectAll()` for a replacement connection | `delay(k, u)` with the injected draw of that loss (C-DLV §5.2) |

A `portCall` timing is the bound the SDK allows the call, not a claim that the injected clock advanced: the
clock advances only where an event's `at` says so, and a timeline states the port calls that consume clock
time. A `connectionPhase` event also carries `anchor.startedAt`, the instant at which the phase began: each
connection phase belongs to one `start()` call, so the checker requires `startedAt` to be the `at` of the event
at which that client's `start()` was called (the event whose label names the call or the creation of the
client) and `valueMs` to be the phase's length measured from `startedAt`. A clock event also carries
`clock.kind`: `attemptTimeout` (the attempt timeout of `attempt` elapsed),
`reconnectArm` (a replacement connection was armed after the `consecutiveLoss`-th consecutive loss of that
relay) or `deadline` (the deadline transition of C-DLV §4.4). The checker recomputes each attempt's begin and
end from `retryDelay` events alone and verifies that every `attemptTimeout` falls exactly `perRelayTimeoutMs`
after the begin of that attempt, so the arithmetic of a timeline cannot be wrong without the checker saying so.

### 1.3 Relays and harness behaviours

A timeline configures at least two relays, each with an index, a loopback host (`127.0.0.1` or `::1`, C-DLV §2
item 6), an ephemeral port, a non-empty `behaviours` array and a `role` sentence. The behaviour names are the
closed list of C-DLV §10: `normal`, `neverAnswering`, `rejecting`, `dropAfterFrames`, `delayFrames`,
`duplicateDelivery`, `reverseOrder`. Two conventions make the injection unambiguous, and the records state
them in the `role` text of the relay they use:

- `dropAfterFrames` counts **EVENT frames published to the relay**, and it applies to the relay's first
  connection only. A behaviour that counted the `REQ` frames of the connection phase would drop before any
  publication, `publish` would return `0`, and C-DLV §5.3 would give `PENDING` and not `UNREACHABLE`; every
  file that uses it says which behaviour its replacement connection has instead of leaving it open.
- `delayFrames` holds every frame the relay sends to the client for `holdMs`; a relay that selects it must declare `holdMs` as a positive integer, and every frame it sends arrives exactly `holdMs` after it was sent, so a relay answer of such a relay cannot arrive before the attempt's publication began plus `holdMs`. The checker recomputes that bound, so a stated arrival that its own declared hold contradicts is a failure and not a reading.
- A relay may select more than one behaviour at once, and the behaviour of a **later** connection is declared in the relay's `replacement` sentence, so a timeline never leaves the second connection's behaviour implicit. Where no relay holds frames, the harness fixes each frame's arrival instant and the timeline states that instant: the frames of two relays of one timeline may arrive in any order the harness fixes, and the order is what the record states, not an artefact of a delay the record does not declare.

### 1.4 Transitions and expectations

Every event that changes the state of an item carries `transitions`, a list of `{ deliveryId, to }` pairs, one
per item the event moves. The **ordered walk derived from the events** is what the record's
`expectedTransitions` must equal, exactly, `deliveryId` by `deliveryId`, and the walk must be legal: it starts
in `QUEUED`, every pair must be one of the transitions of the `transitionsUsed` map of the C-DLV record (§12),
and no pair may follow a terminal state. `expectedItemStates` gives the final state of every item, and it must
agree with the end of the walk. Because a publication phase ends at the **first** acceptance of an item in
`IN_FLIGHT` (C-DLV §4.3, §5.3), the checker also requires, **per item**, that the event which moves
the item into `RELAY_ACCEPTED` or `RELAY_ACCEPTED_AWAITING_RECEIPT` is the first event of that item's walk
that records an accepted relay answer for it, and that every later accepted answer for that item moves no
item. Two items of one timeline may have their first acceptances at different instants.

## 2. Purpose items and the harness scenarios

| Purpose item | File | Timelines | C-DLV §12 harness scenarios |
| --- | --- | --- | --- |
| `hungRelay` | `hung-relay.md` | `hungRelayAlongsideNormal`, `twoHungRelaysExhaustion` | `hungRelay` |
| `relayLoss` | `relay-loss.md` | `relayLossAndReplacement` | `relayLossAndReplacement` |
| `duplicateAndReordered` | `duplicate-and-reordered.md` | `inboundDuplicateReordered`, `outboundDuplicateAccepted` | `duplicateAndReordered` |
| `offlineRecipient` | `offline-recipient.md` | `receiptBeforeDeadline`, `receiptAfterDeadline`, `receiptExactlyAtDeadline` | `offlineRecipient` |
| `queueRestartLost` | `queue-restart-lost.md` | `lostAtShutdownThenNewClient`, `nonEmptyStoreRefused` | `shutdownLostThenNewClient` |

## 3. The files

- `hung-relay.md` — the hung relay beside a normal one, and the exhaustion of the attempt count when no relay
  ever answers.
- `relay-loss.md` — a relay that drops its connection after receiving the event, is reported `UNREACHABLE` for
  that attempt and is retired and replaced.
- `duplicate-and-reordered.md` — duplicate inbound copies suppressed in the bounded window, arrival order
  rather than sending order, and a republished event answered `duplicate:`.
- `offline-recipient.md` — a recipient absent during the sender's attempt, with the receipt before the
  deadline, after it, and exactly at it.
- `queue-restart-lost.md` — the `LOST_ON_SHUTDOWN` transitions at an orderly shutdown, the timers that do not
  survive it, the new client that recovers nothing, and the storage port that refuses to adopt a queue.
- `README.md` — this index.

## 4. How the records are checked

`validate_scen3.py` is an external checker written in the Python standard library, kept outside the
repository and delivered as evidence of this card beside this directory; no file of this directory cites it
as if it lived inside the repository. It reads the two ratified documents, parses the closed JSON record
inside C-DLV §12 and derives from it the parameters and their bounds, the fixed values, the backoff
formula and its base and cap, the closed state set, the `transitionsUsed` map, the per-relay outcome set, the
code set, the relay behaviour list, the harness scenario list and the snapshot fields of C-SDK §11; it then
checks every file of this directory against those derived values, including a duplicate-key check, the
closed key set of every level of every record, the two-way agreement between the record's clauses, its
events' citations and the prose, and every bounded timing. It also checks a set of **mutations** — one
deliberate defect at a time. Each mutation names the check family it is meant to prove, and a mutation counts
as caught only when a failure of that family appears; the mutations that name no family (they are the ones
whose family is a group of checks rather than a single label) count as caught when any check fails. A run is only green when every positive check passes, every mutation is caught on its own
label, and no mutation is missed. The same checker can be pointed at another directory, and it reports its
positives, its mutations and its failures in one JSON object.

## 5. Principal clauses checked

The full clause list of a file is its own `clauses`; it is exactly the union of the `clauses` of its
timelines, each timeline's list is exactly the union of the citations of its events' `checks`, and the file's
list is exactly the set of clauses its prose cites after the record, so the record and its prose agree in
both directions and a clause cannot appear in one and not in the other. Every citation resolves to a real
section of C-SDK or C-DLV. The table below lists the principal ones, the clauses a reader should start from.

| Scenario | Principal checks |
| --- | --- |
| `hung-relay.md` | C-DLV §4.3, C-DLV §4.4, C-DLV §5.3, C-DLV §4.6, C-SDK §6.1, C-SDK §6.3 |
| `relay-loss.md` | C-DLV §5.1, C-DLV §5.2, C-DLV §5.3, C-SDK §6.2, C-SDK §6.3 |
| `duplicate-and-reordered.md` | C-DLV §8, C-DLV §7.1, C-DLV §7.2, C-DLV §7.3, C-DLV §5.4, C-DLV §5.3, C-SDK §2, C-SDK §4.3 |
| `offline-recipient.md` | C-DLV §4.4, C-DLV §7.3, C-DLV §5.4, C-DLV §5.3, C-SDK §6.1, C-SDK §2 |
| `queue-restart-lost.md` | C-DLV §4.6, C-DLV §4.5, C-DLV §5.2, C-DLV §6.4, C-DLV §2, C-SDK §8.1 |

## 6. Injected clock and randomness

Timings are read on the injected clock port (C-SDK §8.4). A timeline states the clock readings and, where a
delay is drawn, the exact `random.nextUint32()` values in draw order, so every delay is exact:
`base(n) = min(1000 × 2^(n−1), 30000)` and `delay(n, u) = floor(base(n) / 2) + floor(u × base(n) / 2^33)`
(C-DLV §3, §4.3). The injected values are not all zero: `hung-relay.md` draws 4294967295, 2147483648,
4294967295 and 0 in that order, which is 999 ms, 1500 ms, 3999 ms and 4000 ms, and `relay-loss.md` and
`duplicate-and-reordered.md` each draw a zero and a non-zero value in the other order, so the jitter term
and the draw order are both exercised. A timeline's stated times assume the injected clock fires each armed timer at exactly its delay;
the host `setTimeout` backstops of C-DLV §4.4, §4.5 and §5.2 are the fallback and are named where they matter.
Unless a timeline says otherwise the parameters take the C-DLV §3 defaults: `maxAttempts` 5, `deadlineMs`
120000, `perRelayTimeoutMs` 12000, `receiptMode` `RELAY_ACCEPTANCE_ONLY`, the port-call timeout 6000, the
terminal processing slack 1000, the relay supervision interval 1000, the backoff base 1000 and cap 30000, the
payload maximum 65536, the queue bound 256, the inbound pending bound 1024 and the inbound duplicate window
4096.

## 7. Non-claims

Every record carries the same `nonClaims` object, whose flags are the C-DLV §2 outer bounds and the C-DLV §11
non-claims: no exactly-once delivery, no ordering, no cross-restart recovery, no unbounded retransmission, no
claim that relay acceptance is recipient receipt, no claim that a receipt proves that a message was opened
(`receiptProvesOpening`) or read by a person (`receiptProvesReading`), no new cryptography, no normative wire
format, no public relay, no durable persistence and
no metadata protection. No scenario asserts that a person read a message, and no scenario asserts that a
recipient's receipt or a relay's acceptance is evidence about a human. The records name the kinds, tags and
record fields of C-DLV §6, which that section declares SDK-internal, experimental and non-normative.

## 8. Hygiene and precedence

No file contains a non-loopback URL, an absolute path, a host name, a cost figure, or a claim about a person
having read a message. **Where a scenario and a ratified document differ, the document wins and the difference
is a defect of the scenario**: this set is a candidate record, and the two documents are the authority.

## 9. Open readings

Three readings are stated in the records themselves, because the two documents leave them open, and each
record that depends on one says so in its preconditions:

1. **The instant of inbound processing during a connection phase.** C-DLV §7.1 processes inbound `EVENT`
   frames per client, one at a time, in arrival order across all relays, and neither C-DLV §5.2 nor §7.1
   holds inbound frames while a `start()` has not yet resolved, when `ClientState` is still `CREATED`
   (C-SDK §4 names `CREATED`, `RUNNING` and `STOPPED` only). A timeline in which a relay replays a stored
   match while the recipient's connection phase is still open therefore fixes the processing instants at
   the arrivals, and says so.
2. **The counting convention of `dropAfterFrames`**, in §1.3 of this file.
3. **The instant at which the harness delivers a frame.** Neither document fixes a per-frame delay. The
   harness of C-DLV §10 offers the `delayFrames` behaviour, which holds frames for a declared time, and where
   no relay holds frames the timelines state the instant at which the harness delivers each frame — that is
   what lets `receiptExactlyAtDeadline` state that both copies of a receipt arrive at exactly the deadline
   reading and no copy before it. The owner decides whether that capability belongs in the §12 harness
   description.
4. **The first relay supervision read.** Relay supervision runs every relay supervision interval from the
   moment `start()` resolves, so the first read after an event at 13000 ms is the read at 13000 ms;
   `relayLossAndReplacement` fixes that reading in its preconditions.
5. **The harness name a timeline attaches itself to.** C-DLV §12 describes `hungRelay` as a never-answering
   relay next to a **normal** one and `shutdownLostThenNewClient` as a shutdown followed by a new client
   with a **new empty** store. Two timelines here need the same behaviour without those neighbours: the
   exhaustion path of the hung relay uses two never-answering relays, and the storage refusal of
   `start()` is reached with a store that is not empty. Each names its `harness` and carries a
   `harnessNote` that states the difference, and the owner decides whether the §12 description or the
   timeline is the one to change.
