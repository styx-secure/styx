# Scenario `duplicateAndReordered` — duplicate copies and reordered arrivals

Purpose item (scope record `O-SCEN3`): **duplicate and reordered delivery**. Harness scenario of C-DLV §12
exercised here: `duplicateAndReordered`.

<!-- styx-m3-scenario:v1:start -->
```json
{
  "schema": "styx-m3-scenario/v1",
  "closed": true,
  "scenarioId": "duplicateAndReordered",
  "purposeItem": "duplicateAndReordered",
  "title": "Duplicate inbound copies are suppressed in a bounded per-process window, the client processes them in arrival order, which need not be the sending order, and a republished event answered duplicate: counts as ACCEPTED",
  "harnessScenarios": [
    "duplicateAndReordered"
  ],
  "contracts": {
    "sdkInterface": {
      "path": "docs/architecture/m3/sdk-interface.md",
      "sha256": "47f75d6cd0bd3d542fd699f99144da6ccd9d6965908e5d1f4b2c1dfd976a9a11"
    },
    "deliveryLayer": {
      "path": "docs/architecture/m3/delivery-layer.md",
      "sha256": "9ffd2accd7bf715d87728bc484669b70501d10c198707f15c4ce12b3935cf1b8"
    }
  },
  "clauses": [
    "C-SDK §2",
    "C-SDK §4.1",
    "C-SDK §4.2",
    "C-SDK §4.3",
    "C-SDK §6.1",
    "C-SDK §6.2",
    "C-SDK §6.3",
    "C-SDK §7",
    "C-SDK §8.4",
    "C-DLV §2",
    "C-DLV §3",
    "C-DLV §4.2",
    "C-DLV §4.3",
    "C-DLV §4.4",
    "C-DLV §4.6",
    "C-DLV §5.1",
    "C-DLV §5.2",
    "C-DLV §5.3",
    "C-DLV §5.4",
    "C-DLV §6.1",
    "C-DLV §6.2",
    "C-DLV §6.3",
    "C-DLV §7.1",
    "C-DLV §7.2",
    "C-DLV §7.3",
    "C-DLV §8",
    "C-DLV §10"
  ],
  "nonClaims": {
    "exactlyOnce": false,
    "ordering": false,
    "crossRestart": false,
    "unboundedRetransmission": false,
    "relayAcceptanceDistinctFromReceipt": true,
    "receiptProvesReading": false,
    "receiptProvesOpening": false,
    "newCryptography": false,
    "normativeWireFormat": false,
    "publicRelay": false,
    "personReadMessage": false,
    "durablePersistence": false,
    "metadataProtection": false
  },
  "timelines": [
    {
      "id": "inboundDuplicateReordered",
      "harness": "duplicateAndReordered",
      "config": {
        "client": "senderAndRecipient",
        "maxAttempts": 5,
        "deadlineMs": 120000,
        "perRelayTimeoutMs": 12000,
        "receiptMode": "RECIPIENT_RECEIPT",
        "portCallTimeoutMs": 6000,
        "terminalProcessingSlackMs": 1000,
        "relaySupervisionMs": 1000,
        "backoffBaseMs": 1000,
        "backoffCapMs": 30000,
        "payloadMaxBytes": 65536,
        "queueBound": 256,
        "inboundPendingBound": 1024,
        "inboundDuplicateWindow": 4096,
        "randomValues": [],
        "relays": [
          {
            "index": 0,
            "host": "127.0.0.1",
            "port": "ephemeral",
            "behaviours": [
              "normal"
            ],
            "role": "normal relay that replays its stored matches in insertion order, then EOSE, then forwards live matches, and answers OK true once per event; its connection for the recipient's subscription opens 200 ms after relay1's, so its copies of the replayed events arrive after relay1's"
          },
          {
            "index": 1,
            "host": "::1",
            "port": "ephemeral",
            "behaviours": [
              "duplicateDelivery",
              "reverseOrder"
            ],
            "role": "delivers every matching event to a subscriber twice and replays its stored matches in reverse insertion order, twice each; answers OK true once per event"
          }
        ]
      },
      "preconditions": [
        "The sender runs in RECIPIENT_RECEIPT mode, so the kind-4741 event carries the r tag as its fourth tag and asks for a receipt.",
        "The recipient client is created and started only after both events were stored by both relays, so the copies it receives come from the relay replay of C-DLV §5.4, which a relay may do for events stored before the client started; the REQ of the subscription is sent on each connection when that connection opens, not at the end of the connection phase.",
        "relay1 replays its stored matches in reverse insertion order, each of them twice, and relay1's connection for the recipient's subscription opens 200 ms before relay0's, so relay1's copies arrive first and relay0's arrive last; neither relay is configured to hold frames, so no arrival below is produced by a frame delay.",
        "C-DLV §7.1 processes inbound EVENT frames per client, one at a time and in arrival order across all relays, and neither §5.2 nor §7.1 holds inbound frames while the recipient's start() has not yet resolved and its state is still CREATED (C-SDK §4 names CREATED, RUNNING and STOPPED only); this timeline therefore fixes the processing instants of the inbound frames at their arrivals, during the connection phase of the recipient client, and marks that reading as the one point where the two documents leave the instant of inbound processing during a connection phase open. The receipt publication of C-DLV §7.2 carries no RUNNING condition of its own: C-DLV §5.2 states no RUNNING condition for inbound processing, and the recipient client of this timeline has no outbound item.",
        "The two payloads differ and the two events carry different n tags, so they have different event ids even though they share the recipient and the created_at second.",
        "The injected clock port fires each armed timer at exactly its delay; no retry delay is drawn in this timeline, so randomValues is empty."
      ],
      "clauses": [
        "C-SDK §2",
        "C-SDK §4.1",
        "C-SDK §4.2",
        "C-SDK §4.3",
        "C-SDK §6.1",
        "C-SDK §6.2",
        "C-SDK §6.3",
        "C-SDK §7",
        "C-SDK §8.4",
        "C-DLV §3",
        "C-DLV §4.2",
        "C-DLV §4.3",
        "C-DLV §4.4",
        "C-DLV §5.1",
        "C-DLV §5.2",
        "C-DLV §5.3",
        "C-DLV §5.4",
        "C-DLV §6.1",
        "C-DLV §6.2",
        "C-DLV §6.3",
        "C-DLV §7.1",
        "C-DLV §7.2",
        "C-DLV §7.3",
        "C-DLV §8",
        "C-DLV §10"
      ],
      "events": [
        {
          "at": 0,
          "actor": "sender",
          "event": "start()",
          "detail": "createStyxClient with the delivery configuration of C-SDK §4.1 and the two injected relay URLs; every parameter is inside the C-DLV §3 bounds; storage is empty; one pool per relay with its automatic reconnect cleared, the subscription for kinds 4741 and 4742 addressed to the client's own key registered before connecting, connectAll() on both pools in parallel",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §3",
            "C-DLV §5.1",
            "C-DLV §5.4",
            "C-SDK §4.1",
            "C-SDK §8.4"
          ]
        },
        {
          "at": 12000,
          "actor": "sender",
          "event": "start() resolves",
          "detail": "{ clientState: RUNNING, connectedRelays: 2 }; CLIENT_STATE_CHANGED with RUNNING",
          "timing": {
            "kind": "connectionPhase",
            "valueMs": 12000,
            "attempt": 1
          },
          "checks": [
            "C-DLV §5.2",
            "C-SDK §4.2"
          ],
          "anchor": {
            "startedAt": 0
          }
        },
        {
          "at": 12000,
          "actor": "sender",
          "event": "send({ recipient, payload }) twice",
          "detail": "two admissions, of payloads P1 and P2, both for the recipient key; the queue bound of 256 non-terminal items is not exceeded; each item gets createdAt 12000, deadlineAt 132000, attempts 0, lastCode null and every relay outcome PENDING: { deliveryId: d1, state: QUEUED } and { deliveryId: d2, state: QUEUED }",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §4.2",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 12000,
          "actor": "sender",
          "event": "attempt 1 of d1 and d2 begins",
          "detail": "each item moves QUEUED to IN_FLIGHT with attempts 1; each event is a kind-4741 event with exactly the tags [p, the recipient key], [v, the interface version string], [n, 32 lowercase hex digits] and, in this mode, [r, 1]; the two n tags differ, so the event ids differ; each event is signed once and published to both relays, and publish returns 1 on both; both relays store both events; the attempt timeouts are armed at the publication start",
          "timing": {
            "kind": "attemptTimeout",
            "valueMs": 12000,
            "attempt": 1
          },
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "IN_FLIGHT"
            },
            {
              "deliveryId": "d2",
              "to": "IN_FLIGHT"
            }
          ],
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.3",
            "C-DLV §6.1",
            "C-DLV §6.2",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 12050,
          "actor": "relay0",
          "event": "OK true for both events",
          "detail": "relay0 answers each of the two event ids with [\"OK\", <event id>, true, \"saved\"]; relay0's entry becomes ACCEPTED for each item, and because both items are IN_FLIGHT in this attempt the first acceptance of each ends its publication phase: d1 and d2 each move to RELAY_ACCEPTED_AWAITING_RECEIPT, not terminal, with lastCode null and one DELIVERY_STATE_CHANGED each; the attempts stay open, because in this mode the accepted attempt is the last and ends only at a receipt, the deadline, a fault, a cancel or shutdown",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 50
          },
          "relayAnswer": {
            "relayIndex": 0,
            "accepted": true,
            "events": 2
          },
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "RELAY_ACCEPTED_AWAITING_RECEIPT"
            },
            {
              "deliveryId": "d2",
              "to": "RELAY_ACCEPTED_AWAITING_RECEIPT"
            }
          ],
          "checks": [
            "C-DLV §4.3",
            "C-DLV §4.4",
            "C-DLV §5.3",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 12060,
          "actor": "relay1",
          "event": "OK true for both events",
          "detail": "relay1 answers both event ids with OK true although it delivers every matching event twice; its entry becomes ACCEPTED for each item and no item changes state, because neither is IN_FLIGHT any more and a per-relay outcome changes an item's state only through the first acceptance of an item in IN_FLIGHT",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "relayAnswer": {
            "relayIndex": 1,
            "accepted": true,
            "events": 2
          },
          "checks": [
            "C-DLV §5.3",
            "C-DLV §8",
            "C-SDK §6.3"
          ]
        },
        {
          "at": 20000,
          "actor": "recipient",
          "event": "the recipient client is created and started",
          "detail": "the recipient client is created with an empty storage port and started; its registration uses one subscriptionId per client (the letter s followed by 32 lowercase hexadecimal digits from randomBytes) and the filter of C-DLV §5.4, which has no since and no limit, so a relay may replay the two events stored before this client started",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §5.2",
            "C-DLV §5.4",
            "C-SDK §4.1",
            "C-SDK §4.2"
          ]
        },
        {
          "at": 21000,
          "actor": "recipient",
          "event": "relay1's connection opens and the REQ is sent on it",
          "detail": "the subscription was registered before the pools connected, so RelayPool sends the REQ for this client when the connection opens; this is the first of the two connections for the recipient's subscription, and relay1 replays its stored matches for that filter in reverse insertion order, each of them twice",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 1000
          },
          "checks": [
            "C-DLV §5.2",
            "C-DLV §5.4",
            "C-SDK §4.2"
          ]
        },
        {
          "at": 21100,
          "actor": "recipient",
          "event": "relay0's connection opens and the REQ is sent on it",
          "detail": "relay0's connection for the recipient's subscription opens 200 ms after relay1's (the harness fixes both instants); relay0 replays its stored matches for that filter in insertion order, then EOSE",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 100
          },
          "checks": [
            "C-DLV §10",
            "C-DLV §5.4",
            "C-DLV §8",
            "C-SDK §4.2"
          ]
        },
        {
          "at": 21105,
          "actor": "recipient",
          "event": "the first copy of e2 arrives",
          "detail": "the kind-4741 event passes every check of C-DLV §7.1 (shape, kind, the four tags with p equal to the client's own key and v equal to the interface version string, the recomputed id and the signature); the duplicate check of C-DLV §8 runs after those checks, its id is not in the window, and an id enters the window when it passes §7.1; the content decodes and session.open returns a plaintext, so MESSAGE_RECEIVED is emitted with the sender key and a fresh copy of P2; because the event carries the r tag, the recipient signs a kind-4742 receipt for this event id and publishes it once on every connected pool",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 5
          },
          "checks": [
            "C-DLV §6.3",
            "C-DLV §7.1",
            "C-DLV §7.2",
            "C-DLV §8",
            "C-SDK §7"
          ]
        },
        {
          "at": 21115,
          "actor": "recipient",
          "event": "the second copy of e2 arrives",
          "detail": "the id of e2 is already in the window, so this copy is dropped without an event and without a second receipt",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §7.2",
            "C-DLV §8",
            "C-SDK §4.3"
          ]
        },
        {
          "at": 21125,
          "actor": "recipient",
          "event": "the first copy of e1 arrives",
          "detail": "the reverse-order replay delivers e1 after e2, so the client processes and emits it after e2 although P1 was sent before P2; the event passes every check of C-DLV §7.1, is not in the window, and MESSAGE_RECEIVED is emitted with a fresh copy of P1; the recipient then signs one kind-4742 receipt for e1 and publishes it once on every connected pool",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §7.1",
            "C-DLV §7.2",
            "C-DLV §8",
            "C-SDK §2"
          ]
        },
        {
          "at": 21135,
          "actor": "recipient",
          "event": "the second copy of e1 arrives",
          "detail": "dropped without an event and without a second receipt",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §7.2",
            "C-DLV §8"
          ]
        },
        {
          "at": 21200,
          "actor": "sender",
          "event": "the first accepted receipt arrives",
          "detail": "the receipt of e2 reaches the sender on relay1's connection; every condition of C-DLV §7.3 holds: the kind-4742 event passed every check of C-DLV §7.1, its p tag equals the sender's own public key, its e tag is the event id of the non-terminal item d2 in RECIPIENT_RECEIPT mode, its pubkey equals that item's recipient, the item has not already taken a receipt, and clock.now() = 21200 is before deadlineAt 132000; the acceptance is recorded and d2 moves RELAY_ACCEPTED_AWAITING_RECEIPT to RECIPIENT_RECEIPT_RECEIVED, terminal, with lastCode null and one DELIVERY_STATE_CHANGED",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 65
          },
          "transitions": [
            {
              "deliveryId": "d2",
              "to": "RECIPIENT_RECEIPT_RECEIVED"
            }
          ],
          "checks": [
            "C-DLV §7.1",
            "C-DLV §7.2",
            "C-DLV §7.3",
            "C-SDK §6.1",
            "C-SDK §7"
          ]
        },
        {
          "at": 21205,
          "actor": "recipient",
          "event": "relay0's copies of the replayed events arrive",
          "detail": "relay0's insertion-order replay of the two stored matches reaches the recipient after relay1's copies; the ids of both events are already in the window, so both copies are dropped without an event and without a second receipt",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 5
          },
          "checks": [
            "C-DLV §10",
            "C-DLV §5.4",
            "C-DLV §8"
          ]
        },
        {
          "at": 21210,
          "actor": "sender",
          "event": "a second copy of the receipt of e2 arrives",
          "detail": "relay1 delivers every matching event twice, so the same receipt id arrives again; the id is already in the window, so the copy is dropped without a second transition and without an event",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 5
          },
          "checks": [
            "C-DLV §7.3",
            "C-DLV §8"
          ]
        },
        {
          "at": 21220,
          "actor": "sender",
          "event": "the receipt of e1 arrives",
          "detail": "accepted on the same conditions of C-DLV §7.3; d1 moves RELAY_ACCEPTED_AWAITING_RECEIPT to RECIPIENT_RECEIPT_RECEIVED, terminal, with lastCode null and one DELIVERY_STATE_CHANGED",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "RECIPIENT_RECEIPT_RECEIVED"
            }
          ],
          "checks": [
            "C-DLV §7.2",
            "C-DLV §7.3",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 21230,
          "actor": "sender",
          "event": "the second copy of the receipt of e1 arrives",
          "detail": "dropped as a duplicate of an id already in the window, without a second transition and without an event",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §8",
            "C-SDK §4.3"
          ]
        },
        {
          "at": 21305,
          "actor": "sender",
          "event": "relay0's copies of both receipts arrive",
          "detail": "the same two receipt ids arrive once more, from relay0 this time, at the instants the harness fixes for that connection, both after relay1's copies; each id is already in the window, so each copy is dropped without a transition and without an event",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 75
          },
          "checks": [
            "C-DLV §5.3",
            "C-DLV §8"
          ]
        },
        {
          "at": 32000,
          "actor": "recipient",
          "event": "start() resolves",
          "detail": "{ clientState: RUNNING, connectedRelays: 2 }; the connection phase of the recipient client ends perRelayTimeoutMs after it began, and the inbound frames processed at 21105 to 21305 were processed while its start() had not yet resolved and its state was still CREATED, which is the reading stated in the preconditions",
          "timing": {
            "kind": "connectionPhase",
            "valueMs": 12000,
            "attempt": 1
          },
          "checks": [
            "C-DLV §5.2",
            "C-DLV §7.1",
            "C-SDK §4.2"
          ],
          "anchor": {
            "startedAt": 20000
          }
        },
        {
          "at": 32010,
          "actor": "sender",
          "event": "getDelivery({ deliveryId: d1 }) and ({ deliveryId: d2 })",
          "detail": "both snapshots report state RECIPIENT_RECEIPT_RECEIVED, terminal true, attempts 1, lastCode null and relayOutcomes [{ relayIndex: 0, outcome: ACCEPTED }, { relayIndex: 1, outcome: ACCEPTED }]",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §5.3",
            "C-SDK §6.2",
            "C-SDK §6.3"
          ]
        },
        {
          "at": 32010,
          "actor": "recipient",
          "event": "getDelivery on the recipient client",
          "detail": "{ ok: false, code: E_SDK_UNKNOWN_DELIVERY }: the recipient client assigned no deliveryId; it emitted exactly two MESSAGE_RECEIVED events, one per event id, in the order it processed them, and published exactly two receipts, one per event id",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 0
          },
          "checks": [
            "C-DLV §7.2",
            "C-DLV §8",
            "C-SDK §4.2"
          ]
        }
      ],
      "expectedTransitions": [
        {
          "deliveryId": "d1",
          "from": "QUEUED",
          "to": "IN_FLIGHT"
        },
        {
          "deliveryId": "d2",
          "from": "QUEUED",
          "to": "IN_FLIGHT"
        },
        {
          "deliveryId": "d1",
          "from": "IN_FLIGHT",
          "to": "RELAY_ACCEPTED_AWAITING_RECEIPT"
        },
        {
          "deliveryId": "d2",
          "from": "IN_FLIGHT",
          "to": "RELAY_ACCEPTED_AWAITING_RECEIPT"
        },
        {
          "deliveryId": "d2",
          "from": "RELAY_ACCEPTED_AWAITING_RECEIPT",
          "to": "RECIPIENT_RECEIPT_RECEIVED"
        },
        {
          "deliveryId": "d1",
          "from": "RELAY_ACCEPTED_AWAITING_RECEIPT",
          "to": "RECIPIENT_RECEIPT_RECEIVED"
        }
      ],
      "expectedItemStates": [
        {
          "deliveryId": "d1",
          "recipient": "<recipient public key>",
          "state": "RECIPIENT_RECEIPT_RECEIVED",
          "terminal": true,
          "attempts": 1,
          "createdAt": 12000,
          "deadlineAt": 132000,
          "lastCode": null,
          "relayOutcomes": [
            {
              "relayIndex": 0,
              "outcome": "ACCEPTED"
            },
            {
              "relayIndex": 1,
              "outcome": "ACCEPTED"
            }
          ]
        },
        {
          "deliveryId": "d2",
          "recipient": "<recipient public key>",
          "state": "RECIPIENT_RECEIPT_RECEIVED",
          "terminal": true,
          "attempts": 1,
          "createdAt": 12000,
          "deadlineAt": 132000,
          "lastCode": null,
          "relayOutcomes": [
            {
              "relayIndex": 0,
              "outcome": "ACCEPTED"
            },
            {
              "relayIndex": 1,
              "outcome": "ACCEPTED"
            }
          ]
        }
      ],
      "expectedRelayStates": [
        {
          "relayIndex": 0,
          "outcome": "ACCEPTED",
          "note": "one OK true per distinct event id; its later connection delivered only duplicate copies at the recipient and at the sender"
        },
        {
          "relayIndex": 1,
          "outcome": "ACCEPTED",
          "note": "one acceptance per event id is recorded although it delivers each matching event twice"
        }
      ],
      "expectedMethodResults": [
        {
          "at": 12000,
          "call": "send({ recipient, payload: P1 })",
          "result": "{ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } }"
        },
        {
          "at": 12000,
          "call": "send({ recipient, payload: P2 })",
          "result": "{ ok: true, value: { deliveryId: 'd2', state: 'QUEUED' } }"
        },
        {
          "at": 32010,
          "call": "getDelivery({ deliveryId: 'd1' })",
          "result": "{ ok: true, value: { deliveryId: 'd1', recipient: '<recipient public key>', state: 'RECIPIENT_RECEIPT_RECEIVED', terminal: true, attempts: 1, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: 'ACCEPTED' }, { relayIndex: 1, outcome: 'ACCEPTED' }] } }"
        },
        {
          "at": 32010,
          "call": "getDelivery on the recipient client",
          "result": "{ ok: false, code: 'E_SDK_UNKNOWN_DELIVERY' }"
        },
        {
          "at": 32010,
          "call": "getDelivery({ deliveryId: 'd2' })",
          "result": "{ ok: true, value: { deliveryId: 'd2', recipient: '<recipient public key>', state: 'RECIPIENT_RECEIPT_RECEIVED', terminal: true, attempts: 1, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: 'ACCEPTED' }, { relayIndex: 1, outcome: 'ACCEPTED' }] } }"
        }
      ],
      "expectedEvents": [
        "CLIENT_STATE_CHANGED with clientState RUNNING in each client at 12000 and 32000",
        "DELIVERY_STATE_CHANGED with state IN_FLIGHT, terminal false, for d1 and d2 at 12000",
        "DELIVERY_STATE_CHANGED with state RELAY_ACCEPTED_AWAITING_RECEIPT, terminal false and lastCode null, for d1 and d2 at 12050",
        "exactly one MESSAGE_RECEIVED for e2 and exactly one for e1, in the order this client processed them, which here is e2 before e1 although P1 was sent before P2",
        "DELIVERY_STATE_CHANGED with state RECIPIENT_RECEIPT_RECEIVED, terminal true and lastCode null, for d2 at 21200 and for d1 at 21220"
      ],
      "notEmitted": [
        "no MESSAGE_RECEIVED and no INBOUND_DISCARDED for a copy whose event id is already in the window, and no second receipt for an event id while that id is in the window",
        "no second DELIVERY_STATE_CHANGED for a terminal item",
        "no ordering guarantee: C-SDK §2 bound 2 and C-DLV §8 say a message may be received zero, one or more times and in any order, and the recipient's processing order here is e2 then e1, the reverse of the sending order, because that is the arrival order",
        "no claim that the relay replay is guaranteed: it is the relay's own behaviour of C-DLV §5.4"
      ]
    },
    {
      "id": "outboundDuplicateAccepted",
      "harness": "duplicateAndReordered",
      "config": {
        "client": "sender",
        "maxAttempts": 5,
        "deadlineMs": 120000,
        "perRelayTimeoutMs": 12000,
        "receiptMode": "RELAY_ACCEPTANCE_ONLY",
        "portCallTimeoutMs": 6000,
        "terminalProcessingSlackMs": 1000,
        "relaySupervisionMs": 1000,
        "backoffBaseMs": 1000,
        "backoffCapMs": 30000,
        "payloadMaxBytes": 65536,
        "queueBound": 256,
        "inboundPendingBound": 1024,
        "inboundDuplicateWindow": 4096,
        "randomValues": [
          0,
          4294967295
        ],
        "relays": [
          {
            "index": 0,
            "host": "127.0.0.1",
            "port": "ephemeral",
            "behaviours": [
              "dropAfterFrames"
            ],
            "role": "stores the event and then closes its first connection after receiving the first EVENT frame published to it, before answering that frame (REQ frames are not counted and the behaviour applies to that first connection only); its stored copy survives the socket drop, and its replacement connection answers a republished event with [\"OK\", <event id>, true, \"duplicate: already have this event\"]"
          },
          {
            "index": 1,
            "host": "::1",
            "port": "ephemeral",
            "behaviours": [
              "neverAnswering"
            ],
            "role": "accepts the connection and never sends any frame"
          }
        ]
      },
      "preconditions": [
        "A retransmission republishes the identical signed event bytes, so the event id is the same in attempt 1 and attempt 2.",
        "relay0 stored the event in attempt 1 and kept it after dropping the socket, so in attempt 2 its replacement connection already holds the event and answers with a duplicate: message.",
        "The injected clock port fires each armed timer at exactly its delay; the injected random port returns the two values of randomValues in draw order, the first for the reconnection delay of the k-th consecutive lost connection, which is 0, and the second which is 4294967295 for the retry delay of attempt 1: delay(1, 4294967295) = floor(1000 / 2) + floor(4294967295 × 1000 / 2^33) = 500 + 499 = 999 ms for the reconnection and delay(1, 4294967295) = 500 + 499 = 999 ms for the retry, so the draw order matters and is exercised."
      ],
      "clauses": [
        "C-SDK §2",
        "C-SDK §4.1",
        "C-SDK §4.2",
        "C-SDK §6.1",
        "C-SDK §6.2",
        "C-SDK §6.3",
        "C-SDK §7",
        "C-SDK §8.4",
        "C-DLV §2",
        "C-DLV §3",
        "C-DLV §4.2",
        "C-DLV §4.3",
        "C-DLV §4.4",
        "C-DLV §4.6",
        "C-DLV §5.1",
        "C-DLV §5.2",
        "C-DLV §5.3",
        "C-DLV §8"
      ],
      "events": [
        {
          "at": 0,
          "actor": "sender",
          "event": "start()",
          "detail": "createStyxClient with the delivery configuration of C-SDK §4.1 and the two injected relay URLs; every parameter is inside the C-DLV §3 bounds; storage is empty; one pool per relay with its automatic reconnect cleared, connectAll() on both in parallel",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §2",
            "C-DLV §3",
            "C-DLV §5.1",
            "C-SDK §4.1"
          ]
        },
        {
          "at": 12000,
          "actor": "sender",
          "event": "start() resolves",
          "detail": "{ clientState: RUNNING, connectedRelays: 2 }",
          "timing": {
            "kind": "connectionPhase",
            "valueMs": 12000,
            "attempt": 1
          },
          "checks": [
            "C-DLV §5.2",
            "C-SDK §4.2"
          ],
          "anchor": {
            "startedAt": 0
          }
        },
        {
          "at": 12000,
          "actor": "sender",
          "event": "send({ recipient, payload })",
          "detail": "admission: deliveryId d1, state QUEUED, createdAt 12000, deadlineAt = createdAt + deadlineMs = 132000, attempts 0, lastCode null, every relay outcome PENDING",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §4.2",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 12000,
          "actor": "sender",
          "event": "attempt 1 begins",
          "detail": "QUEUED to IN_FLIGHT, attempts 1; the kind-4741 event is signed and published to both relays, and publish returns 1 on both; both entries are PENDING; the attempt timeout is armed at the publication start",
          "timing": {
            "kind": "attemptTimeout",
            "valueMs": 12000,
            "attempt": 1
          },
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "IN_FLIGHT"
            }
          ],
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.3",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 12050,
          "actor": "relay0",
          "event": "the connection is dropped after the EVENT frame is received",
          "detail": "the first EVENT frame published to relay0 on this connection reaches it and is stored, and the socket closes before any matching OK frame; publish returned 1 on relay0 in this attempt, and no outcome is set at this instant",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 50
          },
          "checks": [
            "C-DLV §5.1",
            "C-DLV §5.3"
          ]
        },
        {
          "at": 13000,
          "actor": "sender",
          "event": "relay supervision read",
          "detail": "the supervision read finds relay0 no longer connected and with no connection attempt in progress, while publish returned 1 on it in this attempt: relay0's outcome is UNREACHABLE and its current pool is retired with dispose(); a new pool is prepared and its connectAll() is armed after delay(1, u) for the first consecutive lost connection of that relay, with the first injected draw 0, so delay(1, 0) = 500",
          "timing": {
            "kind": "reconnectDelay",
            "valueMs": 500,
            "attempt": 1
          },
          "clock": {
            "kind": "reconnectArm",
            "consecutiveLoss": 1
          },
          "checks": [
            "C-DLV §5.1",
            "C-DLV §5.2",
            "C-DLV §5.3",
            "C-SDK §6.3",
            "C-SDK §8.4"
          ]
        },
        {
          "at": 13500,
          "actor": "relay0",
          "event": "the replacement connection opens",
          "detail": "the new pool's connection opens; nothing is published on it in attempt 1",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 500
          },
          "checks": [
            "C-DLV §5.1",
            "C-DLV §5.2"
          ]
        },
        {
          "at": 24000,
          "actor": "clock",
          "event": "the attempt timeout of attempt 1 elapses and the retry is armed",
          "detail": "the attempt timeout elapses: relay1 is still PENDING and becomes TIMED_OUT; relay0 keeps UNREACHABLE for this attempt; no acceptance was recorded, so the SDK draws the second value and computes delay(1, 4294967295) = floor(1000 / 2) + floor(4294967295 × 1000 / 2^33) = 500 + 499 = 999; clock.now() + 500 = 24999 is before deadlineAt 132000, so the retry is armed; IN_FLIGHT to QUEUED",
          "timing": {
            "kind": "retryDelay",
            "valueMs": 999,
            "attempt": 1
          },
          "clock": {
            "kind": "attemptTimeout",
            "attempt": 1
          },
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "QUEUED"
            }
          ],
          "checks": [
            "C-DLV §4.3",
            "C-DLV §4.4",
            "C-DLV §5.3",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 24999,
          "actor": "sender",
          "event": "attempt 2 republishes the identical event bytes",
          "detail": "QUEUED to IN_FLIGHT, attempts 2; relay0 is set to PENDING and published to on its replacement connection, which returns 1; relay1 is set to PENDING and published to, and returns 1; the event id is unchanged, because every retransmission republishes exactly the signed bytes kept with the item; the attempt timeout is armed",
          "timing": {
            "kind": "attemptTimeout",
            "valueMs": 12000,
            "attempt": 2
          },
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "IN_FLIGHT"
            }
          ],
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.2",
            "C-DLV §5.3",
            "C-DLV §8",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 25099,
          "actor": "relay0",
          "event": "OK true with a duplicate: message",
          "detail": "[\"OK\", <event id>, true, \"duplicate: already have this event\"]; relay0 holds the very same event from attempt 1, so this answer counts as ACCEPTED; relay0's entry becomes ACCEPTED and, because d1 is IN_FLIGHT in this attempt, the first acceptance ends the publication phase and moves the item to RELAY_ACCEPTED, terminal in this mode, with lastCode null and one DELIVERY_STATE_CHANGED",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 100
          },
          "relayAnswer": {
            "relayIndex": 0,
            "accepted": true,
            "events": 1
          },
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "RELAY_ACCEPTED"
            }
          ],
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.3",
            "C-DLV §8",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 36999,
          "actor": "clock",
          "event": "the attempt timeout of attempt 2 elapses",
          "detail": "the attempt timeout elapses: relay1's entry is still PENDING and becomes TIMED_OUT; the entry settles although the item is terminal and the attempt is over, which is the settle window of C-DLV §5.3; no delay is drawn and no attempt 3 starts, because no retransmission happens after an acceptance",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 11900
          },
          "clock": {
            "kind": "attemptTimeout",
            "attempt": 2
          },
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.3",
            "C-SDK §6.3"
          ]
        },
        {
          "at": 36999,
          "actor": "sender",
          "event": "getDelivery({ deliveryId: d1 })",
          "detail": "{ ok: true, value: { deliveryId: d1, recipient: <recipient public key>, state: RELAY_ACCEPTED, terminal: true, attempts: 2, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: ACCEPTED }, { relayIndex: 1, outcome: TIMED_OUT }] } }",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 0
          },
          "checks": [
            "C-DLV §5.3",
            "C-SDK §6.2",
            "C-SDK §6.3"
          ]
        },
        {
          "at": 37009,
          "actor": "sender",
          "event": "shutdown()",
          "detail": "every relay outcome is frozen at its current value; the only item is terminal, so the result is { clientState: STOPPED, lost: 0 } and CLIENT_STATE_CHANGED with STOPPED is emitted; every pool, subscription and timer is closed",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §4.6",
            "C-DLV §5.3",
            "C-SDK §2",
            "C-SDK §4.2",
            "C-SDK §7"
          ]
        }
      ],
      "expectedTransitions": [
        {
          "deliveryId": "d1",
          "from": "QUEUED",
          "to": "IN_FLIGHT"
        },
        {
          "deliveryId": "d1",
          "from": "IN_FLIGHT",
          "to": "QUEUED"
        },
        {
          "deliveryId": "d1",
          "from": "QUEUED",
          "to": "IN_FLIGHT"
        },
        {
          "deliveryId": "d1",
          "from": "IN_FLIGHT",
          "to": "RELAY_ACCEPTED"
        }
      ],
      "expectedItemStates": [
        {
          "deliveryId": "d1",
          "recipient": "<recipient public key>",
          "state": "RELAY_ACCEPTED",
          "terminal": true,
          "attempts": 2,
          "createdAt": 12000,
          "deadlineAt": 132000,
          "lastCode": null,
          "relayOutcomes": [
            {
              "relayIndex": 0,
              "outcome": "ACCEPTED"
            },
            {
              "relayIndex": 1,
              "outcome": "TIMED_OUT"
            }
          ]
        }
      ],
      "expectedRelayStates": [
        {
          "relayIndex": 0,
          "outcome": "ACCEPTED",
          "note": "its duplicate: answer to the republished event counts as ACCEPTED"
        },
        {
          "relayIndex": 1,
          "outcome": "TIMED_OUT",
          "note": "never answered in either attempt"
        }
      ],
      "expectedMethodResults": [
        {
          "at": 12000,
          "call": "send({ recipient, payload })",
          "result": "{ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } }"
        },
        {
          "at": 36999,
          "call": "getDelivery({ deliveryId: 'd1' })",
          "result": "{ ok: true, value: { deliveryId: 'd1', recipient: '<recipient public key>', state: 'RELAY_ACCEPTED', terminal: true, attempts: 2, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: 'ACCEPTED' }, { relayIndex: 1, outcome: 'TIMED_OUT' }] } }"
        },
        {
          "at": 36999,
          "call": "shutdown()",
          "result": "{ ok: true, value: { clientState: 'STOPPED', lost: 0 } }"
        }
      ],
      "expectedEvents": [
        "CLIENT_STATE_CHANGED with clientState RUNNING at 12000",
        "DELIVERY_STATE_CHANGED with state IN_FLIGHT at 12000 and 24999",
        "DELIVERY_STATE_CHANGED with state QUEUED at 24000",
        "DELIVERY_STATE_CHANGED with state RELAY_ACCEPTED, terminal true and lastCode null at 25099",
        "CLIENT_STATE_CHANGED with clientState STOPPED at 37009"
      ],
      "notEmitted": [
        "no exactly-once claim: relay0 held the event since attempt 1 and answered duplicate: in attempt 2, and no claim is made about how many copies a relay stores",
        "no acceptance recorded for relay1, and no DELIVERY_STATE_CHANGED for a per-relay outcome",
        "no third attempt and no change of state after the terminal event"
      ]
    }
  ]
}
```
<!-- styx-m3-scenario:v1:end -->

## Prose: what the record fixes

Both timelines use the C-DLV §3 bounds and the transport use of C-DLV §5.1. The subscription is the one of
C-DLV §5.4 — one `subscriptionId` per client and the filter `{ "kinds": [4741, 4742], "#p": [<own public
key>] }`, with no `since` and no `limit` — and the relay behaviours are the per-relay behaviours of C-DLV §10.

**`inboundDuplicateReordered`.** Every inbound event is validated in the order of C-DLV §7.1, the duplicate
check of §8 runs after those checks, and an id enters the window when it passes them; a copy whose id is
already in the window is dropped without an event and without a second receipt. The two event ids differ
because of the `n` tag of C-DLV §6.2; each receipt is the kind-4742 structure of C-DLV §6.3, sent after a
successful `open` and `MESSAGE_RECEIVED` (§7.2) and at most once per event id while that id is in the window.
The reordered and duplicated copies come from the relay's own replay of C-DLV §5.4, which a relay may do for
events stored before the client started, combined with the `reverseOrder` and `duplicateDelivery` behaviours
of C-DLV §10; the `REQ` is sent when each connection opens, not at the end of the connection phase. The
sender accepts each receipt under the five conditions of C-DLV §7.3 and reaches
`RECIPIENT_RECEIPT_RECEIVED`, the success state of that mode in C-SDK §6.1. The timeline asserts counts and
the "no second event, no second receipt" rule, and it fixes the processing instants of the inbound frames at
their arrivals, in arrival order across relays as C-DLV §7.1 requires, which is exactly why the recipient
emits `e2` before `e1` here and why that order is not an ordering guarantee.

**`outboundDuplicateAccepted`.** A relay that already holds the event answers the republished event with
`OK true` and a `duplicate:` message, which C-DLV §5.3 and §8 define as `ACCEPTED`; the republished bytes are
the identical signed event, as C-DLV §4.3 requires, so the event id is unchanged and no exactly-once claim
follows (C-SDK §2 bound 2). The lost connection is reported `UNREACHABLE` for that attempt (C-DLV §5.3) and
the pool is retired and replaced before the next attempt (C-DLV §5.1, §5.2), with the snapshot rules of
C-SDK §6.2 and the outcomes of C-SDK §6.3.

The injection is stated so that it produces the timelines: `dropAfterFrames` counts EVENT frames and applies
to the first connection only, so relay0 drops after the event was stored and after `publish` returned `1`,
which is what makes `UNREACHABLE` (and not `PENDING`) the right outcome for that attempt under C-DLV §5.3.
The replacement connection is declared separately — it answers `duplicate:` here — so no reader can take the
two files that use `dropAfterFrames` as disagreeing about a replacement connection.

**Clauses.** C-SDK §2 (outer bounds), C-SDK §4.1 (createStyxClient and delivery config),
C-SDK §4.2 (client
methods), C-SDK §4.3 (inbound messages), C-SDK §6.1 (closed states),
C-SDK §6.2 (snapshot), C-SDK §6.3 (per-relay outcomes), C-SDK §7 (events),
C-SDK §8.4 (clock and randomness), C-DLV §2 (outer bounds), C-DLV §3 (bounds and defaults),
C-DLV §4.2 (admission), C-DLV §4.3 (attempts, the first
acceptance and backoff),
C-DLV §4.4 (deadline), C-DLV §4.6 (shutdown), C-DLV §5.1 (one pool per relay, replaced after loss),
C-DLV §5.2 (supervision and reconnection), C-DLV §5.3 (per-relay outcomes),
C-DLV §5.4 (subscribe, REQ when a connection opens), C-DLV §6.1 (event shape),
C-DLV §6.2 (message event), C-DLV §6.3 (receipt event), C-DLV §7.1 (inbound processing),
C-DLV §7.2 (message
events and receipts), C-DLV §7.3 (receipt events),
C-DLV §8 (duplicate handling), C-DLV §10.
