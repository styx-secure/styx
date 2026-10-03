# Scenario `offlineRecipient` — a recipient that is absent when the sender's attempt runs

Purpose item (scope record `O-SCEN3`): **offline recipient**. Harness scenario of C-DLV §12 exercised here:
`offlineRecipient`.

<!-- styx-m3-scenario:v1:start -->
```json
{
  "schema": "styx-m3-scenario/v1",
  "closed": true,
  "scenarioId": "offlineRecipient",
  "purposeItem": "offlineRecipient",
  "title": "A recipient that is absent during the sender's attempt leaves the item in RELAY_ACCEPTED_AWAITING_RECEIPT, and the item's success state depends only on whether a valid receipt arrives before the deadline",
  "harnessScenarios": [
    "offlineRecipient"
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
      "id": "receiptBeforeDeadline",
      "harness": "offlineRecipient",
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
            "role": "stores the event and answers OK true; on a later REQ it replays its stored matches in insertion order, then EOSE, then forwards live matches, sending every frame at once"
          },
          {
            "index": 1,
            "host": "::1",
            "port": "ephemeral",
            "behaviours": [
              "normal"
            ],
            "role": "stores the event and answers OK true; it replays its stored matches in insertion order too, and its connection for the recipient's subscription opens 100 ms after relay0's, so its copy of the replayed match arrives after relay0's"
          }
        ]
      },
      "preconditions": [
        "The recipient client does not exist during the sender's attempt: it is created and started only at 60000, so no kind-4742 receipt can reach the sender before that.",
        "The relays keep the stored event: relay0's replay delivers it to the recipient when the recipient's REQ arrives, which is the replay C-DLV §5.4 allows for events stored before a client started.",
        "The REQ of the subscription is sent on each connection when that connection opens, not at the end of the connection phase.",
        "C-DLV §7.1 processes inbound EVENT frames per client, one at a time and in arrival order across all relays, and neither §5.2 nor §7.1 holds inbound frames while a start() has not yet resolved and the state is CREATED; the instants at which the recipient processes the replayed frame are therefore fixed at its arrival, during the recipient's connection phase, and that reading is marked as the one point where the two documents leave the instant of inbound processing during a connection phase open. The receipt publication of C-DLV §7.2 carries no RUNNING condition of its own.",
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
          "detail": "createStyxClient with the delivery configuration of C-SDK §4.1 and the two injected relay URLs; every parameter is inside the C-DLV §3 bounds; storage is empty; one pool per relay with its automatic reconnect cleared, the subscription registered before connecting, connectAll() on both pools in parallel",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §3",
            "C-DLV §5.1",
            "C-SDK §4.1",
            "C-SDK §8.4"
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
            "C-DLV §6.1",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 12050,
          "actor": "relay0",
          "event": "OK true",
          "detail": "relay0 becomes ACCEPTED, and because d1 is IN_FLIGHT in this attempt the first acceptance ends the publication phase: the item moves to RELAY_ACCEPTED_AWAITING_RECEIPT, not terminal, with lastCode null and one DELIVERY_STATE_CHANGED; the attempt stays open, because in this mode the accepted attempt is the last and ends only at a receipt, the deadline, a fault, a cancel or shutdown; the recipient does not exist yet, so no receipt can arrive now",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 50
          },
          "relayAnswer": {
            "relayIndex": 0,
            "accepted": true,
            "events": 1
          },
          "transitions": [
            {
              "deliveryId": "d1",
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
          "event": "OK true",
          "detail": "relay1 becomes ACCEPTED; no item changes state, because d1 is no longer IN_FLIGHT and a per-relay outcome changes an item's state only through the first acceptance of an item in IN_FLIGHT; both relays now hold the event",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "relayAnswer": {
            "relayIndex": 1,
            "accepted": true,
            "events": 1
          },
          "checks": [
            "C-DLV §5.3",
            "C-SDK §6.3"
          ]
        },
        {
          "at": 24000,
          "actor": "clock",
          "event": "the attempt timeout elapses",
          "detail": "the attempt timeout fires one per-relay timeout after the publication start and settles no entry: both relays are ACCEPTED, and an accepted entry is sticky; the item stays RELAY_ACCEPTED_AWAITING_RECEIPT and the accepted attempt stays open until a receipt, the deadline, a fault, a cancel or shutdown",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 11940
          },
          "clock": {
            "kind": "attemptTimeout",
            "attempt": 1
          },
          "checks": [
            "C-DLV §4.3",
            "C-DLV §4.4",
            "C-DLV §5.3"
          ]
        },
        {
          "at": 60000,
          "actor": "recipient",
          "event": "the recipient client is created and started",
          "detail": "the recipient is created with an empty storage port and started; one subscriptionId per client and the filter of C-DLV §5.4 with no since and no limit, so a relay may replay the event stored before this client started",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §5.2",
            "C-DLV §5.4",
            "C-SDK §4.2"
          ]
        },
        {
          "at": 61000,
          "actor": "recipient",
          "event": "relay0's connection opens and the REQ is sent on it",
          "detail": "the subscription was registered before the pools connected, so RelayPool sends the REQ when the connection opens; relay0 replays its stored match for that filter at once, then EOSE",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 1000
          },
          "checks": [
            "C-DLV §5.2",
            "C-DLV §5.4"
          ]
        },
        {
          "at": 61100,
          "actor": "recipient",
          "event": "relay1's connection opens and the REQ is sent on it",
          "detail": "relay1's connection for the recipient's subscription opens 100 ms after relay0's and its matching replay arrives after relay0's copy; neither relay is configured to hold frames",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 100
          },
          "checks": [
            "C-DLV §10",
            "C-DLV §5.4"
          ]
        },
        {
          "at": 61105,
          "actor": "recipient",
          "event": "relay0's stored match arrives",
          "detail": "the kind-4741 event passes every check of C-DLV §7.1, its id is not in the window, the content decodes and session.open returns a plaintext, so MESSAGE_RECEIVED is emitted with the sender key and a fresh copy of the payload; because the event carries the r tag, the recipient signs a kind-4742 receipt for this event id and publishes it once on every connected pool; the message is delivered to the recipient 49055 ms after the sender recorded its acceptance, which is the store-and-forward delay a relay's replay may introduce and no guarantee of the delivery layer",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 5
          },
          "checks": [
            "C-DLV §2",
            "C-DLV §5.4",
            "C-DLV §6.3",
            "C-DLV §7.1",
            "C-DLV §7.2",
            "C-SDK §7"
          ]
        },
        {
          "at": 61200,
          "actor": "sender",
          "event": "the receipt arrives",
          "detail": "the receipt reaches the sender on relay0's connection inside the attempt that is still open; every condition of C-DLV §7.3 holds: the kind-4742 event passed every check of C-DLV §7.1, its p tag equals the sender's own public key, its e tag is the event id of the non-terminal item d1 in RECIPIENT_RECEIPT mode, its pubkey equals that item's recipient, the item has not already taken a receipt, and clock.now() = 61200 is before deadlineAt 132000; d1 moves RELAY_ACCEPTED_AWAITING_RECEIPT to RECIPIENT_RECEIPT_RECEIVED, terminal, with lastCode null and one DELIVERY_STATE_CHANGED; the accepted attempt ends here",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 95
          },
          "transitions": [
            {
              "deliveryId": "d1",
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
          "at": 61250,
          "actor": "recipient",
          "event": "the second copy of the same message event arrives",
          "detail": "the same kind-4741 message id arrives once more, from relay1's copy; that id is already in the window, so this copy is dropped without an event and without a second receipt; the kind-4742 receipt of this timeline is addressed to the sender (its p tag is the sender's own key) and is never delivered to this subscription",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 50
          },
          "checks": [
            "C-DLV §7.1",
            "C-DLV §7.2",
            "C-DLV §8",
            "C-SDK §4.3"
          ]
        },
        {
          "at": 61260,
          "actor": "sender",
          "event": "the second copy of the same receipt event arrives at the sender",
          "detail": "relay1 sends its copy of the same kind-4742 receipt to the sender's subscription; the sender's window already holds that id, so the copy is dropped without a second receipt and without an event",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §7.3",
            "C-DLV §8"
          ]
        },
        {
          "at": 72000,
          "actor": "recipient",
          "event": "start() resolves",
          "detail": "{ clientState: RUNNING, connectedRelays: 2 }; the connection phase ends perRelayTimeoutMs after it began, and the inbound frame processed at 61105 was processed while the recipient's start() had not yet resolved and its state was still CREATED, which is the reading stated in the preconditions",
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
            "startedAt": 60000
          }
        },
        {
          "at": 72010,
          "actor": "sender",
          "event": "getDelivery({ deliveryId: d1 })",
          "detail": "{ ok: true, value: { deliveryId: d1, recipient: <recipient public key>, state: RECIPIENT_RECEIPT_RECEIVED, terminal: true, attempts: 1, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: ACCEPTED }, { relayIndex: 1, outcome: ACCEPTED }] } }",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-SDK §6.2",
            "C-SDK §6.3"
          ]
        },
        {
          "at": 72020,
          "actor": "sender",
          "event": "shutdown()",
          "detail": "every relay outcome is frozen at its current value; the only item is terminal, so { clientState: STOPPED, lost: 0 }; every pool, subscription and timer is closed",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §4.6",
            "C-SDK §2",
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
          "deliveryId": "d1",
          "from": "IN_FLIGHT",
          "to": "RELAY_ACCEPTED_AWAITING_RECEIPT"
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
        }
      ],
      "expectedRelayStates": [
        {
          "relayIndex": 0,
          "outcome": "ACCEPTED",
          "note": "answered OK true once and replayed the stored match to the recipient at 61105"
        },
        {
          "relayIndex": 1,
          "outcome": "ACCEPTED",
          "note": "answered OK true once; its later replay produced only a duplicate at the recipient"
        }
      ],
      "expectedMethodResults": [
        {
          "at": 12000,
          "call": "send({ recipient, payload })",
          "result": "{ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } }"
        },
        {
          "at": 72010,
          "call": "getDelivery({ deliveryId: 'd1' })",
          "result": "{ ok: true, value: { deliveryId: 'd1', recipient: '<recipient public key>', state: 'RECIPIENT_RECEIPT_RECEIVED', terminal: true, attempts: 1, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: 'ACCEPTED' }, { relayIndex: 1, outcome: 'ACCEPTED' }] } }"
        },
        {
          "at": 72020,
          "call": "shutdown()",
          "result": "{ ok: true, value: { clientState: 'STOPPED', lost: 0 } }"
        }
      ],
      "expectedEvents": [
        "CLIENT_STATE_CHANGED with clientState RUNNING in each client at 12000 and 72000",
        "DELIVERY_STATE_CHANGED with state IN_FLIGHT at 12000",
        "DELIVERY_STATE_CHANGED with state RELAY_ACCEPTED_AWAITING_RECEIPT, terminal false and lastCode null at 12050",
        "exactly one MESSAGE_RECEIVED at the recipient at 61105",
        "DELIVERY_STATE_CHANGED with state RECIPIENT_RECEIPT_RECEIVED, terminal true and lastCode null at 61200"
      ],
      "notEmitted": [
        "no DELIVERY_STATE_CHANGED for a per-relay outcome and no state change from the attempt timeout",
        "no second MESSAGE_RECEIVED and no second receipt for the event id already in the window",
        "no store-and-forward or exactly-once guarantee: the relay replay of C-DLV §5.4 is the relay's own behaviour, and C-DLV §2 item 4 leaves the case of a crash or an abrupt termination unclaimed",
        "no claim that the receipt proves that a person read the message"
      ]
    },
    {
      "id": "receiptAfterDeadline",
      "harness": "offlineRecipient",
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
            "role": "stores the event and answers OK true; replays its stored matches on a later REQ and sends every frame at once"
          },
          {
            "index": 1,
            "host": "::1",
            "port": "ephemeral",
            "behaviours": [
              "normal"
            ],
            "role": "stores the event and answers OK true; its connection for the recipient's subscription opens 100 ms after relay0's, so its copy of the replayed match arrives after relay0's"
          }
        ]
      },
      "preconditions": [
        "The recipient client is created and started only after the sender's deadline has passed: its start() is called at 133000, strictly after deadlineAt 132000.",
        "No receipt can reach the sender from that recipient before the deadline, so the deadline transition of C-DLV §4.4 is what ends the item.",
        "The harness fixes the instants at which the relays deliver frames, so the arrival times below are exact.",
        "The injected clock port fires each armed timer at exactly its delay; no retry delay is drawn in this timeline, so randomValues is empty.",
        "The recipient has not resolved its start() when it processes the inbound frame, so its state is still CREATED (C-SDK §4 names CREATED, RUNNING and STOPPED only); that reading is the one stated in the index under open readings, and the two documents fix no instant at which inbound frames are processed during a connection phase."
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
        "C-DLV §4.6",
        "C-DLV §5.1",
        "C-DLV §5.2",
        "C-DLV §5.3",
        "C-DLV §5.4",
        "C-DLV §6.1",
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
          "detail": "the configuration of C-SDK §4.1 with the C-DLV §3 bounds of this timeline; storage is empty; one pool per relay with its automatic reconnect cleared, the subscription registered before connecting, connectAll() on both in parallel",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §3",
            "C-DLV §5.1",
            "C-SDK §4.1",
            "C-SDK §8.4"
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
          "detail": "admission: deliveryId d1, state QUEUED, createdAt 12000, deadlineAt 132000, attempts 0, lastCode null, every relay outcome PENDING",
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
          "detail": "QUEUED to IN_FLIGHT, attempts 1; the kind-4741 event is signed and published to both relays, and publish returns 1 on both; the attempt timeout is armed at the publication start",
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
            "C-DLV §6.1",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 12050,
          "actor": "relay0",
          "event": "OK true",
          "detail": "the first acceptance of an item in IN_FLIGHT: relay0 becomes ACCEPTED and d1 moves to RELAY_ACCEPTED_AWAITING_RECEIPT, not terminal, with lastCode null; both relays hold the event and the recipient does not exist yet",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 50
          },
          "relayAnswer": {
            "relayIndex": 0,
            "accepted": true,
            "events": 1
          },
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "RELAY_ACCEPTED_AWAITING_RECEIPT"
            }
          ],
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.3",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 12060,
          "actor": "relay1",
          "event": "OK true",
          "detail": "relay1 becomes ACCEPTED; no item changes state",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "relayAnswer": {
            "relayIndex": 1,
            "accepted": true,
            "events": 1
          },
          "checks": [
            "C-DLV §5.3",
            "C-SDK §6.3"
          ]
        },
        {
          "at": 132000,
          "actor": "clock",
          "event": "the deadline elapses",
          "detail": "clock.now() reaches deadlineAt = createdAt + deadlineMs = 132000, which is not before deadlineAt, so the deadline transition applies at once: d1 is in RELAY_ACCEPTED_AWAITING_RECEIPT and carries no receipt, so it moves to FAILED_NO_RECEIPT, terminal, with lastCode null and one DELIVERY_STATE_CHANGED",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 119940
          },
          "clock": {
            "kind": "deadline"
          },
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "FAILED_NO_RECEIPT"
            }
          ],
          "checks": [
            "C-DLV §4.3",
            "C-DLV §4.4",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 133000,
          "actor": "recipient",
          "event": "the recipient client is created and started",
          "detail": "the recipient starts strictly after the deadline; its empty storage and its subscription of C-DLV §5.4 with no since and no limit are registered before the pools connect, so a relay may replay the stored event",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §5.2",
            "C-DLV §5.4",
            "C-SDK §4.2"
          ]
        },
        {
          "at": 134000,
          "actor": "recipient",
          "event": "relay0's connection opens and the REQ is sent on it",
          "detail": "RelayPool sends the REQ when the connection opens; relay0 replays the stored match at once",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 1000
          },
          "checks": [
            "C-DLV §5.2",
            "C-DLV §5.4"
          ]
        },
        {
          "at": 134100,
          "actor": "recipient",
          "event": "relay1's connection opens and the REQ is sent on it",
          "detail": "relay1's connection opens 100 ms after relay0's and its matching replay arrives after relay0's copy; neither relay is configured to hold frames",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 100
          },
          "checks": [
            "C-DLV §10",
            "C-DLV §5.4"
          ]
        },
        {
          "at": 134105,
          "actor": "recipient",
          "event": "relay0's stored match arrives",
          "detail": "the event passes every check of C-DLV §7.1 and is not in the window, so MESSAGE_RECEIVED is emitted and the recipient signs and publishes a kind-4742 receipt for it once on every connected pool; the message reaches the recipient 2105 ms after the sender's item became terminal",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 5
          },
          "checks": [
            "C-DLV §6.3",
            "C-DLV §7.1",
            "C-DLV §7.2",
            "C-SDK §7"
          ]
        },
        {
          "at": 134250,
          "actor": "recipient",
          "event": "relay1's copy of the replayed match arrives",
          "detail": "dropped as a duplicate of an id already in the window",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 145
          },
          "checks": [
            "C-DLV §7.2",
            "C-DLV §8"
          ]
        },
        {
          "at": 135000,
          "actor": "sender",
          "event": "the receipt arrives after the deadline",
          "detail": "the receipt is ignored without an event, because two conditions of C-DLV §7.3 fail: its e tag names an item that is no longer non-terminal, and clock.now() = 135000 is not before deadlineAt 132000; an item that took a deadline transition is terminal and no receipt can clear it; the failure is not a parsing, version, signature or open failure, so nothing is emitted",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 750
          },
          "checks": [
            "C-DLV §4.4",
            "C-DLV §7.1",
            "C-DLV §7.3",
            "C-DLV §8",
            "C-SDK §4.3"
          ]
        },
        {
          "at": 145000,
          "actor": "recipient",
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
            "startedAt": 133000
          }
        },
        {
          "at": 146010,
          "actor": "sender",
          "event": "getDelivery({ deliveryId: d1 }) and shutdown()",
          "detail": "the snapshot reports state FAILED_NO_RECEIPT, terminal true, attempts 1, createdAt 12000, deadlineAt 132000, lastCode null and relayOutcomes [{ relayIndex: 0, outcome: ACCEPTED }, { relayIndex: 1, outcome: ACCEPTED }]; shutdown() then gives { clientState: STOPPED, lost: 0 }",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 1010
          },
          "checks": [
            "C-DLV §4.6",
            "C-DLV §5.3",
            "C-SDK §2",
            "C-SDK §6.2",
            "C-SDK §6.3"
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
          "to": "RELAY_ACCEPTED_AWAITING_RECEIPT"
        },
        {
          "deliveryId": "d1",
          "from": "RELAY_ACCEPTED_AWAITING_RECEIPT",
          "to": "FAILED_NO_RECEIPT"
        }
      ],
      "expectedItemStates": [
        {
          "deliveryId": "d1",
          "recipient": "<recipient public key>",
          "state": "FAILED_NO_RECEIPT",
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
          "note": "accepted the event, so the failure is a missing receipt and not a missing acceptance"
        },
        {
          "relayIndex": 1,
          "outcome": "ACCEPTED",
          "note": "same"
        }
      ],
      "expectedMethodResults": [
        {
          "at": 12000,
          "call": "send({ recipient, payload })",
          "result": "{ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } }"
        },
        {
          "at": 146010,
          "call": "getDelivery({ deliveryId: 'd1' })",
          "result": "{ ok: true, value: { deliveryId: 'd1', recipient: '<recipient public key>', state: 'FAILED_NO_RECEIPT', terminal: true, attempts: 1, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: 'ACCEPTED' }, { relayIndex: 1, outcome: 'ACCEPTED' }] } }"
        },
        {
          "at": 146010,
          "call": "shutdown()",
          "result": "{ ok: true, value: { clientState: 'STOPPED', lost: 0 } }"
        }
      ],
      "expectedEvents": [
        "CLIENT_STATE_CHANGED with clientState RUNNING in each client at 12000 and 145000",
        "DELIVERY_STATE_CHANGED with state IN_FLIGHT at 12000",
        "DELIVERY_STATE_CHANGED with state RELAY_ACCEPTED_AWAITING_RECEIPT at 12050",
        "DELIVERY_STATE_CHANGED with state FAILED_NO_RECEIPT, terminal true and lastCode null at 132000",
        "one MESSAGE_RECEIVED at the recipient at 134105, after the sender's item was already terminal"
      ],
      "notEmitted": [
        "no DELIVERY_STATE_CHANGED when the late receipt arrives: a receipt never clears a terminal item",
        "no FAILED_NOT_ACCEPTED: at least one relay accepted the event, so the deadline transition from RELAY_ACCEPTED_AWAITING_RECEIPT is the one of C-DLV §4.4",
        "no claim that the recipient's MESSAGE_RECEIVED at 134105 changes anything for the sender, and no receipt of the message to the sender's item"
      ]
    },
    {
      "id": "receiptExactlyAtDeadline",
      "harness": "offlineRecipient",
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
            "role": "stores the event and answers OK true; replays its stored matches on a later REQ at once"
          },
          {
            "index": 1,
            "host": "::1",
            "port": "ephemeral",
            "behaviours": [
              "normal"
            ],
            "role": "stores the event and answers OK true; its connection for the recipient's subscription opens 100 ms after relay0's, so its copy of the replayed match arrives after relay0's"
          }
        ]
      },
      "preconditions": [
        "The receipt is delivered to the sender at exactly deadlineAt: this timeline is the boundary case of C-DLV §7.3, whose condition is clock.now() < deadlineAt.",
        "The recipient client is created and started at 121000, before deadlineAt 132000, so it exists and signs a receipt in time. It starts while the sender's item is awaiting a receipt, its connection phase is still open when it processes the replayed match at 122105, and the receipt is published at that instant on every connected pool. The harness fixes the arrival of both copies of that receipt at exactly 132000, the clock reading of deadlineAt, and no copy of it reaches the sender before that reading, so this timeline is the boundary case of C-DLV §7.3, whose condition is clock.now() < deadlineAt, and not a case in which an earlier valid copy decides the item.",
        "The injected clock port fires each armed timer at exactly its delay; no retry delay is drawn in this timeline, so randomValues is empty.",
        "The recipient has not resolved its start() when it processes the inbound frame, so its state is still CREATED; that reading, and the reading that the harness fixes the arrival instant of each frame it delivers, are the ones stated in the index under open readings."
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
          "detail": "the configuration of C-SDK §4.1 with the C-DLV §3 bounds of this timeline; storage is empty; one pool per relay with its automatic reconnect cleared, the subscription registered before connecting, connectAll() on both in parallel",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §3",
            "C-DLV §5.1",
            "C-SDK §4.1",
            "C-SDK §8.4"
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
          "detail": "admission: deliveryId d1, state QUEUED, createdAt 12000, deadlineAt 132000, attempts 0, lastCode null, every relay outcome PENDING",
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
          "detail": "QUEUED to IN_FLIGHT, attempts 1; the event is signed and published to both relays, and publish returns 1 on both; the attempt timeout is armed at the publication start",
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
            "C-DLV §6.1",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 12050,
          "actor": "relay0",
          "event": "OK true",
          "detail": "relay0 becomes ACCEPTED and, as the first acceptance of an item in IN_FLIGHT, moves d1 to RELAY_ACCEPTED_AWAITING_RECEIPT, not terminal, with lastCode null",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 50
          },
          "relayAnswer": {
            "relayIndex": 0,
            "accepted": true,
            "events": 1
          },
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "RELAY_ACCEPTED_AWAITING_RECEIPT"
            }
          ],
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.3",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 12060,
          "actor": "relay1",
          "event": "OK true",
          "detail": "relay1 becomes ACCEPTED; no item changes state",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "relayAnswer": {
            "relayIndex": 1,
            "accepted": true,
            "events": 1
          },
          "checks": [
            "C-DLV §5.3",
            "C-SDK §6.3"
          ]
        },
        {
          "at": 121000,
          "actor": "recipient",
          "event": "the recipient client is created and started",
          "detail": "the recipient starts while the item is still awaiting a receipt; its subscription of C-DLV §5.4 with no since and no limit may receive the stored event from a relay's replay",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §5.2",
            "C-DLV §5.4",
            "C-SDK §4.2"
          ]
        },
        {
          "at": 122000,
          "actor": "recipient",
          "event": "relay0's connection opens and the REQ is sent on it",
          "detail": "RelayPool sends the REQ when the connection opens; relay0 replays the stored match at once",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 1000
          },
          "checks": [
            "C-DLV §5.2",
            "C-DLV §5.4"
          ]
        },
        {
          "at": 122100,
          "actor": "recipient",
          "event": "relay1's connection opens and the REQ is sent on it",
          "detail": "relay1's connection opens 100 ms after relay0's and its matching replay arrives after relay0's copy; neither relay is configured to hold frames",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 100
          },
          "checks": [
            "C-DLV §10",
            "C-DLV §5.4"
          ]
        },
        {
          "at": 122105,
          "actor": "recipient",
          "event": "relay0's stored match arrives",
          "detail": "the event passes every check of C-DLV §7.1 and is not in the window, so MESSAGE_RECEIVED is emitted and the recipient signs and publishes one kind-4742 receipt for it on every connected pool",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 5
          },
          "checks": [
            "C-DLV §6.3",
            "C-DLV §7.1",
            "C-DLV §7.2",
            "C-SDK §7"
          ]
        },
        {
          "at": 122250,
          "actor": "recipient",
          "event": "relay1's copy of the replayed match arrives",
          "detail": "dropped as a duplicate of an id already in the window",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 145
          },
          "checks": [
            "C-DLV §7.2",
            "C-DLV §8"
          ]
        },
        {
          "at": 132000,
          "actor": "clock",
          "event": "the deadline elapses and the boundary receipt arrives at the same clock reading",
          "detail": "the deadline transition of C-DLV §4.4 applies at once, because clock.now() = 132000 is not before deadlineAt: d1 moves from RELAY_ACCEPTED_AWAITING_RECEIPT to FAILED_NO_RECEIPT, terminal, with lastCode null and one DELIVERY_STATE_CHANGED; the receipt frame of the same clock reading is then ignored without an event, because the condition of C-DLV §7.3 is clock.now() < deadlineAt and the item is already terminal; the order of the two events at the same reading does not change the result, since the receipt fails the deadline condition of §7.3 either way and a receipt never clears a state the deadline set; both copies of the receipt — relay0's and relay1's — arrive at exactly this reading, which the harness fixes, and no copy of it arrives earlier, so the boundary is the only receipt reading of this timeline",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 9750
          },
          "clock": {
            "kind": "deadline"
          },
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "FAILED_NO_RECEIPT"
            }
          ],
          "checks": [
            "C-DLV §4.3",
            "C-DLV §4.4",
            "C-DLV §7.3",
            "C-SDK §6.1"
          ]
        },
        {
          "at": 133000,
          "actor": "recipient",
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
            "startedAt": 121000
          }
        },
        {
          "at": 133010,
          "actor": "sender",
          "event": "getDelivery({ deliveryId: d1 }) and shutdown()",
          "detail": "the snapshot reports state FAILED_NO_RECEIPT, terminal true, attempts 1, createdAt 12000, deadlineAt 132000, lastCode null and relayOutcomes [{ relayIndex: 0, outcome: ACCEPTED }, { relayIndex: 1, outcome: ACCEPTED }]; shutdown() gives { clientState: STOPPED, lost: 0 }",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §4.6",
            "C-DLV §5.3",
            "C-SDK §2",
            "C-SDK §6.2",
            "C-SDK §6.3"
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
          "to": "RELAY_ACCEPTED_AWAITING_RECEIPT"
        },
        {
          "deliveryId": "d1",
          "from": "RELAY_ACCEPTED_AWAITING_RECEIPT",
          "to": "FAILED_NO_RECEIPT"
        }
      ],
      "expectedItemStates": [
        {
          "deliveryId": "d1",
          "recipient": "<recipient public key>",
          "state": "FAILED_NO_RECEIPT",
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
          "note": "accepted the event; the failure is the deadline, not the acceptance"
        },
        {
          "relayIndex": 1,
          "outcome": "ACCEPTED",
          "note": "same"
        }
      ],
      "expectedMethodResults": [
        {
          "at": 12000,
          "call": "send({ recipient, payload })",
          "result": "{ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } }"
        },
        {
          "at": 133010,
          "call": "getDelivery({ deliveryId: 'd1' })",
          "result": "{ ok: true, value: { deliveryId: 'd1', recipient: '<recipient public key>', state: 'FAILED_NO_RECEIPT', terminal: true, attempts: 1, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: 'ACCEPTED' }, { relayIndex: 1, outcome: 'ACCEPTED' }] } }"
        },
        {
          "at": 133010,
          "call": "shutdown()",
          "result": "{ ok: true, value: { clientState: 'STOPPED', lost: 0 } }"
        }
      ],
      "expectedEvents": [
        "CLIENT_STATE_CHANGED with clientState RUNNING in each client at 12000 and 133000",
        "DELIVERY_STATE_CHANGED with state RELAY_ACCEPTED_AWAITING_RECEIPT at 12050",
        "DELIVERY_STATE_CHANGED with state FAILED_NO_RECEIPT, terminal true and lastCode null at 132000",
        "one MESSAGE_RECEIVED at the recipient at 122105, inside the deadline"
      ],
      "notEmitted": [
        "no DELIVERY_STATE_CHANGED for the receipt that arrives at exactly deadlineAt",
        "no RECIPIENT_RECEIPT_RECEIVED: a receipt at the deadline is not accepted, because C-DLV §7.3 requires clock.now() < deadlineAt",
        "no claim that the two instants of the same clock reading are ordered in the record; both orderings give FAILED_NO_RECEIPT"
      ]
    }
  ]
}
```
<!-- styx-m3-scenario:v1:end -->

## Prose: what the record fixes

All three timelines hold the C-DLV §3 bounds, use the transport use of C-DLV §5.1 and a subscription of
C-DLV §5.4 with no `since` and no `limit`. The recipient is absent for the whole of the sender's first
attempt, so the sender can only reach `RELAY_ACCEPTED_AWAITING_RECEIPT` — the state C-DLV §4.3 gives when the
publication phase ends with an acceptance in `RECIPIENT_RECEIPT` mode — and everything that follows is
decided by the receipt rules of C-DLV §7.3: the five conditions there are, in order, every inbound check of
§7.1 including the `p` tag, an `e` tag naming a non-terminal item in this mode, a `pubkey` equal to the
item's recipient, the first receipt for the item, and `clock.now() < deadlineAt`.

**`receiptBeforeDeadline`.** The receipt is published by a recipient that came online 47950 ms after the
acceptance and reaches the sender at 61200, well before the deadline: the item reaches
`RECIPIENT_RECEIPT_RECEIVED`. The message reached the recipient through the relay's own replay of C-DLV §5.4,
which is a store-and-forward behaviour of the relay and not a guarantee of the delivery layer; C-DLV §2 item 4
leaves the case of a crash or abrupt termination unclaimed and no exactly-once, ordering or cross-restart
claim appears anywhere in this file.

**`receiptAfterDeadline`.** The recipient starts strictly after `deadlineAt`, so no receipt can arrive in
time: the deadline transition of C-DLV §4.4 moves the item from `RELAY_ACCEPTED_AWAITING_RECEIPT` to
`FAILED_NO_RECEIPT`, terminal. The receipt that arrives at 135000 fails two conditions of C-DLV §7.3 — the
`e` tag names an item that is no longer non-terminal, and `clock.now()` is not before `deadlineAt` — and is
ignored without an event, because it is not a parsing, version, signature or `open` failure.

**`receiptExactlyAtDeadline`.** The boundary of §7.3: the receipt is delivered at exactly `deadlineAt`, which
is not *before* `deadlineAt`, so it is not accepted, and the deadline transition applies at once. The record
fixes both at the same clock reading and states that the order between them does not matter, because neither
reading can produce `RECIPIENT_RECEIPT_RECEIVED`.

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
C-DLV §6.3 (receipt event), C-DLV §7.1 (inbound processing),
C-DLV §7.2 (message
events and receipts), C-DLV §7.3 (receipt events),
C-DLV §8 (duplicate handling), C-DLV §10.
