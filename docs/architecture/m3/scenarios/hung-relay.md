# Scenario `hungRelay` — a relay that answers and a relay that never answers

Purpose item (scope record `O-SCEN3`): **hung relay**. Harness scenario of C-DLV §12 exercised here:
`hungRelay`, which C-DLV §12 describes as "a never-answering relay next to a normal one (the normal
relay's outcome and the item's acceptance arrive within one per-relay timeout)".

<!-- styx-m3-scenario:v1:start -->
```json
{
  "schema": "styx-m3-scenario/v1",
  "closed": true,
  "scenarioId": "hungRelay",
  "purposeItem": "hungRelay",
  "title": "A hung relay keeps the attempt open in RECIPIENT_RECEIPT mode and settles TIMED_OUT at its per-relay timeout, while the normal relay's acceptance moves the item at once",
  "harnessScenarios": [
    "hungRelay"
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
    "C-DLV §5.5",
    "C-DLV §6.1",
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
      "id": "hungRelayAlongsideNormal",
      "harness": "hungRelay",
      "config": {
        "client": "sender",
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
              "neverAnswering"
            ],
            "role": "accepts the connection and never sends any frame; it is the first configured relay, so an implementation that awaits relays in configuration order cannot pass"
          },
          {
            "index": 1,
            "host": "::1",
            "port": "ephemeral",
            "behaviours": [
              "normal"
            ],
            "role": "answers an EVENT frame with [\"OK\", <event id>, true, \"saved\"] within 50 ms"
          }
        ]
      },
      "preconditions": [
        "Both relay servers run inside the test on loopback IP literals and ephemeral ports (C-DLV §2 item 6, §10) and the relay URLs reach the client only through config.relays (C-SDK §4.1).",
        "The hung relay is configured first, so the timeline fails for any implementation that awaits relay answers one after another in configuration order.",
        "The recipient client of this message is not present in this timeline, so no kind-4742 receipt for the item is ever published; the receipt mode only decides the success state of the sender's item.",
        "The injected clock port fires each armed timer at exactly its delay; no retry delay is drawn in this timeline, so randomValues is empty."
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
        "C-DLV §5.4",
        "C-DLV §5.5",
        "C-DLV §6.1",
        "C-DLV §10"
      ],
      "events": [
        {
          "at": 0,
          "actor": "sender",
          "event": "start()",
          "detail": "createStyxClient is given the delivery configuration of C-SDK §4.1 and the two injected relay URLs; every parameter of this timeline is inside the C-DLV §3 bounds: maxAttempts 5 (1 to 10), deadlineMs 120000 (30000 to 600000), perRelayTimeoutMs 12000 (11000 to 30000) and the receipt mode RECIPIENT_RECEIPT; storage is empty; one pool per relay is prepared with the transport calls of C-DLV §5.1, its automatic reconnect is cleared with disconnectAll, the subscription of C-DLV §5.4 is registered before connecting, and connectAll() runs on both pools in parallel",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §3",
            "C-DLV §5.1",
            "C-DLV §5.2",
            "C-DLV §5.4",
            "C-SDK §4.1",
            "C-SDK §8.4"
          ]
        },
        {
          "at": 12000,
          "actor": "sender",
          "event": "start() resolves",
          "detail": "the connection phase ended perRelayTimeoutMs after it began; both relays are connected, so start() succeeds and resolves { clientState: RUNNING, connectedRelays: 2 }; CLIENT_STATE_CHANGED with RUNNING",
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
          "detail": "admission of payload P for the recipient key: the payload is inside payloadMaxBytes 65536 and the queue bound of 256 non-terminal items is not exceeded, so the item is admitted with deliveryId d1, state QUEUED, createdAt 12000, deadlineAt = createdAt + deadlineMs = 132000, attempts 0, lastCode null and every relay outcome PENDING",
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
          "detail": "d1 moves QUEUED to IN_FLIGHT with attempts 1; the kind-4741 event is built with the tags [p, the recipient key], [v, the interface version string], [n, 32 lowercase hex digits] and, in this mode, [r, 1], and signed once; relay0 and relay1 are set to PENDING and published to, and publish returns 1 on both because both sockets are open; the attempt timeout is armed at the publication start, which is the first signature, and elapses perRelayTimeoutMs later",
          "timing": {
            "kind": "attemptTimeout",
            "valueMs": 12000,
            "attempt": 1
          },
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.3",
            "C-DLV §6.1",
            "C-SDK §6.1"
          ],
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "IN_FLIGHT"
            }
          ]
        },
        {
          "at": 12050,
          "actor": "relay1",
          "event": "OK true",
          "detail": "[\"OK\", <event id>, true, \"saved\"]; relay1 becomes ACCEPTED, and because d1 is IN_FLIGHT in this attempt this first acceptance ends the publication phase: the item moves to RELAY_ACCEPTED_AWAITING_RECEIPT, which is not terminal, with lastCode null and one DELIVERY_STATE_CHANGED; relay0 is still PENDING and the attempt stays open, because in this mode the accepted attempt is the last and ends only at a receipt, the deadline, a fault, a cancel or shutdown; no retry delay is drawn and no further attempt is armed; C-DLV §10's bound on this harness scenario holds here: the normal relay's outcome and the item's acceptance are both recorded at 12050, within one per-relay timeout of the publication start, although the hung relay beside it answers nothing",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 50
          },
          "relayAnswer": {
            "relayIndex": 1,
            "accepted": true,
            "events": 1
          },
          "checks": [
            "C-DLV §10",
            "C-DLV §2",
            "C-DLV §4.3",
            "C-DLV §4.4",
            "C-DLV §5.3",
            "C-SDK §6.1"
          ],
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "RELAY_ACCEPTED_AWAITING_RECEIPT"
            }
          ]
        },
        {
          "at": 24000,
          "actor": "clock",
          "event": "the attempt timeout of attempt 1 elapses",
          "detail": "the attempt timeout elapses perRelayTimeoutMs after the publication start: relay0 is still PENDING and becomes TIMED_OUT, because a relay that holds its connection open and never answers is TIMED_OUT, not UNREACHABLE; relay1 keeps ACCEPTED, because an accepted entry is sticky and no later frame changes it; an entry settles at the attempt timeout even though the item is already in a non-terminal state other than IN_FLIGHT; no retransmission happens after an acceptance, so the item stays RELAY_ACCEPTED_AWAITING_RECEIPT with no attempt 2 and no second attempt timeout",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 11950
          },
          "clock": {
            "kind": "attemptTimeout",
            "attempt": 1
          },
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.3"
          ]
        },
        {
          "at": 24010,
          "actor": "sender",
          "event": "getDelivery({ deliveryId: d1 })",
          "detail": "{ ok: true, value: { deliveryId: d1, recipient: <recipient public key>, state: RELAY_ACCEPTED_AWAITING_RECEIPT, terminal: false, attempts: 1, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: TIMED_OUT }, { relayIndex: 1, outcome: ACCEPTED }] } }; the hung relay's TIMED_OUT arrived one per-relay timeout after the publication start, which is the settle rule of C-DLV §5.3 for a relay that accepts the connection and never answers, and C-SDK §6.3 for the resulting per-relay outcome",
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
          "at": 24020,
          "actor": "sender",
          "event": "shutdown()",
          "detail": "the queue is frozen at its current values; one admitted item is not terminal, so it takes LOST_ON_SHUTDOWN, terminal, and is reported in the result: { clientState: STOPPED, lost: 1 }; every pool is disposed, every subscription closed and every timer cleared; the CLIENT_STATE_CHANGED with STOPPED is emitted after the state changes it reports are recorded, as C-SDK §7 requires of every event",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §4.6",
            "C-DLV §5.5",
            "C-SDK §4.2",
            "C-SDK §7"
          ],
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "LOST_ON_SHUTDOWN"
            }
          ]
        },
        {
          "at": 24030,
          "actor": "sender",
          "event": "start() after shutdown()",
          "detail": "{ ok: false, code: E_SDK_CLIENT_STOPPED }; a stopped client serves no further call of start, send, cancel or shutdown, and the frozen snapshot of a terminal item is unchanged",
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
          "to": "LOST_ON_SHUTDOWN"
        }
      ],
      "expectedItemStates": [
        {
          "deliveryId": "d1",
          "recipient": "<recipient public key>",
          "state": "LOST_ON_SHUTDOWN",
          "terminal": true,
          "attempts": 1,
          "createdAt": 12000,
          "deadlineAt": 132000,
          "lastCode": null,
          "relayOutcomes": [
            {
              "relayIndex": 0,
              "outcome": "TIMED_OUT"
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
          "outcome": "TIMED_OUT",
          "note": "never answered; the per-relay timeout settled it without touching the item's state"
        },
        {
          "relayIndex": 1,
          "outcome": "ACCEPTED",
          "note": "one OK true, and the first acceptance of the item ended the publication phase"
        }
      ],
      "expectedMethodResults": [
        {
          "at": 12000,
          "call": "send({ recipient, payload })",
          "result": "{ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } }"
        },
        {
          "at": 24010,
          "call": "getDelivery({ deliveryId: 'd1' })",
          "result": "{ ok: true, value: { deliveryId: 'd1', recipient: '<recipient public key>', state: 'RELAY_ACCEPTED_AWAITING_RECEIPT', terminal: false, attempts: 1, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: 'TIMED_OUT' }, { relayIndex: 1, outcome: 'ACCEPTED' }] } }"
        },
        {
          "at": 24020,
          "call": "shutdown()",
          "result": "{ ok: true, value: { clientState: 'STOPPED', lost: 1 } }"
        },
        {
          "at": 24030,
          "call": "start()",
          "result": "{ ok: false, code: 'E_SDK_CLIENT_STOPPED' }"
        }
      ],
      "expectedEvents": [
        "CLIENT_STATE_CHANGED with clientState RUNNING at 12000",
        "DELIVERY_STATE_CHANGED with state IN_FLIGHT, terminal false at 12000",
        "DELIVERY_STATE_CHANGED with state RELAY_ACCEPTED_AWAITING_RECEIPT, terminal false and lastCode null at 12050",
        "DELIVERY_STATE_CHANGED with state LOST_ON_SHUTDOWN, terminal true and lastCode null at 24020",
        "CLIENT_STATE_CHANGED with clientState STOPPED at 24020"
      ],
      "notEmitted": [
        "no DELIVERY_STATE_CHANGED for relay0's TIMED_OUT: a per-relay outcome never changes the item's state except the first acceptance of an item in IN_FLIGHT",
        "no further publication attempt after the acceptance of an accepted attempt: no attempt 2 and no second attempt timeout (the accepted receipt-mode attempt itself still ends at a valid receipt, at the deadline, at a fault, at cancel or at the shutdown of this timeline, C-DLV §4.3)",
        "no receipt, no RECIPIENT_RECEIPT_RECEIVED and no claim that any relay acceptance proves that the recipient received or read the message"
      ]
    },
    {
      "id": "twoHungRelaysExhaustion",
      "harness": "hungRelay",
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
          4294967295,
          2147483648,
          4294967295,
          0
        ],
        "relays": [
          {
            "index": 0,
            "host": "127.0.0.1",
            "port": "ephemeral",
            "behaviours": [
              "neverAnswering"
            ],
            "role": "accepts the connection and never sends any frame"
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
        "No relay ever answers, so no attempt records an acceptance and the item can only end at maxAttempts or at the deadline.",
        "The injected random port returns the four values of randomValues in the order the retry delays are drawn, so the jitter term of delay(n, u) is exercised and only the last draw is zero: delay(1, 4294967295) = 999 ms, delay(2, 2147483648) = 1500 ms, delay(3, 4294967295) = 3999 ms, delay(4, 0) = 4000 ms.",
        "Every retry is armed because clock.now() + delay < deadlineAt = 132000 at each attempt end, so the deadline never ends the item before the attempt count is exhausted.",
        "The injected clock port fires each armed timer at exactly its delay."
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
        "C-DLV §6.1"
      ],
      "events": [
        {
          "at": 0,
          "actor": "sender",
          "event": "start()",
          "detail": "the configuration of C-SDK §4.1 with the C-DLV §3 defaults and bounds of this timeline; storage is empty; one pool per relay with its automatic reconnect cleared, the subscription registered before connecting, connectAll() on both in parallel",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §3",
            "C-DLV §5.1",
            "C-SDK §4.1"
          ]
        },
        {
          "at": 12000,
          "actor": "sender",
          "event": "start() resolves",
          "detail": "{ clientState: RUNNING, connectedRelays: 2 }; a connected relay that never answers is not a failed connection: the hung relay keeps its socket, so the connection phase ends with both relays connected",
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
          "detail": "admission with deliveryId d1, state QUEUED, createdAt 12000, deadlineAt 132000; every relay outcome PENDING",
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
          "detail": "QUEUED to IN_FLIGHT, attempts 1; the kind-4741 event is signed and published to both relays, which both return 1; both entries are PENDING; the attempt timeout is armed at the publication start",
          "timing": {
            "kind": "attemptTimeout",
            "valueMs": 12000,
            "attempt": 1
          },
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.3",
            "C-DLV §6.1",
            "C-SDK §6.1"
          ],
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "IN_FLIGHT"
            }
          ]
        },
        {
          "at": 24000,
          "actor": "clock",
          "event": "the attempt timeout of attempt 1 elapses and the retry is armed",
          "detail": "both entries are still PENDING and become TIMED_OUT; no acceptance was recorded; attempts 1 is below maxAttempts 5, so the SDK draws the first value and computes base(1) = min(1000 × 2^0, 30000) = 1000 and delay(1, 4294967295) = floor(1000 / 2) + floor(4294967295 × 1000 / 2^33) = 500 + 499 = 999; clock.now() + 999 = 24999 is before deadlineAt 132000, so the deadline does not end the item; d1 moves IN_FLIGHT to QUEUED and the next attempt is armed after 999 ms",
          "timing": {
            "kind": "retryDelay",
            "valueMs": 999,
            "attempt": 1
          },
          "clock": {
            "kind": "attemptTimeout",
            "attempt": 1
          },
          "checks": [
            "C-DLV §4.3",
            "C-DLV §4.4",
            "C-DLV §5.3",
            "C-SDK §6.1",
            "C-SDK §8.4"
          ],
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "QUEUED"
            }
          ]
        },
        {
          "at": 24999,
          "actor": "sender",
          "event": "attempt 2 begins",
          "detail": "QUEUED to IN_FLIGHT, attempts 2; both entries are set back to PENDING, because an entry is set to PENDING for a new attempt unless it is already ACCEPTED; the identical signed event bytes are published to both; attempt timeout armed",
          "timing": {
            "kind": "attemptTimeout",
            "valueMs": 12000,
            "attempt": 2
          },
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.3",
            "C-SDK §6.1"
          ],
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "IN_FLIGHT"
            }
          ]
        },
        {
          "at": 36999,
          "actor": "clock",
          "event": "the attempt timeout of attempt 2 elapses and the retry is armed",
          "detail": "both entries PENDING to TIMED_OUT; base(2) = 2000 and delay(2, 2147483648) = 1000 + floor(2147483648 × 2000 / 2^33) = 1000 + 500 = 1500; IN_FLIGHT to QUEUED; the next attempt is armed after 1500 ms",
          "timing": {
            "kind": "retryDelay",
            "valueMs": 1500,
            "attempt": 2
          },
          "clock": {
            "kind": "attemptTimeout",
            "attempt": 2
          },
          "checks": [
            "C-DLV §4.3",
            "C-DLV §4.4",
            "C-DLV §5.3",
            "C-SDK §6.1",
            "C-SDK §8.4"
          ],
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "QUEUED"
            }
          ]
        },
        {
          "at": 38499,
          "actor": "sender",
          "event": "attempt 3 begins",
          "detail": "QUEUED to IN_FLIGHT, attempts 3; both entries PENDING again; attempt timeout armed",
          "timing": {
            "kind": "attemptTimeout",
            "valueMs": 12000,
            "attempt": 3
          },
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.3",
            "C-SDK §6.1"
          ],
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "IN_FLIGHT"
            }
          ]
        },
        {
          "at": 50499,
          "actor": "clock",
          "event": "the attempt timeout of attempt 3 elapses and the retry is armed",
          "detail": "both entries PENDING to TIMED_OUT; base(3) = 4000 and delay(3, 4294967295) = 2000 + 1999 = 3999; IN_FLIGHT to QUEUED; the next attempt is armed after 3999 ms",
          "timing": {
            "kind": "retryDelay",
            "valueMs": 3999,
            "attempt": 3
          },
          "clock": {
            "kind": "attemptTimeout",
            "attempt": 3
          },
          "checks": [
            "C-DLV §4.3",
            "C-DLV §4.4",
            "C-DLV §5.3",
            "C-SDK §6.1",
            "C-SDK §8.4"
          ],
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "QUEUED"
            }
          ]
        },
        {
          "at": 54498,
          "actor": "sender",
          "event": "attempt 4 begins",
          "detail": "QUEUED to IN_FLIGHT, attempts 4; both entries PENDING again; attempt timeout armed",
          "timing": {
            "kind": "attemptTimeout",
            "valueMs": 12000,
            "attempt": 4
          },
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.3",
            "C-SDK §6.1"
          ],
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "IN_FLIGHT"
            }
          ]
        },
        {
          "at": 66498,
          "actor": "clock",
          "event": "the attempt timeout of attempt 4 elapses and the retry is armed",
          "detail": "both entries PENDING to TIMED_OUT; base(4) = min(8000, 30000) = 8000 and delay(4, 0) = 4000 + 0 = 4000; clock.now() + 4000 = 70498 is before deadlineAt 132000; IN_FLIGHT to QUEUED; the next attempt is armed after 4000 ms",
          "timing": {
            "kind": "retryDelay",
            "valueMs": 4000,
            "attempt": 4
          },
          "clock": {
            "kind": "attemptTimeout",
            "attempt": 4
          },
          "checks": [
            "C-DLV §4.3",
            "C-DLV §4.4",
            "C-DLV §5.3",
            "C-SDK §6.1",
            "C-SDK §8.4"
          ],
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "QUEUED"
            }
          ]
        },
        {
          "at": 70498,
          "actor": "sender",
          "event": "attempt 5 begins",
          "detail": "QUEUED to IN_FLIGHT, attempts 5; both entries PENDING again; the attempt timeout is armed; no delay is drawn, because a delay is drawn only when an attempt ends below maxAttempts",
          "timing": {
            "kind": "attemptTimeout",
            "valueMs": 12000,
            "attempt": 5
          },
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.3",
            "C-SDK §6.1"
          ],
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "IN_FLIGHT"
            }
          ]
        },
        {
          "at": 82498,
          "actor": "clock",
          "event": "the attempt timeout of attempt 5 elapses",
          "detail": "both entries PENDING to TIMED_OUT; attempts 5 equals maxAttempts 5 and no acceptance was recorded, so the item moves IN_FLIGHT to FAILED_NOT_ACCEPTED, terminal, with lastCode null and one DELIVERY_STATE_CHANGED; no delay is drawn and no further attempt is armed; the finite attempt bound of C-DLV §2 item 1 holds, and the item is terminal 49502 ms before deadlineAt",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 12000
          },
          "clock": {
            "kind": "attemptTimeout",
            "attempt": 5
          },
          "checks": [
            "C-DLV §2",
            "C-DLV §4.3",
            "C-DLV §4.4",
            "C-DLV §5.3",
            "C-SDK §2",
            "C-SDK §6.1"
          ],
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "FAILED_NOT_ACCEPTED"
            }
          ]
        },
        {
          "at": 82508,
          "actor": "sender",
          "event": "getDelivery({ deliveryId: d1 })",
          "detail": "{ ok: true, value: { deliveryId: d1, recipient: <recipient public key>, state: FAILED_NOT_ACCEPTED, terminal: true, attempts: 5, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: TIMED_OUT }, { relayIndex: 1, outcome: TIMED_OUT }] } }",
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
          "at": 82518,
          "actor": "sender",
          "event": "shutdown()",
          "detail": "{ clientState: STOPPED, lost: 0 }; nothing was admitted non-terminal at the call, because the only item was already terminal, so the lost count is zero; every pool, subscription and timer is closed",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §4.6",
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
          "to": "FAILED_NOT_ACCEPTED"
        }
      ],
      "expectedItemStates": [
        {
          "deliveryId": "d1",
          "recipient": "<recipient public key>",
          "state": "FAILED_NOT_ACCEPTED",
          "terminal": true,
          "attempts": 5,
          "createdAt": 12000,
          "deadlineAt": 132000,
          "lastCode": null,
          "relayOutcomes": [
            {
              "relayIndex": 0,
              "outcome": "TIMED_OUT"
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
          "outcome": "TIMED_OUT",
          "note": "PENDING at every attempt begin, TIMED_OUT at every attempt end, five times"
        },
        {
          "relayIndex": 1,
          "outcome": "TIMED_OUT",
          "note": "same as relay0; neither relay ever answered, and neither delayed the other's outcome"
        }
      ],
      "expectedMethodResults": [
        {
          "at": 12000,
          "call": "send({ recipient, payload })",
          "result": "{ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } }"
        },
        {
          "at": 82508,
          "call": "getDelivery({ deliveryId: 'd1' })",
          "result": "{ ok: true, value: { deliveryId: 'd1', recipient: '<recipient public key>', state: 'FAILED_NOT_ACCEPTED', terminal: true, attempts: 5, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: 'TIMED_OUT' }, { relayIndex: 1, outcome: 'TIMED_OUT' }] } }"
        },
        {
          "at": 82518,
          "call": "shutdown()",
          "result": "{ ok: true, value: { clientState: 'STOPPED', lost: 0 } }"
        }
      ],
      "expectedEvents": [
        "CLIENT_STATE_CHANGED with clientState RUNNING at 12000",
        "DELIVERY_STATE_CHANGED with state IN_FLIGHT at 12000, 24999, 38499, 54498 and 70498",
        "DELIVERY_STATE_CHANGED with state QUEUED at 24000, 36999, 50499 and 66498",
        "DELIVERY_STATE_CHANGED with state FAILED_NOT_ACCEPTED, terminal true and lastCode null at 82498",
        "CLIENT_STATE_CHANGED with clientState STOPPED at 82518"
      ],
      "notEmitted": [
        "no receipt and no RECIPIENT_RECEIPT_RECEIVED: the receipt mode of this timeline is RELAY_ACCEPTANCE_ONLY and no recipient is present",
        "no attempt 6 and no attempt after the terminal event, and no retry delay drawn after maxAttempts",
        "no DELIVERY_STATE_CHANGED for a per-relay TIMED_OUT",
        "no claim of exactly-once delivery, of ordering or of cross-restart recovery"
      ],
      "harnessNote": "C-DLV §12 describes `hungRelay` as a never-answering relay next to a normal one; this timeline runs the never-answering behaviour on both relays to reach the exhaustion path of the same harness scenario, which the §12 description does not name separately. It is a reading, stated in the index under open readings."
    }
  ]
}
```
<!-- styx-m3-scenario:v1:end -->

## Prose: what the record fixes

Both timelines hold the C-DLV §3 bounds and use exactly the transport calls of C-DLV §5.1: one current
`RelayPool` per relay, its automatic reconnect cleared with `disconnectAll`, the subscription registered
before connecting and `connectAll()` on every pool in parallel.

**`hungRelayAlongsideNormal`.** The hung relay is configured first and never answers, so an implementation
that awaits relay answers one after another in configuration order cannot record relay1's `ACCEPTED` at 12050, and cannot
pass this timeline. Relay1's `OK true` is the first acceptance of an item in `IN_FLIGHT`, and C-DLV §4.3
makes that acceptance end the publication phase: the item moves to `RELAY_ACCEPTED_AWAITING_RECEIPT` at
12050, in the same instant, and relay0's later settlement cannot move it again (C-DLV §5.3: a per-relay
outcome changes an item's state only through the first acceptance of an item in `IN_FLIGHT`). In this receipt
mode the accepted attempt is the last one and it ends only at a receipt, the deadline, a fault, a cancel or
shutdown, so no retry delay is drawn and no second attempt begins; the attempt timeout still settles relay0
`TIMED_OUT` at 24000, one per-relay timeout after the publication start, which is the settlement rule of C-DLV §5.3 (a relay still `PENDING` at the attempt timeout becomes `TIMED_OUT`); the bound of C-DLV §10 on this harness scenario concerns the normal relay's outcome and the item's acceptance, both of which this timeline records at 12050, and it is not a rule about a hung relay. That C-DLV §10 places
on this harness scenario. The item is not terminal at the shutdown of 24020, so it takes `LOST_ON_SHUTDOWN`
and the result counts it, exactly as C-DLV §2 item 4 and §4.6 require of any non-terminal item at an orderly
`shutdown()`.

**`twoHungRelaysExhaustion`.** No relay answers, so the finite attempt bound of C-DLV §2 item 1 does the
work: the item walks `QUEUED` to `IN_FLIGHT` and back four times, with the four delays drawn from the
injected random port in draw order and checked against `delay(n, u) = floor(base(n) / 2) +
floor(u × base(n) / 2^33)`, and reaches `FAILED_NOT_ACCEPTED` at the end of attempt 5. Each retry is armed
only because `clock.now() + delay < deadlineAt`; at the end of attempt 5 no draw happens at all, because a
delay is drawn only when an attempt ends below `maxAttempts`. The clock readings are those of the injected
clock port of C-SDK §8.4.

**Clauses.** C-SDK §2 (outer bounds), C-SDK §4.1 (createStyxClient and delivery config),
C-SDK §4.2 (client
methods), C-SDK §6.1 (closed states), C-SDK §6.2 (snapshot),
C-SDK §6.3 (per-relay outcomes), C-SDK §7 (events), C-SDK §8.4 (clock and randomness),
C-DLV §2 (outer bounds), C-DLV §3 (bounds and defaults), C-DLV §4.2 (admission),
C-DLV §4.3 (attempts, the first
acceptance and backoff), C-DLV §4.4 (deadline),
C-DLV §4.6 (shutdown), C-DLV §5.1 (one pool per relay, replaced after loss),
C-DLV §5.2 (supervision and reconnection), C-DLV §5.3 (per-relay outcomes),
C-DLV §5.4 (subscribe, REQ when a connection opens), C-DLV §5.5 (closing),
C-DLV §6.1 (event shape), C-DLV §10.
