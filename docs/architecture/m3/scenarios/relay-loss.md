# Scenario `relayLoss` — a relay lost after publication, retired and replaced

Purpose item (scope record `O-SCEN3`): **relay loss**. Harness scenario of C-DLV §12 exercised here:
`relayLossAndReplacement`; the relay-loss step of this set is the same mechanism the §12 list describes for a connection lost after publication, and the record claims only the one name its timeline runs.

<!-- styx-m3-scenario:v1:start -->
```json
{
  "schema": "styx-m3-scenario/v1",
  "closed": true,
  "scenarioId": "relayLoss",
  "purposeItem": "relayLoss",
  "title": "A relay drops its connection after receiving the event, is reported UNREACHABLE for that attempt and is retired and replaced before the next attempt",
  "harnessScenarios": [
    "relayLossAndReplacement"
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
      "id": "relayLossAndReplacement",
      "harness": "relayLossAndReplacement",
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
              "delayFrames"
            ],
            "role": "holds every frame it sends for 20000 ms, on its first connection and on every later one; that delay is longer than one per-relay timeout, so its OK frame for an attempt arrives after that attempt has ended",
            "holdMs": 20000
          },
          {
            "index": 1,
            "host": "::1",
            "port": "ephemeral",
            "behaviours": [
              "dropAfterFrames"
            ],
            "role": "with dropAfterFrames it stores the event and then closes its first connection after receiving the first EVENT frame published to it, before answering that frame (the REQ frames of the connection phase are not counted and the behaviour applies to that first connection only); the stored event survives the socket drop, which is what its replacement connection holds",
            "replacement": "its replacement connection accepts the connection and never sends any frame on it (the neverAnswering behaviour of C-DLV §10) until the item's next attempt, in which the replacement connection is published to and answers nothing"
          }
        ]
      },
      "preconditions": [
        "Both relay servers run inside the test on loopback IP literals and ephemeral ports (C-DLV §2 item 6, §10) and their URLs reach the client only through config.relays (C-SDK §4.1).",
        "relay1's dropAfterFrames counts EVENT frames, and it applies to its first connection only; every later connection of relay1 is neverAnswering.",
        "relay0 keeps both its connections open, so it is never UNREACHABLE: a relay that holds its connection and does not answer is TIMED_OUT.",
        "The injected clock port fires each armed timer at exactly its delay; the injected random port returns the two values of randomValues in draw order, the first for the reconnection delay of the k-th consecutive lost connection and the second for the retry delay of attempt 1, which is 4294967295, so delay(k, 0) = floor(base(k) / 2) for the reconnection and delay(1, 4294967295) = floor(1000 / 2) + floor(4294967295 × 1000 / 2^33) = 999 for the retry.",
        "No relay answers attempt 1 inside its per-relay timeout, so attempt 1 records no acceptance.",
        "Relay supervision runs every relay supervision interval from the moment start() resolves, so the first supervision read after the socket drop is the one at 13000 ms; that reading is stated in the index under open readings."
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
          "detail": "createStyxClient with the delivery configuration of C-SDK §4.1 and the two injected relay URLs; every parameter is inside the C-DLV §3 bounds; storage is empty; the key is read once; one pool per relay is prepared with the transport calls of C-DLV §5.1 and its automatic reconnect is cleared with disconnectAll; the subscription of C-DLV §5.4 is registered before connecting; connectAll() runs on both pools in parallel",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §3",
            "C-DLV §5.1",
            "C-DLV §5.4",
            "C-SDK §4.1"
          ]
        },
        {
          "at": 12000,
          "actor": "sender",
          "event": "start() resolves",
          "detail": "the connection phase ends perRelayTimeoutMs after it began; both relays are connected, so { clientState: RUNNING, connectedRelays: 2 }; the REQ of the subscription was sent on each connection when that connection opened (C-DLV §5.4)",
          "timing": {
            "kind": "connectionPhase",
            "valueMs": 12000,
            "attempt": 1
          },
          "checks": [
            "C-DLV §5.2",
            "C-DLV §5.4",
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
          "detail": "QUEUED to IN_FLIGHT, attempts 1; the kind-4741 event is signed once and published to both relays, and publish returns 1 on both; both entries are PENDING; the attempt timeout is armed at the publication start",
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
          "event": "the connection is dropped after the EVENT frame is received",
          "detail": "the first EVENT frame published to relay1 on this connection reaches it and is stored, and the socket is closed before any matching OK frame; publish had already returned 1 for this attempt and no outcome is set at this instant, because an outcome is set by an OK frame, by the attempt timeout or by the supervision read",
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
          "detail": "the supervision read of the relay supervision interval finds relay1 no longer connected and with no connection attempt in progress, while publish returned 1 on it in this attempt: relay1's outcome for this attempt is UNREACHABLE and its current pool is retired with dispose(); a new pool for relay1 is prepared and its connectAll() is armed after delay(1, u) for the first consecutive lost connection of that relay, with the first injected draw 0, so delay(1, 0) = floor(1000 / 2) + 0 = 500",
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
          "at": 13000,
          "actor": "sender",
          "event": "getDelivery({ deliveryId: d1 })",
          "detail": "{ ok: true, value: { deliveryId: d1, recipient: <recipient public key>, state: IN_FLIGHT, terminal: false, attempts: 1, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: PENDING }, { relayIndex: 1, outcome: UNREACHABLE }] } }",
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
          "at": 13500,
          "actor": "relay1",
          "event": "the replacement connection opens",
          "detail": "the new pool's connection opens; nothing is published on it in attempt 1, because the replacement pool is used from the next attempt on, and the retired pool's late socket close cannot remove the new socket from the pool that owns it",
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
          "detail": "the attempt timeout elapses perRelayTimeoutMs after the publication start: relay0 is still PENDING and becomes TIMED_OUT, because it holds its connection open and never answers; relay1 keeps UNREACHABLE for this attempt, because UNREACHABLE is set by the supervision read and the attempt timeout only turns a PENDING entry into TIMED_OUT; no acceptance was recorded; attempts 1 is below maxAttempts 5, so the SDK draws the second value 4294967295 and computes delay(1, 4294967295) = 500 + 499 = 999; clock.now() + 999 = 24999 is before deadlineAt 132000, so the deadline does not end the item and the retry is armed after 999 ms; IN_FLIGHT to QUEUED",
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
            "C-SDK §6.1"
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
          "detail": "QUEUED to IN_FLIGHT, attempts 2; relay0 is set to PENDING and published to on its current connection, and relay1 is set to PENDING and published to on its replacement connection, which returns 1; the identical signed event bytes are republished, so the event id is unchanged; the attempt timeout is armed at the publication start",
          "timing": {
            "kind": "attemptTimeout",
            "valueMs": 12000,
            "attempt": 2
          },
          "checks": [
            "C-DLV §4.3",
            "C-DLV §5.2",
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
          "at": 32000,
          "actor": "relay0",
          "event": "the OK frame held since attempt 1 arrives",
          "detail": "[\"OK\", <event id>, true, \"saved\"]; an OK frame is matched by event id and relay while that relay is PENDING in the latest attempt, and it is attributed to no particular attempt; because every attempt republishes the identical event bytes, this frame counts for attempt 2: relay0 becomes ACCEPTED, and because d1 is IN_FLIGHT in this attempt the first acceptance ends the publication phase and moves the item to RELAY_ACCEPTED, terminal in this mode, with lastCode null and one DELIVERY_STATE_CHANGED",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 7001
          },
          "relayAnswer": {
            "relayIndex": 0,
            "accepted": true,
            "events": 1
          },
          "checks": [
            "C-DLV §10",
            "C-DLV §4.3",
            "C-DLV §5.3",
            "C-SDK §6.1",
            "C-SDK §7"
          ],
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "RELAY_ACCEPTED"
            }
          ]
        },
        {
          "at": 36999,
          "actor": "clock",
          "event": "the attempt timeout of attempt 2 elapses",
          "detail": "the attempt timeout elapses: relay1's entry is still PENDING and becomes TIMED_OUT, because its replacement connection accepted the connection and never answered; the entry settles although the item is already terminal and the attempt is over, which is the settle window of C-DLV §5.3: it ends only at shutdown or at the attempt timeout; no delay is drawn, because no retransmission happens after an acceptance",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 4999
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
          "detail": "every relay outcome is frozen at its current value, every non-terminal item would be reported LOST_ON_SHUTDOWN and the one item here is already terminal, so the result is { clientState: STOPPED, lost: 0 }; CLIENT_STATE_CHANGED with STOPPED; every pool is disposed, every subscription closed and every timer cleared, and the retired pool's socket close is confined to the retired pool",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §2",
            "C-DLV §4.6",
            "C-DLV §5.5",
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
          "note": "its one OK frame was held past the end of attempt 1 and counted for attempt 2; an accepted entry is sticky"
        },
        {
          "relayIndex": 1,
          "outcome": "TIMED_OUT",
          "note": "UNREACHABLE in attempt 1 after the socket drop; the pool was retired and replaced before attempt 2, which published to the replacement connection, whose neverAnswering behaviour settled it TIMED_OUT"
        }
      ],
      "expectedMethodResults": [
        {
          "at": 12000,
          "call": "send({ recipient, payload })",
          "result": "{ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } }"
        },
        {
          "at": 13000,
          "call": "getDelivery({ deliveryId: 'd1' })",
          "result": "{ ok: true, value: { deliveryId: 'd1', recipient: '<recipient public key>', state: 'IN_FLIGHT', terminal: false, attempts: 1, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: 'PENDING' }, { relayIndex: 1, outcome: 'UNREACHABLE' }] } }"
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
        "DELIVERY_STATE_CHANGED with state RELAY_ACCEPTED, terminal true and lastCode null at 32000",
        "CLIENT_STATE_CHANGED with clientState STOPPED at 37009"
      ],
      "notEmitted": [
        "no publication on relay1's replacement connection during attempt 1, and no UNREACHABLE entry for relay1 in the latest attempt",
        "no DELIVERY_STATE_CHANGED for a per-relay outcome, and no acceptance recorded for relay1",
        "no attempt 3 and no change of state, terminal flag or lastCode after the terminal event",
        "no open connection, subscription or timer after shutdown() resolves, and no exactly-once, ordering or cross-restart claim"
      ]
    }
  ]
}
```
<!-- styx-m3-scenario:v1:end -->

## Prose: what the record fixes

The record keeps the C-DLV §3 bounds and the transport use of C-DLV §5.1: one current `RelayPool` per relay,
never reconnected, with the automatic reconnect cleared before connecting and the pool retired and replaced
after a loss, so that a late close of an old socket stays confined to the retired pool.

The injection is stated so that it produces the timeline: `dropAfterFrames` counts EVENT frames published to
the relay and applies to the relay's first connection only, so the drop happens after the event was stored
and after `publish` had returned `1`; a behaviour that counted the connection phase's `REQ` frames would drop
before any publication, `publish` would return `0`, and C-DLV §5.3 would then give `PENDING` and not
`UNREACHABLE`. The replacement connection of relay1 is declared `neverAnswering`, so the two files that use
`dropAfterFrames` cannot be read as disagreeing about a replacement: here the replacement never answers, and
in `duplicate-and-reordered.md` the replacement answers a republished event with `duplicate:`.

The per-relay outcome follows C-DLV §5.3 exactly: `UNREACHABLE` is set only for a relay on which `publish`
returned `1` in this attempt and whose connection was then lost before any matching OK frame; relay0 holds
its connection open and never answers inside the attempt, so it is `TIMED_OUT` at 24000. The `OK` frame that
arrives at 32000 is matched by event id and relay while relay0 is `PENDING` in the latest attempt and is
attributed to no attempt, so it counts for attempt 2 — sound because every retransmission publishes the
identical signed event bytes (C-DLV §4.3). The supervision read of C-DLV §5.2 detects the loss within the
relay supervision interval and arms the replacement connection after `delay(k, u)` for the k-th consecutive
lost connection; with the injected draw 0 that is 500 ms, exactly as the injected clock port of C-SDK §8.4
measures it. The finite bounds hold: the item is terminal at its first acceptance and no attempt follows it
(C-DLV §2 item 1, §4.3), and `shutdown()` freezes the outcomes and closes everything (C-DLV §4.6, §5.5).

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
