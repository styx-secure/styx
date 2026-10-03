# Scenario `queueRestartLost` — the in-memory queue does not survive the process

Purpose item (scope record `O-SCEN3`): **a restart of the in-memory queue whose pending items are reported as
lost**. Harness scenario of C-DLV §12 exercised here: `shutdownLostThenNewClient`, whose point is that a new
client with a fresh empty store does not see the items an orderly `shutdown()` reported as lost.

<!-- styx-m3-scenario:v1:start -->
```json
{
  "schema": "styx-m3-scenario/v1",
  "closed": true,
  "scenarioId": "queueRestartLost",
  "purposeItem": "queueRestartLost",
  "title": "Every non-terminal item is reported LOST_ON_SHUTDOWN at an orderly shutdown, no timer survives it, and a new client neither recovers the queue nor accepts a store that still holds records",
  "harnessScenarios": [
    "shutdownLostThenNewClient"
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
    "C-SDK §5.2",
    "C-SDK §6.1",
    "C-SDK §6.2",
    "C-SDK §6.3",
    "C-SDK §7",
    "C-SDK §8.1",
    "C-DLV §2",
    "C-DLV §3",
    "C-DLV §4",
    "C-DLV §4.2",
    "C-DLV §4.3",
    "C-DLV §4.5",
    "C-DLV §4.6",
    "C-DLV §5.1",
    "C-DLV §5.2",
    "C-DLV §5.3",
    "C-DLV §5.5",
    "C-DLV §6.1",
    "C-DLV §6.4",
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
      "id": "lostAtShutdownThenNewClient",
      "harness": "shutdownLostThenNewClient",
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
        "randomValues": [],
        "relays": [
          {
            "index": 0,
            "host": "127.0.0.1",
            "port": "ephemeral",
            "behaviours": [
              "neverAnswering"
            ],
            "role": "accepts the connection and never sends any frame, so nothing can be accepted before the shutdown"
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
        "shutdown() is called at 20000, 4000 ms before the attempt timeout of the running attempt would fire at 24000, so the attempt is interrupted by an orderly shutdown while it is still running.",
        "Neither relay answers, so no item can be accepted and every item is non-terminal at the shutdown.",
        "The new client of 20100 is a separate client with its own storage port, which returns an empty array to its storage.list(); the two clients share nothing but the two relay servers.",
        "The old client is read again at 36010, which is after 24000, the instant at which a leaked attempt timeout would have fired had it not been cleared; the read shows that no timer survived the shutdown.",
        "The injected clock port fires each armed timer at exactly its delay; no retry delay is drawn in this timeline, so randomValues is empty.",
        "The timer handles themselves are asserted through the injected clock port: the port-call expectation of this timeline records the five clearTimer calls of the shutdown step, so the timeline checks the cancellation of the handles and not only the immutability of the snapshot."
      ],
      "clauses": [
        "C-SDK §2",
        "C-SDK §4.1",
        "C-SDK §4.2",
        "C-SDK §5.2",
        "C-SDK §6.1",
        "C-SDK §6.2",
        "C-SDK §6.3",
        "C-SDK §7",
        "C-SDK §8.1",
        "C-DLV §2",
        "C-DLV §3",
        "C-DLV §4",
        "C-DLV §4.2",
        "C-DLV §4.3",
        "C-DLV §4.5",
        "C-DLV §4.6",
        "C-DLV §5.1",
        "C-DLV §5.2",
        "C-DLV §5.3",
        "C-DLV §5.5",
        "C-DLV §6.1",
        "C-DLV §6.4",
        "C-DLV §10"
      ],
      "events": [
        {
          "at": 0,
          "actor": "sender",
          "event": "start()",
          "detail": "createStyxClient with the delivery configuration of C-SDK §4.1 and the two injected relay URLs; every parameter is inside the C-DLV §3 bounds; storage.list() returns an empty array on the storage port of C-SDK §8.1, which is the only value that lets start() continue; the key is read once; one pool per relay with its automatic reconnect cleared; connectAll() on both pools in parallel",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §3",
            "C-DLV §5.1",
            "C-DLV §5.2",
            "C-SDK §4.1",
            "C-SDK §8.1"
          ]
        },
        {
          "at": 12000,
          "actor": "sender",
          "event": "start() resolves",
          "detail": "{ clientState: RUNNING, connectedRelays: 2 }; both hung relays count as connected, because a relay that never answers keeps its socket open",
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
          "detail": "two admissions, each written through storage.put as the item record of C-DLV §6.4 (admission is the only storage call that writes a new record): { deliveryId: d1, state: QUEUED } and { deliveryId: d2, state: QUEUED }; createdAt 12000, deadlineAt 132000 for both; every relay outcome PENDING",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §4.2",
            "C-DLV §6.4",
            "C-SDK §6.1",
            "C-SDK §8.1"
          ]
        },
        {
          "at": 12000,
          "actor": "sender",
          "event": "attempt 1 of d1 and d2 begins",
          "detail": "both items move QUEUED to IN_FLIGHT with attempts 1; each event is signed and published to both relays, which both return 1; both entries of both items are PENDING; the attempt timeouts are armed at the publication start and would elapse at 24000",
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
            "C-SDK §6.1"
          ]
        },
        {
          "at": 20000,
          "actor": "sender",
          "event": "shutdown()",
          "detail": "the orderly shutdown of C-DLV §4.6 runs in its fixed order: it records the stopped state and refuses further start, send, cancel and shutdown calls; it stops the supervision timer; and it clears every timer handle the client still holds, which at this instant are two deadline timers (one per item of C-DLV §4.2 step 4), two attempt timers (one per item, armed at 12000 when the item entered IN_FLIGHT) and the supervision timer of C-DLV §5.2 — five handles in all (expectedPortCalls), each passed to clearTimer a single time; the listeners of C-SDK §4.2 are removed",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "transitions": [
            {
              "deliveryId": "d1",
              "to": "LOST_ON_SHUTDOWN"
            },
            {
              "deliveryId": "d2",
              "to": "LOST_ON_SHUTDOWN"
            }
          ],
          "checks": [
            "C-DLV §10",
            "C-DLV §4.2",
            "C-DLV §4.5",
            "C-DLV §4.6",
            "C-DLV §5.2",
            "C-DLV §5.5",
            "C-SDK §4.2",
            "C-SDK §7"
          ]
        },
        {
          "at": 20010,
          "actor": "sender",
          "event": "getDelivery({ deliveryId: d1 }) and ({ deliveryId: d2 }) on the stopped client",
          "detail": "each snapshot reports state LOST_ON_SHUTDOWN, terminal true, attempts 1, createdAt 12000, deadlineAt 132000, lastCode null and relayOutcomes [{ relayIndex: 0, outcome: PENDING }, { relayIndex: 1, outcome: PENDING }]; the per-relay outcomes are frozen at their admission values, because an entry in PENDING is frozen by the shutdown and never becomes TIMED_OUT",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §4.6",
            "C-DLV §5.3",
            "C-SDK §4.2",
            "C-SDK §5.2",
            "C-SDK §6.2",
            "C-SDK §6.3"
          ]
        },
        {
          "at": 20100,
          "actor": "newClient",
          "event": "a new client is created with a fresh empty store and started",
          "detail": "a separate client, with its own storage port whose storage.list() returns an empty array, is created and started; nothing of the old client is reachable from it: the queue of C-DLV §4 resides in the memory of one client in one process (C-DLV §2 item 4)",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §2",
            "C-DLV §4",
            "C-SDK §4.1",
            "C-SDK §8.1"
          ]
        },
        {
          "at": 32100,
          "actor": "newClient",
          "event": "start() resolves",
          "detail": "{ clientState: RUNNING, connectedRelays: 2 }; the new client has an empty queue",
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
            "startedAt": 20100
          }
        },
        {
          "at": 32110,
          "actor": "newClient",
          "event": "getDelivery({ deliveryId: d1 })",
          "detail": "{ ok: false, code: E_SDK_UNKNOWN_DELIVERY }: the new client never assigned d1, so it has no record of it and does not see the item the old client reported as lost; nothing is recovered, resumed or resent after the shutdown",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §2",
            "C-DLV §4.6",
            "C-SDK §4.2",
            "C-SDK §5.2"
          ]
        },
        {
          "at": 36010,
          "actor": "sender",
          "event": "getDelivery({ deliveryId: d1 }) again, 12010 ms after the instant at which the attempt timeout of attempt 1 would have elapsed (12000 + perRelayTimeoutMs = 24000)",
          "detail": "the orderly shutdown of C-DLV §4.6 runs in its fixed order: it records the stopped state and refuses further start, send, cancel and shutdown calls; it stops the supervision timer; and it clears every timer handle the client still holds, which at this instant are two deadline timers (one per item of C-DLV §4.2 step 4), two attempt timers (one per item, armed at 12000 when the item entered IN_FLIGHT) and the supervision timer of C-DLV §5.2 — five handles in all (expectedPortCalls), each passed to clearTimer a single time; the listeners of C-SDK §4.2 are removed",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 3900
          },
          "checks": [
            "C-DLV §4.2",
            "C-DLV §4.3",
            "C-DLV §4.5",
            "C-DLV §4.6",
            "C-DLV §5.2",
            "C-SDK §4.2",
            "C-SDK §6.2"
          ]
        },
        {
          "at": 36020,
          "actor": "sender",
          "event": "send({ recipient, payload }) on the stopped client",
          "detail": "{ ok: false, code: E_SDK_CLIENT_STOPPED }: no item can be admitted after shutdown, so the lost set cannot grow",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 10
          },
          "checks": [
            "C-DLV §4.6",
            "C-SDK §2",
            "C-SDK §4.2",
            "C-SDK §5.2"
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
          "to": "LOST_ON_SHUTDOWN"
        },
        {
          "deliveryId": "d2",
          "from": "IN_FLIGHT",
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
              "outcome": "PENDING"
            },
            {
              "relayIndex": 1,
              "outcome": "PENDING"
            }
          ]
        },
        {
          "deliveryId": "d2",
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
              "outcome": "PENDING"
            },
            {
              "relayIndex": 1,
              "outcome": "PENDING"
            }
          ]
        }
      ],
      "expectedRelayStates": [
        {
          "relayIndex": 0,
          "outcome": "PENDING",
          "note": "publish returned 1 in attempt 1 and no OK frame and no attempt timeout ever followed, because the shutdown froze the entry"
        },
        {
          "relayIndex": 1,
          "outcome": "PENDING",
          "note": "same"
        }
      ],
      "expectedMethodResults": [
        {
          "at": 12000,
          "call": "send({ recipient, payload })",
          "result": "{ ok: true, value: { deliveryId: 'd1', state: 'QUEUED' } }; the second admission returns the same shape for d2"
        },
        {
          "at": 20000,
          "call": "shutdown()",
          "result": "{ ok: true, value: { clientState: 'STOPPED', lost: 2 } }"
        },
        {
          "at": 20010,
          "call": "getDelivery({ deliveryId: 'd1' })",
          "result": "{ ok: true, value: { deliveryId: 'd1', recipient: '<recipient public key>', state: 'LOST_ON_SHUTDOWN', terminal: true, attempts: 1, createdAt: 12000, deadlineAt: 132000, lastCode: null, relayOutcomes: [{ relayIndex: 0, outcome: 'PENDING' }, { relayIndex: 1, outcome: 'PENDING' }] } }"
        },
        {
          "at": 32110,
          "call": "getDelivery({ deliveryId: 'd1' }) on the new client",
          "result": "{ ok: false, code: 'E_SDK_UNKNOWN_DELIVERY' }"
        },
        {
          "at": 36020,
          "call": "send({ recipient, payload }) on the stopped client",
          "result": "{ ok: false, code: 'E_SDK_CLIENT_STOPPED' }"
        }
      ],
      "expectedEvents": [
        "CLIENT_STATE_CHANGED with clientState RUNNING at 12000 and at 32100 for the new client",
        "DELIVERY_STATE_CHANGED with state IN_FLIGHT for d1 and d2 at 12000",
        "DELIVERY_STATE_CHANGED with state LOST_ON_SHUTDOWN, terminal true and lastCode null for d1 and d2 at 20000",
        "CLIENT_STATE_CHANGED with clientState STOPPED at 20000"
      ],
      "notEmitted": [
        "no DELIVERY_STATE_CHANGED after 20000: no attempt timeout, no retry, no acceptance and no LOST_ON_SHUTDOWN for the new client, which has no item",
        "no cross-restart recovery of any kind: the new client neither lists, resumes nor resends the old items, and C-DLV §2 item 4 claims nothing after a crash or an abrupt termination",
        "no durable persistence claim: the storage port is the injected port of C-SDK §8.1 and the record format is not persisted"
      ],
      "expectedPortCalls": [
        {
          "at": 20000,
          "port": "clock",
          "call": "clearTimer",
          "count": 5
        }
      ]
    },
    {
      "id": "nonEmptyStoreRefused",
      "harness": "shutdownLostThenNewClient",
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
        "randomValues": [],
        "relays": [
          {
            "index": 0,
            "host": "127.0.0.1",
            "port": "ephemeral",
            "behaviours": [
              "normal"
            ],
            "role": "a relay server that is reachable whenever it is asked to accept a connection; it is never used, because this timeline never gets past the storage check"
          },
          {
            "index": 1,
            "host": "::1",
            "port": "ephemeral",
            "behaviours": [
              "normal"
            ],
            "role": "a relay server that is reachable whenever it is asked to accept a connection; it is never used, because this timeline never gets past the storage check"
          }
        ]
      },
      "preconditions": [
        "The storage port of this client returns the two records the old client wrote, still in state LOST_ON_SHUTDOWN, as a caller would obtain by trying to resume a queue across a restart.",
        "Both records carry only values inside the closed sets of the interface — LOST_ON_SHUTDOWN is a member of the state enumeration, RELAY_ACCEPTANCE_ONLY a member of the receipt modes, null a member of the last-code set and PENDING a member of the per-relay outcome enumeration — so the closed-slot check of C-DLV §5.2 does not fire and the emptiness rule does.",
        "The injected clock port fires each armed timer at exactly its delay and no timer is armed in this timeline."
      ],
      "clauses": [
        "C-SDK §4.1",
        "C-SDK §4.2",
        "C-SDK §5.2",
        "C-SDK §6.1",
        "C-SDK §8.1",
        "C-DLV §2",
        "C-DLV §4.6",
        "C-DLV §5.2",
        "C-DLV §6.4"
      ],
      "events": [
        {
          "at": 0,
          "actor": "sender",
          "event": "start() on a client whose storage port returns two records",
          "detail": "start() runs its storage checks in the fixed order of C-DLV §5.2: storage.list() returns an array, and each element is a plain object; the closed-slot check looks at the state, at the receipt mode, at the last code and at the outcome of every per-relay entry of each record, and every value there is inside its closed set, so no E_SDK_UNKNOWN_CODE fires; then the shape check runs and each element has exactly the field names of the item record of C-DLV §6.4, so no E_SDK_STORAGE_FAILED fires",
          "timing": {
            "kind": "portCall",
            "valueMs": 6000
          },
          "checks": [
            "C-DLV §5.2",
            "C-DLV §6.4",
            "C-SDK §5.2",
            "C-SDK §6.1",
            "C-SDK §8.1"
          ]
        },
        {
          "at": 5,
          "actor": "sender",
          "event": "the emptiness rule is applied",
          "detail": "both checks above passed and the array is not empty, so the result is any other non-empty array: E_SDK_STORAGE_NOT_EMPTY; nothing of the old queue is adopted, resumed or resent, which is the storage side of the same harness scenario: the delivery layer has no path that recovers a queue across a process boundary",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 5
          },
          "checks": [
            "C-DLV §2",
            "C-DLV §4.6",
            "C-DLV §5.2"
          ]
        },
        {
          "at": 10,
          "actor": "sender",
          "event": "start() resolves",
          "detail": "{ ok: false, code: E_SDK_STORAGE_NOT_EMPTY }; the client never reaches RUNNING, no pool is prepared and no connection is opened, so no relay is used and no item, timer or subscription exists; there is no item to read and no relay outcome to report for this client",
          "timing": {
            "kind": "deltaFromPrevious",
            "valueMs": 5
          },
          "checks": [
            "C-DLV §5.2",
            "C-SDK §4.1",
            "C-SDK §4.2"
          ]
        }
      ],
      "expectedTransitions": [],
      "expectedItemStates": [],
      "expectedRelayStates": [],
      "expectedMethodResults": [
        {
          "at": 10,
          "call": "start()",
          "result": "{ ok: false, code: 'E_SDK_STORAGE_NOT_EMPTY' }"
        }
      ],
      "expectedEvents": [
        "no event of any kind: a failed start() emits no CLIENT_STATE_CHANGED, and no item was ever admitted, so no DELIVERY_STATE_CHANGED can exist"
      ],
      "notEmitted": [
        "no CLIENT_STATE_CHANGED, because the client never reached RUNNING or STOPPED",
        "no relay connection, no subscription and no pool, because the storage checks run before the pools are prepared",
        "no LOST_ON_SHUTDOWN and no recovery: the records are refused rather than adopted"
      ],
      "harnessNote": "C-DLV §10's description of `shutdownLostThenNewClient` gives a new empty store; this timeline runs the same new client against a non-empty store to show the refusal of C-DLV §5.2, a case the §12 description does not name. It is a reading, stated in the index under open readings."
    }
  ]
}
```
<!-- styx-m3-scenario:v1:end -->

## Prose: what the record fixes

**`lostAtShutdownThenNewClient`.** C-DLV §4.6 fixes the order of an orderly `shutdown()`: the stopped state
and the refusal of further `start`, `send`, `cancel` and `shutdown` calls, then the stop of relay-frame
acceptance, then the `LOST_ON_SHUTDOWN` transitions of every admitted non-terminal item, then the writes back
through `storage.update` (each bounded by the port-call timeout, after the events are delivered), the
clearing of every timer and the closing of every relay connection. Both items are in `IN_FLIGHT` at the
shutdown, so both take `LOST_ON_SHUTDOWN` and the result counts two; the attempt timers, which would have
fired at 24000, are cleared, and the read at 36010 — after the instant at which a leaked timer would have
fired — shows the frozen `PENDING` entries of C-DLV §5.3. The new client of 20100 is a separate client with
its own empty store: it starts, and it has no record of `d1`, so nothing is recovered, resumed or resent.
C-SDK §2 and C-DLV §2 item 4 are the clauses that make this the whole truth about a restart: the queue lives
in the memory of one client in one process, and after a crash or an abrupt termination nothing is reported at
all.

**`nonEmptyStoreRefused`.** The other side of the same scenario: the storage port is the only place where a
queue could survive a process, and C-DLV §5.2 refuses to adopt anything from it. The checks run in order —
the array shape, then the closed-slot check over `state`, `receiptMode`, `lastCode` and every `relayOutcomes`
outcome, then the field-name shape of the record of C-DLV §6.4 — and only an empty array lets `start()`
continue. Both records here carry values inside the closed sets, so the emptiness rule is what fires and the
answer is `E_SDK_STORAGE_NOT_EMPTY`. No pool is prepared, no connection is opened and no item exists, so this
timeline has no per-item and no per-relay state to report at all.

**Clauses.** C-SDK §2 (outer bounds), C-SDK §4.1 (createStyxClient and delivery config),
C-SDK §4.2 (client
methods), C-SDK §5.2 (closed code set), C-SDK §6.1 (closed states),
C-SDK §6.2 (snapshot), C-SDK §6.3 (per-relay outcomes), C-SDK §7 (events),
C-SDK §8.1 (storage port), C-DLV §2 (outer bounds), C-DLV §3 (bounds and defaults), C-DLV §4,
C-DLV §4.2 (admission), C-DLV §4.3 (attempts, the first
acceptance and backoff),
C-DLV §4.5 (timers and faults), C-DLV §4.6 (shutdown),
C-DLV §5.1 (one pool per relay, replaced after loss), C-DLV §5.2 (supervision and reconnection),
C-DLV §5.3 (per-relay outcomes), C-DLV §5.5 (closing), C-DLV §6.1 (event shape),
C-DLV §6.4 (admission is the only storage call that writes a new record), C-DLV §10.
