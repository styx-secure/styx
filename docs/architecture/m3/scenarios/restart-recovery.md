# Scenario `restartRecovery` — durable reception across stop, restart and crash

Purpose item: **the conditional durable-receive exception of C-SDK and C-DLV, exercised against the
experimental Node reference receiver**. This is the only record of the set that declares the cross-restart
claim, and it declares it only under the condition the two documents state: a client configured with
`ports.receiveState` and a caller that meets the caller semantics of the session port and of the
receive-state port. The harness is `referenceReceiver`: the reference receiver and its tests, the two trees of
the import exception for the reference receiver, with the real MLS engine, the immutable vendored WASM, the SDK
client and one loopback relay.

<!-- styx-m3-scenario:v1:start -->
```json
{
  "schema": "styx-m3-scenario/v1",
  "closed": true,
  "scenarioId": "restartRecovery",
  "purposeItem": "restartRecovery",
  "title": "With ports.receiveState over the reference receiver, a recipient stopped at any write step or inside openCandidate recovers every staged event, opens no committed id again and settles; resolve is read-only; an older copy of the archive is not detected",
  "harnessScenarios": [
    "referenceReceiver"
  ],
  "contracts": {
    "sdkInterface": {
      "path": "docs/architecture/m3/sdk-interface.md",
      "sha256": "b432b8ab67a9aef965f6fcc3270ebd3785b4e122028aec4b57524435a08f3dbf"
    },
    "deliveryLayer": {
      "path": "docs/architecture/m3/delivery-layer.md",
      "sha256": "ad0cae8f621260c061cf509a350ba3ac290cadac88f275ff077bc8642c79b77c"
    }
  },
  "clauses": [
    "C-SDK §2",
    "C-SDK §4.2",
    "C-SDK §7.1",
    "C-SDK §8.2",
    "C-SDK §8.5",
    "C-SDK §9",
    "C-DLV §5.4",
    "C-DLV §7.4"
  ],
  "nonClaims": {
    "exactlyOnce": false,
    "ordering": false,
    "crossRestart": true,
    "unboundedRetransmission": false,
    "relayAcceptanceDistinctFromReceipt": true,
    "receiptProvesReading": false,
    "receiptProvesOpening": false,
    "newCryptography": false,
    "normativeWireFormat": false,
    "publicRelay": false,
    "personReadMessage": false,
    "durablePersistence": true,
    "metadataProtection": false
  },
  "durableReceive": {
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
  "declaredLimits": {
    "archiveRollbackDetected": false,
    "secureErase": false,
    "keyRotation": false
  },
  "timelines": [
    {
      "id": "killAtEveryWritePoint",
      "harness": "referenceReceiver",
      "preconditions": [
        "The sender and the recipient each use an SDK client whose ports.session and ports.receiveState are the reference receiver of their own archive, with the real MLS engine and the immutable vendored WASM.",
        "The two parties are joined in one MLS 1:1 group through the session ports before any message is sent; the recipient's binding is an invitee binding, completed by the first message.",
        "One loopback relay on 127.0.0.1 with an ephemeral port stores every event and serves stored matches on each new subscription; it is the only relay of both clients.",
        "The sender's clock port is held while the recipient's processes run, so no deadline or periodic pass of the sender depends on how long those processes take; every wait of the oracle is a wait for an event, bounded only by a hang guard.",
        "One execution of the timeline is one kill point: every rewrite operation of the reference receiver at every named write step, and openCandidate, each in a fresh pair of archives; the n-th rewrite is the first for seal and commitCursor and the first, second or third for the others, by repetition."
      ],
      "clauses": [
        "C-DLV §5.4",
        "C-DLV §7.4",
        "C-SDK §2",
        "C-SDK §4.2",
        "C-SDK §7.1",
        "C-SDK §8.2",
        "C-SDK §8.5",
        "C-SDK §9"
      ],
      "setup": {
        "sender": "alice",
        "recipient": "bob",
        "relays": 1,
        "messages": 3,
        "payloads": [
          "m0",
          "m1",
          "m2"
        ],
        "receiptMode": "RECIPIENT_RECEIPT"
      },
      "runs": [
        {
          "run": "prepare",
          "process": "same",
          "kind": "setup",
          "detail": "The sender's client starts over its reference receiver, the recipient's archive is created and joined to the sender's group through the session ports, and the sender sends the three messages, which the relay stores. The reference receiver and the crash child process are the two trees of the C-SDK §9 exception.",
          "checks": [
            "C-SDK §8.2",
            "C-SDK §9"
          ]
        },
        {
          "run": "killed",
          "process": "separate",
          "kind": "kill",
          "detail": "A new process of the recipient starts a client with ports.receiveState over the reference receiver of the archive, receives the stored messages and is stopped by SIGKILL at the kill point of this execution: before the named step of the named rewrite, or inside openCandidate.",
          "checks": [
            "C-SDK §8.5",
            "C-DLV §7.4"
          ]
        },
        {
          "run": "recovered",
          "process": "separate",
          "kind": "restart",
          "detail": "A further process opens the same archive: load returns the staged and committed entries, the recovery pass opens every PENDING entry once in stage order before the first relay connection, READY entries are emitted again, and the listener acknowledges each message it receives.",
          "checks": [
            "C-SDK §7.1",
            "C-SDK §8.5",
            "C-DLV §7.4",
            "C-SDK §4.2"
          ]
        },
        {
          "run": "replied",
          "process": "separate",
          "kind": "restart",
          "detail": "A third process opens the archive again, sends a reply sealed from the recovered MLS state and waits for its relay acceptance, stops in order, and a fresh receiver instance reads the final durable state.",
          "checks": [
            "C-SDK §8.2",
            "C-SDK §8.5"
          ]
        },
        {
          "run": "judged",
          "process": "same",
          "kind": "verify",
          "detail": "The joint oracle reads the logs of the three processes, the final durable state, the sender's events and, from the final archive, the outcome of opening every committed ciphertext again.",
          "checks": [
            "C-SDK §8.5",
            "C-DLV §5.4"
          ]
        }
      ],
      "killPoints": {
        "operations": [
          "stage",
          "commit",
          "ack",
          "receiptDone",
          "commitCursor",
          "seal"
        ],
        "steps": [
          "temp-create",
          "temp-write",
          "temp-fsync",
          "temp-close",
          "rename",
          "directory-fsync",
          "reported"
        ],
        "openCandidate": true
      },
      "invariants": [
        {
          "id": "killPointReached",
          "holds": true,
          "checks": [
            "C-SDK §8.5"
          ],
          "detail": "The killed process stops by SIGKILL exactly at the declared point, and the two later processes end normally."
        },
        {
          "id": "stagedNotLost",
          "holds": true,
          "checks": [
            "C-SDK §2",
            "C-SDK §8.5"
          ],
          "detail": "Every stage that returned in the killed process is in the seen set that load returns after the restart."
        },
        {
          "id": "committedNotOpenedAgain",
          "holds": true,
          "checks": [
            "C-SDK §8.2",
            "C-SDK §8.5"
          ],
          "detail": "No event id durably committed before the restart reaches openCandidate in a later process."
        },
        {
          "id": "everyMessageDeliveredWithPayload",
          "holds": true,
          "checks": [
            "C-SDK §7.1"
          ],
          "detail": "Each of the three messages reaches a listener with its own payload, in one of the three processes."
        },
        {
          "id": "noDeliveryAfterAcknowledgement",
          "holds": true,
          "checks": [
            "C-SDK §4.2",
            "C-SDK §7.1"
          ],
          "detail": "Once an acknowledgement of an id has returned success, that id never reaches a listener again."
        },
        {
          "id": "finalStateSettled",
          "holds": true,
          "checks": [
            "C-SDK §8.5",
            "C-DLV §5.4"
          ],
          "detail": "In the final durable state nothing is PENDING, READY or owed, the seen and acknowledged sets are the three sent ids without repetition, and one cursor is stored."
        },
        {
          "id": "recoveredStateSealsToPeer",
          "holds": true,
          "checks": [
            "C-SDK §8.2"
          ],
          "detail": "The reply sealed after the recovery opens at the sender, so the live MLS state was not behind the committed one."
        },
        {
          "id": "checkpointNotBehind",
          "holds": true,
          "checks": [
            "C-SDK §8.2",
            "C-SDK §8.5"
          ],
          "detail": "From the final archive no committed ciphertext opens again as an application message: the durable MLS checkpoint is not behind the committed entries."
        },
        {
          "id": "receiptsReachSender",
          "holds": true,
          "checks": [
            "C-DLV §7.4"
          ],
          "detail": "Every sent item reaches RECIPIENT_RECEIPT_RECEIVED at the sender: a receipt obligation still due at the kill is published by a later process."
        }
      ],
      "expectedEvents": [
        "The recipient's processes emit MESSAGE_RECEIVED with eventId and payload for every sent message, possibly more than once before its acknowledgement.",
        "The sender's client emits RECIPIENT_RECEIPT_RECEIVED for each of the three items and MESSAGE_RECEIVED for the reply sealed after the recovery."
      ],
      "notEmitted": [
        "No call of openCandidate in a restarted process carries the ciphertext of an id committed before the restart.",
        "No MESSAGE_RECEIVED of an id follows the successful acknowledgement of that id, in the same process or a later one."
      ]
    },
    {
      "id": "uncertainCommitResolved",
      "harness": "referenceReceiver",
      "preconditions": [
        "The sender and the recipient use SDK clients over their own reference receivers in one process, joined in one MLS 1:1 group through the session ports, with one loopback relay on 127.0.0.1 and an ephemeral port.",
        "The recipient's commit port is wrapped: the first commit is passed to the reference receiver and then throws, and the second throws without reaching it; every later commit is passed unchanged.",
        "The recipient's resolve port records each answer and, at once after it, calls resolve twice more with the same operation id and reads the snapshot file's SHA-256 and the receiver's write count before and after.",
        "The recipient's listener acknowledges each message it receives; the sender's clock port is held for the whole timeline, and every wait is a wait for an event."
      ],
      "clauses": [
        "C-DLV §5.4",
        "C-DLV §7.4",
        "C-SDK §4.2",
        "C-SDK §7.1",
        "C-SDK §8.5"
      ],
      "setup": {
        "sender": "alice",
        "recipient": "bob",
        "relays": 1,
        "messages": 2,
        "payloads": [
          "first",
          "second"
        ],
        "receiptMode": "RECIPIENT_RECEIPT"
      },
      "runs": [
        {
          "run": "prepare",
          "process": "same",
          "kind": "setup",
          "detail": "The two archives are created and joined, both clients start, and the sender sends the first message; the second is sent after the first has been acknowledged.",
          "checks": [
            "C-SDK §8.5"
          ]
        },
        {
          "run": "lostResult",
          "process": "same",
          "kind": "fault",
          "detail": "The first commit takes effect in the reference receiver, but its result does not reach the SDK: the wrapper throws after the write returned, which is an uncertain result. The SDK pauses the receive state and calls resolve at once.",
          "checks": [
            "C-SDK §8.5"
          ]
        },
        {
          "run": "neverWritten",
          "process": "same",
          "kind": "fault",
          "detail": "The second commit never reaches the reference receiver and throws as well. The SDK pauses and calls resolve; after the aborted answer the same commit is presented to the receiver late, and is refused.",
          "checks": [
            "C-SDK §8.5"
          ]
        },
        {
          "run": "retried",
          "process": "same",
          "kind": "verify",
          "detail": "The entry of the second message stays PENDING; the periodic pass retries it after its budget renews, the retry commits and the listener receives and acknowledges the message.",
          "checks": [
            "C-DLV §7.4",
            "C-SDK §7.1",
            "C-SDK §4.2"
          ]
        },
        {
          "run": "restarted",
          "process": "same",
          "kind": "restart",
          "detail": "A new receiver instance and a new client open the archive; the relay serves both stored copies again, and the first cursor commit of this run marks the point after which every replayed copy was accounted.",
          "checks": [
            "C-DLV §5.4",
            "C-SDK §8.5"
          ]
        }
      ],
      "killPoints": {
        "operations": [],
        "steps": [],
        "openCandidate": false
      },
      "invariants": [
        {
          "id": "resolveAnswersCommitted",
          "holds": true,
          "checks": [
            "C-SDK §8.5"
          ],
          "detail": "resolve of the first commit answers committed with that commit's exact application result and payload."
        },
        {
          "id": "resolveAnswersAborted",
          "holds": true,
          "checks": [
            "C-SDK §8.5"
          ],
          "detail": "resolve of the second commit, which never reached the receiver, answers aborted."
        },
        {
          "id": "resolveRepeatable",
          "holds": true,
          "checks": [
            "C-SDK §8.5"
          ],
          "detail": "The two further calls of resolve made at once after each answer, with the same operation id, return the same answer."
        },
        {
          "id": "resolveWritesNothing",
          "holds": true,
          "checks": [
            "C-SDK §8.5"
          ],
          "detail": "Across every resolve call the snapshot file keeps the same SHA-256 and the receiver's write count does not change: resolve is read-only."
        },
        {
          "id": "abortedCommitNeverTakesEffect",
          "holds": true,
          "checks": [
            "C-SDK §8.5"
          ],
          "detail": "The late arrival of the aborted commit is refused with E_SDK_RECEIVE_STATE_FAILED and changes neither the snapshot file nor the write count."
        },
        {
          "id": "eachMessageDeliveredOnce",
          "holds": true,
          "checks": [
            "C-SDK §4.2",
            "C-SDK §7.1"
          ],
          "detail": "In this run each message reaches the listener once and its acknowledgement succeeds."
        },
        {
          "id": "committedNotOpenedAgain",
          "holds": true,
          "checks": [
            "C-DLV §5.4",
            "C-SDK §8.5"
          ],
          "detail": "After the restart neither message reaches openCandidate or the listener again, and the loaded state holds both ids as acknowledged with nothing PENDING."
        }
      ],
      "expectedEvents": [
        "MESSAGE_RECEIVED for the first message after resolve answered committed, and for the second after its retry committed.",
        "acknowledgeMessage returns success for both messages, each after its MESSAGE_RECEIVED."
      ],
      "notEmitted": [
        "No second commit of the first message and no commit of the second under the operation id that resolve answered aborted.",
        "No MESSAGE_RECEIVED and no openCandidate of either message after the restart."
      ]
    },
    {
      "id": "archiveRollbackUndetected",
      "harness": "referenceReceiver",
      "preconditions": [
        "The sender and the recipient use SDK clients over their own reference receivers in one process, joined in one MLS 1:1 group through the session ports, with one loopback relay on 127.0.0.1 and an ephemeral port.",
        "The reference receiver declares that it has no rollback protection: replacing the archive with an older copy of itself is not detected, and acknowledged payloads may reappear.",
        "The older copy is the snapshot file as it was after the message was committed and before it was acknowledged; it is written back over the authoritative file between two runs, and every wait is a wait for an event."
      ],
      "clauses": [
        "C-SDK §4.2",
        "C-SDK §7.1",
        "C-SDK §8.5"
      ],
      "setup": {
        "sender": "alice",
        "recipient": "bob",
        "relays": 1,
        "messages": 1,
        "payloads": [
          "kept"
        ],
        "receiptMode": "RECIPIENT_RECEIPT"
      },
      "runs": [
        {
          "run": "prepare",
          "process": "same",
          "kind": "setup",
          "detail": "The two archives are created and joined, the recipient's first client receives the message without acknowledging it and stops in order, and a copy of the snapshot file is kept.",
          "checks": [
            "C-SDK §7.1",
            "C-SDK §8.5"
          ]
        },
        {
          "run": "acknowledged",
          "process": "same",
          "kind": "restart",
          "detail": "A new receiver instance and a new client open the archive; the message is emitted again and the listener acknowledges it.",
          "checks": [
            "C-SDK §4.2",
            "C-SDK §7.1"
          ]
        },
        {
          "run": "readAfterAck",
          "process": "same",
          "kind": "verify",
          "detail": "A fresh receiver instance loads the archive: the id is acknowledged and its payload is in no READY or PENDING entry.",
          "checks": [
            "C-SDK §8.5"
          ]
        },
        {
          "run": "restored",
          "process": "same",
          "kind": "restore",
          "detail": "The kept copy is written over the authoritative snapshot file, as a backup restore or a file-system snapshot would do.",
          "checks": [
            "C-SDK §8.5"
          ]
        },
        {
          "run": "reopened",
          "process": "same",
          "kind": "restart",
          "detail": "A new receiver instance and a new client open the restored archive; start succeeds and the listener receives the acknowledged message again with its payload.",
          "checks": [
            "C-SDK §7.1",
            "C-SDK §8.5"
          ]
        }
      ],
      "killPoints": {
        "operations": [],
        "steps": [],
        "openCandidate": false
      },
      "invariants": [
        {
          "id": "payloadAbsentAfterAcknowledgement",
          "holds": true,
          "checks": [
            "C-SDK §8.5"
          ],
          "detail": "After the acknowledgement the payload leaves the active state and every later load of the current archive."
        },
        {
          "id": "archiveRollbackDetected",
          "holds": false,
          "checks": [
            "C-SDK §8.5"
          ],
          "detail": "The restored older copy loads like any other archive and start succeeds: the replacement is not detected, a declared limit of the reference receiver."
        },
        {
          "id": "acknowledgedPayloadReappears",
          "holds": true,
          "checks": [
            "C-SDK §7.1",
            "C-SDK §8.5"
          ],
          "detail": "The message acknowledged before the restore is delivered again with its payload after it: the declared consequence of the missing rollback protection."
        }
      ],
      "expectedEvents": [
        "MESSAGE_RECEIVED of the message in the first run, again in the run that acknowledges it, and again after the restore.",
        "A successful start of the client that opens the restored archive."
      ],
      "notEmitted": [
        "No refusal of the restored archive at load and no RECEIVE_STATE_FAILED in the run that opens it: the replacement is not detected.",
        "No claim that the payload was erased from the medium: an older copy of the archive still holds it."
      ]
    }
  ]
}
```
<!-- styx-m3-scenario:v1:end -->

## Prose: what the record fixes

**Condition.** Every claim of this record holds only for a client configured with `ports.receiveState` and a
caller that meets the caller semantics of the session port and the receive-state port (C-SDK §8.2,
C-SDK §8.5), which the SDK cannot verify. With `ports.receiveState`, every admitted inbound kind-4741 event
whose `stage` has completed durably stays recoverable locally across stop, restart and crash, no committed
event id is passed to `openCandidate` again, and every committed application result is redelivered until it
is acknowledged (C-SDK §2, bound 2). The `durableReceive` object of the record is the C-SDK record's
conditional durable-receive exception, copied exactly. Without `ports.receiveState` the default stands: no
cross-restart recovery and no durable persistence, as every other record of this set declares.

**What is not claimed.** The flags `crossRestart` and `durablePersistence` are the only values of
`nonClaims` that differ from the other records, and only for that condition. There is no exactly-once
application effect (a message may reach the listener again until it is acknowledged), no ordering, no
completeness (before `stage`, recovery still depends on the relays), and no outbound resume: the sender's
items keep the process-lifetime bound. The harness is the reference receiver of the C-SDK §9 exception and
nothing else; no other caller implementation is covered.

**Kill points.** `killAtEveryWritePoint` stops a real recipient process at each named step of each rewrite of
the reference receiver (the five receive-state writes of C-SDK §8.5 and the `seal` checkpoint) and inside
`openCandidate`. The next process recovers through `load` and the recovery pass of C-DLV §7.4, the cursor is
committed only after the barrier of C-DLV §5.4, receipts still due are published after the restart, and the
listener's acknowledgement (C-SDK §4.2, C-SDK §7.1) ends redelivery. The oracle checks the nine invariants of
the timeline after every kill point.

**Resolution.** `uncertainCommitResolved` fixes the two answers of `resolve` against the reference receiver:
`committed` for a commit that took effect but whose result was lost, and `aborted` for one that never reached
the receiver, after which that commit can no longer take effect. Each answer is repeatable and leaves the
snapshot file and the write count unchanged.

**Declared limits.** `declaredLimits` records three limits of the reference receiver that its own description
declares: an older copy of the archive is not detected (`archiveRollbackUndetected` shows an acknowledged
payload reappearing after such a restore), there is no secure erase from the medium, and there is no rotation
of the at-rest key. No timeline asserts the opposite of any of them.

**How the record is run.** The external checker reads this record and, with `--execute`, runs its three
timelines against the reference receiver of a repository checkout and compares every observed invariant with
the `holds` value declared here.

**Clauses.** C-SDK §2, C-SDK §4.2, C-SDK §7.1, C-SDK §8.2, C-SDK §8.5, C-SDK §9, C-DLV §5.4, C-DLV §7.4.
