# Phase B3.3b-2a: exact retained application-message window

Date: 2026-08-16

Issue: #190

Pull request: #193

Disposition: **implementation evidence is a bounded GO; exact-final-HEAD review,
CI and human gates remain required**

## Question and normative rule

B3.3b-2a isolates one question from future fork convergence: at the exact
B3.3b-1 Styx tuple and pinned MDK revision, do both engines implement Marmot's
five-past-epoch application delivery rule at the same boundary?

The normative rule comes from `protocol-core/retained-history.md` at Marmot
revision `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`:

```text
reference_tip_epoch - message_epoch <= 5
```

This increment exercises delivery only. It does not admit application messages
as convergence witnesses and does not implement branch scoring.

## Frozen inputs and algorithm

B3.3b-2a reuses without modification:

- OpenMLS `09e92777dba0528d3d29e2e5e681b7e91637c7be`, tree
  `fde242458abe5594fbebf2556dca0a135367a817`;
- Marmot `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`, tree
  `10d941f358de5d9fe4ee1db75581f3e5363f5e92`;
- MDK `9396adb6aa6b95b521a7979facd5ea7040c07288`, tree
  `a1145de604e616634dae9a1ef6bf5033c9c9e879`;
- the B3.3b-1 five-file artifact tuple recorded in the companion report;
- ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`);
- exact member profiles `STYX_B32A` and `MDK_PIN_9396ADB`;
- exactly five retained past epochs in both engines.

One fresh authenticated two-member group begins at epoch 1. The harness retains
application messages created at epochs 1, 2 and 3, then applies six sequential,
acknowledged, proposal-free self-updates with deterministic alternating authors:

```text
1→2 MDK, 2→3 Styx, 3→4 MDK, 4→5 Styx, 5→6 MDK, 6→7 Styx
```

At canonical epoch 7 those messages have distances 6, 5 and 4 respectively.
The receiving peer is restarted from durable state before boundary delivery.
The Styx receiver is a separate process for every invocation; MDK is closed,
reopened and restored from its encrypted SQLite store.

## Adversarial matrix and result

| Case | MDK → Styx | Styx → MDK | Required result |
| --- | --- | --- | --- |
| distance 4 | passed | passed | authenticated delivery exactly once |
| distance 5 | passed | passed | authenticated delivery exactly once |
| distance 6 | passed | passed | rejection without output or authority mutation |
| replay after accepted delivery | passed | passed | no second output |
| replay after rejected delivery | passed | passed | no output or transition |
| corrupted distance-4 ciphertext | passed | passed | fail closed |
| future-epoch ciphertext | passed | passed | fail closed without authority mutation |
| caller-forged metadata | passed | passed | ignored or rejected; never authoritative |

The dedicated probe reaches `B33B2A=GO`. It emits eleven ordered, canonical,
safe evidence records followed by exactly one terminal verdict. Records contain
only case identity, direction, message/reference epochs, ciphertext SHA-256,
bounded public checkpoints, outcome and authenticated sender evidence where a
message is delivered. Plaintext, ciphertext bytes, provider state, account
secrets and raw MLS state are never emitted or committed.

The exact standalone environment name is `B33B2A_MDK_ROOT`; it is validated as
an absolute path and must resolve to the same checkout used by B3.3b-1. CI sets
both phase variables to the single exact pinned checkout. Conflicting roots fail
closed.

## Asymmetric error semantics

MDK exposes the pinned typed stale reason `BeyondAppRetention` for the first
distance-six rejection. A subsequent exact replay may be classified as a
duplicate after restart; it still produces no application output or canonical
transition.

The frozen Styx WASM boundary exposes one opaque processing error for both a
distance-six ciphertext and a corrupted in-window ciphertext. This report does
not relabel that error as typed stale. The negative corruption control proves
the indistinguishability explicitly.

## Inherited hostile coverage

Wrong group, parent, profile, proof/signature key, ciphertext digest and
historical artifact/verifier mutation are already fail-closed assertions of the
unchanged B3.3b-1 suite. B3.3b-2a reruns that suite rather than copying or
weakening those controls. Its new controls cover the retained-window boundary,
fresh restore, future epochs, replay and untrusted caller metadata.

## Evidence reproducibility

The paired-evidence runner requires two independent groups, participant sets,
GroupContexts and fresh locked MDK executable builds. It validates the same
ordered eleven-case verdict sequence, exact pins, artifact tuple, retention
policy, transition count, restart counts and terminal bounded claim. Any reuse,
omission, reordering, pin drift or malformed evidence is `B33B2A_BLOCKED`.

Exact-final run identities and safe report digests are attached to PR #193 so
the evidence can name the final commit without creating a self-referential
document change.

## Non-claims and remaining work

- No concurrent Commit race, branch comparison, supersession, witness scoring,
  rewind chain, missing-parent acquisition, pruning or compaction.
- No membership change, multi-device, account/signature-key rotation or rejoin.
- No product, PWA, browser vault, worker, Nostr, relay, push, media or reference
  chat integration.
- No network, anonymity, metadata-privacy, complete-history, production,
  certification, audit-inheritance or general Marmot-conformance claim.
- Five retained epochs keep more private MLS material than retention zero. This
  exact-pin GO measures compatibility and does not choose a product policy.
- The Styx wrapper remains unaudited and `extensions-draft` remains experimental.

The next independent increment, B3.3b-2b, owns concurrent same-parent fork
convergence and durable recovery. It must not infer branch behaviour from this
delivery-only result.

Rollback is deletion of the isolated task branch before merge or an atomic
revert of PR #193 after merge. The proof creates no product database or
migration.
