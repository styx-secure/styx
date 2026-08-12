# Phase B2.5b: publish-before-apply local arbitration

`STYX_SPIKE_PROTOTYPE` — isolated, non-product executable evidence for Issue
#157.

This directory closes one B2.5a asymmetry: a member's own freshly prepared MLS
Commit cannot be staged through the inbound API. B2.5b retains both the clean
parent and the pending provider state, keeps the canonical head unchanged until
typed acknowledgement evidence is durable, and then admits the exact local
Commit into the same bounded ordering as direct inbound siblings.

It does **not** implement a transport, prove delivery, authenticate an external
acknowledgement source, provide full Marmot convergence, protect IndexedDB from
a malicious origin, or authorize product use.

## Frozen identity

- Styx base: `44f953e79e8f61632b528a0a2b1ffbe5fe965cb7`
- OpenMLS: `09e92777dba0528d3d29e2e5e681b7e91637c7be`
- Marmot specification: `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`
- WASM SHA-256:
  `60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a`
- Ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
- Database prefix: `styx-b2-5b-poc-v1-`
- Stores: exactly eight
- Frozen candidate cap: 16

## State separation

The canonical head remains `STABLE` while the separate local record moves
through:

```text
QUEUED -> PREPARED -> PUBLISHING -> ACKNOWLEDGED
                |          |              |
                v          v              v
           CANCELLED   DISCARDED     FROZEN arbitration
                                           |
                         CONFIRMED / CLEARED_LOST / CLEARED_REJECTED
```

`FAILURE` is evidence, not permission to guess that publication did not happen.
Discard is a separate action, allowed only after a failure and before any ACK.
ACK dominates failure. Every terminal state is immutable: a later ACK is
preserved as `LATE_ACK`, a later failure is evidence-only, and neither can
resurrect the pending state or change its counters or disposition. Duplicate
outcomes are idempotent by attempt, recipient and semantic kind even if a caller
changes untrusted payload bytes. Attempt and outcome lookup is additionally
scoped by the exact Commit digest, so attempt ordinals may restart safely for a
later local generation without binding to historical publication evidence.
The artifact codec rechecks the digest-to-byte binding, and the coordinator
refuses a new attempt before the bounded evidence store would lack room for at
least one outcome; that refusal leaves the prepared record cancellable.
Retry emits only the exact stored Commit bytes; no public method accepts
replacement artifact bytes or a success boolean.

## Arbitration

At an explicit cutoff the local digest is eligible only if its ACK was already
durable. The immutable batch contains that digest, when eligible, plus every
admitted inbound direct child. Both origins derive the same authority shape and
use the frozen B2.5a tuple:

```text
(priority, authenticated account identity, SHA-256(exact MLS Commit bytes))
```

Local admission restores the pending snapshot, re-projects and re-runs B2.4;
it never stages the member's own Commit inbound. A local winner confirms that
exact pending handle. An inbound winner is independently restored and merged
from the retained clean parent, while the losing pending annex and any Welcome
are tombstoned atomically.

An inbound-only batch may freeze while a same-parent local record is merely
`PREPARED` or `PUBLISHING`. If that batch advances the head, the excluded
local record becomes terminal `CLEARED_LOST / LOSING_OUTSIDE_BATCH`; a later
ACK is contradiction evidence only. The journal reserves one of the 16 bounded
candidate slots whenever a local opportunity is active, so later
acknowledgement cannot make the next cutoff unrepresentable.

An inbound echo of active or terminal local Commit bytes is classified as
`own_echo` before input creation. A post-cutoff input cannot affect the frozen
batch. Input from a superseded earlier parent is retained and then resolves as
`NOT_CANDIDATE`; no rewind or false convergence claim is made.

## Files

- `b2-5b-canonical.mjs`: runtime identity, limits, store names, error/state
  vocabulary, B2.5b domains, and frozen B2.5a tuple/batch imports.
- `b2-5b-record.mjs`: strict codecs for head, retained state, local pending,
  publication evidence, input, batch, candidate and transition records.
- `b2-5b-journal.mjs`: isolated eight-store journal, public bounded operations,
  and private adapter-bound atomic capabilities.
- `b2-5b-engine-adapter.mjs`: real-WASM preparation, publication admission,
  local/inbound evaluation, winner application and recovery.
- `b2-5b-coordinator.mjs`: explicit clock-free scheduling surface.
- `harness.html`, `journal.browser.spec.js`, `playwright.config.js`: real
  IndexedDB two-connection CAS probes on Chromium and Firefox.
- `../../test/crypto/mls-phase-b2-5b-local-publisher.test.js`: real-WASM hostile
  lifecycle, ordering, rollback, restart and limitation evidence.

## Run

```bash
cd styx-js
npm test -- --runInBand \
  test/crypto/mls-phase-b2-5b-local-publisher.test.js --testTimeout=20000
npx playwright test -c spikes/marmot-phase-b2-5b/playwright.config.js
```

See
`docs/architecture/spikes/2026-08-12-marmot-openmls-phase-b2-5b-local-publisher.md`
for the full trust boundary, durable schema, evidence and residual risks.
