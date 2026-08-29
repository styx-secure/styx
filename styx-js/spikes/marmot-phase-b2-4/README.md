# Marmot/OpenMLS Phase B2.4 authorization proof

This directory is an isolated, non-product security proof. Nothing under
`styx-js/src`, the chat PWA, vault, worker, transport, Flegias or its survey
package imports
it. It is not a full Marmot implementation or a sensitive-use release.

## What it proves

The mandatory B2.4 adapter does not accept a Commit merely because OpenMLS can
stage it. For each tested local or inbound transition it reconstructs the
fresh durable parent, verifies every parent and candidate
`marmot.member.account-identity-proof.v2`, and applies one synchronous
default-deny policy. Only these shapes may pass:

- one inline Add by a current parent administrator;
- one inline Remove of a non-admin, non-committer member by a current parent
  administrator; or
- a proposal-free self update that retains the account and MLS signature key.

The result is bound to the group, parent epoch and GroupContext, exact Commit,
complete canonical candidate projection, candidate epoch and GroupContext,
verified-leaf digest, operation and committer tuple. It is evidence for that
one operation, not a bearer capability.

## Files

- `b2-4-canonical.mjs` freezes the v1 domains, reason vocabulary, limits and
  distinct `styx-b2-4-poc-v1-` database prefix.
- `b2-4-policy.mjs` projects the current parent, decodes the canonical
  administrator vector, verifies proof v2 and evaluates the bounded policy.
- `b2-4-journal.mjs` wraps the unchanged B2.3 records in the distinct v1
  namespace without exposing its inner B2.3 journal.
- `b2-4-engine-adapter.mjs` makes the policy mandatory before local CAS,
  inbound merge/CAS and recovered pending confirmation.

The B2.3 factory and adapter require both an actual `B23Journal` and the B2.3
database prefix. The B2.4 factory separately requires the frozen B2.4 prefix,
and its wrapper has a private construction token. A permissive B2.3 adapter
therefore cannot be pointed at the B2.4 store to reintroduce a caller-selected
boolean.

## Recovery rule

A durable `PREPARED` record contains no authorization boolean or token. After
reload, the adapter restores the exact pending state, reconstructs the parent,
reprojects the candidate and reruns the frozen v1 policy over the durable
Commit. Confirmation proceeds only if the exact v1 computation returns
`ALLOW`; otherwise the pending state remains durable and unchanged.

## Run the focused evidence

```bash
cd styx-js
npm test -- --runInBand \
  test/crypto/mls-phase-b2-3-journal.test.js \
  test/crypto/mls-phase-b2-4-policy.test.js \
  --testTimeout=20000
```

## Explicit non-claims

This proof does not establish full Marmot interoperability, same-epoch fork
convergence, rollback resistance, authenticated local storage, delivery,
metadata anonymity, malicious-origin resistance, Safari/native persistence,
application authorization, audit status, beta readiness or fitness for real
whistleblowing data. The pinned WASM artifact remains a trusted input.
