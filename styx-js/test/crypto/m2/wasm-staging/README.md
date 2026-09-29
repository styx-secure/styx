# F-WASM exact-artifact pre-apply staging probe

This directory is the complete F-WASM repository change. It does not implement a product
adapter or storage transaction. It probes whether the frozen OpenMLS/WASM artifact exposes
enough call-level boundaries for a later adapter to keep durable authority outside WASM
until storage reports a closed commit result.

## Result rule

The probe reports `POSITIVE` only when all seven operation classes execute against the
frozen artifact and satisfy the checks below:

1. session creation;
2. Welcome onboarding, including candidate-local one-shot KeyPackage consumption;
3. application protect;
4. application open;
5. outbound proposal-free self-update;
6. inbound proposal-free self-update;
7. two distinct-committer self-update candidates from one immutable parent, with the
   lower account identity selected and the losing candidate retained as bounded evidence.

Any missing or failed class makes the Jest run fail, so it cannot emit a positive overall
result. The final `F_WASM_REPORT=<json>` line contains one record per class and the exact
call boundary exercised.

## Authority model exercised

The actual OpenMLS candidate bytes come from `Provider.serialize_state()` after an
operation runs in a scratch `Provider` restored from the durable predecessor. A small
probe-only `AuthoritySlot` then verifies the integration boundary expected by M2:

- staging never replaces the authoritative predecessor;
- `COMMITTED` selects the complete candidate;
- `NOT_COMMITTED` discards it;
- `INDETERMINATE` keeps the predecessor authoritative and retains the operation identity
  plus candidate SHA-256 for later reconciliation;
- reconciliation accepts only an externally supplied durable readback receipt whose outcome
  is `COMMITTED` and whose operation identity and candidate digest match the retained
  candidate; it then selects the already-computed candidate without repeating the MLS
  transition. The receipt is injected by this call-level probe: no storage implementation is
  claimed here.

Ciphertext and plaintext are inspected inside the probe to verify the candidate operation,
but the probe makes no claim that either is externally released before `COMMITTED`.

The probe also reloads and uses predecessor bytes before selection. Its negative controls
reject every changed file in the frozen five-file artifact tuple before WASM initialization,
detect premature authority changes, reject a non-`COMMITTED` receipt, and reject
reconciliation under a mismatched persisted operation identity or candidate digest.

This is feasibility evidence only. It does not claim that the later IndexedDB transaction,
worker lifecycle, or crash-recovery implementation is complete.

## Reproduce

From `styx-js` after `npm ci`:

```text
npm test -- --runInBand test/crypto/m2/wasm-staging/staging.test.js
```

The test fails before artifact execution unless the contract base is an ancestor of HEAD,
the complete commit diff is confined to this directory, and the frozen OpenMLS revision,
SS-0 ciphersuite, vendor tree, and WASM SHA-256 match the ratified tuple.
