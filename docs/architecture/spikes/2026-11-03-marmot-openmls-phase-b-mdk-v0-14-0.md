# Phase B interoperability with MDK v0.14.0

Date: 2026-11-03

Authority: owner scope extension and contract on Issue #400 (M3 early lane);
the contract Issue of this change

Disposition: **the bounded Phase B live proofs pass against MDK v0.14.0; the
CI MDK pin moves from `9396adb6` to v0.14.0**

This report is additive. The [Phase B verdict](2026-08-17-marmot-openmls-phase-b-verdict.md)
and the increment reports keep their exact historical revisions, artifacts and
results; nothing in them is relabelled.

## Revisions

| Boundary | Exact value |
| --- | --- |
| MDK (new CI pin) | v0.14.0, `3fb4b4759ac676b0c21c4c3527074866c9fa4c89` / tree `4019e3f9844331b4e365a85653418586c385a0d2`, `Cargo.lock` SHA-256 `8286bc2731edeec804cd1fae2e40eefad3bb87a068d3aff15d94a4e5e14bc9cc` |
| MDK (previous pin, regression only) | `9396adb6aa6b95b521a7979facd5ea7040c07288` / tree `a1145de604e616634dae9a1ef6bf5033c9c9e879` |
| OpenMLS | `09e92777dba0528d3d29e2e5e681b7e91637c7be` (unchanged) |
| Ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`, unchanged) |
| OpenMLS WASM | `openmls_wasm_bg.wasm` `bbc995739a49bc104c6a63e86723a6898a477e47e27e33d9e48fae39f942d3f4`; other four generated files unchanged |
| Member profiles | `STYX_B32A`, `MDK_PIN_9396ADB`, `MDK_RFC9420` |

## Join boundary and correction

With MDK v0.14.0 every live proof stopped at the durable Welcome join with
`PHASE_B32A_WELCOME_AUTHOR_PROFILE_INVALID`. The Welcome author leaf was
validated by exact equality with the `9396adb6` capabilities, which list the
default extension type RequiredCapabilities (`0x0003`). RFC 9420 section 7.2
states that the default proposal types `0x0001`-`0x0007` and extension types
`0x0001`-`0x0005` MUST NOT be listed, and MDK v0.14.0 no longer lists them.

`patch/lib.rs` now classifies an MDK leaf as follows:

- `MDK_PIN_9396ADB`: the exact previous capability value, unchanged;
- `MDK_RFC9420`: no default type listed; GREASE values (RFC 9420 section 13.5)
  ignored; version MLS 1.0, the single probe ciphersuite, the Basic credential,
  the non-default extension AppDataDictionary and the non-default proposal
  AppDataUpdate exact; any other value refused.

The dictionary ids, supported components, empty safe-AAD list and
account-identity proof checks are unchanged for both MDK profiles. An RFC 9420
MDK leaf has exactly the capabilities of the Styx leaf, so the safe-AAD
dictionary entry `0x0002` now separates the MDK profile from the Styx profile;
a leaf with the Styx capabilities and that entry must pass every MDK check. A
refused Welcome author reports its sub-cause, for example
`PHASE_B32A_WELCOME_AUTHOR_PROFILE_INVALID: PHASE_B32A_MDK_CAPABILITIES_EXTENSIONS_INVALID`.
The JavaScript projection check accepts `MDK_RFC9420` with the flags
`listsDefaultRequiredCapabilities = false` and `emitsEmptySafeAad = true`.

The rebuilt artifact changes leaf-profile validation only. The previous
`fef05368…` artifact remains an exact MLS state-writer compatibility tuple.

## Behaviour after the join

Three MDK interface changes between `9396adb6` and v0.14.0 appeared after the
join. Each is handled in the external MDK peer driver or the probes; none
changes a Styx validation rule.

1. Application-visible outputs are durable until acknowledged. MDK keeps
   `MessageReceived` and `GroupJoined` in a pending-output store until the
   application calls `MessageStorage::delete_pending_application_events`, and
   re-emits unacknowledged outputs when it hydrates a group. The driver returns
   every drained event to the probe in the same response, so it acknowledges
   those outputs at the drain. Restoration still fails closed on any pending
   event.
2. Same-epoch rivals always go through stored distributed convergence. MDK
   removed the committer's pairwise fork fast path and the `ForkRecovered`
   event (marmot-protocol/mdk#1293). A rival delivered before or after a
   restart is now buffered at its own (source) epoch and settled by the
   convergence pass that the probe already used after a restart, with the
   unchanged selection trace, decisive `tip_committer` rule, deferred loser and
   `CommitRolledBack` plus `GroupStateInvalidated` events.
3. A convergence pass no longer reports application messages that were
   already delivered (on the direct path or by an earlier pass) as already-seen
   witnesses. The accepted messages are unchanged and the only event of the
   pass is still the epoch transition, so no message is delivered twice.

## Results

All runs used fresh locked builds of the MDK peer and fresh probe directories.

| Live proof | MDK v0.14.0 | MDK `9396adb6`, previous harness |
| --- | --- | --- |
| B3.3b-1 stage 0 | PASS | PASS |
| B3.3b-1 stage 1 | PASS | PASS |
| B3.3b-2a retained window | PASS | PASS |
| B3.3b-2b stage 0 fork | PASS | PASS |
| B3.3b-2b durable fork, two paired runs | PASS, `B33B2B=BOUNDED_GO` | PASS, `B33B2B=BOUNDED_GO` |

The second column uses the new WASM artifact with the `9396adb6` peer and the
probes as they were before this change: the RFC 9420 classification does not
alter the previous profile.

## Limits

This is the same bounded, isolated, synthetic direct-MLS profile as the Phase B
verdict, now at MDK v0.14.0. It is not a general conformance or product claim.
Unknown non-GREASE capability values remain refused, which is stricter than the
RFC 9420 section 13 rule to ignore unknown values; a future MDK leaf that
advertises an additional capability will need a new reviewed profile.
