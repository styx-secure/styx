# Phase B final verdict: exact-pin Styx/MDK interoperability profile

Date: 2026-08-17

Authority: Issue #196; Phase B planning epic #128

Baseline: `dbe60607b28eda11a6aa75e96f91ea04efb7b211`, tree
`d1193e7829c6280676f220e5af3752a4087b6ddc`

Disposition: **GO for the bounded exact-pin isolated interoperability profile;
no general Marmot-conformance or product-activation claim**

## Decision

Phase B has answered its approved engineering question. At the revisions and
profile below, Styx and the independent MDK implementation completed the
synthetic direct-MLS lifecycle that Phase B was designed to test: compatible
KeyPackage handling, durable Welcome join and restart, bidirectional
application traffic, sequential self-updates, retained-epoch delivery and a
bounded concurrent same-parent fork settlement.

This is a positive, reproducible interoperability result for one exact
configuration. It is not evidence that current Styx builds implement the
complete Marmot protocol, use Marmot's Nostr transport envelopes, or are ready
for users. The isolated proof remains outside the chat, PWA, vault and Styx
application protocol.

## Frozen profile

| Boundary | Exact value |
| --- | --- |
| Styx evidence baseline | `dbe60607b28eda11a6aa75e96f91ea04efb7b211` / tree `d1193e7829c6280676f220e5af3752a4087b6ddc` |
| OpenMLS | `09e92777dba0528d3d29e2e5e681b7e91637c7be` / tree `fde242458abe5594fbebf2556dca0a135367a817` |
| Marmot specification | `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` / tree `10d941f358de5d9fe4ee1db75581f3e5363f5e92` |
| MDK | `9396adb6aa6b95b521a7979facd5ea7040c07288` / tree `a1145de604e616634dae9a1ef6bf5033c9c9e879` |
| Ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`) |
| Member profiles | `STYX_B32A`, `MDK_PIN_9396ADB` |
| Retained application history | exactly five past epochs |
| Latest terminal result | `B33B2B=BOUNDED_GO` |

The installed five-file OpenMLS WASM tuple is recorded in the
[B3.3b-1 report](2026-08-16-marmot-openmls-phase-b3-3b-1.md). Any source,
revision, feature, profile, artifact or retention-policy drift invalidates this
verdict until the affected evidence is reproduced.

## Evidence chain

The intermediate NO-GO results were useful typed boundaries, not failures to
be hidden. Each later increment addressed one boundary without weakening the
earlier validation rules.

| Increment | Authority and evidence | Bounded result |
| --- | --- | --- |
| B1 | Issue #129, PR #130; [report](2026-08-08-marmot-openmls-phase-b1.md) | The pinned OpenMLS source can expose an isolated AES-128-GCM profile with framed non-last-resort KeyPackages, separate Nostr account and MLS signing identities, account-identity-proof v2, staged inbound Commits and explicit local pending-Commit control while retaining the legacy profile. |
| B2.0–B2.7 | Issues #145, #147, #149, #151, #153, #155, #157, #159, #161 and #163; PRs #146, #148, #150, #152, #154, #156, #158, #160, #162 and #164; [B2.7 report](2026-08-13-marmot-openmls-phase-b2-7-stage-2.md) | Isolated durable recovery, account binding, bounded authorization, publish-before-apply, branch selection, retained-history reconsideration, crash-safe message-ratchet persistence and authenticated sender attribution were exercised fail closed. These are local proof surfaces, not MDK interoperability by themselves. |
| B3 | Issue #165, PR #166; [report](2026-08-13-marmot-openmls-phase-b3.md) | The first direct peer attempt produced a typed NO-GO at missing application capability `0x8001`. |
| B3.1 | Issue #167, PR #168; [report](2026-08-14-marmot-openmls-phase-b3-1.md) | MDK accepted the corrected Styx KeyPackage and created a group whose profile state Styx decoded; the next typed boundary was external RatchetTree delivery. |
| B3.2 | Issue #173, PR #174; [report](2026-08-14-marmot-openmls-phase-b3-2.md) | MDK created an embedded-tree Welcome and Styx durably recorded it; strict founder-profile equality exposed the next typed incompatibility. |
| B3.2a | Issue #175, PR #176; [report](2026-08-14-marmot-openmls-phase-b3-2a.md) | The exact profiles were normalized without weakening proof validation. Styx validated, committed and restored the joined candidate after a fresh-process restart. |
| B3.3a | Issue #185, PR #186; [report](2026-08-15-marmot-openmls-phase-b3-3a.md) | Fresh independent runs completed bidirectional application traffic, replay rejection, durable checkpoints and fresh-process restoration. |
| B3.3b-1 | Issue #188, PR #189; [report](2026-08-16-marmot-openmls-phase-b3-3b-1.md) | Either member performed ordinary proposal-free self-updates; both engines recovered and converged on the authenticated GroupContext while retaining preceding-epoch traffic. |
| B3.3b-2a | Issue #190, PR #193; [report](2026-08-16-marmot-openmls-phase-b3-3b-2a.md) | Both engines accepted authenticated application messages at distances four and five, rejected distance six, and produced no duplicate output on replay. |
| B3.3b-2b | Issue #194, PR #195; [report](2026-08-16-marmot-openmls-phase-b3-3b-2b.md) | For exactly two authenticated, proposal-free, depth-one same-parent self-update candidates with no application witnesses, both engines selected the same winner, restored the same successor and completed one idempotent settlement effect. |

## What the GO means

The positive public claim is deliberately limited to this form:

> At exact OpenMLS, Marmot and MDK revisions recorded in the Phase B report,
> Styx interoperated with the pinned MDK peer in an isolated synthetic
> direct-MLS profile through durable Welcome join, bidirectional application
> traffic, sequential self-update, a five-past-epoch delivery boundary and
> bounded two-candidate same-parent convergence.

Shorter statements such as “Styx is Marmot-compatible”, “Marmot support is
complete”, or “the Styx app now uses Marmot” are not supported by this evidence.

## Non-claims

Phase B does not establish:

- general Marmot conformance or compatibility with other revisions or clients;
- Marmot/Nostr event envelopes, Welcome delivery, relay behavior, push,
  notifications, media or network convergence;
- integration with the Styx application protocol, reference chat, PWA, worker,
  browser vault or a native runtime;
- anonymity, unlinkability, metadata privacy or safety against a compromised
  origin, endpoint, operating system, extension or recipient;
- membership change beyond the tested ordinary self-updates, external Commits,
  PSKs, ReInit, account rotation, multi-device, rejoin or missing-parent
  acquisition;
- three or more candidates, deeper branches, witness-scored selection,
  arbitrary multi-pass convergence, pruning or compaction;
- power-loss-safe product storage, keyed journal authenticity or detection of a
  coherent whole-profile rollback;
- security audit, certification, legal compliance, production readiness,
  upstream endorsement or transfer of any upstream audit.

The current Styx-authored Rust/JavaScript wrapper, journal and harness remain
unaudited. They depend on the pinned experimental `extensions-draft` surface.
Retaining five past epochs and the losing branch extends private-material
lifetime; Phase B measured that configuration but did not select a shipping
retention policy.

## Remaining tracked work

[Issue #184](https://github.com/styx-secure/styx/issues/184) remains open for
non-blocking B3.2a documentation corrections and redundant negative isolation
tests. Its findings are not silently closed by this verdict.

Before any product path can use this proof, a separate approved increment must
define a versioned secure-session adapter and its support boundary. That work
must choose and test at least:

- how the application protocol binds to the session profile without importing
  chat semantics;
- a product-grade authenticated persistence and rollback model;
- retention, compaction and losing-branch disposal;
- crash-safe reliable delivery and truthful acknowledgement states;
- the Marmot/Nostr transport scope and residual metadata model;
- runtime-specific custody, origin and storage guarantees;
- migration and rollback for every persisted product format.

The integration increment must retain this exact proof as a conformance fixture
or reproduce it at any new pin. It must not activate the isolated artifact by
renaming it or treating the Phase B file journal as product storage.

## Final Phase B disposition

**Phase B is complete with a bounded GO.** The exact-pin isolated
Styx/MDK secure-session profile is feasible and interoperable for the operations
enumerated above. **Product adoption remains a separate NO-GO until an approved
integration contract supplies the missing application, transport, persistence,
runtime and assurance boundaries.**
