# Styx application-kernel v0 outcome taxonomy

Status: bounded normative O-10 decision for transcript-only C0.3 entry.

This document closes the local outcome vocabulary needed to build the C0.3
adversarial corpus. It does not select wire codes, HTTP statuses, UI wording,
transport acknowledgements, storage encodings or product recovery behavior.
Every primary is trusted-boundary information. Except for `APPLIED`, an
untrusted remote projection is only `OPAQUE_REMOTE_FAILURE`.

## Closed cardinalities

- 25 local primaries;
- one historical input alias, `FORK_QUARANTINED`, normalized to
  `LINEAGE_QUARANTINED` and forbidden as emitted primary;
- two post-C0.3 markers, `SESSION_PROFILE_REQUIRED` and
  `TRANSPORT_PROFILE_REQUIRED`, forbidden as local primaries;
- one untrusted remote collapse, `OPAQUE_REMOTE_FAILURE`.

Unknown identifiers, fields or uppercase protocol-like tokens fail closed.
Auxiliary evidence may accompany one primary but never authorizes a transition
and never creates a second primary.

## Primary registry

| Primary | Owner | Evaluation point | Mutation | Recovery class |
| --- | --- | --- | --- | --- |
| `APPLIED` | AP | after S6 | applied | none |
| `AUTHENTIC_BUT_UNAUTHORIZED` | AP | event-local | not applied | reject same bytes |
| `AUTHORITY_PROJECTION_UNAVAILABLE` | AP | S5 | not applied | preserve context and restore authority capability |
| `COMMITMENT_MISMATCH` | K | S3 | not applied | reject same bytes |
| `CONTEXT_CAPACITY_EXHAUSTED` | K | S4 or S6 | not applied | new context or ratified profile required |
| `CREDENTIAL_BINDING_MISMATCH` | K | S3 | not applied | reject same bytes |
| `CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED` | K | S3 | not applied | reject same bytes |
| `CURRENT_OBJECT_OUT_OF_PROFILE` | K | S3 | not applied | new context or ratified profile required |
| `DEPENDENCY_DEFERRED` | K | S4 or S6 | not applied | retry after authenticated dependency change |
| `DUPLICATE` | K | S3 | not applied, idempotent | no action |
| `FORK_EVIDENCE` | K | event-local | not applied | quarantine lineage and replay |
| `INVALID` | K | S3 | not applied | reject same bytes |
| `LENGTH_MISMATCH` | K | S3 | not applied | reject same bytes |
| `LINEAGE_QUARANTINED` | AP | event-local | not applied | quarantine lineage and replay |
| `OPENING_MISSING` | K | S3 | not applied | supply verified opening and replay |
| `PENDING_ANCESTOR` | K | event-local | not applied | retry after authenticated dependency change |
| `PENDING_OPENING` | K | event-local | not applied | supply verified opening and replay |
| `POST_REVOCATION` | AP | event-local | not applied | reject same bytes |
| `PROFILE_ACTIVATION_UNSUPPORTED` | K | S0 | not applied | new context or ratified profile required |
| `REFERENCE_COLLISION_UNSUPPORTED` | K | S3 | not applied | reject same bytes |
| `REMOVAL_INAPPLICABLE` | K | event-local | not applied | reject same bytes |
| `STALE_EVIDENCE` | K | post-S3 replay evidence | not applied | refresh live evidence and replay |
| `STRUCTURAL_REJECTION` | K | S3 | not applied | reject same bytes |
| `UNRESOLVABLE_CREDENTIAL` | K | S3 | not applied | reject same bytes |
| `UNRESOLVED_CREDENTIAL_BINDING` | K | S3 | not applied | reject same bytes |

The machine-readable registry under
`tools/causal-flow-simulator/o10/outcome-taxonomy.json` fixes the complete
owner, stage, mutation, recovery, retry-precondition and local-observability
tuple. Prose is explanatory; the closed canonical artifact and its validator
are the falsification target.

## Selection order

Evaluation is stage-ordered and independent of arrival/presentation order:

1. unsupported profile activation;
2. K structural failures in the closed K precedence list;
3. duplicate;
4. stale live evidence;
5. S4 resource/dependency admission;
6. authority-projection availability;
7. event-local fork/pending/removal/revocation/quarantine/authorization;
8. S6 deterministic durable-capacity/dependency admission;
9. applied.

Within K, the order is `STRUCTURAL_REJECTION`, `LENGTH_MISMATCH`,
`CURRENT_OBJECT_OUT_OF_PROFILE`, `COMMITMENT_MISMATCH`, `OPENING_MISSING`,
`UNRESOLVABLE_CREDENTIAL`, `UNRESOLVED_CREDENTIAL_BINDING`,
`CREDENTIAL_BINDING_MISMATCH`, `REFERENCE_COLLISION_UNSUPPORTED`,
`CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED`, `INVALID`. Within the
event-local stage it is `FORK_EVIDENCE`, `PENDING_OPENING`,
`PENDING_ANCESTOR`, `REMOVAL_INAPPLICABLE`, `POST_REVOCATION`,
`LINEAGE_QUARANTINED`, `AUTHENTIC_BUT_UNAUTHORIZED`.

## Recovery invariants

A recovery class is a safe caller constraint, never a promise of eventual
success. Identical candidate bytes plus unchanged authenticated state cannot be
blindly retried when a non-null recovery class applies. Timeout, retry count,
relay choice and presentation order are not authenticated state changes.
Recovery cannot discard an existing context, transcript, opening or authority
projection. Authority-projection failure preserves authority as unavailable;
it never turns authority into an empty set.

## Remote privacy boundary

Every non-`APPLIED` result, including `DUPLICATE`, collapses to the same
canonical `OPAQUE_REMOTE_FAILURE` for an unauthenticated or otherwise
untrusted peer. Auxiliary membership and diagnostic perturbations do not alter
those bytes. This does not eliminate the bounded existence signal between
`APPLIED` and a replayed authentic candidate. A future ratified secure-session
or transport acknowledgement profile owns that residual oracle.

## Residual non-claims

O-10 does not define a production API, stable numeric code, wire response,
timing, padding, persistence behavior, delivery acknowledgement, recovery
workflow or UI. It does not make parser internals remotely observable. It does
not close O-11, O-12, O-13, O-15 or O-16, and does not by itself authorize the
C0.3 corpus.

Because S4 admission precedes event-local classification, adversarial resource
pressure can select an S4 primary while a lower event-local cause remains only
auxiliary evidence. This never authorizes mutation or erases the lower cause,
but O-10 does not promise that the primary diagnostic alone identifies the
event-local condition. Reordering those stages would be a new availability and
diagnostic-policy decision requiring human ratification and renewed
falsification.
