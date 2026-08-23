# Styx application protocol v0: credential succession and two-sided authority

- **Status:** selected C0.2j design; bounded executable evidence, independent
  review and human ratification remain required before merge.
- **Issue:** [#233](https://github.com/styx-secure/styx/issues/233)
- **Exact base:** `f9b7d5f30a3535a709f1466dafac691871e1568e`
- **Scope:** language-neutral K credential binding, AP operational authority,
  succession and fork containment. This is not production code or a claim that
  a deployed runtime enforces the rules.

## 1. Decision summary

C0.2j selects a **grant-rooted credential identifier** for every non-genesis
credential. The identifier is the existing O-06b-1 event reference of the one
K-valid `GRANT` that carries the grantee signature-suite identifier and
verification-key octets. The `GRANT` carries no subject identifier: its own
reference is computed only after the complete transcript is encoded and hashed.
The actor credential in common field 11 is the issuer and the O-03 tuple binds
the context. Consequently context, issuer, grantee suite and grantee key all
affect the credential identifier without a circular preimage.

Only that `GRANT` creates a K binding. Every other event uses its field-11
credential identifier only as a lookup key and is accepted for K graph admission
only after the bound suite/key verifies its signature. An absent or forward-only
binding rejects; it never creates attacker-controlled pending state.

Operational authority remains an AP fact. C0.2j replaces one chosen replay order
with a deterministic two-sided fold over every bounded causal linearization of
the same complete K-admitted credential-control evidence:

- authority expansion, producer eligibility and operational authority require
  `MustAuth` (authorized in every admissible interpretation);
- authority reduction uses `MayAuth` (authorized in at least one admissible
  interpretation); and
- an actor unauthorized in every interpretation cannot reduce authority merely
  because it still holds a valid signing key.

Revocation and fork quarantine terminate the target credential and every
grant-descendant in its provenance lineage. The scope is that lineage, not the
whole context; independent definitely authorized lineages can continue. No rule
chooses a winner by event-reference order, arrival, relay, storage or timeout.

## 2. Candidate comparison

| Family | Authenticated inputs and ownership | Collision behavior | Concurrency and fork behavior | Rotation/recovery/late evidence | Anonymous profile, DoS and bounds | Transcript consequence, rejected inference and residual claim | Decision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Current random identifier plus whole-context quarantine | Identifier is carried in K transcript; key binding is symbolic K evidence; AP owns authority | A second K-valid binding freezes the identifier and creates a cheap retroactive DoS | One canonical order can preserve a concurrent successor; any fork empties the entire AP context | `ROTATE`/`RECOVER` are no-ops; late evidence requires replay | Context-local but collision and one fork stop all peers | No new bytes; falsely treating local uniqueness as global safety is rejected | Rejected |
| Derivation-bound identifier plus transitive revocation | Hash context, issuer, suite and key into a new identifier format; K owns derivation | Collision-resistant if framing/domain are correct; adds a second identifier primitive | Provenance closes laundering, but one chosen order still decides concurrent authority | Fresh derived identifiers permit succession | Compatible, but duplicates event-reference machinery and adds migration surface | Requires a new domain/format; derivation alone does not make an issuer authorized | Rejected |
| Grant-rooted identifier | Existing K `GRANT` transcript/reference binds context, issuer, suite and key | Byte-identical grant is idempotent; distinct evidence has a distinct reference except under stated SHA-256 assumptions | Provides exact provenance but needs a separate authority fold and fork rule | Fresh `GRANT` is the only binding source; rotate/recover reference it | Case-ephemeral and transport-neutral; direct lookup is bounded | Adds one K control role/tail, no hash domain; event-reference equality is not AP authority | Selected component |
| Derivation-bound identifier plus `MayAuth`/`MustAuth` | K binding plus AP fold over all causal linearizations | Strong if derivation is strong | Removes order winner; without provenance, accepted descendants can survive ancestor compromise | Can govern succession but still needs exact binding source | Permutation work must be bounded and fail closed | Larger new identifier surface without benefit over grant-rooting | Rejected in favor of combined selection |
| Scoped credential/lineage quarantine | K fork evidence and provenance; AP excludes terminated lineages | Does not repair identity by itself | Forking signer and descendants are terminal; independent authority continues | Late fork/revocation recomputes the full projection; fresh independent grant restores continuity | Better availability than whole-context quarantine; lineage/event/order bounds required | Cannot erase fork evidence or expand authority; availability is not guaranteed | Selected component |
| Grant-rooted + two-sided fold + scoped provenance | K owns exact binding, evidence set and lineage; AP owns authority functions | Direct collision-resistant reference, fail-closed collision handling | All admissible orders; Must expansion, May reduction; lineage quarantine | Rotation = fresh grant plus retirement; recovery = independent fresh grant plus recovery evidence; no resurrection | Context-local, endpoint-specific, case-ephemeral; one common bounded envelope | One role/tail amendment only; no session/transport/UI authority; single-authority takeover remains possible | **Selected** |

## 3. Exact K binding contract

### 3.1 Non-genesis credential identity

For a valid non-genesis binding grant `g`:

```text
credential_id(g) = event_reference(g)
```

The complete O-06b-1 transcript of `g` authenticates:

1. the complete O-03 context tuple;
2. the issuing credential identifier in common field 11;
3. role class `0x02` and control kind `GRANT`;
4. the grantee signature-suite identifier; and
5. the grantee verification-key octets.

The tail contains neither `credential_id(g)` nor a declared subject identifier.
The existing `D_EVENT_REF` domain and reference suite are unchanged. A future
O-07 genesis credential identifier must use a domain distinct from
`D_EVENT_REF` or a structurally disjoint encoding; equality between a genesis
identifier and a grant event reference is rejected.

### 3.2 Binding resolution

K builds the monotone map:

```text
credential_id -> (context, issuer_credential_id,
                  grantee_suite_id, grantee_verification_key,
                  grant_event_reference)
```

only from structurally valid, causally available, signature-valid `GRANT`
events. AP authorization is deliberately not an input to this map. A K-valid
grant by an unauthorized issuer remains historical binding evidence, while its
credential receives no operational authority.

Every non-`GRANT` event must resolve field 11 to exactly one admitted binding,
derive the suite/key from that binding and verify the event. Supplied AP bytes,
MLS membership, Nostr identity, storage location, UI assignment and key
possession never create or replace a binding. A missing/forward binding,
suite/key mismatch, malformed control tail or observed distinct-preimage
reference collision fails closed before AP evaluation.

Two identifiers may visibly bind the same `(suite, key)` pair. This is alias
evidence, not a K rejection and not shared AP authority: revoking one lineage
does not silently revoke the independently granted alias. Profiles that require
stronger alias coupling must define it explicitly and accept the linkability and
availability consequences.

## 4. Closed credential-control vocabulary

O-06b-1 role class `0x02` carries exactly these K-readable control kinds:

| Code | Kind | K binding/provenance effect | AP authority class |
| ---: | --- | --- | --- |
| `0x01` | `GRANT` | Creates the only non-genesis binding and one issuer edge | Expansion; requires `MustAuth` |
| `0x02` | `REVOKE` | Names one credential to terminate with descendants | Reduction; accepted under `MayAuth` |
| `0x03` | `ROTATE` | Names retiring credential and an already admitted fresh `GRANT`; creates no binding | Reduction for retirement; replacement grant is evaluated separately under `MustAuth` |
| `0x04` | `RECOVER` | Names retired credential and an already admitted fresh `GRANT`; creates no binding or resurrection | Expansion-sensitive; requires `MustAuth` |
| `0x05` | `POLICY` | No generic K authority-set mutation; retains authenticated control evidence | Expansion-sensitive; requires `MustAuth`; profile effect remains AP-owned |
| `0x06` | `CLOSURE` | No generic K authority-set mutation; retains authenticated control evidence | Expansion-sensitive; requires `MustAuth`; profile effect remains AP-owned |

`REMOVE` stays role class `0x01` and is not credential control. A removal
directive targeting credential-control evidence is structurally inapplicable
and changes no binding, provenance or authority.

All `0x02` events require `content_class == NONE`. This check precedes tail
parsing, binding lookup and AP evaluation. K never derives the control kind,
suite, key or target from the AP transition block or AP registries.

## 5. Total two-sided authority function

For a complete validated set `S`, let `E(S)` be every K-admitted
`CREDENTIAL_CONTROL` event in the live graph, including events whose AP outcome
is pending, post-revocation, authentic-but-unauthorized, inapplicable or not
currently applied. Content availability, removal and checkpoint-only evidence
do not filter `E(S)`.

Let `L(E)` be every topological linearization consistent with K causal edges.
For each `l` in `L(E)`, start with O-07's initial authority set, then scan `l`:

1. an actor is authorized at its acting prefix only if it is currently in the
   interpretation's authority set and neither it nor an ancestor is terminated;
2. an authorized `GRANT` adds its grant-rooted identifier;
3. an authorized `REVOKE` or `ROTATE` removes its target and all provenance
   descendants; and
4. `RECOVER`, `POLICY` and `CLOSURE` do not create a K binding or generic
   authority-set member.

For event `e`:

```text
MayAuth(e)  = exists l in L(E): actor(e) is authorized at e's prefix in l
MustAuth(e) = forall l in L(E): actor(e) is authorized at e's prefix in l
```

The accepted-control set contains `REVOKE`/`ROTATE` events satisfying
`MayAuth`; every other credential-control event must satisfy `MustAuth`.
Terminal operational authority is recomputed deterministically from O-07
initial authority plus accepted grants, minus the transitive provenance closure
of accepted reduction targets and forked credentials. No chosen linearization
is the final result.

The implementation may use an equivalent symbolic algorithm only if it emits
the same complete result. C0.2j selects fresh full replay; it makes no
incremental-cache claim.

## 6. Provenance, succession and fork scope

Every accepted `GRANT` creates one immutable edge from issuer to the
grant-rooted credential. Revoking or forking a credential terminates it and the
transitive closure of those edges. Historical K records remain admitted and
verifiable; termination changes AP operational effect, not authentication.

Rotation uses a fresh `GRANT` plus a `ROTATE` that references that admitted
grant and the retiring identifier. Recovery uses an independently authorized
fresh `GRANT` plus a `RECOVER` reference. Neither control creates a binding;
neither may re-grant or resurrect an old identifier. If only the reduction is
accepted, availability can be lost safely. If only the fresh grant is accepted,
the new independently authorized credential can coexist with the old one.

A same-author fork is two distinct K-valid events at the same
`(credential_id, author_sequence, direct_predecessor)` slot. It permanently
quarantines that credential lineage in v0, independent of actor role, control
kind, arrival or current revocation state. Independent lineages continue only
when their actions satisfy the same `MustAuth`/`MayAuth` rules. Late evidence
always triggers fresh full replay.

## 7. Bounds and failure behavior

The v3 experiment uses one common envelope for every candidate and witness:

| Dimension | Bound |
| --- | ---: |
| events | 12 |
| credential-control events | 6 |
| causal parents per event | 4 |
| credential lineage depth | 4 |
| admissible topological orders | 720 |
| exhaustive delivery-permutation width | 6 |
| credentials | 10 |
| verification-key octets | 64 |

These are experiment bounds, not O-08 production limits. Exceeding any bound
fails closed before authority expansion, producer eligibility or operational
authority. Unevaluated evidence is never treated as absent.

## 8. Security and availability consequences

The selected design removes identifier collision as a practical cheap freeze,
prevents concurrent successor laundering in the bounded model and replaces a
single canonical-order winner with a set-relative deterministic result. It also
allows independent authority to continue around an unrelated fork.

It deliberately does not promise quorum governance. One uncontested compromised
authority can still revoke every peer in causal sequence and remain the sole
operational producer. Mutual concurrent revocation can leave no operational
authority. A fork or revocation can permanently terminate a lineage, and an
independently granted same-key alias survives. These are explicit governance and
availability limits, not repaired with timestamps, majority, relay observation
or hidden recovery.

Grant-rooted identifiers expose the corresponding grant to authorized
observers and are not unlinkability evidence. The rules do not establish
anonymity, rollback resistance, checkpoint freshness, finality, irreversible
effects, runtime capacity, implementation security or sensitive-use readiness.

## 9. Reopen and downstream gates

Reopen C0.2j if executable evidence finds an ordering or delivery divergence,
a non-`GRANT` can create/rebind a credential, provenance traversal can expand
authority, scoped quarantine resurrects a terminated lineage, a supported
signature suite cannot fit the exact tail/key bound, or an admitted profile
requires authority semantics outside this closed vocabulary.

The O-06b-1 amendment reopens if O-14 requires a different canonical
verification-key encoding or an event-selected signature algorithm. O-14 still
owns the suite registry and exact key/signature encodings.

C0.2k must next bind the selected credential identifier and author sequence into
the O-06b-2 commitment context. O-06c must then falsify the complete exact-byte
construction. C0.3 remains `NO-GO`; O-07, O-08, O-10 and O-14 remain open.
