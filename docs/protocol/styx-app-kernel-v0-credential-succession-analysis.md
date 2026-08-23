# Styx application protocol v0: credential succession and two-sided authority

- **Status:** selected C0.2j design; bounded executable evidence, independent
  review and human ratification remain required before merge.
- **Issue:** [#233](https://github.com/styx-secure/styx/issues/233)
- **Exact base:** `8f30f1940e4417fcb47b156b08c2242f405dc09b`
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
with a deterministic two-sided Pass-0 fold over every bounded causal
linearization of the same complete K-admitted credential-control evidence:

- authority expansion, producer eligibility and operational authority require
  `Must0` in Pass0 (authorized in every admissible interpretation before the
  bounded contested-reduction selection);
- definitely authorized reduction uses `Must0`; a `May0`-only reduction may use
  only the first eligible author-sequence slot of its actor, with every eligible
  sibling in that slot applied as an unordered set;
- an actor unauthorized in every interpretation cannot reduce authority merely
  because it still holds a valid signing key.

The bounded exception is deliberately non-recursive. It excludes `May0`-only
self-lineage reductions, never selects by event reference, and gives each
credential at most one contested slot. Any K-admitted reduction, including a
later-slot or self-lineage reduction that is ultimately rejected, can lower
Pass-0 `Must0` for its target subtree. That can make another actor's reductions
contested, move that actor's selected slot and reduce accepted-reduction
membership. The influencing reduction itself remains outside accepted
termination. This conservative cross-actor availability and accounting effect is
required by the all-interpretations rule and is reported rather than hidden.

A `REVOKE`, and the retiring side of `ROTATE`, may name a non-genesis target only
when its binding `GRANT` is in the reduction's authenticated causal ancestry.
`RECOVER` has its separate fresh-grant transcript rule and is not subjected to
that target test. Its retired identifier is an opaque continuity annotation that
K does not resolve or use for an authority effect. Self-rotation is structurally
rejected in v0.

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
| Grant-rooted + two-sided Pass-0 fold + first-contested-slot reduction + scoped provenance | K owns exact binding, evidence set, author chain and lineage; AP owns authority functions | Direct collision-resistant reference, fail-closed collision handling | All admissible orders; Must0 expansion; Must0 reduction plus one eligible May0-only actor slot; any fork quarantines its lineage | Rotation = fresh grant plus independent retirement; recovery = independent fresh grant plus recovery evidence; no resurrection or self-rotation | Context-local, endpoint-specific, case-ephemeral; one joint bounded envelope and typed DP limits | One role/tail amendment only; no session/transport/UI authority; single-authority takeover and bounded residual destructive standing remain possible | **Selected** |

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
| `0x01` | `GRANT` | Creates the only non-genesis binding and one issuer edge | Expansion; requires Pass0 `Must0` |
| `0x02` | `REVOKE` | Names one credential to terminate with descendants | Reduction; accepted with Pass0 `Must0` or by the bounded first-contested-slot rule |
| `0x03` | `ROTATE` | Names retiring credential and an already admitted fresh `GRANT`; creates no binding | Retirement is accepted with Pass0 `Must0` or by the bounded first-contested-slot rule; replacement grant is evaluated separately under Pass0 `Must0` |
| `0x04` | `RECOVER` | Names retired credential and an already admitted fresh `GRANT`; creates no binding or resurrection | Expansion-sensitive; requires Pass0 `Must0` and retains the bootstrap target exemption |
| `0x05` | `POLICY` | No generic K authority-set mutation; retains authenticated control evidence | Expansion-sensitive; requires Pass0 `Must0`; profile effect remains AP-owned |
| `0x06` | `CLOSURE` | No generic K authority-set mutation; retains authenticated control evidence | Expansion-sensitive; requires Pass0 `Must0`; profile effect remains AP-owned |

`REMOVE` stays role class `0x01` and is not credential control. A removal
directive targeting credential-control evidence is structurally inapplicable
and changes no binding, provenance or authority.

Acceptance of the retiring side of `ROTATE` does not imply that its referenced
replacement is operational. In particular, a replacement `GRANT` authored by
the lineage being retired can be K-valid and APPLIED, but the accepted retirement
terminates both issuer and grant descendant in complete-disclosure operational
authority. Profiles must provide an independently authorized recovery path
rather than infer atomic authority transfer from an accepted `ROTATE`.

All `0x02` events require `content_class == NONE`. This check precedes tail
parsing, binding lookup and AP evaluation. K never derives the control kind,
suite, key or target from the AP transition block or AP registries.

## 5. Total two-sided authority function

For a complete validated set `S`, let `E(S)` be every K-admitted
`CREDENTIAL_CONTROL` event in the live graph, including events whose AP outcome
is pending, post-revocation, authentic-but-unauthorized, inapplicable or not
currently applied. Content availability, removal and checkpoint-only evidence
do not filter `E(S)`. One virtual fork join is added for each complete
same-credential, same-sequence sibling set. The join is ordered after all its
siblings and before every event whose authenticated causal past acknowledges
that complete sibling set.

### 5.1 Pass-0 interpretation

Let `L(E)` be every topological linearization of the controls and virtual joins
consistent with K causality. For each `l` in `L(E)`, start with O-07's initial
authority set, then scan `l`:

1. an actor is authorized at its acting prefix only if it is currently in the
   interpretation's authority set and neither it nor an ancestor is terminated;
2. an authorized `GRANT` adds its grant-rooted identifier;
3. an authorized `REVOKE` or `ROTATE` removes its target and all provenance
   descendants;
4. a fork join removes its actor credential and all provenance descendants; and
5. `RECOVER`, `POLICY` and `CLOSURE` create neither a K binding nor a generic
   authority-set member.

For every control event `e`:

```text
May0(e)  = exists l in L(E): actor(e) is authorized at e's prefix in l
Must0(e) = forall l in L(E): actor(e) is authorized at e's prefix in l
```

The accepted expansion-sensitive set is exactly the `GRANT`, `RECOVER`,
`POLICY` and `CLOSURE` controls satisfying `Must0`. Every structurally valid
`REVOKE` or `ROTATE` satisfying `Must0` is also accepted and consumes no
contested slot.

### 5.2 Bounded contested-reduction selection

For each structurally valid `REVOKE` or `ROTATE` satisfying `May0 && !Must0`:

1. exclude it from the contested pool if its actor belongs to
   `desc(target)`, the transitive provenance closure containing the target;
2. otherwise group it by its actor credential; and
3. for each actor accept every eligible reduction in the lowest
   `author_sequence` containing at least one eligible reduction.

The slot is exactly `(actor_credential_id, author_sequence)`. A valid author
chain totally orders distinct sequences. Every eligible sibling in the selected
slot is accepted as an unordered set-union of reduction effects; no reference,
hash, arrival, relay or storage order selects a winner. Later slots and `NoAuth`
reductions are authentic but unauthorized. A self-lineage exclusion consumes no
slot. The selector is evaluated once over the finite Pass-0 result and never
iterates to a fixed point.

The final accepted-control set is therefore exactly:

```text
Must0 expansion-sensitive controls
union Must0 structurally valid reductions
union the eligible May0-only reductions in each actor's first contested slot
```

Terminal authority is recomputed from O-07 initial authority plus accepted
grants, minus the provenance closure of accepted reduction targets and every
forked credential. A rejected reduction is never an accepted revocation and
never creates inherited standing. Nevertheless, it can permanently lower
Pass-0 `Must0` for its target and the target's grant descendants because Pass-0
deliberately considers every admissible interpretation of all K-admitted control
evidence. The first-slot rule bounds the accepted-reduction set, not this
separate operational availability effect. R-1 rejects a direct reduction of a
fresh non-genesis target whose grant was not observed, but one reduction of a
visible issuer can still lower `Must0` for that issuer and every future grant in
its provenance subtree. The experiment bounds this reach only through the common
O-08 handoff envelope; it makes no production availability claim.

### 5.3 State-space computation and ordinary-event probes

The normative result is the set semantics above. The executable production
model computes it by dynamic programming over reachable states keyed by:

```text
(processed_authority_items, current_authority, revoked_roots, forked_roots)
```

`processed_authority_items` determines the ready frontier; the other three
components are exactly the state read by the next Pass-0 transition. Path
multiplicity is accumulated only as a diagnostic. The factorial enumerator is a
test oracle and must agree with the reachable-state computation throughout its
bounded domain.

An ordinary event is not inserted into `E`. Its Pass0 `May0`/`Must0` query ranges
over already reachable control states whose processed down-set contains every
control/join causally before the event and none causally after it. It consumes no
control-event, fork-slot or topological-order budget.

The set-valued Pass-0 terminal diagnostics remain:

```text
PossibleTerminalAuthority(S)  = union of Pass-0 terminal authority sets
NecessaryTerminalAuthority(S) = intersection of Pass-0 terminal authority sets
```

Operational authority and producer eligibility use the relevant per-event
acting-prefix `Must0`; after complete disclosure they use
`NecessaryTerminalAuthority(S)`. The terminal authority recomputed from accepted
controls records accepted terminations only. It is diagnostic and cannot
authorize an actor absent from `Must0`. `PossibleTerminalAuthority(S)` likewise
never substitutes for an acting-prefix predicate.

If live replay dependencies are unavailable, the whole projection is
`STALE_EVIDENCE`. If the reachable-state or transition ceiling would be crossed,
the whole projection is respectively unavailable with
`REACHABLE_STATE_LIMIT` or `REACHABLE_TRANSITION_LIMIT`, and each admitted event
receives primary outcome `AUTHORITY_PROJECTION_UNAVAILABLE`. No accepted set,
per-event authority, terminal authority or producer eligibility is exposed.
Unavailable is never encoded as a proven empty authority set and never throws a
partially usable authority result.

C0.2j selects fresh full replay and makes no incremental-cache claim.

## 6. Provenance, succession and fork scope

Every K-admitted `GRANT` creates one immutable edge from issuer to the
grant-rooted credential, whether or not AP later accepts that grant as an
authority expansion. Revoking or forking a credential terminates it and the
transitive closure of those edges. Historical K records remain admitted and
verifiable; termination changes AP operational effect, not authentication.

A `REVOKE`, and the retiring side of `ROTATE`, may target a genesis credential
without additional target evidence. A non-genesis target is structurally valid
only when its binding `GRANT` belongs to the reduction's authenticated causal
ancestry. A resolvable but non-causal target is `STRUCTURAL_REJECTION`; a target
that resolves to no admitted binding is `UNRESOLVABLE_CREDENTIAL`. Neither case
is deferred. This prevents a *direct* omitted-history veto against that unseen
fresh identifier. It does not prevent an indirect veto: a compromised credential
can omit its own revocation, reduce a visible issuer, and thereby keep future
grants by that issuer below `Must0`. The hostile witness records that one-slot
availability loss explicitly.

Strict target availability has a measured cost: mutually concurrent reductions
between independently granted non-genesis credentials reject when neither actor
acknowledges the other's binding grant, so both credentials survive. The direct
issuer of a non-genesis credential necessarily has that binding grant in its own
causal ancestry and can issue a valid cleanup reduction if the issuer itself is
authorized at that acting prefix. If that issuer path is also lost, C0.2j claims
no automatic cleanup.

Rotation uses a fresh `GRANT` plus a `ROTATE` by a distinct independently
authorized credential that references that admitted grant and the retiring
identifier. A `ROTATE` whose actor is the retiring credential is structurally
rejected in v0. Recovery uses an independently authorized fresh `GRANT` plus a
`RECOVER` reference. `RECOVER` is not a reduction and does not require the old
binding grant in its causal ancestry; its fresh-grant/recovery transcript rule
remains authoritative. Neither control creates a binding; neither may re-grant
or resurrect an old identifier. If only the reduction is accepted, availability
can be lost safely. If only the fresh grant is accepted, the new independently
authorized credential can coexist with the old one.

These checks form a transitive rejection closure before authority evaluation.
If R-1, self-rotation or a binding failure removes an event after binding
discovery, every admitted descendant that depends on it is structurally rejected.
An otherwise independent event whose actor binding is unavailable becomes
`UNRESOLVED_CREDENTIAL_BINDING`; dependency rejection wins when both apply. A
reduction whose target binding disappeared becomes `UNRESOLVABLE_CREDENTIAL`.
This prevents a dependent event from retaining K admission only because the
invalid ancestor was discovered in an earlier pass.

A same-author fork is two or more distinct K-valid events at the same
`(credential_id, author_sequence)` slot. For non-genesis sequence positions the
siblings have the same immediately preceding sequence position; the direct
predecessor is evidence used to prove the divergence, not a third component of
the slot identity. The fold creates one virtual fork join for the complete
sibling set at that slot, rather than one join per sibling pair. The join
permanently quarantines that credential lineage in v0, independent of actor
role, control kind, arrival, current revocation state or whether the forked slot
is the actor's selected contested slot. Eligible reduction siblings in a
selected forked slot are evaluated before the join and may all apply; the join
then terminates the forker's lineage without resurrecting their targets.
Independent lineages continue only when their actions satisfy the same Pass-0
and bounded-standing rules. Late evidence always triggers fresh full replay.

The fork namespace is credential-local. Two independently granted credentials
that bind the same suite/key bytes are visible aliases but occupy different
fork namespaces. A holder of the shared private key can therefore equivocate
under both identifiers without either pair becoming one cross-credential fork.
This is a measured containment limit, not a claim that aliases are harmless.

## 7. Bounds and failure behavior

The v3 experiment uses one common envelope for every candidate and witness:

| Dimension | Bound |
| --- | ---: |
| events | 18 |
| credential-control events | 6 |
| same-sequence fork slots | 6 |
| causal parents per event | 4 |
| credential lineage depth | 4 |
| factorial-oracle topological orders | 720 |
| reachable authority states | 65,536 |
| reachable authority transitions | 524,288 |
| exhaustive delivery-permutation width | 6 |
| credentials | 10 |
| verification-key octets | 64 |

These are experiment bounds, not O-08 production limits. Eighteen events make
the maxima jointly admissible as six distinct fork slots, each containing one
credential-control sibling and two ordinary siblings. The joint witness reaches 4,033 DP states, 14,556
state transitions and represents 7,484,400 complete causal paths. The 720-order
ceiling belongs only to the equivalence oracle; it is not a production gate.

Exceeding a structural input bound rejects the bounded experiment. Crossing a
reachable-state or reachable-transition ceiling yields the typed whole-
projection-unavailable result from section 5. Unevaluated evidence is never
treated as absent and empty authority is never substituted for unavailable.

One fork slot consumes one fork-slot unit regardless of sibling count; siblings
remain ordinary events and controls for their respective independent bounds.
This prevents a bounded k-way fork from manufacturing a quadratic number of
pairwise control items and turning lineage-local quarantine into an accidental
whole-context failure.

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

V0 has no atomic rotation or recovery for a sole-authority context. A descendant
pre-provisioned while the sole issuer is operational can act only while that
issuer remains operational; retiring the issuer also terminates the descendant.
Compromise or loss without an independently rooted authorized recovery lineage is
therefore terminal.

A grant issued by an actor that is `May0` but not `Must0` is rejected as an
authority expansion, so its descendant never becomes operational merely from
that grant. Nevertheless the K-valid grant and provenance edge remain historical
evidence. Each K-valid descendant credential can receive its own first contested
slot when it is `May0` at that acting prefix, even when its grant is not accepted
as an expansion. One revoked credential can therefore retain its own slot plus
one slot for every stockpiled May0 descendant. This per-credential
choice preserves authenticated author-chain locality and avoids inventing a
global/root selector, at an explicit availability cost.

A `May0 && !Must0` self-lineage reduction consumes no selected slot. A `Must0`
descendant can nevertheless reduce its own issuer and thereby terminate the
complete lineage, including itself. This is another explicit sole-authority
availability limit, not an autonomous recovery mechanism.

Within the common envelope the exact accepted-standing bound is at most one
selected contested slot per credential, at most six accepted contested
reductions and at most six distinct accepted target subtrees in total. A selected forked slot can
concentrate five sibling reductions under one credential, with the sixth control
event supplying the contesting reduction. One reduction can terminate a whole
bounded subtree: structurally at most nine credentials under the ten-credential
cap, and at most five credentials in the executable six-control subtree witness.
Stockpiled descendants and independently rooted same-key aliases multiply the
per-credential budget, but never beyond those common-envelope totals.

An unselected later-slot or excluded self-lineage reduction can still
conservatively and permanently block operations and expansions by lowering
Pass-0 `Must0` for its target subtree. It can thereby make another actor's
reductions contested, move that actor's selected slot and change accepted-
reduction membership, while never entering accepted-termination accounting
itself. R-1 prevents the same event
from directly naming an unseen later grant, but not from indirectly disabling
future grants by reducing their visible issuer. The number of accepted
reductions is therefore not a bound on operational availability loss; within
this experiment the latter is bounded only by the shared evidence envelope.
These are measured availability powers, not quorum-safe governance claims.

Grant-rooted identifiers expose the corresponding grant to authorized
observers and are not unlinkability evidence. The rules do not establish
anonymity, rollback resistance, checkpoint freshness, finality, irreversible
effects, runtime capacity, implementation security or sensitive-use readiness.

## 9. Reopen and downstream gates

Reopen C0.2j if executable evidence finds an ordering or delivery divergence,
a non-`GRANT` can create/rebind a credential, provenance traversal can expand
authority, a rejected reduction enters accepted termination, its disclosed
bounded slot-steering effect exceeds the common envelope or expands operational
authority, the DP state key diverges from the factorial oracle, a resource
ceiling exposes a partial authority result, scoped quarantine resurrects a
terminated lineage, a supported signature suite cannot fit the exact tail/key
bound, or an admitted profile requires authority semantics outside this closed
vocabulary.

The O-06b-1 amendment reopens if O-14 requires a different canonical
verification-key encoding or an event-selected signature algorithm. O-14 still
owns the suite registry and exact key/signature encodings.

C0.2k must next bind the selected credential identifier and author sequence into
the O-06b-2 commitment context. O-06c must then falsify the complete exact-byte
construction. C0.3 remains `NO-GO`; O-07, O-08, O-10 and O-14 remain open.
