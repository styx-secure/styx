# Styx application protocol v0: identity and context analysis

Status: C0.2b normative decision analysis for O-02 and O-03, amended by the
selected C0.2j credential-succession contract

Base: `d387c27dc712bffb69f682841cc8e34e756c09d0`

Issue: [#209](https://github.com/styx-secure/styx/issues/209)

## 1. Scope and non-claims

This document decides the application-protocol meaning of an author credential
and an application/case context. It does not select wire or storage encoding,
signature algorithms, causal topology, event identifiers, complete genesis
content, MLS membership policy, Nostr routing identity, vault custody or a
product workflow.

The rules constrain a future specification. Current Dart and JavaScript code do
not conform merely because this document exists. The analysis does not establish
implementation security, anonymity, unlinkability, Marmot interoperability,
audit coverage, production readiness or regulatory compliance. Current Styx
builds remain experimental and unsuitable for sensitive or high-risk use.

The terms **MUST**, **MUST NOT**, **SHALL**, **SHALL NOT** and **REJECT** describe
the chosen protocol semantics. Exact bytes and conformance vectors remain
blocked until the dependent registry items close.

## 2. Evidence and provenance

### 2.1 Normative repository inputs

- [C0.2 decision registry](styx-app-kernel-v0-decisions.md), especially K-01,
  K-02, K-03, K-07, K-09, K-11 and O-01 through O-09;
- [C0.2a responsibility matrix](styx-app-kernel-v0-responsibility-matrix.md),
  especially `OB-K01`, `OB-K08`, `OB-K09`, `OB-AP02`, `OB-AP03`, `OB-AP09`,
  `OB-SS01`, `OB-RS01` and the `AP → K` / `SS → K` boundaries;
- [Styx threat model](../security/STYX-THREAT-MODEL.md), especially A2, A3,
  A7, A9, A10, A11, A12 and A14;
- [application capability model](../platform/application-capability-model.md)
  §§5.1–5.3, 5.6, 5.13 and 5.14; and
- C0.1 evidence `PRIV-01`, `PRIV-03` and `PRIV-04`, which shows why possession
  of a supplied verification key is not application authorization and why
  influential context/author fields must be authenticated.

### 2.2 External primary and exact-pin inputs

- [RFC 9420 §5.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3)
  defines MLS credentials as presented identities associated with a leaf
  signature key, leaves application identifiers and reference-identifier
  policy to the application, and calls a BasicCredential identity a bare
  application-defined assertion.
- [RFC 9420 §16.10](https://www.rfc-editor.org/rfc/rfc9420.html#section-16.10)
  treats compromise of the authentication service as an impersonation risk.
- Styx Phase B pins Marmot revision
  `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`. At that exact revision,
  [Marmot identity](https://github.com/marmot-protocol/marmot/blob/4ad4ae21479c3f3fa9950c6fc4556a76941a62e1/foundation/identity.md)
  maps a Nostr account to a BasicCredential identity while keeping the MLS leaf
  signing key distinct.
- At the same revision,
  [account-identity-proof v2](https://github.com/marmot-protocol/marmot/blob/4ad4ae21479c3f3fa9950c6fc4556a76941a62e1/app-components/account-identity-proof-v2.md)
  proves that the account key authorized one exact leaf signature key and says
  explicitly that this proof does not authorize the leaf to join or remain in
  a group.
- The [Least Authority MDK final report](https://leastauthority.com/wp-content/uploads/2026/03/Least-Authority-White-Noise-MDK-Final-Audit-Report.pdf)
  found separate failures involving account-to-KeyPackage identity binding,
  message authorship, administrative authorization and identity changes. Its
  reviewed MDK revisions differ from the Styx pins, so it is design evidence,
  not inherited assurance.

Current external specifications may evolve. The exact Marmot pin above is the
only Marmot revision used to justify a statement about Phase B. Current RFC text
is cited as external architecture input and does not define Styx application
authority.

## 3. Identity classes are not interchangeable

| Identity or authority class | Meaning | Owner | Forbidden inference |
| --- | --- | --- | --- |
| Persistent person/account identity | Optional durable relationship identity selected by an application profile | `AP`; custody by `RS`/`PV` | A public account key is required in every case or action |
| Application-scoped identity | Identity used only within one application family or deployment | `AP` | It is unlinkable if routing, storage or recovery reuses a stable handle |
| Case-ephemeral identity | Fresh identity material for one context and no other | `AP`; custody by `RS` | Absence of a legal name proves anonymity |
| Device credential | One context-local authoring key and credential record for one device | `AP` authority; `K` binding; `RS` custody | One person and all their devices are one cryptographic actor |
| Organization-role authority | Context-local authorization granted to an operational role | `AP`; human mapping by `PV` | The application transcript must name the employee or organization account |
| Anonymous return capability | High-entropy bearer secret used to regain bounded access to one context | `AP`; custody by `RS`/`PV` | A bearer secret is an author signature key or a personal identity |
| MLS leaf/session identity | Identity and signing key authenticated by the selected secure-session profile | `SS` | MLS membership or successful decryption authorizes an application action |
| Nostr/routing/mailbox identity | Key or handle used to publish, retrieve or route an outer envelope | `TR` | The routing key is the application author or may be reused as a case identifier |
| Human/organizational assignment | Operational record mapping a person to a role or credential | `PV` | The mapping must be published or placed in the application transcript |

An implementation may hold several of these at once. It MUST preserve their
separate purposes and lifecycles. A profile may add an authenticated mapping
between two classes, but the mapping is a distinct, context-bound fact; equality
or shared storage is not a mapping.

## 4. O-02 candidate comparison

### 4.1 Candidate A — durable account key signs every object

The author field is a persistent account key, such as a Nostr public key, and
that key signs every application object.

Advantages are simple verification and continuity across devices. The costs are
cross-context correlation, difficult device revocation, account-key exposure to
every verifier, poor separation from transport identity and pressure to equate
account possession with role authority. A compromised durable key has a broad
blast radius. This candidate cannot support the case-ephemeral requirement by
default and is **REJECTED** as the kernel author model. A persistent profile may
use such a key only to authorize a context-local credential through a separate
grant.

### 4.2 Candidate B — MLS leaf or immediate session sender is the author

The application accepts the member attribution returned by `SS` as the author
and relies on the MLS message authentication.

This avoids a second signature but couples durable application evidence to one
session engine and epoch. It cannot independently verify a forwarded object,
makes session membership look like application authorization, and turns leaf
rotation/removal into application identity semantics. It also conflicts with a
transport-neutral semantic kernel. This candidate is **REJECTED**.

### 4.3 Candidate C — self-asserted application key plus role text

Each object includes a public key and a claimed role; the signature is verified
under that key.

It is easy to implement and can use ephemeral keys. It proves only possession:
an attacker can substitute a new key and claim an allowed role unless a prior
authenticated state binds both. This is the defect class already identified by
C0.1. The candidate is **REJECTED**.

### 4.4 Candidate D — context-local endpoint credential plus authorization state

Each authoring endpoint has a fresh signing key and a context-local credential
identifier. An endpoint is one bounded signer instance, normally one device but
potentially a separately governed service signer. An authenticated application
transition grants that credential a bounded authority in one context. Every
authored object binds its context and credential identifier in the signed
transcript. `K` verifies the transcript, signature and credential binding; `AP`
evaluates whether the credential was authorized for that action in the validated
predecessor state.

This candidate separates possession from authorization, supports independent
device revocation, permits optional persistent-account proof without requiring
one, and keeps MLS/Nostr identities outside application semantics. It adds a
credential/grant lifecycle and requires the future causal representation to
define concurrent rotation and stale-object behavior. Those costs are necessary
for the declared profiles. Candidate D is **SELECTED**.

### 4.5 Candidate E — bearer capability as the only author

A high-entropy secret authorizes every operation without an author signing key.
This can be useful for initial anonymous return, but sharing or exfiltration
cannot be distinguished from legitimate use, evidence cannot attribute two
devices separately, and revocation/rotation becomes coarse. It is **REJECTED**
as the general author model. A profile may use a one-context capability to admit
or recover a context-local credential under the rules in §7.7.

### 4.6 Comparison summary

| Dimension | A durable account | B session sender | C self-asserted key | D context-local credential | E bearer only |
| --- | --- | --- | --- | --- | --- |
| Possession separate from authorization | No | No | No | Yes | No |
| Case unlinkability by construction | No | Session-dependent | Possible but unauthorised | Possible with fresh context material | Possible, but compromised capability use is indistinguishable from legitimate use |
| Device-specific revocation | Weak | Session-only | Undefined | Explicit | Coarse |
| Offline verifiable object | Yes | No | Signature only | Yes | Usually no |
| Transport/session neutrality | Partial | No | Yes | Yes | Yes |
| Multi-device support | Key cloning or extra scheme | MLS leaves | Undefined | Separate credentials and grants | Secret copying |
| Compromise blast radius | Cross-context | Session/group | Context if fresh | One credential/context by default | Whole capability scope |
| Rotation/revocation/expiry | Broad account lifecycle | Coupled to session lifecycle | Undefined | Explicit grant-state transitions and profile validity mode | Replace shared secret; prior use ambiguous |
| Recovery | Restores broad identity | Session-dependent | Undefined | Fresh credential; no authority resurrection | Possession recovers all bearer authority |
| Fork/rollback behavior | Broad stale-authority risk | MLS-epoch dependent | Undefined | Explicit O-01/RS dependency and fail-closed stale-state rule | Stolen/rolled-back bearer state is hard to distinguish |
| Denial-of-service and parsing | Fixed key, simple | Session engine surface | Attacker-selected key/role | Bounded credential/grant records; O-08 limits | Online guessing and redemption limits required |
| Versioning/migration | Account-wide | Session-profile migration | No model | Hard versioned application cut and explicit admission | Capability format/lifecycle migration |
| Selected | No | No | No | **Yes** | Admission/recovery only |

## 5. O-03 candidate comparison

### 5.1 Candidate A — account, organization or database identifier

Reusing a person key, organization identifier, database name or deployment name
is operationally convenient. It creates stable correlators, enables accidental
cross-application acceptance and makes context uniqueness depend on external
naming rules. It is **REJECTED**.

### 5.2 Candidate B — MLS group ID or Nostr routing handle

Reusing an MLS group identifier, relay tag, mailbox key or Nostr event key binds
application validity to a replaceable session/transport profile and may expose a
stable correlation handle outside the encrypted application object. It also
prevents more than one session from carrying the same application context. It is
**REJECTED**.

### 5.3 Candidate C — hash of complete genesis

Deriving the context solely from the complete genesis object makes binding
content-addressed and deterministic. It cannot be finalized until O-06 and O-07
select object identity and complete genesis fields. It also makes any later
change to genesis framing a context migration. It is **REJECTED** as the context
identifier, while an authenticated genesis reference remains necessary for
later objects.

### 5.4 Candidate D — raw opaque random context identifier

A locally generated 32-byte value provides a large collision domain and is not
derived from a person, organization, session or route. By itself, however, it
does not distinguish two application profiles if software accidentally reuses
the same value, and it says nothing about protocol/profile version. It is a
necessary input but not the complete context tuple.

### 5.5 Candidate E — explicit application-context tuple

The authoritative context is the tuple:

```text
(styx protocol version,
 application-profile identifier,
 application-profile version,
 32-byte random context identifier)
```

All four values are fixed-width or length-framed validated bytes under K-02.
The random identifier is generated locally from the `RS` profile's declared
CSPRNG and MUST NOT be derived from identity, human data, time, transport,
session state, database names or counters. It MUST NOT be reused. Candidate E
is **SELECTED**.

The tuple, not the random value alone, is the application/case context. The
genesis transcript authenticates the complete tuple. Every later authoritative
object authenticates the same tuple and an unambiguous reference or commitment
to that genesis. O-06 will define the exact authenticated genesis-reference
semantics; O-07 will define the remaining genesis fields. Neither may remove or
reinterpret the tuple.

The 32-byte random domain makes accidental collision negligible under the
declared CSPRNG assumption; it does not create an absolute uniqueness claim.
Duplicate tuple detection is still required within available local state. If a
collision or prohibited reuse is observed, creation fails closed and generates
a fresh independent value rather than merging contexts.

### 5.6 Comparison summary

| Dimension | A ambient ID | B session/route ID | C genesis hash | D random value | E explicit tuple |
| --- | --- | --- | --- | --- | --- |
| Independent of personal identity | Not generally | Possibly | Depends on genesis | Yes | Yes |
| Independent of session/transport | Not generally | No | Yes | Yes | Yes |
| Application/profile separation | External convention | No | If encoded | No | Explicit |
| Can close before O-06/O-07 | No | No | No | Partly | Yes, with reference mechanics deferred |
| Cross-context rejection input | Ambiguous | Coupled | Strong after genesis fixed | Context only | Protocol + profile + context |
| Collision/uniqueness | External naming rules | Session rules | Hash semantics depend on full genesis | 256-bit random domain | 256-bit random domain plus explicit profile tuple |
| Replay/fork/rollback | External and ambiguous | Coupled to session history | Strong only after O-06/O-07 | Requires companion genesis/profile binding | Explicit tuple plus deferred authenticated genesis reference |
| Denial-of-service/parsing | Variable external grammar | Session/transport surface | Full-genesis hashing/parsing | Fixed 32 bytes | Bounded version/profile fields plus fixed 32 bytes |
| Migration/versioning | External | Session migration | Genesis-breaking | Needs companion fields | Explicit profile version |
| Selected | No | No | No | Input only | **Yes** |

## 6. Selected O-02 author and authority model

### 6.1 Credential record

An application profile SHALL define a bounded credential record with at least
these semantic fields:

- the complete application-context tuple from §5.5;
- the context-local credential identifier selected below;
- one verification key and its algorithm identifier;
- the credential class (`device`, `case-ephemeral`, `organization-role`, or an
  explicitly defined persistent-profile class);
- the authenticated issuer/grant transition reference;
- an explicit validity mode and bound, including an explicit `no-expiry` mode
  when the profile permits it; and
- profile-defined constraints required to evaluate authorized actions.

O-14 still owns the exact signature-suite registry, key/signature encodings and
active key-length bounds. A human name, organization mapping, Nostr account key,
MLS leaf key, routing handle and recovery secret are not mandatory credential
fields.

For every non-genesis credential, the identifier is exactly the O-06b-1 event
reference of the one K-valid binding `GRANT`. That grant authenticates the O-03
context, issuer credential, grantee suite and grantee key in the exact
credential-control tail, and carries no subject identifier. The resulting
reference is fixed-width, context-local, collision-resistant under the selected
SHA-256 assumptions and non-circular because it is absent from its own preimage.
It is a reference, not a secret, possession proof or authorization fact.

Only the binding `GRANT` creates the monotone K record. Every other event treats
its credential identifier as a direct lookup key and verifies under the suite
and key derived from that record. Missing/forward lookup, suite/key mismatch,
wrong-context evidence and an observed distinct-preimage reference collision
fail closed before AP evaluation. Byte-identical duplicate grant evidence is
idempotent. K never chooses a binding by arrival, replay position, checkpoint,
AP authority or external identity.

O-07 still owns the exact genesis credential construction. It must use a domain
distinct from the event-reference domain or a structurally disjoint encoding;
K rejects equality between a genesis credential identifier and a grant event
reference.

### 6.2 Signed application object

Every authored authoritative object MUST authenticate at least:

- the K-02 object/version domain;
- the complete application-context tuple;
- the credential identifier;
- every semantic field required by K-01, including the later-selected causal,
  identifier and payload-commitment fields; and
- the signature under the verification key bound to that credential in the
  validated application state.

Verification establishes possession of the endpoint signing key for that object.
It does not establish that the action is allowed.

### 6.3 Authorization evaluation

Credential binding is a monotone K-level historical fact. `AP` evaluates
reversible authority over the complete finite K-admitted credential-control set.
For every causal linearization, it evaluates the actor at that event's acting
prefix. `MayAuth` means authorized in at least one such interpretation;
`MustAuth` means authorized in every interpretation. Authority expansion,
producer eligibility and operational authority require `MustAuth`; revocation
and retirement reductions use `MayAuth`. An actor unauthorized in every
interpretation cannot reduce authority merely by proving key possession.

Binding never implies authority: a grant by a bound but unauthorized issuer can
establish signature-verification evidence while its grantee remains
`AUTHENTIC_BUT_UNAUTHORIZED`. `K` verifies binding and preserves graph evidence
but applies only the AP-authorized transition; it MUST NOT parse human role
names or invent permissions. Openings, pending status, removal, retention and
current AP applicability never alter the authority evidence set, K binding,
admission, ordering, duplicate identity or forks. C0.2j selects fresh full
replay and makes no incremental-authority-cache claim.

The following do not satisfy `AP` authorization:

- a valid object signature;
- a supplied verification key;
- an MLS credential or current MLS membership;
- successful MLS decryption;
- a Nostr event signature or relay acceptance;
- local durability; or
- a UI login, organizational directory entry or human approval not represented
  by the profile's authenticated policy transition.

### 6.4 Session attribution and forwarding

`SS` reports the authenticated immediate session sender separately from the
application author. A peer may relay an already signed object, so equality is
not a kernel invariant. An application profile may require a context-bound
session-to-credential admission mapping for direct submissions, but that mapping
does not grant a role and cannot replace the inner application signature.

### 6.5 Issuance and delegation

Genesis establishes only the initial authority inputs later fixed by O-07. Any
non-genesis credential is effective only after an authenticated, authorized
grant transition in the same context. Only a K-valid `GRANT` creates its
binding; that credential becomes operational only if the grant satisfies
`MustAuth`. Its immutable provenance parent is the issuer credential. A
credential MUST NOT self-authorize.

Delegation is unsupported unless a profile defines a closed delegation grammar,
maximum depth, allowed action subset, validity bound and revocation semantics.
An implementation MUST reject an unknown or unbounded delegation chain.

### 6.6 Rotation, revocation and expiry

Rotation creates a fresh binding `GRANT` and a `ROTATE` control that names both
the fresh admitted grant and the retiring identifier; it does not overwrite a
key under the old identifier. The grant is an authority expansion evaluated
under `MustAuth`; retirement is a reduction evaluated under `MayAuth`. If only
retirement is accepted the system may lose availability but never resurrects
authority. If only the definitely authorized fresh grant is accepted, the two
credentials may coexist. `ROTATE` creates no binding. Revocation is
context-local authenticated history; its AP authorization and effect are
recomputed under set-relative full replay and cannot be replaced by restoring
an ambient older credential record.

An object whose credential has an AP-authorized revocation in its causal past
remains K-admitted and parent-usable but receives typed AP-fold outcome
`POST_REVOCATION` or `LINEAGE_QUARANTINED` and applies no transition. Its
descendants remain graph evidence. Revocation terminates the target and every
transitive grant descendant; a late ancestor revocation therefore contains a
concurrently laundered successor regardless of its grindable reference order.

Any K-admitted same-author fork permanently quarantines the forking credential
and its provenance descendants. The fork slot is exactly
`(credential_id, author_sequence)` and one classification covers the complete
sibling set, independent of role, privilege, arrival or
current revocation state. It cannot expand authority. Independent lineages may
continue only when their controls satisfy the same two-sided rule. This scoped
rule improves availability over whole-context quarantine but can still leave no
operational authority. Late admission always recomputes the full projection;
arrival order never chooses authority. A physical-time expiry is forbidden
until O-05/O-12 define its authenticated time semantics. Profiles may instead
use an explicit no-expiry mode, a causal/state bound, or a later approved
physical-time bound.

### 6.7 Recovery and anonymous return

Recovery requires a fresh binding `GRANT` plus a `RECOVER` control that names
that admitted grant and the retired identifier. Both are expansion-sensitive
and require `MustAuth`; `RECOVER` creates no binding. Recovery MUST NOT re-grant
or resurrect a revoked identifier, reset context history or silently clone a
device key. A profile with no independent recovery authority MUST state that
device or capability loss can be permanent.

An anonymous return capability is fresh, high-entropy and scoped to one context.
It may admit or recover a context-local credential, but it is not written into
ordinary authored objects, not reused across contexts and not described as a
person identity. A successful redemption consumes the current capability and
commits its replacement together with the newly granted credential; replay of a
consumed capability is rejected. O-01 must define concurrent-redemption
classification, and `RS` must make consumption and replacement atomic before a
profile may support recovery. Theft of an unused capability remains
indistinguishable from legitimate bearer use until a new credential is
established; the product must state that limitation.

Multi-device enrollment, when supported, uses a profile-defined authenticated
endpoint-add transition rather than copying either an author signing key or the
bearer capability. A case-ephemeral profile without such a transition MUST
declare multi-device participation unsupported.

### 6.8 Optional persistent-account and organization mappings

A persistent profile may authenticate a proof that a durable account authorized
a context-local credential. The proof is a separate `AP` input and MUST bind the
context and exact credential key. It does not make the account key the object
author. Marmot's pinned account-identity proof is an `SS`-profile example of an
account-to-MLS-leaf binding, not a Styx application-authorization credential.

An organization-role credential uses a context-local key. The mapping from a
human operator to that key may remain in organizational custody under `PV`.
Styx does not require that mapping in the application transcript and does not
claim to verify the organization's identity process.

## 7. Selected O-03 context and genesis model

### 7.1 Creation

The creating runtime obtains exactly 32 fresh random bytes from the declared
`RS` CSPRNG. `AP` supplies a supported application-profile identifier and
version. `K` validates and authenticates the four-part tuple in §5.5. No
component is inferred from an ambient database, URL, account, group, relay,
clock or user label.

For a case-ephemeral profile, every new case uses a new tuple and new
context-local credential material. Reusing a device, browser or installation
must not cause reuse of either value.

### 7.2 Genesis binding

The genesis transcript MUST contain and authenticate the full context tuple.
Every non-genesis authoritative object MUST contain and authenticate the same
tuple plus one unambiguous reference or commitment to the accepted genesis.
Moving an otherwise valid object to another application profile, profile
version, random context or genesis therefore changes authenticated semantics and
must fail verification or authorization.

O-06 will select whether the genesis reference is a signed-object identifier or
another uniquely purposed commitment. O-07 will select the remaining genesis
fields and initial authority content. Those decisions MUST preserve this rule;
they do not reopen the selected tuple unless no compliant binding can be built.

### 7.3 Visibility and use

The context tuple is application plaintext protected by the selected
secure-session profile when transported. `TR` MUST use a separately specified
routing handle and MUST NOT copy the application context into an outer envelope
unless a later profile explicitly accepts the resulting metadata disclosure.
The context identifier is not an anonymity mechanism when disclosed, logged or
reused.

`RS` namespaces records by a versioned storage binding that includes the context
tuple, but a storage key is not automatically a protocol transcript or public
routing value. Backup, recovery, notification and telemetry profiles must avoid
creating a stable cross-context mapping accessible to their declared adversary.

### 7.4 Collision, duplicate creation and replay

A producer rejects a locally known duplicate tuple. A consumer never merges
histories merely because an identifier collides: it validates the genesis
binding and rejects inconsistent state. A missing local history prevents an
absolute global-uniqueness claim; 32 random bytes reduce accidental collision
risk under the stated CSPRNG assumption but do not protect a compromised RNG.

Cross-context ciphertext rejection remains an `SS` requirement through its
session/AAD contract. Cross-context application-object rejection is independent:
`K` authenticates the context tuple and genesis binding, and `AP` evaluates the
action only in that context's state. One layer's check cannot substitute for the
other.

## 8. Hostile negative cases

| Case | Required result | Owner |
| --- | --- | --- |
| Attacker substitutes a verification key while retaining a credential ID | Signature/binding rejection before policy evaluation | `K` |
| Valid key claims an ungranted role or action | Unauthorized result; no state transition | `AP` |
| Current MLS member submits an unauthorized application action | Unauthorized result despite valid session | `AP`; attribution remains `SS` evidence |
| Relay or peer moves an object to another context tuple | Transcript/context rejection | `K` |
| Same random context bytes appear under another application/profile version | Distinct tuple; cross-profile object rejected | `K` |
| Creator attempts a locally known tuple reuse | Creation rejected and fresh randomness required | `RS` generation; `AP` activation |
| Persistent account key is reused across anonymous cases | Profile activation or admission rejected | `AP` |
| Stale or revoked credential signs a later action | Unauthorized/revoked result | `AP` after `K` signature validation |
| Old storage snapshot omits a revocation | Rollback is reported when independent evidence exists; no silent recovery claim | `RS`; `AP` revalidates |
| Rotation and old-key action are concurrent | Evaluate the fresh grant under `MustAuth`, retirement under `MayAuth`; old lineage remains inert after accepted retirement | `K`, then `AP` |
| Compromised credential issues a concurrent grant while a peer revokes it | Grant fails `MustAuth`; ancestor revocation terminates every descendant regardless of reference order | `K`, `AP` |
| Holder of valid or revoked key material creates a same-author fork | Permanently quarantine that credential lineage; independent definitely authorized lineages may continue | `K`, `AP`, `PV`; future recovery O-15/O-16 |
| Compromised device uses its still-valid credential | Actions remain attributable and within its current authority; one uncontested authority can still remove peers, so governance/incident response remain required | `AP`, `RS`, `PV` |
| Malicious organization operator maps a role key to the wrong human | Outside cryptographic proof; operational audit/incident process, while the authenticated credential-to-action record remains available under the retention policy | `PV` |
| Stolen anonymous return capability is redeemed | Treat as bearer use; establish a new credential and expose the limitation | `AP`, `PV` |
| Recovery attempts to restore a revoked key or earlier context history | Reject; recovery cannot reset revocation or context | `AP`, `RS` |
| Nostr/MLS/account proof validates but application grant is absent | Unauthorized result | `AP` |
| Context identifier appears in an outer routing envelope | Metadata-profile violation; no anonymity claim | `TR` |
| Two distinct valid grant preimages produce one reference | Fail closed as an observed cryptographic collision; never choose by arrival/order | `K` |

## 9. Resource, denial-of-service and migration bounds

- Credential identifiers, context identifiers and verification keys have fixed
  or registry-bounded lengths before allocation or signature work.
- Unknown algorithms, profiles, versions, credential classes and grant types
  fail closed.
- Authorization explores every admissible causal interpretation within the
  declared bound; lineage traversal, controls and orders are bounded and fail
  closed before any positive authority result.
- A profile sets maximum active credentials, pending grants, revocations and
  recovery attempts under O-08. This document does not choose those numbers.
- Historical verification after compaction must preserve the authenticated
  evidence required to establish a credential's authority at the relevant state;
  retention mechanics remain coordinated with O-04.
- The v1 application tuple and credential semantics are a hard versioned cut
  from `styx-legacy-c0`. Existing objects are not silently reinterpreted.
- Marmot account/leaf bindings and current Styx chat identities are not migrated
  into application credentials by default. Any future adapter maps them through
  an explicit, context-bound admission rule.

## 10. Decision record

| Item | Decision | Rejected alternatives | Dependencies retained |
| --- | --- | --- | --- |
| O-02 | Grant-rooted context-local endpoint credential plus two-sided AP authority, transitive provenance and lineage-scoped fork quarantine; optional persistent proof and bearer admission/recovery remain separate | Durable account as universal author; MLS sender as author; self-asserted key/role; bearer-only authorship; random identifier freeze; canonical-order authority | O-01 defines causality; O-05/O-12 gate physical expiry; O-06 supplies references/tail; O-07 initial authority; O-08 limits; O-10 errors; O-14 suites |
| O-03 | Explicit tuple of protocol version, application-profile ID/version and fresh 32-byte random context ID; genesis and all later objects authenticate the tuple | Ambient/account/org/database ID; MLS/Nostr handle; complete-genesis hash as context ID; raw random value without profile tuple | O-06 defines genesis reference mechanics; O-07 completes genesis; SS/TR/RS profiles bind their own namespaces without reusing the tuple publicly |

### 10.1 Security and privacy consequences

The selected design limits a normal credential compromise to one context and
endpoint by default, supports independent revocation and avoids requiring a global
identity in anonymous cases. It cannot prevent linkability caused by transport,
storage, notifications, recovery, user behavior or an implementation that
violates profile separation. A currently valid compromised credential can act
within its granted authority. C0.2j prevents a concurrent successor from
surviving ancestor revocation within the bounded model and scopes fork
quarantine to that lineage. It does not add quorum: one uncontested authority
can still remove all peers and remain the sole producer, while mutual reduction
or fork containment can leave no operational authority.

Random context identifiers prevent semantic derivation from personal data; they
do not hide a context if exposed as stable metadata. Application signatures
provide durable attribution to a credential, which may conflict with deniability
goals. A profile must choose that trade-off explicitly and may minimize retained
human mappings, but this protocol does not promise cryptographic deniability.

### 10.2 Reopen conditions

Reopen O-02 if the chosen causal model cannot define rotation/revocation without
accepting stale authority, if a required profile cannot use context-local
credentials, if independent evidence shows that the `AP → K` split permits an
authorization bypass, or if an acceptable anonymous-return design requires
bearer-only authorship rather than credential admission.

Reopen O-03 if O-06/O-07 cannot provide an unambiguous, substitution-resistant
and independently verifiable authenticated genesis binding that preserves the
context tuple's privacy constraints; if 32-byte context identifiers cannot be
generated within a supported runtime envelope; if a supported profile requires
deterministic public context discovery that conflicts with metadata separation;
or if cross-profile negative vectors reveal an accepted replay.

## 11. Downstream transcript and vector inventory

O-06c/C0.3 must include or derive explicit fields for:

- protocol version and object-kind domain;
- application-profile identifier and version;
- 32-byte context identifier;
- credential identifier;
- credential verification-key/algorithm binding through authenticated state;
- the exact role-`0x02` control kind and GRANT/target/replacement arm;
- genesis reference or commitment;
- policy/grant version or authenticated state reference needed for the exact
  authorization decision; and
- every remaining K-01 semantic field selected by O-01/O-04/O-05/O-06/O-07.

Required negative-vector families include all rows in §8, plus malformed lengths,
unknown versions, duplicate credential IDs, invalid keys, invalid signatures,
grant escalation, revocation replay, context/profile substitution, genesis
substitution and prohibited legacy acceptance. These are inventory requirements,
not vectors or byte encodings created by this task.
