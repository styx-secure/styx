# Styx application protocol v0 — responsibility matrix

- **Status:** C0.2a normative responsibility allocation, amended by
  C0.2b/C0.2c/C0.2e/C0.2f/C0.2i/C0.2j/C0.2k/O-06c/O-14, O-06a, O-06b-1 and O-06b-2 only for decided dependencies;
  not a protocol byte specification or implementation claim.
- **Authority:** Issues #207, #209, #211, #213, #215, #217, #219, #221, #223,
  #225, #233, #239, #243 and #246,
  ADR-0007 and `docs/security/STYX-THREAT-MODEL.md`.
- **O-06c evidence baseline:** Issue #243 supplies isolated bounded combined
  falsification of the exact C0.2j/C0.2k construction; exact candidate identity
  and the six canonical report digests are recorded by the Issue/PR evidence.
- **O-14 evidence baseline:** Issue #246 selects internal suite `0x0001` and
  supplies isolated guarded-language, raw-backend, cross-runtime and mutation
  evidence. It is not product conformance; Dart/browser claims and the
  placeholder-substituted O-06c rerun remain separate gates.
- **Decision effect:** C0.2a closes O-09; C0.2b closes O-02/O-03; C0.2c closes
  O-01/O-05 and fixes O-06 semantic roles; exact derivation was then split;
  C0.2e/C0.2f supplied the historical O-04 envelope; Issue #225 and merged PR
  #226 returned O-01/O-02/O-04 to `DECIDED` with the C0.2i pending-subtree
  replay baseline. Issue #233 replaces C0.2i's temporary collision freeze,
  non-transitive authority fold and whole-context fork quarantine with
  grant-rooted credential identity, the bounded Pass0/selected-slot authority fold and
  lineage-scoped containment; O-06a fixes the
  semantic transcript inventory and exposes O-14 signature-suite ownership;
  O-06b-1 fixes the transcript framing, domain registry and reference digest;
  O-06b-2 fixes the commitment suite, preimages and chunk-tree construction;
  C0.2k binds both commitment roles to the exact C0.2j credential identifier
  and author sequence without changing the interior-node format. O-06c supplies
  bounded combined falsification, making O-06/O-06c condition-bearing
  `DECIDED`. O-14 selects one downgrade-resistant guarded signature language
  and is condition-bearing `DECIDED`; O-07 is bounded `DECIDED`; O-08 and O-10 through O-13 remain
  open within their recorded conditional or downstream roles.

This matrix assigns each known normative obligation to exactly one owning
layer. Ownership means that the layer defines the rule, its conformance
evidence and its fail-closed outcome. Another layer may enforce an input
contract at its boundary, but it must not reinterpret, weaken or independently
redefine the owned rule.

## 1. Layer identifiers and authority

| ID | Sole owner | Authority and exclusions |
| --- | --- | --- |
| `K` | **Styx application semantic kernel** | Language-neutral authenticated application-object semantics, deterministic validation, causality, replay/fork classification, transition mechanics and evidence-preserving retention/pruning mechanics. It does not define roles, session membership, key custody, routing or organizational procedure. |
| `AP` | **Application profile** | Versioned application schema, roles, authorization, conflict policy, context/identity profile requirements, retention intent and assurance-profile selection. It does not redefine kernel validity, cryptographic sessions, runtime atomicity or transport truth. |
| `SS` | **Secure-session adapter** | Session membership, epochs, handshake/Commit policy, confidential authenticated session payloads, session replay handling, session convergence and session-secret lifecycle for one exact supported profile. It does not define application authorization, application causal order or business workflow. |
| `RS` | **Runtime/storage profile** | Local key custody, workers, durable transactions, outbox durability, crash recovery, concurrency, rollback boundary, storage limits, distribution and update provenance for one runtime. It does not define application meaning or transport confirmation. |
| `TR` | **Transport/routing profile** | Envelope and routing semantics, relay selection, publication/confirmation, retry/failover, outer metadata, padding/batching/onion policy, notification transport and network resource controls. It does not validate application truth or claim human delivery. |
| `PV` | **Product vertical and organizational operations** | User experience, organizational workflow, deployment configuration, human roles in practice, training, safeguarding, legal/privacy process, operational audit, emergency response and pilot/readiness decisions. It does not redefine protocol validity or cryptographic guarantees. |

The application profile is a versioned machine-evaluable policy contract. The
product vertical is the concrete human and organizational deployment that
selects and operates one or more profiles. This distinction prevents an
organization's procedure from becoming an implicit protocol rule while still
allowing the application profile to reject unauthorized transitions locally.

## 2. One-owner invariant

Every normative rule must satisfy all of these conditions:

1. it has exactly one owner ID from §1;
2. its inputs and outputs at every crossed boundary are explicit;
3. callers may check that an input satisfies the owner's contract, but may not
   substitute a different semantic decision;
4. no lower layer may infer application authorization from possession of a key,
   successful decryption, session membership or relay acceptance;
5. no upper layer may treat a runtime, session or transport failure as a valid
   application transition;
6. unsupported versions or missing required evidence fail closed at the
   earliest owning boundary; and
7. a profile may strengthen its own guarantee but cannot weaken a kernel
   invariant or claim another layer's property.

An apparent overlap is resolved by splitting the rule into distinct
obligations. For example, `K` defines deterministic duplicate classification,
`RS` makes the accepted effect crash-durable, and `TR` may retry publication.
Those are three different obligations, not three owners for deduplication.

## 3. Cross-layer interface contracts

The names below describe semantic data, not selected structs, APIs or wire
bytes.

| Producer → consumer | Required input/output contract | Consumer validation | Forbidden inference |
| --- | --- | --- | --- |
| `PV → AP` | Deployment-selected application/profile version, organizational policy inputs and user intent | `AP` accepts only a supported, internally consistent profile and closed-schema request | UI consent or operator login proves protocol authorization |
| `AP → K` | Bounded transition request; application/case context; claimed author/credential reference; schema version; authenticated policy inputs; payload commitment input; declared conflict disposition | `K` validates the future canonical object, resolves non-genesis credentials only through an admitted grant-rooted binding and returns a classified transition result under the deterministic set-relative `AP` authority fold | Supplied verification key, author-selected stale policy version, one replay order or key possession alone authorizes the action |
| `K → AP` | Authenticated object identity, causal classification, validation result and typed application-conflict handoff | `AP` applies its declared domain policy and never changes the kernel's causal facts | Deterministic order is business truth |
| `AP/K → SS` | Versioned opaque application object plus selected session/context binding | `SS` accepts only a supported exact session profile and authenticated session destination | Valid application bytes imply valid MLS membership change |
| `SS → K` | Authenticated plaintext bytes, sender/session attribution, session epoch/profile identity and a typed session outcome | `K` still validates application version, context, author binding, transcript and replay rules | Successful decryption proves application authorization or freshness |
| `K/AP/SS → RS` | Atomic local-state mutation set, protected records, outbox intent and typed commit preconditions | `RS` validates bounds, namespace, version and transaction preconditions; success means durable only within its declared runtime model | Durable local commit means relay publication or remote receipt |
| `RS → K/AP/SS` | Restored records plus provenance/version, transaction result and rollback/recovery status | Each owner revalidates its own authoritative state after restore | Parsable storage is valid protocol or session state |
| `RS/SS → TR` | Opaque bounded envelope, routing handle, publication policy, expiry and idempotency reference needed by the profile | `TR` validates its envelope grammar, limits and routing policy | Opaque payload is safe, authorized or non-sensitive in metadata |
| `TR → RS/AP` | Typed publication, retry, expiry, relay observation and authenticated remote-ack evidence when defined | `RS` durably reconciles delivery state; `AP` maps only named evidence into UI/workflow state | Relay `OK`, WebSocket send or HTTP success means device, application or human receipt |
| `TR/RS → PV` | Minimized availability, delivery and diagnostic signals allowed by the deployment profile | `PV` exposes truthful user states and follows continuity/incident procedures | Missing telemetry means no failure; notification means a person read content |

## 4. Normative obligation register

Each row has one and only one owner. “Open dependency” means the owner is fixed
but the concrete rule is not yet selected.

### 4.1 Application semantic kernel (`K`)

| Obligation | Owned rule | Required input / emitted result | Status dependency |
| --- | --- | --- | --- |
| `OB-K01` | Authenticate every semantic field that influences validation, causality, replay/fork handling or deterministic order | Candidate object → authenticated-semantics result | Decided by registry K-01 |
| `OB-K02` | Use versioned domain separation and unambiguous fixed/length framing for regenerated cryptographic transcripts | Validated semantic fields → transcript bytes | Decided by registry K-02 |
| `OB-K03` | Admit only pinned byte grammars and reject repair, truncation, clamping, normalization and locale-dependent interpretation | Candidate scalar/bytes → canonical value or rejection | Decided by registry K-03 |
| `OB-K04` | Enforce exact numeric signedness, width, range and non-wrapping arithmetic before state change | Numeric field → bounded integer or rejection | Decided by registry K-04; O-06b-1 fixes transcript scalar widths and O-06b-2 fixes geometry widths/cross-field validity, while AP schema and O-08 supported maxima remain open |
| `OB-K05` | Define transcript-only causal representation and classify predecessor, concurrent, duplicate, missing-parent, replay and fork relationships independently of openings and AP authority; classify the complete sibling set at one `(credential_id, author_sequence)` slot as one fork without choosing a sibling | Authenticated object set → causal classification, admitted graph and lineage-fork evidence | O-01 and C0.2j lineage containment are selected. C0.2k binds the commitment to that same slot but does not collapse siblings or select a winner. O-06c bounded evidence passes; O-08 bounds remain open |
| `OB-K06` | Derive deterministic total order only after causality; compute pending roots and their causal-descendant closure without AP input; never let replay position supply authority, priority or physical-destruction permission; retain graph/pending diagnostics while the AP Pass0/selected-slot fold determines scoped operational authority | Concurrent authenticated objects plus monotone verified-opening set → unchanged graph/order, pending set, canonical replay inputs and scoped fork evidence | C0.2i pending/no-substitution behavior, C0.2j authority/containment and C0.2k context binding selected; O-06c bounded evidence passes; O-08 production bounds remain open |
| `OB-K07` | Define the purpose and authenticated derivation/binding of event, content and parent identifiers | Authenticated object fields → identifiers/references | O-06a inventory, O-06b-1 transcript/reference profile and O-06b-2 commitment profile fixed; O-06c bounded evidence passes with recorded rerun triggers |
| `OB-K08` | Bind application/case context and the derived genesis reference into every authoritative object and reject cross-context replay | Context plus candidate object → accepted context or rejection | O-07 closes the genesis-authored share: one O-03 tuple/reference pair independently authenticated by a local CeremonyBoundary capability is fixed and every descendant is compared to it; grant-rooted O-06c evidence remains historical until the separate placeholder-substituted rerun |
| `OB-K09` | Define fresh deterministic genesis and initial authenticated authority inputs | Profile/context inputs → genesis object | O-07 selects the seven-field single-root transcript, O-14 signature and an opaque local capability issued after out-of-band ceremony verification; creator-local state is mechanically distinct and is not evidence for another replica, while production ceremony realization remains later AP/PV/RS work |
| `OB-K10` | Authenticate the O-04 content descriptor; derive/verify the randomized-opening commitment; keep class, availability, binding, retention and replay readiness distinct; reject content-bearing control events; validate append-only removal structure | Payload/opening, descriptor or retained commitment/removal evidence → typed verification/readiness/pending/quarantine result | O-04 and C0.2k select unchanged-opening rejection across credential/sequence contexts plus content-free credential controls; knowledgeable recomputation remains possible. O-06c bounded evidence passes; O-08 and O-10 remain open |
| `OB-K11` | Distinguish empty, uninitialized and valid histories | Stored/input history → classified state | Decided by registry K-08; O-10 error code open |
| `OB-K12` | Apply deterministic state-transition mechanics and hand semantically concurrent conflicts to `AP` without inventing universal business resolution | Valid authenticated object plus state → applied/rejected/conflict outcome | K-07 decided; profile schemas open |
| `OB-K13` | Define logical replay and duplicate idempotency semantics for application objects | Object identifier plus history → new/duplicate/replay outcome | O-06b-1 fixes reference derivation and O-06c bounded evidence passes; O-10 outcomes remain open |
| `OB-K14` | Preserve descriptors, commitments, authority transcripts and AP-authorized removal evidence across compaction; mark the whole projection stale only when a required dependency is absent from the live admitted graph and retained solely as checkpoint evidence; never substitute checkpoints for retained authenticated history or expose authority while stale | Valid history plus direct content/authority evidence → verifiable transition, pending subtree, fork quarantine or whole-projection stale result with authority explicitly unavailable | O-07 keeps the suppress-side rule but makes it unreachable in v0: no checkpoint object or compaction exists and checkpoint evidence is structurally empty. Any future checkpoint or compaction capability reopens this obligation; O-13 remains open |
| `OB-K15` | Reject legacy `styx-legacy-c0` objects as v1 and prevent implicit dual acceptance | Versioned object → v1 result or legacy rejection | Decided by registry K-10 |
| `OB-K16` | Emit stable, bounded protocol outcomes required for safe caller behavior without leaking parser internals | Validation site → stable classified outcome | O-10 open |
| `OB-K17` | Define physical-time semantics only if retained; never use ambient wall time as unbounded authority | Optional time input → bounded field or absence | O-05 removes kernel time; O-12 remains profile-conditional |
| `OB-K18` | Resolve each non-genesis credential identifier as the event reference of exactly one causally available K-valid role-`0x02` `GRANT`; take context, issuer, suite and key only from that authenticated grant; treat non-`GRANT` author IDs as lookup keys and expose same-key aliases without merging authority | Whole validated set, causal ancestry and signed transcript/signature → bound author, invalid signature, dangling/forward binding, visible alias or unsupported collision | C0.2j selects grant-rooted binding and exact K-readable tail; O-06c independently exercises grant-rooted derivation; O-14 selects suite `0x0001`, canonical 32-octet keys, canonical 64-octet signatures, prime-order guards and terminal no-fallback verification |
| `OB-K19` | Build immutable issuer-to-grant provenance, compute bounded transitive termination for revoked or forked credential lineages, require R-1 causal availability for `REVOKE` and retiring-`ROTATE` targets, and present the complete K-admitted control-evidence set to AP without filtering it by AP outcome, content availability, removal or checkpoint substitution | Complete admitted control graph plus fork/reduction targets → provenance graph, terminated lineages, scoped quarantine evidence or typed fail-closed bound result | C0.2j selected with fresh full replay only; `RECOVER` retains its authorized bootstrap exemption. O-06c restates the pinned authority outcomes and re-exercises only their fail-closed boundary guards, without creating a second oracle; O-08 production bounds and O-10 outcomes remain open |

### 4.2 Application profile (`AP`)

| Obligation | Owned rule | Required input / emitted result | Status dependency |
| --- | --- | --- | --- |
| `OB-AP01` | Define closed application object schemas, versions, bounded payload types and unknown-version behavior; encode grant/revoke/rotate/policy/closure control events as content-free authenticated transitions | User/product intent → bounded transition request | C0.2i fixes the `NONE` control-class rule; exact K-readable carriage and concrete profiles remain future work |
| `OB-AP02` | Define actor/credential types and reversible role authority, delegation, rotation, revocation and expiry without redefining K binding/admission; compute Pass0 reachable authority before contested reductions, admit expansion only from necessary Pass0 authority, and accept reductions only from each actor's first eligible contested author-sequence slot, including every eligible sibling there; expose possible/necessary reachable authority and final recomputed terminal authority without selecting one replay order | Complete non-stale K-authenticated binding/control evidence plus the AP policy and O-07 initial authority → authorized, authentic-but-unauthorized, post-revocation, terminated-lineage, scoped-quarantine or typed authority-unavailable outcome | O-02/C0.2j selected in the bounded v3 model with fresh full replay and DP state/transition envelopes; a rejected later-slot or excluded self-lineage reduction may lower Pass0 `Must0`, make another actor contested, move that actor's selected slot and change accepted-reduction membership, but cannot itself enter accepted termination or expand operational authority. Same-key aliases retain independent authority/fork scope. Profile policy, O-08 bounds, O-10 outcomes and O-06c evidence remain open |
| `OB-AP03` | Select context and identity profiles and require cross-context/cross-case separation | Deployment/profile choice → requirements consumed by `K`, `SS`, `RS` and `TR` | O-02/O-03 decided after C0.2i ratification; individual application profiles remain future work |
| `OB-AP04` | Define domain conflict policy: accept, reject, supersede, combine or require human review | Kernel causal/conflict result plus profile state → policy disposition | Profile-specific; K-07 fixed |
| `OB-AP05` | Define retention, legal hold, append-only logical removal, export, opening retention and post-removal reconstruction by data class; authorize content-free controls without redefining K validity or pending mechanics | Authenticated `NONE` policy action plus O-04 class/evidence → reversible bounded request to K/RS/PV | O-04 and the bounded C0.2i mechanics are decided after exact-final ratification; profile policy, O-15 lifecycle and O-13 irreversible effects remain open |
| `OB-AP06` | Select allowed assurance capabilities and reject an internally inconsistent combination | Runtime/session/transport capability declarations → activated or rejected profile | O-08 open |
| `OB-AP07` | Define application-level acknowledgement meanings and which authenticated actor may issue them | Kernel/session evidence → named application-ack state | Future SDK/delivery work |
| `OB-AP08` | Define closed content types, `REQUIRED` versus `DETACHABLE` use, semantic size/expansion bounds and isolated sanitization; forbid detachment when authoritative reconstruction needs the bytes | Candidate content/metadata → admitted class and bounded application object or rejection | O-04 class contract is decided after C0.2i exact-final ratification; concrete profile and O-08 numeric bounds remain future work |
| `OB-AP09` | Define capability/recovery authority without treating recovery as implicit revocation bypass | Recovery proof plus context/profile → bounded authorized recovery action | O-02 forbids authority resurrection; concrete recovery profiles remain future work |
| `OB-AP10` | Define first-profile actor/cardinality, clock-skew and activation bounds as profile rules rather than kernel limits | Capability/resource evidence → in-profile or out-of-profile result | O-08 open |

### 4.3 Secure-session adapter (`SS`)

| Obligation | Owned rule | Required input / emitted result | Status dependency |
| --- | --- | --- | --- |
| `OB-SS01` | Authenticate session members and bind the exact session profile without equating membership with application role | Session credential/profile → authenticated member attribution | Supported adapter future work |
| `OB-SS02` | Enforce authorized staged membership changes before merge/apply | Proposal/Commit plus session policy → rejected, staged or applied outcome | Bounded Phase B evidence only |
| `OB-SS03` | Provide confidential authenticated session payload delivery for the declared ciphersuite/profile | Opaque application bytes plus session state → ciphertext/plaintext outcome | Exact-pin Phase B evidence only |
| `OB-SS04` | Manage epochs, generations, replay windows, concurrent Commits and session convergence within declared bounds | Session message/Commit plus state → new session state or typed failure | Exact-pin Phase B evidence only |
| `OB-SS05` | Define KeyPackage creation, consumption, expiry, last-resort policy and Welcome handling | Session onboarding objects → accepted/rejected join | Supported adapter and upstream-gap review future work |
| `OB-SS06` | Define session-secret lifecycle, retention, rotation, forward secrecy and post-compromise recovery claims | Session transitions → retained/deleted secret state and bounded claim | Shipping retention policy open |
| `OB-SS07` | Persist or export session-state mutations only through an atomic `RS` contract and halt on ambiguous failure | Candidate session mutation → durable checkpoint precondition/result | Product persistence future work |
| `OB-SS08` | Expose typed, bounded session diagnostics without secret or stable group-identifier leakage | Session failure → redacted outcome | Supported adapter future work |
| `OB-SS09` | Maintain exact revision/ciphersuite/extension provenance and invalidate evidence on drift | Artifact/profile tuple → supported/unsupported result | Phase B exact-pin rule established |

### 4.4 Runtime/storage profile (`RS`)

| Obligation | Owned rule | Required input / emitted result | Status dependency |
| --- | --- | --- | --- |
| `OB-RS01` | Confine root, wrapping, session and application keys to the minimum local execution boundary and expose data-only bounded operations | Profile request → cryptographic/storage result without raw-secret return | Browser component evidence; product boundary future work |
| `OB-RS02` | Encrypt and authenticate protected records/manifests before persistence with namespace and purpose separation | Protected record → durable ciphertext record | Product namespaces/formats separately gated |
| `OB-RS03` | Serialize mutations and make application, session, outbox and acceptance-state updates atomic where their invariant requires joint commit | Mutation set and preconditions → committed or unchanged | Product journal future work |
| `OB-RS04` | Treat quota, persistence and transaction failure as failure and never continue from ambiguous advanced state | Storage operation → durable success or typed halt/recovery | Runtime-specific implementation evidence required |
| `OB-RS05` | Define crash recovery, prepared/stable states and reconciliation without duplicate application effect | Durable journal/outbox → recovered state | Product integration future work |
| `OB-RS06` | Make the outbox durable before publication and reconcile transport results without conflating them with local/application truth | Valid outbound intent → queued/reconciled delivery state | Minimum SDK/reliable delivery future work |
| `OB-RS07` | Coordinate tabs/processes while retaining atomic compare-and-swap or equivalent as the safety property | Concurrent local mutations → one accepted durable successor | Runtime-specific implementation evidence required |
| `OB-RS08` | Define storage bounds and custody for every `REQUIRED` opening in an honest frontier's causal ancestry; handle quota, eviction, suspension and background behavior without interpreting loss as removal | Runtime capability, retained frontier/openings and probe → supported/unsupported profile or typed loss | O-08/O-11/O-13 and runtime evidence open; C0.2i supplies no availability guarantee |
| `OB-RS09` | Define rollback detection, external evidence and fail-closed limits without claiming undetectable whole-profile rollback protection; expose rollback-past-removal as a privacy regression | Restored state plus available anchor/evidence → accepted, stale or unknown outcome | Authenticated product persistence future work |
| `OB-RS10` | Perform versioned migrations with verified copy/commit/rollback and no destructive source removal before success | Old durable format → migrated state or intact old state | Each migration separately gated |
| `OB-RS11` | Implement lock, timeout, reset and crash closure; state locked and unlocked endpoint guarantees separately | Lifecycle event → closed/cleared handles and typed state | Browser/native profile-specific |
| `OB-RS12` | Authenticate distributed artifacts, updates and rollback within the runtime's trust-root model | Release artifact/configuration → accepted/rejected version | Distribution milestone future work |
| `OB-RS13` | Produce privacy-minimized local diagnostics and enforce retention/access boundaries for them | Runtime event → bounded local diagnostic record | Runtime/product profile future work |

### 4.5 Transport/routing profile (`TR`)

| Obligation | Owned rule | Required input / emitted result | Status dependency |
| --- | --- | --- | --- |
| `OB-TR01` | Define strict outer-envelope grammar, event authentication, size/version limits and visible fields | Candidate transport object → accepted/rejected envelope | Supported Marmot/Nostr adapter future work |
| `OB-TR02` | Define routing handles, relay subscriptions, mailbox/group rotation and recipient fan-out | Opaque envelope plus profile route → publication plan | Metadata-minimizing profile future work |
| `OB-TR03` | Define publication, relay confirmation, quorum, expiry and deletion semantics without claiming recipient/human receipt | Relay response set → typed transport state | Reliable-delivery profile future work |
| `OB-TR04` | Retry, back off, jitter, fail over and dead-letter within explicit resource and privacy bounds | Durable outbox item plus relay outcomes → next transport action | Reliable-delivery profile future work |
| `OB-TR05` | Handle relay duplication, reordering, stale return, omission and censorship without becoming application authority; support the future authenticated O-11 fetch contract without treating relay/peer response as opening substitution | Relay objects and opening request → candidate delivery set and observation | Transport/fetch conformance future work; C0.2i forbids substitution |
| `OB-TR06` | Minimize declared sender, recipient, group/case, timing, size, frequency and route metadata for a named adversary | Profile choice plus envelope → measurable exposure | Concrete Marmot/NIP analysis open |
| `OB-TR07` | Define padding, batching, delay, dummy traffic and onion-routing policy including cost/latency limits | Opaque envelope stream → scheduled network traffic | Metadata-minimizing profile future work |
| `OB-TR08` | Define privacy-safe push/wake-up transport and prohibit content or direct case identity unless separately approved | Notification intent → minimized provider signal | Product/runtime future work |
| `OB-TR09` | Enforce network-side resource/abuse bounds without silently excluding Tor/NAT users or creating identifying logs | Connection/publication demand → accepted, delayed or rejected action | Deployment-specific policy future work |
| `OB-TR10` | Declare relay/provider observability and retention; multiple relays never imply anonymity or consensus | Concrete configuration → public metadata/data-flow statement | Each deployment profile |

### 4.6 Product vertical and organizational operations (`PV`)

| Obligation | Owned rule | Required input / emitted result | Status dependency |
| --- | --- | --- | --- |
| `OB-PV01` | Present truthful UI states for local save, queued, published, pending opening/ancestor, provisional replay, whole-projection stale, credential-lineage quarantine, acknowledged, read, rejected and conflicted states | Typed lower-layer outcomes → user-facing state | C0.2j requires pending/provisional/stale/lineage-quarantined honesty; Themis/reference UI future work |
| `OB-PV02` | Define real organizational roles, least privilege, assignment/reassignment, separation of duties and continuity when personnel change | Deployment procedure and AP role model → operator access/process | Themis operations future work |
| `OB-PV03` | Require independent/high-impact authorization for export, destruction, policy change and declared emergency access where the deployment model calls for it | Operator actions → approved/rejected/audited operation | Deployment-specific |
| `OB-PV04` | Maintain minimized operator/security audit access, review and incident handling without creating a universal plaintext administrator or social graph | Operational events → protected audit and response | Themis operations future work |
| `OB-PV05` | Define safeguarding, immediate-danger, conflict-of-interest and alternative-reporting procedures | Human/case condition → trained escalation path | External readiness gate |
| `OB-PV06` | Perform legal/privacy analysis, DPIA where applicable, notices, training and policy governance; never infer compliance from protocol features | Deployment/jurisdiction facts → approved procedure or NO-GO | External readiness gate |
| `OB-PV07` | Define backup, restore, relay/provider loss, key compromise and business-continuity drills | Operational failure → tested recovery/incident result | Deployment milestone future work |
| `OB-PV08` | Protect operators and users from abuse, spam, traumatic content and illegal material without silently defeating the anonymity profile | Abuse signal and procedure → quarantine/escalation/limit | Themis safety design future work |
| `OB-PV09` | Control attachments, exports, external viewers and sanitization services in the deployed environment | Admitted AP object → safe operational handling | Product-specific |
| `OB-PV10` | Authorize synthetic exercise, pilot or production only after explicit technical, security, privacy, legal and human-readiness gates | Evidence package → GO/NO-GO | Milestone 6 / separate authorization |
| `OB-PV11` | Communicate pending subtrees, permanent opening loss, replica-asymmetric fork arrival, reversible pre-quarantine views, credential-lineage quarantine, provisional/finality limits, recovery loss, anonymity and removal limits; never promise deletion, availability, stable finality or rollback-stable removal without evidence | Profile/deployment facts → user documentation | Every product release; O-13, O-15 and O-16 gate stronger claims |

## 5. Required validation and state-change order

A supported composition must preserve this logical order even if an
implementation combines some operations atomically:

1. `TR` rejects an invalid or out-of-bounds outer envelope before routing it to
   a session parser.
2. `SS` authenticates and processes the exact supported session profile before
   emitting candidate application bytes and sender/session attribution.
3. `K` validates version, framing, canonical fields, authenticated semantics,
   context, identifiers and causal/replay relationships.
4. `AP` evaluates context-bound application authorization, schema and conflict
   policy using the kernel's immutable classification.
5. `K` derives the deterministic application transition or classified
   rejection/conflict result.
6. `RS` commits the mutually dependent local application/session/outbox state
   atomically or reports failure without false success.
7. `TR` attempts publication according to the durable outbox and returns only
   its precisely named evidence.
8. `PV` presents the corresponding truthful state and applies any human or
   organizational process.

This order does not choose a wire encoding, transaction API or session engine.
It prevents a lower-layer success from bypassing an upper-layer security rule.

## 6. Decision allocation

| Registry item | Decision owner | Required contributors | Status after C0.2f/O-06b-1 |
| --- | --- | --- | --- |
| O-01 causal representation | `K` | `AP`, `RS`, `TR` supply conflict, resource and privacy requirements | **Decided, amended by C0.2j:** per-credential chain/frontier topology remains; any K-admitted sibling fork terminates only the forked credential lineage and cannot expand authority. Independent lineages remain subject to the same bounded AP fold. |
| O-02 author/rotation/authorization binding | `AP` for authority semantics; `K` for authenticated binding mechanics and provenance | `SS`, `RS`, `PV` supply member, custody and operational constraints | **Decided, amended by C0.2j:** non-genesis IDs are binding-grant references; only `GRANT` binds; Pass0 governs expansion, each actor has at most one first eligible contested reduction slot, R-1 governs reduction-target availability, termination is provenance-transitive and succession uses fresh grants. |
| O-03 context/genesis binding | `K` for binding; `AP` for context-profile requirements | `SS`, `RS`, `TR` supply namespace and linkability constraints | **Decided:** protocol/profile tuple plus fresh 32-byte random context identifier, authenticated by genesis and all later objects. |
| O-04 payload commitment/detachment | `K` for descriptor, commitment, typed state and pending-subtree mechanics; `AP` for content-free control policy/authority; `RS` for opening custody/effects | `SS`, `TR` and `PV` supply protected delivery, authenticated fetch and truthful pending/provisional/quarantined presentation | **Decided, amended by C0.2j/C0.2k/O-06c:** descriptor-only randomized-opening commitment; authenticated `NONE`/`REQUIRED`/`DETACHABLE`; append-only logical removal; pending root plus causal descendants; role `0x01` removal and role `0x02` credential controls require `NONE`; fork handling is lineage-scoped; no checkpoint substitution; 84-octet context binds credential and author sequence in both commitment roles. O-06c is bounded evidence, not implementation proof. |
| O-05 clock placement | `K` if kernel time is necessary; otherwise the owning profile | `AP`, `RS`, `TR` supply authorization, precision and privacy needs | **Decided:** no HLC/physical time in K; optional purpose-bound time belongs to AP profiles. |
| O-06 event/content identifiers | `K` | `AP`, `RS`, `TR` supply idempotency, storage and correlation requirements | **Condition-bearing `DECIDED`:** O-06a/O-06b-1/O-06b-2/C0.2k select the complete semantic inventory, exact framing, seven-role domains, full-width SHA-256 references, randomized-opening commitment, left-complete chunk tree and credential/sequence-bound context. O-06c bounded evidence passes; placeholder selection or counterexample triggers rerun/reopen. |
| O-07 genesis and checkpoint evidence | `K` for transcript/signature/reference validation; `AP` for the locally configured CeremonyBoundary and initial authority; `RS` for the abstract acceptance transition; `PV` for disclosure only | `RS` still supplies durable custody/rollback bounds; product profiles must realize the unselected Boundary transport, issuer credential/witness and trusted path | **Decided:** exact single-root transcript and genesis credential; opaque non-transferable local capability after independent ceremony authentication; immutable acceptance-scoped tuple/reference; mechanically separate creator-local state; duplicate idempotency and distinct-root rejection. Every checkpoint grant-side use is unsupported and the suppress-side input is structurally unreachable in v0. No product ceremony, durability, recovery, freshness or availability follows. |
| O-08 skew/cardinality/activation bounds | `AP` | `K`, `SS`, `RS`, `TR`, `PV` provide capability/resource envelopes | No first supported profile or runtime capacity evidence is selected. |
| O-09 responsibility split | This document | All six layers | **Decided:** one kernel plus explicit profiles and the ownership rules in §§1–5. |
| O-10 stable error taxonomy | `K` for protocol outcomes; each profile for its own typed failures | All consumers supply safe-recovery distinctions | O-06b-1 and O-06b-2 enumerate transcript/reference/commitment rejection sites without assigning codes; the stable taxonomy depends on the remaining object decisions. |
| O-11 wire/storage encoding | Owner of each representation: `K` transcript regeneration; `RS` opening custody; `TR` authenticated fetch/envelope | Honest frontier producers must retain and be able to serve every `REQUIRED` opening in the frontier's causal ancestry; a stale or fork-quarantined projection is never producer-eligible; decoders supply surface evidence | Exact containers and fetch protocol remain open; loss stays typed pending/stale and never permits substitution. |
| O-12 physical-time details | The time-bearing `AP` profile | `RS` and `TR` supply precision/lifetime/linkability evidence | Inapplicable to profiles without time; open for any profile retaining a signed time claim. |
| O-13 irreversible-effect authorization | `AP` for authorization semantics | `RS` owns execution/custody/typed loss; `PV` owns disclosure/claims; `K` supplies retained evidence | **Open coordinating record.** Quarantine-only interim; gates destruction-capable increments and deletion/erasure/unlinkability claims, not O-04/C0.2f/transcript-only C0.3. |
| O-14 signature-suite registry | `K` for verification mechanics and registry; `AP` for admitted credential/assurance profiles | `RS` and implementation evidence supply key custody/runtime capability | **Condition-bearing `DECIDED`:** internal suite `0x0001` is pure Ed25519 over the exact O-06b-1 transcript with canonical 32/64-octet key/signature encodings, `S < L`, prime-order `A`/`R`, one pinned verifier and no alternate selector/fallback. Product adapters remain unclaimed; Dart/browser evidence and the separately ratified placeholder-substituted O-06c rerun remain gated. |
| O-15 lifecycle/profile succession | `AP` for version succession and any future disposition semantics; `K` only for authenticated version pinning | `RS`, `TR` and `PV` supply migration, availability and presentation constraints | **Open:** v0 contexts are pinned; no profile-upgrade, abandonment or control-lane mechanism is selected. Blocks product readiness, not transcript-only C0.3 while v0 stays pinned. |
| O-16 finality/stability | `AP` for semantic finality policy; `K` for evidence classification only | `RS`, `TR` and `PV` supply rollback, delivery and truthful-presentation constraints | **Open:** every visible AP result is provisional under late evidence; no irreversible-effect or finality claim is selected. |

O-02 deliberately retains split ownership because “who may act” (`AP`) and “how
that authority is cryptographically bound into the object” (`K`) are separate
normative obligations. Neither owner may omit the other's validated output.
O-07 uses the same obligation split: `K` owns candidate transcript, signature
and reference validation; `AP` owns the authenticated ceremony and initial
authority decision; `RS` owns the abstract local acceptance transition; `PV`
discloses but never authorizes. V0 has no checkpoint object or producer. Any
future capability must assign those responsibilities through a reopened
decision rather than infer them from possession. O-14 selects verification mechanics and the
closed `0x0001` signature registry under `K`, while `AP` alone selects admitted
credential/assurance profiles under O-02. A valid `0x0001` result cannot
substitute for AP authorization.

## 7. Capability-model coverage

The exploratory capability model is decomposed into owned obligations as
follows. A source section may map to several rows because it contains several
different obligations; no individual rule gains multiple owners.

| Capability-model section | Owned obligations |
| --- | --- |
| §5.1 context/domain separation | `OB-AP03`, `OB-K08`, `OB-RS02`, `OB-TR02` |
| §5.2 identity profiles | `OB-AP02`, `OB-AP03`, `OB-SS01`, `OB-RS01` |
| §5.3 unlinkability | `OB-AP03`, `OB-TR06`, `OB-TR10`, `OB-PV11` |
| §5.4 E2EE objects/schema | `OB-AP01`, `OB-K01`–`OB-K04`, `OB-SS03` |
| §5.5 groups/membership | `OB-SS01`–`OB-SS06`; application roles remain `OB-AP02` |
| §5.6 authorization/delegation | `OB-AP02`, `OB-PV02`, `OB-PV03` |
| §5.7 local vault | `OB-RS01`–`OB-RS05`, `OB-RS10`, `OB-RS11` |
| §5.8 transport/federation | `OB-TR01`–`OB-TR05`, `OB-TR10` |
| §5.9 reliability/store-and-forward | `OB-K13`, `OB-AP07`, `OB-RS03`–`OB-RS06`, `OB-TR03`, `OB-TR04`, `OB-PV01` |
| §5.10 ordering/synchronization/conflicts | `OB-K05`–`OB-K07`, `OB-K12`, `OB-AP04`, `OB-RS09` |
| §5.11 metadata protection | `OB-AP03`, `OB-TR02`, `OB-TR06`–`OB-TR10`, `OB-PV11` |
| §5.12 attachments | `OB-K10`, `OB-AP08`, `OB-PV09` |
| §5.13 multi-device/compromise | `OB-AP02`, `OB-SS01`–`OB-SS06`, `OB-RS09`, `OB-PV07` |
| §5.14 recovery/capability custody | `OB-AP09`, `OB-RS01`, `OB-RS09`, `OB-PV11` |
| §5.15 retention/deletion/export | `OB-K10`, `OB-K14`, `OB-AP05`, `OB-RS10`, `OB-PV03`, `OB-PV09` |
| §5.16 audit/receipts/evidence | `OB-K14`, `OB-AP07`, `OB-RS13`, `OB-TR03`, `OB-PV01`, `OB-PV04` |
| §5.17 SDK/capability discovery | `OB-AP01`, `OB-AP06`; each owner exposes only its own typed capability/result |
| §5.18 distribution/updates | `OB-RS12`, `OB-PV07`, `OB-PV10` |
| §5.19 observability/continuity | `OB-RS13`, `OB-TR08`, `OB-TR10`, `OB-PV04`, `OB-PV07` |
| §5.20 organizational custody | `OB-AP02`, `OB-PV02`–`OB-PV04`, `OB-PV07` |
| §5.21 compliance hooks | `OB-AP05`, `OB-PV06`; the protocol makes no compliance claim |
| §5.22 abuse resistance/safety | `OB-AP08`, `OB-TR09`, `OB-PV05`, `OB-PV08` |

## 8. Conformance and change control

Each layer needs separate conformance evidence:

- `K`: language-neutral positive and adversarial vectors plus independent
  implementations derived from the specification;
- `AP`: schema, authorization, conflict, retention and cross-context policy
  cases;
- `SS`: exact-profile peer interoperability, malicious Commit/member cases,
  crash/retention behavior and revision provenance;
- `RS`: transaction, crash, quota, concurrency, eviction, rollback, migration
  and release-verification tests on every supported runtime;
- `TR`: envelope/parser, relay-fault, metadata-capture, resource and
  confirmation-state tests on real infrastructure; and
- `PV`: end-to-end synthetic scenarios, accessibility, operator-role,
  incident, continuity, privacy/legal and safeguarding exercises.

A passing layer test is not evidence for another layer. A composition is
supportable only when every selected layer exposes a compatible versioned
contract and the full-path tests preserve the required validation order.

This matrix must be reopened if a normative rule has no owner, two owners claim
the same decision, a layer consumes an undocumented input, a profile weakens a
kernel invariant, or a product claim depends on evidence from only part of the
path.

## 9. O-09 decision

The Styx specification is factored into one application semantic kernel plus
separately versioned application, secure-session, runtime/storage,
transport/routing and product/organizational profiles. Sections 1–8 assign the
currently known obligations, define their cross-layer inputs and reject both
duplicate and ownerless authority.

Rejected alternatives are:

- a monolithic “core” that owns workflow, cryptography, storage and transport;
- the chat, JavaScript, Dart, Rust/OpenMLS or a runtime becoming authority by
  implementation accident;
- session membership or signature validity standing in for application role;
- runtime durability or relay publication standing in for application truth or
  human delivery; and
- a product vertical redefining kernel acceptance to fit one workflow.

Security consequence: a bypass at one layer cannot be legitimized by a success
signal from another layer. Residual risk: C0.2k supplies bounded commitment-
context evidence, O-06c supplies bounded combined-construction evidence and
O-14 supplies bounded guarded-signature evidence; none is proof or product
implementation. Genesis contents, production bounds, stable outcomes and AP
semantic injectivity remain owned by O-08/O-10/AP after O-07 fixes the outer
genesis block boundary. O-14's selected
semantics still trigger the separately ratified O-06c placeholder-substitution
rerun, and Dart/browser conformance remains unclaimed. The completed
C0.2d/C0.2f/C0.2k/O-06c/O-14 models remain bounded evidence. This allocation
alone is not executable protocol behavior.

Reopen O-09 only if a future obligation cannot be assigned without violating
the one-owner invariant, a new trust boundary requires a seventh normative
owner, or implementation evidence proves that an interface cannot preserve the
required validation/state-change order.
