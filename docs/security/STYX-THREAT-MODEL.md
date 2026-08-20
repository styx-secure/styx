# Styx application-protocol threat model

- **Status:** C0.2a security model; design input, not an implementation or
  readiness claim.
- **Authority:** Issue #207, ADR-0007 and the approved Styx Vision.
- **Scope:** the future language-neutral Styx application protocol and its
  boundaries with application, secure-session, runtime/storage, transport and
  organizational profiles.
- **Evidence baseline:** `main @
  6409bc1b530622dfd592e4ebdb66e242f458b378`.
- **C0.2e amendment:** O-04 payload commitment and logical-removal properties
  were refined by Issue #215 at base
  `b49482a13e239b3cec42ac0b264ca452cd78bd9f`.
- **C0.2f/O-06a amendments:** bounded payload-state falsification passed under
  Issue #217; Issue #219 inventories the semantic transcript and records
  digest-reference grinding without selecting cryptographic bytes.
- **Language:** English is canonical.

Styx is experimental, has not completed an independent security audit, and is
not ready for sensitive, high-risk or life-critical use. This document states
security objectives and ownership boundaries. It does not prove that current
code satisfies them, select the still-open v0 formats, or transfer assurance
from OpenMLS, Marmot, MDK or any upstream audit to Styx.

## 1. Security objective and scope

Styx is a secure application substrate for mutually distrustful environments.
Its application protocol is intended to let independently implemented clients
validate the same authenticated application history and apply the same
language-neutral transition rules while secure-session, runtime, transport and
product profiles supply their own bounded guarantees.

The protected system is therefore not only an encrypted message path. It is the
composition:

```text
person / organizational procedure
        |
        v
product vertical and application profile
        |  typed application intent, roles and policy
        v
Styx application semantic kernel
        |  authenticated application objects and classified outcomes
        v
secure-session adapter
        |  confidential authenticated session payloads and membership events
        v
runtime/storage profile
        |  key custody, durable state, rollback boundary and release provenance
        v
transport/routing profile
        |  store-and-forward envelopes, routing and observable metadata
        v
relay / network / notification infrastructure
```

The arrow is a trust boundary, not a claim that the current repository already
implements the complete path. The authoritative allocation of obligations is
the [C0.2a responsibility matrix](../protocol/styx-app-kernel-v0-responsibility-matrix.md).

## 2. Protected assets and properties

| Asset | Intended property | Detection/recovery expectation | Owner reference | Important limit |
| --- | --- | --- | --- | --- |
| Application plaintext and attachments | Confidentiality to the recipients selected by an authorized application transition | Authentication failure rejects delivery; compromise invokes rotation and product incident handling | `OB-SS03`, `OB-AP08`, `OB-PV09` | An authorized or compromised endpoint can disclose plaintext; attachment metadata requires separate handling. |
| Application event meaning | Integrity and authenticity of every field that affects validation, authorization, causality, ordering or conflict handling | Invalid transcripts and semantics are rejected before authoritative state change | `OB-K01`–`OB-K04`, `OB-K12` | A valid signature proves key possession, not role authorization or truth. |
| Application and case context | Domain separation and rejection of cross-context replay | Cross-context objects fail kernel validation | `OB-K08`, requirements from `OB-AP03` | O-03 and O-06a select the context tuple and genesis-reference role; exact O-06 bytes and O-07 genesis contents remain open. |
| Author and role authority | Explicit, rotatable, context-bound authorization | Unauthorized or stale authority is rejected; compromise invokes profile rotation/revocation | `OB-AP02`; binding by `OB-K01` | O-02 decides credential construction and binding; concrete profile grants and bounds remain future work. |
| Causal history and state | Deterministic validation, replay/fork detection and bounded convergence | Classified duplicate, replay, missing-parent, fork or conflict result | `OB-K05`–`OB-K07`, `OB-K13` | O-01/O-05/O-06a decide causality, clock placement and semantic transcript inputs; exact O-06 derivation remains open and digest tiebreaks are grindable. |
| Durable local state | Confidentiality, atomicity, crash safety and rollback behavior within a declared runtime profile | Fail closed on ambiguous persistence; restore/reconcile or require intervention | `OB-RS02`–`OB-RS10` | Browser storage may be evicted; a coherent whole-profile rollback may be undetectable without external evidence. |
| Session secrets and membership | Confidential authenticated delivery, membership control, forward secrecy and post-compromise recovery within the selected session profile | Reject invalid or unauthorized session transitions; rotate/recover within profile bounds | `OB-SS01`–`OB-SS09` | Phase B proves only the exact pinned isolated profile recorded by its verdict. |
| Return capabilities and recovery material | Unforgeability, confidentiality, context separation and intentional recovery semantics | Reject invalid/reused context; explain intentional irrecoverability or use the approved recovery route | `OB-AP09`, custody by `OB-RS01` | Loss may be unrecoverable; screenshots, backups and phishing can disclose a capability. |
| Routing and relationship metadata | Minimization and unlinkability only against the adversaries named by a concrete transport/product profile | Capture concrete data flow and run negative-linkage tests; rotate or disable exposed handles | `OB-TR02`, `OB-TR06`–`OB-TR10` | E2EE does not hide IP addresses, timing, size, frequency or stable routing handles by itself. |
| Local and remote delivery evidence | Truthful distinction between durable local commit, publication, device receipt and application receipt | Reconcile each typed stage; never promote missing evidence | `OB-RS06`, `OB-TR03`, `OB-AP07` | A relay acknowledgement is not proof that a person received or read an object. |
| Human workflow state | Truthful distinction between assignment, reading, action, rejection and closure | Authenticated workflow transition plus human/organizational audit where required | `OB-AP01`, `OB-AP02`, `OB-PV01`–`OB-PV04` | Software cannot prove that a human understood, acted lawfully or told the truth. |
| Content commitment, retention and evidence | Authenticated bounded descriptor and randomized-opening content binding; availability remains distinct from validity; logical removal is append-only | Preserve descriptor/commitment/removal evidence; halt the whole REQUIRED AP suffix when direct verification is unavailable; never substitute current checkpoint state | `OB-AP05`, mechanics by `OB-K10`/`OB-K14`, custody by `OB-RS02`–`OB-RS09`, presentation by `OB-PV03`/`OB-PV11` | Length/type/commitment may remain identifying; opening destruction prevents later ledger-only verification and may halt replay permanently; peers, backups, flash and screenshots may retain copies. |
| Software and configuration | Reproducible, attributable and rollback-aware distribution within a runtime profile | Reject unverifiable/rolled-back artifacts or surface an explicit unsupported state | `OB-RS12`, release decision by `OB-PV10` | A browser origin controlling the first response remains able to substitute JavaScript unless another trust root detects or prevents it. |
| Operational continuity | Bounded availability, recovery and separation of duties | Typed outage state, tested restore/failover and incident procedure | `OB-TR03`/`OB-TR04`, `OB-PV02`/`OB-PV07` | No profile promises uninterrupted service or protection from every correlated infrastructure failure. |

The model distinguishes the following properties rather than using “secure” as
a synonym for all of them:

- **content confidentiality**: an unauthorized observer cannot recover the
  protected plaintext;
- **cryptographic authenticity**: an object verifies under a declared key or
  session member;
- **application authorization**: that authenticated actor may perform the
  requested transition in this context and role;
- **integrity**: authenticated semantics cannot be modified undetectably;
- **causality and convergence**: clients classify predecessor, concurrent,
  replay, fork and conflict relationships consistently within declared bounds;
- **availability**: a profile has explicit retry, redundancy and recovery
  behavior, without treating delivery as guaranteed;
- **unlinkability**: a declared observer lacks a shared identifier or mapping
  for the scoped actions, subject to traffic-analysis limits;
- **erasure**: a logical transition and best-effort deletion policy, never an
  absolute physical-erasure guarantee;
- **content binding**: supplied content plus its opening recomputes the
  authenticated descriptor commitment; this is separate from event validity
  and does not prove content truth;
- **reconstructibility**: in v0 a fresh replica derives authoritative AP state
  from retained events and every directly verified in-horizon `REQUIRED`
  content/opening, or reports a declared deferred/stale limit. Current
  checkpoints never substitute for those inputs;
- **delivery state**: evidence for a precisely named stage, not a generic
  “sent” flag; and
- **human and organizational assurance**: procedures, training, independence
  and legal controls that cryptography cannot create.

## 3. Adversaries and capabilities

### A1 — Malformed-input sender

Can submit arbitrary, oversized, non-canonical, truncated, duplicated,
reordered or version-skewed bytes to any exposed parser. May adapt inputs from
observable errors and repeat them to exhaust CPU, memory, storage or logs.

The system must reject before state change when grammar, bounds,
canonicality, authentication or profile requirements fail. The model does not
assume that network input is well formed merely because it arrived inside an
authenticated session.

### A2 — Cryptographically valid but unauthorized actor

Controls a valid signing key, session membership credential or return
capability, but lacks the application role required for an action. May replay a
valid object in another case, use a stale role, attempt delegation or rotation,
or exploit disagreement between clients.

This adversary is why key possession, session membership and application
authorization are separate checks. O-02 fixes the semantic credential and
rotation model; concrete profile grants/bounds and the O-14 signature-suite
registry remain open.

### A3 — Malicious peer

Is intentionally authorized to receive some content and may withhold,
duplicate, reorder, fork, selectively relay or disclose it. It may propose
conflicting valid actions, omit parents, lie about local delivery/read state,
retain data after a deletion request, or repeatedly vary otherwise valid signed
inputs to bias its own digest-derived concurrent replay position.

Styx aims to make authoritative transitions and contradictions detectable and
deterministic. It cannot prevent an authorized recipient from copying content,
taking a screenshot, colluding outside the protocol or lying in the content of
a signed statement. Deterministic replay order is not a fairness mechanism:
application policy must not derive authorization, priority, first-writer-wins
truth or irreversible-effect authority from that position.

### A4 — Compromised authorized peer

An attacker obtains a currently authorized endpoint, device credential,
session state or application capability. The attacker may exercise all rights
that the compromised material permits until revocation or rotation takes
effect, and may retain any plaintext already available.

Profiles must define compromise response, revocation, rotation, history access
and post-compromise recovery. They must not claim retroactive confidentiality
for content already exposed.

### A5 — Hostile or colluding relay and service provider

Can observe connections and envelope metadata, store, omit, duplicate,
reorder, delay, replay, selectively censor or return stale objects. Multiple
relays may collude. A relay may lie about publication and deletion.

Relays are never authoritative for application validity, order, membership or
human delivery. Redundancy may improve availability while increasing the
observer set. A transport profile must declare every visible field and its
confirmation semantics.

### A6 — Network observer

Can observe one or more network links, including source/destination addresses,
timing, size, frequency and availability events. A stronger observer may
correlate several relays, push providers or origins but does not automatically
control endpoints or decrypt authenticated ciphertext.

No current Styx profile claims resistance to a global passive observer.
Padding, batching, delay, onion routing and cover traffic are profile choices
with cost, latency and residual statistical leakage.

### A7 — Compromised browser origin or release channel

Can serve targeted JavaScript, WASM loaders, configuration or updates and can
use an unlocked worker as an encryption/decryption oracle. It may exfiltrate
input before encryption or plaintext after decryption without extracting a
non-extractable key.

The PWA is deliberately a weaker runtime profile against this adversary. CSP,
Trusted Types, pinned artifacts, reproducible builds and transparency can make
substitution harder or detectable but cannot make an untrusted first response
trustworthy. A signed native profile may provide a stronger trust root but
requires its own threat model and audit.

### A8 — Same-origin script, XSS or malicious extension

Executes with page or browser privileges, can invoke exposed APIs, observe the
DOM and inputs, capture output, or abuse a crypto worker as an oracle. An
extension may exceed page-origin controls.

Worker confinement and non-extractable keys reduce accidental exposure; they
are not a complete boundary against a hostile caller with legitimate access to
plaintext operations. The runtime profile owns prevention, API minimization,
locking, containment and residual claims.

### A9 — Compromised or seized endpoint

Controls the operating system, input, screen, memory, accessibility services,
swap or device administration, or physically obtains the device. The attacker
may capture passwords and plaintext while unlocked. When locked, protection is
bounded by the concrete vault, KDF, hardware and password strength.

Styx cannot reliably zero JavaScript strings, guarantee physical deletion from
flash, or protect plaintext displayed to the user. A runtime profile must state
the locked and unlocked cases separately.

### A10 — Storage fault, eviction or rollback source

Can cause quota exhaustion, partial writes, corruption, deletion, eviction,
stale restoration or coherent rollback through browser behavior, backup,
filesystem snapshots or synchronization. This actor need not know plaintext.

Persistence failure must not be reported as success. Eviction or teardown loss
of the last content/opening copy is a typed durability failure, never logical
removal or erasure. Each runtime profile must define atomicity, recovery and
rollback-detection limits. Rolling back before a removal directive can
re-expose quarantined content and is a privacy regression. Security may require
halting rather than continuing from ambiguous state.

### A11 — Malicious organizational operator or administrator

Has legitimate access to some cases, administrative interfaces, logs,
infrastructure or policy. May exceed role, collude, alter retention, export
data, misuse emergency access, correlate reporters or conceal actions.

Least privilege, role separation, independent audit, revocation and high-impact
authorization are product/organizational obligations. Styx cannot guarantee
handler independence, lawful processing or protection from retaliation.

### A12 — Supply-chain or build adversary

Can compromise a dependency, build host, package registry, signing key,
artifact store or configuration channel. May target a single release or user.

Pins and reproducible builds are necessary evidence, not sufficient release
authentication. Runtime/distribution profiles own provenance, verification,
signing, rollback and incident response; upstream audits apply only to their
recorded source and scope.

### A13 — Availability adversary

Can block domains, relays, app stores, push services or network routes; exhaust
quotas; flood invitation or case endpoints; or cause correlated infrastructure
failure. It may exploit privacy defenses because per-IP controls can harm Tor
or NAT users and create identifying logs.

Profiles must bound resources and provide explicit offline, retry, failover and
abuse behavior. Styx does not claim unstoppable or cost-free delivery.

### A14 — Curious backup, telemetry or notification provider

Does not necessarily alter traffic but can retain storage replicas, crash
reports, endpoint identifiers, wake-up timing or diagnostic fields and combine
them with other data.

Sensitive profiles must minimize or forbid such services unless the exact
metadata and retention are reviewed. Encryption of application content does not
make telemetry or push metadata harmless.

### 3.1 Adversary coverage and required response

| Adversary | Primary assets/properties at risk | Required response and evidence | Sole obligation owners | Residual non-claim |
| --- | --- | --- | --- | --- |
| A1 malformed-input sender | Event meaning, session/runtime availability | Strict bounded parsing, canonical rejection, stable outcomes and resource tests before state change | `OB-K02`–`OB-K04`, `OB-SS08`, `OB-TR01` each at its parser boundary | A conforming parser cannot prevent all bandwidth exhaustion before bytes reach it. |
| A2 valid but unauthorized actor | Role authority, case state, retention/export | Separate authentication from context-bound authorization; negative role, rotation and revocation cases | `OB-AP02`; cryptographic binding by `OB-K01` | Concrete profile grants and bounds remain future work. |
| A3 malicious peer | Plaintext, causal state, availability, erasure | Detect replay/fork/conflict, preserve deterministic evidence, expose refusal/timeout, apply product incident process | `OB-K05`–`OB-K14`, `OB-AP04`, `OB-PV04` | An authorized peer can copy plaintext, withhold input or lie in signed content. |
| A4 compromised authorized peer | Current rights, plaintext and session history | Revoke/rotate, bound synchronized history, recover session and disclose the compromise state | `OB-AP02`, `OB-SS04`–`OB-SS06`, `OB-PV07` | No retroactive protection for plaintext or keys already obtained. |
| A5 hostile/colluding relay | Availability, freshness, routing metadata | Verify outer objects, ignore relay order as authority, retry/fail over and measure concrete exposure | `OB-TR01`–`OB-TR06`, `OB-TR10` | Colluding relays can correlate all metadata visible to their profile. |
| A6 network observer | Relationship and activity metadata | Use only profile-approved routing/padding/batching/onion measures and validate via traffic capture | `OB-TR06`/`OB-TR07` | No resistance claim against a global passive observer. |
| A7 hostile origin/release | Plaintext, keys-as-oracles, software integrity | Enforce distribution/profile controls, external verification and explicit unsupported/rollback outcomes | `OB-RS12`, release gate `OB-PV10` | The current PWA cannot make an adversary-controlled first response trustworthy. |
| A8 XSS/extension | Plaintext operations, UI trust, local metadata | Minimize callable interfaces and third-party code, lock promptly, enforce runtime containment and test browser controls | `OB-RS01`, `OB-RS11`, product copy `OB-PV11` | A privileged hostile caller can use an unlocked client as an oracle. |
| A9 seized/compromised endpoint | Plaintext, password, local state and recovery material | Distinguish locked/unlocked guarantees, encrypt storage, rotate after compromise and follow incident procedure | `OB-RS01`/`OB-RS02`/`OB-RS11`, `OB-PV07` | Keylogger, screen capture, memory and authorized-recipient leakage remain possible. |
| A10 fault/eviction/rollback | Durable state, causality, availability | Atomic fail-closed persistence, crash reconciliation, runtime probes and bounded rollback evidence | `OB-RS03`–`OB-RS10` | Coherent rollback can remain undetectable when no independent evidence exists. |
| A11 malicious operator | Case confidentiality, role authority, audit and erasure | Least privilege, separation of duties, high-impact approval, minimized independent audit and alternate route | `OB-PV02`–`OB-PV06`; machine role semantics `OB-AP02` | Protocol cannot ensure independence, lawful action or prevent off-protocol disclosure. |
| A12 supply-chain/build adversary | Software/configuration and all plaintext handled by it | Exact provenance, reproducible artifacts, signed/verified updates, rollback control and incident response | `OB-RS12`, `OB-PV07`/`OB-PV10` | Upstream audit evidence does not transfer across revision, configuration or Styx integration. |
| A13 availability adversary | Delivery, access and organizational continuity | Bounds, backoff, failover, offline truth, abuse-aware controls and continuity drills | `OB-TR03`/`OB-TR04`/`OB-TR09`, `OB-PV07`/`OB-PV08` | Styx does not guarantee unstoppable, timely or cost-free delivery. |
| A14 backup/telemetry/push provider | Local replicas, endpoint mapping and behavioral metadata | Minimize/forbid external signals, declare retention, isolate audit and test notification data flow | `OB-RS13`, `OB-TR08`, `OB-PV04` | Providers may retain allowed metadata and correlate it with external datasets. |

## 4. Trust assumptions

The semantic-kernel objectives depend on all of these assumptions:

1. the chosen cryptographic primitives remain sound and are invoked according
   to their reviewed contracts;
2. clients execute the same ratified specification and fail closed on unknown
   versions, invalid inputs and unsupported profiles;
3. private keys and capabilities are generated with a cryptographically secure
   random source and remain confidential until the modeled compromise;
4. application authorization inputs are themselves authenticated and bound to
   the same application/case context;
5. at least one honest local execution observes the relevant history when a
   property depends on local detection; and
6. human operators follow the separately declared organizational procedure
   where the claimed property depends on people rather than protocol state.

These assumptions are not transitive. For example, an authenticated session
does not make a role assignment valid, successful local storage does not prove
remote delivery, and a reproducible WASM artifact does not authenticate all
JavaScript delivered by a web origin.

## 5. Trust boundaries and visible information

| Boundary | Input crossing the boundary | Receiver may learn | Receiver must not be trusted to decide |
| --- | --- | --- | --- |
| Person → product vertical | Plaintext intent, consent, recovery action and human context | Everything the UI collects or displays | Cryptographic validity, causal order or safe persistence merely from user input |
| Product/application profile → kernel | Closed-schema transition request, claimed actor/context, bounded payload and authenticated authorization state or explicit approved state reference | Application semantics intentionally supplied | Whether an unauthenticated, author-selected stale-policy or out-of-context request is valid |
| Kernel → secure-session adapter | Versioned authenticated application object plus destination/session reference selected by a profile | Object size and the session-routing input exposed by that interface | Application authorization, conflict policy or durable application truth |
| Secure-session adapter → runtime/storage | Session secrets/state, ciphertext, membership outcomes and typed recovery needs | The local runtime necessarily handles protected state | Product role semantics or relay publication as proof of delivery |
| Secure-session/runtime → transport | Opaque envelope, routing handle, relay set, timing and delivery request | At least envelope size, time, route and connection metadata declared by the transport profile | Plaintext validity, application order, membership authority or human receipt |
| Transport → relay/network | Protocol-specific event or blob and network connection | All outer fields, IP/network data, timing, size, frequency and retry pattern visible in that profile | Event truth, authoritative order, deletion completion or final delivery |
| Runtime → notification/telemetry provider | Wake-up token or minimized diagnostic signal | Endpoint mapping, timing, client/profile attributes included in the signal | Case identity, message content or authoritative workflow state |
| Product → organizational operations | Case view, role action, audit event, retention/export request | Content and metadata allowed by the role and deployment | Universal plaintext access, unrecorded override or automatic legal correctness |

Every supported profile must instantiate this table with concrete fields. An
unknown field is visible until evidence shows otherwise. Encryption claims
cover only the bytes actually protected by the named layer.

## 6. Required adversarial outcomes

The following are requirements on future specifications and profiles, not
claims about current code.

| Scenario | Required outcome | Detection or recovery expectation | Owning layer or explicit obligation split |
| --- | --- | --- | --- |
| Malformed or non-canonical application object | Reject before authoritative state change | Stable classified failure; no parser detail leak beyond the future error policy | Application semantic kernel |
| Valid signature under an unauthorized key | Reject the transition | Product can explain authorization failure without treating it as bad cryptography | Application profile |
| Object replayed in another case/application | Reject by authenticated context binding | Cross-context negative evidence | Application semantic kernel |
| Duplicate authenticated object in one context | Idempotent duplicate classification | No duplicate application effect | Application semantic kernel |
| Missing parent, fork or concurrent operation | Classify under the selected bounded causal model | Deterministic recovery, rejection or application conflict handoff | Application semantic kernel |
| Authorized author grinds a concurrent event reference | Preserve validity/causal/fork classification; treat the result only as a deterministic replay position | Application policy independently resolves the conflict and never grants priority or irreversible authority from position | Application semantic kernel plus application profile |
| Semantically conflicting but individually valid operations | Do not infer business truth from total order | Apply the application profile's declared conflict rule or escalate | Application profile |
| Unauthorized session membership change | Reject before applying the membership transition | Typed session failure and recovery path | Secure-session adapter |
| Relay duplication, reordering, omission or stale response | Never alter application validity; reconcile within delivery policy | Retry/failover or explicit unavailable/expired state | Transport/routing profile |
| Crash between durable transition and send | Resume without duplicate effect or false delivery | Reconcile outbox and idempotency state | Runtime/storage profile |
| Persistence or quota failure | Fail closed; do not report success | Typed fatal/recoverable outcome according to the runtime contract | Runtime/storage profile |
| Coherent local rollback | Detect only within the profile's declared anchor/evidence model; otherwise state the non-claim; rollback past removal may re-expose quarantined content | Halt, resynchronize or require user action when detected; never present re-exposure as corrected state | Runtime/storage profile |
| Targeted malicious web release | No PWA guarantee beyond the declared prevention/detection controls | External artifact verification or migration to a stronger signed profile | Runtime/storage profile |
| Metadata-minimizing delivery | Reveal only the fields allowed by the concrete profile | Data-flow capture and negative linkage evidence against named observers | Transport/routing profile |
| Operator attempts unauthorized export or policy change | Enforce role and high-impact authorization policy | Minimized independent audit record and incident procedure | Product vertical and organizational operations |
| Retention/deletion request authorization | Admit only a context-bound action permitted by the selected data-class policy | Reject unauthorized or out-of-policy requests | Application profile |
| Evidence-preserving prune transition | Apply the authenticated logical transition without promising physical erasure | Preserve the declared commitment/proof and classify invalid history | Application semantic kernel |
| Content bytes or opening absent | Keep the event valid and causal identity unchanged; expose typed availability/binding/readiness | Defer a `REQUIRED` replay suffix or apply the profile's declared `DETACHABLE` reconstruction contract | Application semantic kernel with application profile |
| Content mismatches descriptor, length or opening | Never reinterpret corruption as absence or removal | Reject content presentation with a stable typed outcome; retain event validity independently | Application semantic kernel |
| Content reappears after valid logical removal | Do not silently reactivate or expose it | Distinguish verified removed presentation, unverifiable presentation and substituted presentation; none becomes active | Application semantic kernel and product vertical |
| Physical destruction requested or caused by runtime pressure | Never infer authority from replay position, timeout, retry/peer count, relay response, quota, eviction or teardown | Quarantine/withhold until O-13 closes; report physical loss as typed durability failure, never removal | Application profile and runtime/storage profile |
| Fresh replica follows compacted history | Continue causal validation from permitted O-01 evidence, but derive AP state only from retained events and directly verified REQUIRED content/openings | Otherwise halt the AP suffix and report deferred/stale; current checkpoints never substitute | Application semantic kernel and application profile |
| Checkpoint material offered for AP-state substitution | Treat the capability as unsupported in v0 | Never trust producer eligibility or AP state; O-07 must first define authentication, authority, acceptance, rollback, equivocation, horizon and late-evidence handling | Application semantic kernel and application profile |
| Service/relay outage | Preserve local truth and expose unavailable delivery state | Bounded retry, alternate routes and continuity procedure | Transport/routing profile |

## 7. Metadata and unlinkability model

Metadata protection is never inherited from payload encryption. A profile must
inventory at least:

- outer author or event key;
- recipient, group, mailbox or case routing handle;
- relay set and subscription filters;
- timestamps and ordering fields outside encryption;
- ciphertext and attachment sizes, padding buckets and chunk counts;
- frequency, retry cadence, typing, presence, read receipt and acknowledgement
  traffic;
- IP address, route, TLS endpoint and onion/non-onion choice;
- push token, wake-up timing and notification payload;
- client version, browser fingerprint and error/telemetry dimensions;
- recovery, backup and support interactions; and
- durable local namespaces or identifiers accessible to the modeled observer.

For each field the profile must state: observer, purpose, lifetime, rotation,
cardinality, correlation risk and mitigation. “Ephemeral” is not synonymous
with “unlinkable”; timing and reuse can correlate ephemeral values. Multiple
relays are not anonymity. NIP-59, NIP-44, Marmot envelopes, padding or Tor may
be evaluated by later profiles but are not selected by this document.

For an anonymous-dialogue profile, anonymity and unlinkability dominate public
rollback anchoring when the latter would create a stable public correlator. A
future design may use in-band mutual evidence, an organization-side anchor or
another bounded construction, but the trade-off requires a separate decision
and adversarial evidence.

## 8. Runtime profiles

### 8.1 Browser/PWA profile

The browser is the first intended runtime profile, not the protocol authority.
Its minimum envelope assumes:

- storage can fail, be cleared, evicted or coherently restored;
- execution can stop at any instruction and background execution is not
  guaranteed;
- multiple same-profile contexts may contend unless serialized;
- the password enters JavaScript and cannot be reliably zeroed;
- an unlocked hostile origin, extension or endpoint can access plaintext
  operations even if keys are non-extractable; and
- first-load code authenticity is weaker than that of a separately verified,
  signed installed client.

A browser profile must test actual supported WebKit, Chromium and Firefox
behavior for persistence, quota, private modes, locking, suspension, restore
and updates. Installation or `navigator.storage.persist()` must not be treated
as an absolute non-eviction guarantee.

### 8.2 Future signed native profile

A native profile may add signed artifacts and updates, operating-system key
stores, hardware-backed keys and stronger rollback controls. Those mechanisms
do not automatically protect a compromised operating system, screen, input,
recipient or organizational process. No native profile is currently promised
or covered by this threat model beyond the boundary requirements shared with
the application protocol.

## 9. Product and organizational limits

The product vertical owns workflow truth: which roles exist, which transitions
they may authorize, what conflicts require human review, and what retention,
export, emergency and safeguarding procedures apply. Cryptographic proof can
show that a declared key authorized bytes under a protocol rule. It cannot
prove that:

- a report is factually true;
- a civil identity is who it claims to be without a separately defined
  verification process;
- an operator is independent or acted lawfully;
- a recipient deleted a copy or screenshot;
- retaliation will not occur;
- a deployment complies with a law, standard or certification; or
- an automated alert reached a trained person in time.

Themis therefore requires a separate deployment threat model, DPIA/legal and
safeguarding review, trained handlers, conflict-of-interest route, incident and
emergency procedures, and explicit pilot authorization. Synthetic data and
non-sensitive exercises do not authorize real reports.

## 10. Current evidence and non-claims

Current evidence establishes only bounded components:

- C0.1 characterizes Dart and JavaScript legacy-ledger behavior; it also shows
  why current matches cannot define the protocol;
- C0.2a through C0.2f decide K-01 through K-11, O-01 through O-05 and O-09
  within their stated evidence bounds; O-06a inventories the semantic
  transcript without selecting cryptographic bytes; O-06, O-07, O-08 and
  O-10 through O-14 remain open;
- Phase B demonstrates the exact-pin isolated Styx/MDK direct-MLS profile
  described in its final verdict; and
- existing vault and chat work provides component evidence under its own
  reports and tests.

This threat model does not establish application-protocol conformance,
supported Marmot/Nostr envelopes, product integration, metadata anonymity,
whole-profile rollback detection, secure first-load PWA distribution, legal
compliance, audit coverage or production readiness.

## 11. Closure and maintenance rules

Before a supported application profile or pilot, the project must add:

1. exact protocol objects, transitions and stable errors derived from closed
   decisions;
2. adversarial conformance cases including replay, fork, rollback, malformed
   input, resource bounds and cross-context negative cases;
3. a concrete profile data-flow capture naming every visible metadata field;
4. implementation and crash evidence on every supported runtime;
5. release provenance and rollback evidence for the distributed artifact;
6. independent review of the exact Styx-authored boundary; and
7. product, privacy, legal and organizational readiness gates appropriate to
   the vertical.

This document must be reopened when a profile adds an actor, trust boundary,
secret, external service, recovery path or security claim not represented
above, or when implementation evidence disproves an assumption. A new profile
may strengthen a guarantee; it must not silently weaken a kernel invariant or
redefine another layer's authority.
