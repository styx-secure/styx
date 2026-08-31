<!-- styx-canonical:v1 mirror="docs/platform/integration-roadmap_IT.md" -->
# Roadmap for integrating application capabilities into Styx

[Italian mirror](integration-roadmap_IT.md)

> **Status:** exploratory, non-normative proposal
> **Observed base:** `main @ d90931a3f59ce89c1594cad64ce385d58857b305`
> **Public-claims synchronization:** assurance and exercise/pilot wording is
> aligned with the current `docs/PROJECT_BRIEF.md`; the capability inventory
> remains the snapshot from the observed base above.
> This roadmap proposes candidates for future Issues. It does not authorize
> code, cryptography, persisted formats, migrations, or vault changes.

## Active planning gate

The [application-protocol hardening plan](../protocol/protocol-hardening-plan.md)
currently freezes new product and runtime implementation. Protocol decisions,
threat-model reconciliation, adversarial evidence and language-neutral
conformance take priority until the plan's human-ratified exit gates pass.
Issue #266 / merged PR #267 completed a bounded evidence GO for the exact D4
transcript/K corpus and evidence package. C0.3 nevertheless remains `NO-GO`
for implementation alignment, demo, product and sensitive use. Only a
separately contracted SS-0 increment limited to the plan's permitted
protocol-artifact classes may proceed; this roadmap does not bypass that gate.

## 1. Method and legend

The assessment starts from current code and decisions. The four permitted
states are:

- **implemented**: a working, tested path exists in the named stack; this does
  not imply an audit or production readiness;
- **partial**: a primitive or incomplete/unintegrated path exists;
- **missing**: no usable path exists in the named product;
- **separate design decision**: implementation must not begin before an
  approved technical or security decision.

The JavaScript/Rust/MLS stack is the canonical product
(`docs/architecture/decisions/ADR-0001-canonical-product-stack.md`). The Dart
stack is a reference implementation and source of requirements/tests, not a
second core to extend (ADR-0003).

## 2. Summary status

| Capability | JS/MLS product | Dart reference | Evidence and primary limitation |
|---|---|---|---|
| 1:1 E2EE chat | **implemented** | **implemented** for the different ledger | JS: `styx-js/src/chat/styx-chat.js`, `styx-js/src/crypto/mls/mls-engine.js`. Dart: `packages/styx/lib/src/sovereign_ledger.dart`. The two models are not interoperable. |
| Authenticated QR pairing | **implemented** | **implemented** | JS: `styx-js/src/chat/styx-chat.js`. Dart: `packages/styx/lib/src/pairing/qr_pairing_service.dart`. This does not amount to civil identity. |
| Safety number / peer verification | **implemented** | **partial** | JS: `styx-js/src/chat/styx-chat.js`, `styx-js/src/chat/contact-roster.js`. Dart: `packages/crypto_core/lib/src/session_verifier.dart`, `packages/styx/lib/src/trust/trust_store_manager.dart`. |
| Remote pairing in the product | **missing** | **implemented** | JS: `styx-js/src/chat/styx-chat.js` raises `remote pairing not implemented yet`. Dart: `packages/styx/lib/src/pairing/remote_pairing_service.dart`. |
| Persistent self-custodied identity | **implemented** | **implemented** | `styx-js/src/crypto/identity.js`; `packages/crypto_core/lib/src/identity_manager.dart`. A durable identity is correlatable. |
| Separate application identity | **missing** | **missing** | There is no `application context` contract or per-application derivation. |
| Ephemeral per-case identity | **missing** | **missing** | There is no one-time key lifecycle or cross-case guarantee. |
| Anonymous return capability | **missing** | **missing** | No capability can reopen a mailbox without an account. |
| Product groups N>2 | **partial** | **separate design decision** | JS: `styx-js/src/crypto/mls/mls-engine.js` handles the MLS core, while `styx-js/src/chat/styx-chat.js` models one session per contact and does not expose complete membership. Dart must not be extended as the core. |
| Application roles, delegation, and revocation | **missing** | **missing** | Trust/pairing do not constitute RBAC or capability authorization. |
| Encrypted IndexedDB vault | **partial** | **missing** | JS: `styx-js/src/storage/vault-db.js`, `styx-js/src/storage/vault-record.js`, `styx-js/docs/vault-test-matrix.md`; the matrix is canary-only and defers cross-worker behavior to US-008. Dart does not implement this canonical web vault. |
| Chat data migration into the vault | **missing** | **separate design decision** | `styx-js/docs/vault-test-matrix.md` marks migration `N/A`; schema, rollback, and product namespace require dedicated Issues. |
| Worker-confined secrets | **partial** | **missing** in the web model | JS: `styx-js/src/crypto/vault-worker-runtime.js`, `styx-js/src/crypto/vault-worker-supervisor.js`, `styx-js/src/crypto/vault-worker-protocol.js`; the full lifecycle is addressed by US-008. |
| Federated Nostr transport | **implemented** | **implemented** as a reference | `styx-js/src/transport/nostr-chat-transport.js`; `packages/transport/lib/src/nostr/`. The product uses multiple relays but does not hide metadata. |
| Incoming event signature verification | **implemented** | **missing** | JS: `styx-js/src/transport/nostr-chat-transport.js`. Dart: `packages/transport/lib/src/nostr/nostr_transport.dart` filters and decrypts but does not verify a Nostr signature. |
| Replay deduplication | **partial** | **partial** | JS: `styx-js/src/transport/nostr-chat-transport.js` uses an in-memory `_seen` capped at 5000. Dart: `packages/transport/lib/src/nostr/nostr_transport.dart` uses an in-memory LRU cache. Both are lost on restart. |
| Persistent product outbox | **missing** | **implemented** as a reference | JS: `styx-js/src/chat/styx-chat.js` persists the message but sends directly. Dart: `packages/transport/lib/src/failover/outbox_worker.dart`, `packages/storage/lib/src/dao/outbox_dao.dart`. |
| Real ACK and delivery states | **missing** | **missing** | JS: `styx-js/src/transport/nostr-chat-transport.js` calls `publish()` without waiting and `styx-js/src/chat/styx-chat.js` marks `sent` on return. Neither stack demonstrates publish ACK plus device ACK end to end. |
| Retry/backoff and dead-letter | **missing** in the chat path | **partial** | JS: `styx-js/src/transport/failover.js` contains legacy primitives not integrated into `styx-js/src/chat/styx-chat.js`. Dart: `packages/transport/lib/src/failover/transport_failover.dart`, `packages/transport/lib/src/failover/outbox_worker.dart`. |
| Persistent idempotency | **missing** | **partial** | JS: UUID and in-memory deduplication in `styx-js/src/transport/nostr-chat-transport.js` are not crash-safe. Dart: identifiers in `packages/ledger_engine/lib/src/event_factory.dart` and outbox persistence in `packages/storage/lib/src/dao/outbox_dao.dart` are reference evidence, not product proof. |
| Ordering and application merge | **missing** in the chat product | **implemented** as a reference ledger | Dart: `packages/ledger_engine/lib/src/hlc.dart`, `packages/ledger_engine/lib/src/vector_clock.dart`, `packages/ledger_engine/lib/src/conflict/deterministic_merge.dart`. The legacy `styx-js/src/ledger/` port is separate from `StyxChat`; policy remains application-specific. |
| Pending commit / MLS ACK-gating | **missing** | **separate design decision** | Explicit debt in `docs/security/2026-07-11-fattibilita-piano-utente.md` §3.5; this requires Rust/WASM APIs. |
| MLS fork detection | **missing** | **separate design decision** | The core does not expose epoch/tree hash/context; see the same plan §3.5. |
| Encrypted read receipt | **implemented** | **missing** as a product | JS: `styx-js/src/chat/styx-chat.js` encrypts `markRead/_sendReceipt` through MLS; the relay still sees the event, timing, and relationship. |
| Encrypted typing payload | **missing** | **missing** | JS: `styx-js/src/chat/styx-chat.js` sends `{t: 'typing'}` outside MLS; `styx-js/src/transport/nostr-chat-transport.js` applies only Base64. M4 remains open in `docs/security/2026-07-10-styx-chat-security-report.md`. |
| Outer metadata protection | **missing** | **partial** conceptually | JS: H2 remains open in `docs/security/2026-07-10-styx-chat-security-report.md`; `styx-js/src/transport/nostr-chat-transport.js` exposes `pubkey`, the `p` tag, time, and size. Dart: `packages/push_bridge_client/lib/src/privacy_profile.dart` provides reference profiles only. |
| Gift wrap / non-identifying mailbox | **missing** | **missing** | Explicit debt in `docs/security/2026-07-11-fattibilita-piano-utente.md` §3.6. Current kind `1059` is not a gift wrap. The concrete technique is a **separate design decision**. |
| Tor/onion in the web product | **missing** | **partial** | JS: `styx-js/README.md` expects external Tor Browser use, not an overlay. Dart: `packages/transport/lib/src/tor/tor_manager.dart`, `packages/transport/lib/src/tor/tor_transport_decorator.dart`; the decorator does not prove end-to-end routing. |
| Push without identity correlation | **missing** | **partial** | JS/server: `push_bridge/src/registry.js` registers endpoints against observable handles. Dart: `packages/push_bridge_client/lib/src/push_bridge_client.dart`, `packages/push_bridge_client/lib/src/privacy_profile.dart`; no end-to-end anonymous handle exists. |
| Padding, batching, cover traffic | **missing** | **partial** conceptually | Dart: `packages/push_bridge_client/lib/src/privacy_profile.dart`, `packages/push_bridge_client/lib/src/dummy_detector.dart`; these are references and do not demonstrate the property in the product. There is no active JS path. |
| Secure attachments | **missing** | **partial** | Dart: `packages/transport/lib/src/email/email_encoder.dart` handles email attachments but not sanitization and metadata for sensitive applications. The JS chat has no path. |
| Identity backup | **missing** in the chat product | **implemented** as a reference | `packages/styx/lib/src/backup/shamir_backup_service.dart`; legacy JS Shamir primitives are not integrated into the canonical MLS core. |
| Multi-device and device revocation | **missing** | **partial** as a reference | Dart: `packages/styx/lib/src/migration/rekey_protocol.dart`, `packages/styx/lib/src/migration/key_migration_service.dart`, `packages/styx/lib/src/sovereign_ledger.dart`. The MLS product requires a separate epic and design. |
| Retention and pruning | **missing** in the chat product | **implemented** as a reference | Dart: `packages/ledger_engine/lib/src/pruning/prune_protocol.dart`, `packages/ledger_engine/lib/src/pruning/retention_manager.dart`. The `styx-js/src/ledger/pruning.js` port is separate from `StyxChat`; nothing ensures recipient deletion. |
| Controlled export / legal hold | **missing** | **missing** | No application policy or role separation exists. |
| Privacy-safe administrative audit | **missing** | **missing** | Event history is not an operator audit. |
| Reproducible WASM build | **implemented** | **separate design decision** | JS: `styx-js/vendor/openmls-wasm/PROVENANCE.md`, `styx-js/vendor/openmls-wasm/build.sh`, `styx-js/vendor/openmls-wasm/verify.sh`; this alone does not authenticate the served PWA. |
| PWA first-load/update authenticity | **partial** | **separate design decision** | JS: the service worker in `styx-js/apps/chat/src/sw.js` and CSP headers in `styx-js/apps/chat/static-server.mjs` reduce some risks; a compromised origin can still serve a malicious client. |
| SDK independent of chat | **missing** | **partial** as a reference facade | JS: `styx-js/src/chat/styx-chat.js` is chat-specific. Dart: `packages/styx/lib/src/sovereign_ledger.dart` is a facade over the non-canonical core. |
| Capability/version discovery | **missing** | **missing** | The worker has an internal protocol version, not an application-platform contract. |
| Compliance hooks | **missing** | **partial** | Dart: `packages/ledger_engine/lib/src/pruning/retention_manager.dart` provides reference retention; workflows, roles, legal hold, and regulatory routing are absent. |
| Verifiable assurance profiles | **missing** | **partial** conceptually | Dart: `packages/push_bridge_client/lib/src/privacy_profile.dart` defines local profiles, not verified end-to-end assurance profiles. |
| Targeted independent review of a bounded high-risk scope | **missing** | **missing** | The README prohibits high-risk use; an upstream OpenMLS audit does not cover the Styx-authored scope, integration, PWA, application protocol, or operations. Review boundaries, residual risks, remediation, and retest must remain explicit. |

## 3. What to reuse and what not to reuse

### From the active JavaScript product

Preserve as a foundation:

- MLS and transport-identity binding in the chat path;
- authenticated QR pairing and safety numbers;
- incoming Nostr event verification;
- versioned MLS envelope and fail-closed behavior;
- dedicated worker and closed-grammar protocol;
- canary vault and its atomicity/corruption tests;
- reproducible build of the WASM boundary;
- CSP, reset, and CI discipline.

Decouple from chat:

- identity;
- object storage;
- delivery states;
- application payload schema;
- relay and notification selection;
- retention/recovery policy.

### From the Dart reference implementation

Turn into requirements or tests:

- ordered outbox and retry;
- transport failover;
- HLC/vector clocks and deterministic merge;
- bilateral/unilateral pruning and retention;
- remote pairing with out-of-band verification;
- threshold backup;
- re-key and blessing of a new device.

Do not transfer implicitly:

- primitives or cryptographic formats incompatible with MLS;
- Tor claims without proof on the canonical client;
- ledger semantics as a universal conflict solution;
- the `SovereignLedger` facade as a product API;
- cross-stack test vectors as proof of MLS chat interoperability.

## 4. Proposed integration sequence

The sequence protects the current critical path and defers sensitive choices to
their human gates.

```text
US-008: vault in the worker (canary)
       │
       ├── product namespace + verified migration
       │
application context + identity profiles
       │
secure object contract + minimum SDK
       │
reliable delivery + sync policy
       │
metadata-minimizing transport
       │
recovery / multi-device / role custody
       │
anonymous-dialogue reference application
       │
targeted bounded review → remediation/retest
       │
separately gated synthetic/non-sensitive exercise or pilot decision
```

### Increment A — Consolidate the canary vault

**Dependency:** US-008.
**Future outcome:** lifecycle and canary operations actually run in the worker,
with complete tests and CI.
**Does not include:** product data or migration.

This increment is already contracted separately and must not be broadened by
the platform effort. That separate contract is paused by the active planning
gate while the protocol-hardening freeze remains in force.

### Increment B — Product namespace and migration

**Dependency:** A.
**Candidate outcome:** an explicit decision on the product database, namespace,
data classes, bootstrap order, and `localStorage → vault` migration with
verified rollback.
**Human gate:** persisted format, migration, and vault architecture.

Before design, every item currently persisted by `StyxChat` must be inventoried,
including aliases, roster, messages, groups, and MLS state. This is not an
acceptable side effect of an application feature.

### Increment C — Application context and domain separation

**Dependency:** B for persistence; a purely formal spike may precede it.
**Candidate outcome:** an application and per-case context model with tests for
separation of keys, AAD, namespaces, and identifiers.
**Human gate:** derivations and formats.

This does not introduce anonymity; it builds the boundary needed to verify it
later.

### Increment D — Identity profile lifecycle

**Dependency:** C.
**Candidate outcome:** a data-only API to create, rotate, revoke, and destroy
`persistent`, `application`, and `case-ephemeral` identities, with a threat
model and non-reuse tests.
**Separate design:** `anonymous-capability` and organizational custody.

### Increment E — Secure application object contract

**Dependencies:** C, D.
**Candidate outcome:** a versioned application envelope schema, bounds, AAD,
idempotency key, and unknown-type handling.
**Does not include:** a universal merge format or executable language.

The goal is to let chat, accounting, and casework share the pipeline without
sharing semantics.

### Increment F — Minimum SDK independent of chat

**Dependency:** E.
**Candidate outcome:** a limited facade for context, identity, session, object,
capability discovery, and typed subscription. `StyxChat` becomes a
consumer/adapter rather than the home of every primitive.

A design mock cannot be the source of the production contract.

### Increment G — Reliable delivery

**Dependencies:** B, E.
**Candidate outcome:** vault-backed outbox, publication acknowledgement,
encrypted device/application ACK, retry, backoff, persistent deduplication,
expiry, and post-crash reconciliation.
**Success criterion:** no “sent” state based solely on calling `publish()`.

Ideas from `packages/transport/lib/src/failover/outbox_worker.dart` are reference
material, not code to connect to the canonical stack.

### Increment H — Synchronization and conflict policy

**Dependency:** G.
**Candidate outcome:** sequence, gap/replay/fork primitives and an API for
application-specific policies.
**Separate design:** pending commit/ACK-gating/MLS fork detection because they
require Rust/WASM APIs and format decisions.

### Increment I — Metadata-minimizing routing

**Dependencies:** D, G.
**Candidate outcome:** non-identifying mailbox, protected outer envelope,
ephemeral outer keys, padding, timestamp policy, and residual metadata analysis.
**Human gate:** selection and concrete profile of NIP-44/NIP-59 or an
alternative.

The work must include a hostile relay, colluding relays, network observer, and
push provider. Hiding the sender while leaving a stable recipient does not
close H2.

### Increment J — Tor/onion and notification profile

**Dependency:** I.
**Candidate outcome:** a documented, tested path through Tor Browser/onion or a
native client, with leak tests; disableable notifications and manual polling.
**Non-goal:** a promise against a global observer.

### Increment K — Recovery and multi-device

**Dependencies:** B, D, H.
**Candidate outcome:** per-device credentials, listing/revocation, rotation,
recovery, and history synchronization.
**Human gate:** MLS state, persisted formats, backup, and compromise.

The Dart Shamir backup becomes a requirement to reassess, not the automatic
solution for MLS.

### Increment L — Organization roles and custody

**Dependencies:** D, F, K.
**Candidate outcome:** roles, assignment, revocation, separation of duties, and
administrative audit.
**Separate design:** threshold/multi-recipient/escrow.

### Increment M — Anonymous return capability

**Dependencies:** C, D, G, I; J for the stronger profile.
**Candidate outcome:** a locally generated high-entropy capability, unlinkable
mailbox/case, recovery UX, and brute-force protection.
**Human gate:** representation, storage, protocol, and rotation.

### Increment N — Reference application: anonymous dialogue

**Dependencies:** F, G, I, M; L when organization-managed.
**Candidate outcome:** a `text-only` application with submission, follow-up,
operator states, retention, and security warnings.
**Does not include:** a compliance or absolute-anonymity claim.

### Increment O — Distribution assurance

May proceed in parallel when files do not overlap, subject to the active
planning gate; it is paused while the protocol-hardening freeze remains in
force.
**Candidate outcome:** PWA and update verification, release manifest,
appropriate transparency or signatures, independent artifact comparison, and a
separate native high-assurance profile.

### Increment P — Targeted review and separately gated exercise/pilot decision

**Dependencies:** those required by the selected profile.
**Candidate outcome:** independent review of a contractually bounded high-risk
scope, remediation, and retest. Only a separate human gate may then authorize a
synthetic or non-sensitive organizational exercise, or a decision about whether
a later controlled pilot can be designed, with privacy-safe metrics.

No high-risk pilot may begin with H1/H2 open or with required CI jobs failed,
cancelled, absent, or skipped without authorization.

## 5. Candidates for future contractual Issues

Each row is intentionally atomic and requires a complete contract.

| Candidate | Observable outcome | Dependencies | Likely sensitive gate |
|---|---|---|---|
| `platform-context-model` | contexts and cross-context tests | vault product design | crypto/persisted format |
| `platform-identity-profiles` | persistent/application/case lifecycle | context | crypto/vault |
| `platform-object-envelope` | versioned data-only schema | context/identity | persisted/wire format |
| `platform-sdk-minimum` | API independent of chat | object envelope | shared interface |
| `transport-reliable-outbox` | ACK, retry, crash-safe idempotency | product vault | workflow/possibly format |
| `transport-mailbox-privacy-design` | threat model and decision record | identity/reliable transport | crypto/protocol |
| `transport-mailbox-privacy-implementation` | tested metadata layer | approved design | crypto/wire format |
| `platform-anonymous-capability-design` | capability and recovery model | context/identity | crypto/persisted format |
| `platform-anonymous-capability-runtime` | reopenable case mailbox | design + metadata | vault/protocol |
| `platform-organization-roles` | roles/revocation/audit | SDK/device identity | authorization/key custody |
| `app-anonymous-dialogue-mvp` | end-to-end text-only flow | platform prerequisites | privacy/legal review |
| `distribution-authenticity-design` | first-load/update model | reproducible builds | release architecture |
| `relay-reference-deployment` | reproducible configuration | metadata design | runtime manifests/secrets |
| `platform-targeted-assurance-review` | bounded report, remediation, and retest | candidate release + approved scope | mandatory human review |
| `platform-nonsensitive-exercise` | synthetic/non-sensitive workflow exercise and findings | targeted review + selected profile prerequisites | separate human/privacy/legal gate |

## 6. Non-regression criteria

Evolution toward a platform must not:

- reactivate “serverless,” “zero metadata,” or “absolute anonymity” claims;
- create a second product cryptographic implementation in Dart;
- expose the Root Key, KEK, password, plaintext, or WASM handles to the page;
- reuse durable chat identities as anonymous identities;
- make incoming event signature verification optional;
- mark delivery without defined evidence;
- migrate or delete data without rollback and a human gate;
- use silent analytics or third parties in sensitive profiles;
- treat an upstream audit as an audit of the complete product;
- turn an exploratory document into a cryptographic decision.

## 7. Open decisions that must not be pre-empted

The following remain explicitly open:

- derivation and representation of `application context` values;
- mailbox form and lifecycle;
- NIP-44/NIP-59, another envelope, or direct onion transport;
- application group and role model;
- object format and version-negotiation policy;
- ACK and idempotency schema;
- recovery secret and backup;
- threshold or multi-recipient custody;
- update transparency and cross-client authentication;
- integration between the vault and real chat data;
- evidence and timestamp standards;
- attachment and sanitization policy.

The active action is to execute the protocol-hardening plan in dependency order.
Each decision still becomes an approved Issue with a threat model, non-goals,
tests and rollback; product integration resumes only after the plan's exit
verdict and under separate contracts.

<!-- styx-protocol-phase-exit-status:v1:start -->
Protocol-hardening phase-exit status: `BOUNDED_GO`. The broad protocol freeze has ended
only for work separately authorized under Section 9 of the hardening plan. Issue #287
itself authorizes no adapter, authenticated persistence, SDK, transport/delivery, product,
demo, deployment or sensitive-use work; US-001 through US-008 remain paused.
<!-- styx-protocol-phase-exit-status:v1:end -->
