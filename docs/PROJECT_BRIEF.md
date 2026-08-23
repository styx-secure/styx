# Styx project brief

> **Status:** public project and funding brief, updated 23 August 2026.
>
> Styx is experimental, has not completed an independent security audit, and
> is not ready for sensitive, high-risk, or life-critical use. This brief
> separates implemented evidence from proposed work. It is not a protocol
> specification, legal opinion, compliance statement, or security guarantee.

Public naming, message hierarchy, and claim boundaries are defined in the
[Styx public identity guide](BRAND_IDENTITY.md). The corresponding
[dependency-free landing-page source](../website/README.md) is a review
artifact, not a deployed service.

## Active protocol-hardening phase

Styx has deliberately paused new product and runtime implementation while the
language-neutral application protocol is hardened. The active work closes
authority, succession, commitment, checkpoint, resource-bound, error and
signature-suite questions; reconciles the threat model; and produces
deterministic adversarial and conformance evidence before implementation
resumes.

The canonical [protocol-hardening plan](protocol/protocol-hardening-plan.md)
defines the freeze boundary, authority order, review bundle and exit gates.
Issue #233 / PR #234 remain isolated experimental evidence and are not treated
as ratified protocol semantics. C0.3 remains `NO-GO`, and this phase does not
authorize a demo, product deployment or sensitive use.

## Mission

Styx is an open-source secure application substrate for sensitive workflows
over infrastructure that must not be trusted with plaintext. Its purpose is to
let applications combine self-custodied identity, end-to-end-encrypted
collaboration, verifiable state transitions, offline operation, and redundant
delivery without making a central service the authoritative record or giving
delivery infrastructure access to application content.

The first vertical, **Themis**, is intended to let a person open and continue a
confidential case without providing an email address, telephone number, or
ordinary account, while authorized organizations manage follow-up, roles,
evidence, retention, and continuity through verifiable encrypted state.

Styx is not a general-purpose messenger. The reference chat exists to exercise
pairing, encrypted sessions, persistence, interoperability, and failure
diagnostics. Product work is driven by the reusable substrate and Themis.

## Problem

Sensitive work rarely ends after one encrypted message. A reporting channel,
safeguarding case, source relationship, or protected organizational process may
need clarification, assignment, receipts, deadlines, evidence history,
retention, recovery, and asynchronous replies. Conventional systems often tie
that continuity to an email address, telephone number, user account, or a
server-side identity register. Those identifiers may expose the person or
discourage the initial report.

End-to-end encryption protects content only within its stated threat model. It
does not by itself define durable application state, prove delivery to a human,
minimize routing metadata, protect a compromised endpoint, authenticate a web
application served by a hostile origin, or provide safe organizational
procedures. Styx addresses the engineering substrate across those boundaries
and requires every product profile to state what remains visible and whom it
trusts.

## Intended beneficiaries

- people who need to report abuse, harassment, discrimination, wrongdoing, or
  safeguarding concerns without first disclosing conventional contact details;
- journalists, civil-society groups, human-rights defenders, and trusted
  intermediaries who maintain sensitive, asynchronous relationships;
- organizations that need least-privilege case handling, continuity, retention,
  and auditable policy without a universal plaintext administrator;
- developers building accounting, casework, coordination, or evidence
  applications that need secure collaboration primitives beyond chat.

The technology cannot decide whether a report is true, determine which law
applies, ensure handler independence, prevent retaliation, or replace trained
operators, safeguarding, a data-protection impact assessment, legal advice, or
emergency services.

## Solution and architecture

Styx separates four layers so that product policy is not hidden inside a chat
client or transport:

| Layer | Responsibility | Current direction |
|---|---|---|
| Product vertical | Workflow, roles, policy, and user experience | Themis first; reference chat minimal |
| Styx application protocol | Versioned objects, state transitions, causality, evidence, retention, pruning, and conformance | Language-neutral specification and vectors are to become authoritative |
| Secure-session profile | Membership, epochs, continuous group key agreement, convergence, and confidential delivery | Bounded exact-pin Styx/MDK direct-MLS proof complete; supported adapter and Nostr-envelope integration remain future work |
| Runtime profile | Key custody, encrypted storage, workers, notifications, distribution, and platform integration | Browser PWA first; signed native profiles are a future higher-assurance option |

No Dart or JavaScript implementation is intended to be the normative protocol.
The active JavaScript ledger is the browser implementation. The independently
developed Dart ledger is a reference and regression oracle whose behavior will
be used to strengthen a language-neutral conformance corpus before the Dart
feature line is frozen.

Nostr is a replaceable store-and-forward transport, not the application
identity or database. MLS, through the pinned OpenMLS implementation, supplies
secure-session primitives but not Themis workflow semantics. Marmot is the
preferred MLS-over-Nostr compatibility target. Phase B demonstrated a bounded
isolated direct-MLS profile against exact pinned OpenMLS, Marmot and MDK
revisions; it did not establish general Marmot conformance, Nostr-envelope
interoperability or product activation. No upstream project has endorsed or
certified Styx.

## Themis: first vertical

The planned text-first flow is deliberately narrower than a consumer
messenger. A reporter would create a fresh case context and a high-entropy
return capability locally, submit an encrypted case object, keep the capability
outside an ordinary account, and later use it to receive questions and send
answers. Distinct states would separate durable local storage, relay
acceptance, cryptographic receipt, human assignment, reading, reply, and
closure.

The operator side would provide role-based intake, assignment and
reassignment, operator rotation and revocation, retention policy, controlled
export, continuity, and minimized administrative audit. A deployment would
need an explicit threat model, trained handlers, an independent route for
conflicts of interest, incident and emergency procedures, legal and privacy
validation, and tested backup coverage.

The objective is anonymity or pseudonymity only against declared observers and
under tested conditions. IP addresses, timing, message sizes, browser
fingerprints, writing style, attachments, monitored workplace networks,
compromised endpoints, malicious recipients, and colluding infrastructure may
still identify or expose a reporter. The initial higher-assurance profile is
therefore expected to be text-only and to minimize third-party services.

## Evidence available today

The repository contains tested foundations, not an integrated anonymous-case
product:

1. **Application-state experience.** The Dart reference implements a signed,
   append-only ledger with causal clocks, deterministic merge, offline outbox,
   retention/pruning, migration, and identity backup. Its baseline of 389
   tests across six packages is implementation evidence, not an audit or an
   interoperability claim
   ([README](../README.md#dart-reference-architecture)).
2. **Browser secure-session path.** The JavaScript stack contains an encrypted
   1:1 MLS reference chat, authenticated QR pairing, Nostr event validation,
   and federated relay transport. Current envelopes expose routing, timing,
   size, and relationship metadata
   ([integration assessment](platform/integration-roadmap.md#2-summary-status)).
3. **Local custody.** Merged work provides a tested IndexedDB vault component,
   empty-vault lifecycle, canary records, crypto-worker lifecycle, vault
   settings, and identity shadow migration. This is component-level evidence,
   not a production-readiness claim. Product data migration and the complete
   application namespace remain separate gated work
   ([PR #99](https://github.com/styx-secure/styx/pull/99),
   [#101](https://github.com/styx-secure/styx/pull/101),
   [#104](https://github.com/styx-secure/styx/pull/104),
   [#109](https://github.com/styx-secure/styx/pull/109),
   [#121](https://github.com/styx-secure/styx/pull/121), and
   [#123](https://github.com/styx-secure/styx/pull/123)).
4. **Pinned cryptographic boundary.** OpenMLS and the Styx KDF are vendored as
   pinned WASM artifacts with provenance and reproducible-build checks. This
   does not authenticate the PWA served on first load and does not transfer an
   upstream audit to Styx
   ([technical specification](../specs/04-tech-spec.md#security-and-persistence-boundaries)).
5. **Bounded secure-session and independent-peer evidence.** Merged Phase
   B1–B2.7 work exposes an isolated AES-128-GCM profile and exercises durable
   staged-Commit authorization, recovery, convergence, message-ratchet and
   current-epoch sender-attribution behavior. These are synthetic proof
   surfaces, not product activation. The exact-pin B3 sequence then exercised
   a real independent MDK peer and closed successive typed KeyPackage,
   RatchetTree and profile boundaries without weakening validation. At the
   recorded pins, fresh runs completed durable Welcome join and restart,
   bidirectional application traffic and replay rejection, sequential ordinary
   self-updates, the inclusive five-past-epoch delivery boundary, and bounded
   convergence for exactly two authenticated proposal-free depth-one
   same-parent candidates. The final result is a **bounded GO** for that
   isolated synthetic direct-MLS profile, not general Marmot conformance,
   product integration or production readiness
   ([final Phase B verdict](architecture/spikes/2026-08-17-marmot-openmls-phase-b-verdict.md)).

Draft or proposed work is not counted as completed evidence. The Phase B proof
does not become a supported product session layer until a separate integration
increment defines and verifies the application adapter, authenticated product
persistence, retention/compaction, transport and runtime boundaries.

## What remains

- complete the active protocol-hardening phase, close or explicitly bound every
  C0.3 blocker, define the language-neutral Styx application protocol and
  adversarial conformance corpus, extract independent Dart cases, and keep
  parallel product implementation frozen until the phase exit verdict;
- turn the completed bounded secure-session proof into a separately versioned,
  supported adapter only after selecting and testing authenticated product
  persistence, retention/compaction, transport and runtime boundaries;
- separate application contexts and identity profiles, define versioned secure
  application objects, and expose a minimal SDK independent of chat;
- add crash-safe outbox, acknowledgement, retry, idempotency, deduplication,
  synchronization, and explicit delivery states;
- design and test metadata-minimizing routing, per-case identity, the anonymous
  return capability, recovery, abuse resistance, and privacy-safe
  notifications;
- implement the reporter experience and operator workspace, including roles,
  revocation, retention, audit, export, continuity, and accessible safety copy;
- improve PWA distribution assurance, define a stronger signed native profile,
  and validate relay and deployment operations;
- commission an independent review of a contractually bounded high-risk scope,
  remediate and retest findings within that scope, and authorize a synthetic or
  non-sensitive organizational exercise or later pilot only through separate
  security, privacy, legal, and safeguarding gates. This is not a promise of a
  complete-product audit within the proposed programme.

The detailed capability gaps and proposed dependency order are recorded in the
[application capability model](platform/application-capability-model.md) and
[integration roadmap](platform/integration-roadmap.md).

## Proposed funded milestones

These are bounded engineering outputs, not a delivery-date or compliance
promise. Each sensitive change still requires its own approved contract,
independent review, exact tests, and human gate.

| Milestone | Concrete output | Completion evidence |
|---|---|---|
| 1. Application protocol and conformance | **Active protocol-hardening freeze:** versioned language-neutral objects, transitions, error rules, adversarial scenarios, and reusable vectors; Dart cases extracted before its feature freeze | The [hardening exit gates](protocol/protocol-hardening-plan.md#8-exit-gates) pass; independent implementations execute the applicable corpus; divergences are resolved in the specification rather than hidden in ports |
| 2. Secure-session interoperability decision | **Bounded evidence complete:** preserve the staged-commit, identity, KeyPackage, Welcome, traffic, self-update, retained-window and two-candidate convergence proofs; next define a separately supported adapter without relabelling the isolated harness as product code | Reproducible exact-pin evidence and the [final bounded GO](architecture/spikes/2026-08-17-marmot-openmls-phase-b-verdict.md); no general-conformance or product claim |
| 3. Minimum SDK and reliable delivery | Data-only application interfaces, context separation, persistent outbox, ACK states, retry, idempotency, deduplication, and crash recovery | Tests demonstrate offline recovery and never label relay publication as recipient or human receipt |
| 4. Anonymous-case capability and Themis alpha | Fresh per-case identity, accountless return capability, text submission and dialogue, operator roles and revocation, retention, and safety UX | Cross-case unlinkability tests under the declared model; end-to-end reporter/operator scenarios without conventional contact details |
| 5. Distribution and deployment assurance | Verifiable artifacts and updates, stricter browser release controls, a native high-assurance profile decision, and reproducible relay/deployment guidance | Independent artifact comparison, update/rollback tests, metadata data-flow evidence, and continuity drills |
| 6. Targeted independent review, remediation, and gated field decision | Contractually bounded review of the highest-risk Styx-authored scope, finding disposition, retest and operational procedures; a synthetic/non-sensitive exercise or later pilot only after separate readiness gates | No unresolved blocking finding within the reviewed scope; reviewed residual risks; trained operators; and an explicit GO/NO-GO decision before any broader field use |

## How success will be measured

- the protocol corpus is versioned, public, reproducible, and exercises both
  valid behavior and malicious, reordered, duplicated, missing, rolled-back,
  or incompatible inputs;
- the secure-session decision is backed by a real independent peer and exact
  wire evidence, whether the result is GO or NO-GO;
- supported clients pass crash, offline, quota, recovery, concurrency, and
  delivery-state tests without silent data loss or false success;
- clean creation of two cases emits no shared protocol identifier or ordinary
  Styx/Nostr chat identity, within the declared test environment;
- relay, hosting, push, browser, and organizational metadata is measured and
  documented rather than described as absent;
- an independent reviewer reproduces the release and verifies the declared
  high-risk review scope, its threat-model boundaries, finding disposition and
  remediation of blocking findings within that scope;
- any separately authorized synthetic/non-sensitive exercise or later pilot
  reports only bounded, non-identifying operational measures such as completion
  of test scenarios, delivery reliability, accessibility findings,
  response-process coverage, and incident-drill results.

User counts, message volume, stars, or a passing primitive test suite do not by
themselves demonstrate safety, anonymity, adoption, or readiness.

## Risks and explicit non-claims

- Styx has not completed an independent audit and is not production-ready.
- The current browser profile is weaker against an adversary controlling the
  origin. Reproducible WASM does not authenticate all JavaScript delivered to a
  user.
- Current delivery exposes metadata. Multiple relays improve some availability
  properties but can increase the observer set.
- E2EE does not protect plaintext on a compromised device, stop an authorized
  recipient taking a screenshot, or prevent identification through content.
- Deletion and pruning cannot guarantee physical erasure from flash, browser
  storage, backups, screenshots, or third-party replicas.
- Themis does not currently exist as a complete application. Its anonymous
  capability, metadata profile, operator controls, and deployment procedure are
  proposed work.
- The completed Phase B work is exact-pin isolated interoperability and
  lifecycle evidence. It is not wired into the product, does not cover Marmot's
  Nostr envelopes, and does not establish general conformance.
- Styx does not claim universal anonymity, absence of servers or metadata,
  legal compliance, certification, upstream endorsement, or equivalence to a
  reviewed messenger.

## Open-source strategy

Original Styx software and documentation are licensed under
AGPL-3.0-or-later. A narrowly enumerated set of interoperability vectors is
Apache-2.0 so independent implementations can reuse conformance material.
Vendored and third-party components retain their upstream licenses and
attribution. External code contributions are currently paused until separate
contributor terms are approved; issues and review feedback remain welcome.

The exact path classifications, notices, trademark boundary, and commercial
licensing statement are defined in [`LICENSING.md`](../LICENSING.md),
[`REUSE.toml`](../REUSE.toml),
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md),
[`CONTRIBUTING.md`](../CONTRIBUTING.md), and
[`TRADEMARKS.md`](../TRADEMARKS.md). This brief does not modify them. Marmot,
MDK, OpenMLS, Nostr, and related names refer to independent upstream projects;
compatibility or use does not imply endorsement.

## Primary references

- [Approved product vision](../specs/01-vision.md)
- [Product requirements synthesis](../specs/02-prd.md)
- [Technical specification synthesis](../specs/04-tech-spec.md)
- [Application capability model](platform/application-capability-model.md)
- [Integration roadmap](platform/integration-roadmap.md)
- [Anonymous bidirectional dialogue use case](platform/use-cases/anonymous-dialogue.md)
- [Marmot/OpenMLS Phase A capability report](architecture/spikes/2026-08-08-marmot-openmls-phase-a.md)
- [Final exact-pin Phase B interoperability verdict](architecture/spikes/2026-08-17-marmot-openmls-phase-b-verdict.md)
- [Current chat security report](security/2026-07-10-styx-chat-security-report.md)
- [Repository governance](../AGENTS.md)
