---
spec_version: "3.0"
spec_type: "prd"
project: "Styx"
last_updated: "2026-08-08T00:00:00Z"
status: "draft"
---

# Styx — Product Requirements (synthesis)

## Authority and scope

This is a product map, not the language-neutral application protocol. The
canonical application authority will be the versioned event formats,
state-transition rules, adversarial scenarios, wire formats, and conformance
vectors. Implementations and product verticals must conform to that authority.

Current builds remain experimental and unsuitable for sensitive, high-risk, or
life-critical use.

## E1 — Styx application protocol and conformance

Define durable application objects and transitions independently of runtime and
transport: canonical event encoding, signatures and hash links, causal clocks,
deterministic conflict behavior, retention and pruning, error semantics, and
adversarial conformance scenarios.

- **Active browser implementation:** `styx-js/src/ledger/**` and
  `styx-js/src/facade/**`.
- **Independent reference:** `packages/` Dart, used to extract missing vectors
  before being frozen.
- **Requirement:** neither implementation is normative.

## E2 — Themis vertical

Themis is the first supported product: anonymous case management with durable
case state, asynchronous two-way dialogue, controlled disclosure, notification
support, evidence integrity, recovery, retention, and safe operational UX.

- **Requirement:** a reporter must not need an email address, phone number, or
  central account to continue the dialogue.
- **Requirement:** application semantics must survive changes in runtime and
  secure-session transport profile.

## E3 — Secure-session compatibility profile

Provide MLS membership, epochs, continuous group key agreement, convergence,
and redundant delivery as a replaceable profile below the application protocol.
Marmot is the preferred compatibility target, subject to a successful bounded
capability and interoperability process.

- **Current implementation evidence:** vendored OpenMLS WASM and the existing
  Nostr chat path.
- **Constraint:** current Styx wire behavior is not Marmot-compatible merely
  because it uses MLS, Nostr, or a Marmot-associated event kind.
- **Gate:** no Phase B implementation starts without explicit licensing,
  crypto/WASM, persisted-state, migration, and transport approval.

## E4 — Runtime profiles

Runtime profiles implement local key custody, durable storage, background
delivery, notifications, and UI integration for a platform.

### Browser PWA profile

The existing vault, crypto worker, IndexedDB persistence, service worker, push
bridge, and React shell form the first runtime profile. Its security statement
must include the weaker guarantee against an adversary controlling the origin.

### Future signed native profiles

Desktop or native profiles may provide stronger code-provenance and endpoint
guarantees while implementing the same application protocol and compatible
secure-session profile.

## E5 — Minimal reference chat

Retain only the chat behavior needed to demonstrate pairing, secure-session
round trips, persistence, notification behavior, interoperability, and failure
diagnostics. Consumer-messenger feature parity is not a product requirement.

## E6 — Vault and local-state protection

Protect local secrets and state with versioned, fail-closed persistence,
memory-hard password derivation, isolated cryptographic execution, explicit
recovery behavior, and atomic security-state transitions.

- **Existing design evidence:**
  `docs/superpowers/specs/2026-07-12-styx-vault-design.md` and
  `docs/superpowers/specs/2026-07-12-mls-state-envelope.md`.
- **Constraint:** vault protection does not remove the browser-origin or
  compromised-endpoint limitations.

## E7 — Delivery and notifications

Support asynchronous application workflows through redundant delivery and
privacy-minimizing notifications. Push infrastructure is a deliberate trust and
metadata boundary and must never receive application plaintext.

## E8 — Supply-chain and security assurance

Keep cryptographic dependencies pinned, reproducibly built, integrity checked,
and reviewed independently. Treat cryptographic code, vendored WASM, persisted
formats, migrations, licensing classifications, and security claims as
human-gated changes.

## Cross-cutting requirements

- English is the canonical documentation language; translations are optional
  and must not become the only source of a requirement.
- Security claims must identify the runtime and threat model to which they
  apply.
- Relay-observable metadata must be documented until a specific profile and
  evidence demonstrate its protection.
- Persisted-state changes require explicit migration and rollback behavior.
- Compatibility claims require wire-level conformance evidence against an
  independent implementation.
- The Dart and JavaScript ledgers must not receive parallel feature work.
