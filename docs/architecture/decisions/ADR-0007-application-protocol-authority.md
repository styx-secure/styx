# ADR-0007 — Application-protocol authority and implementation roles

- **Status:** Accepted (2026-08-17).
- **Human decision:** approved product direction recorded by Issue #124 and
  `specs/01-vision.md`; reconciliation authorized by Issue #201.
- **Supersedes:** ADR-0001 where it describes the canonical product,
  application protocol, universal web client, or chat-led roadmap.
- **Clarifies:** ADR-0003 without reopening the Dart feature line.

## Context

Styx contains independently developed application-ledger implementations in
JavaScript and Dart, a Rust/OpenMLS secure-session engine exposed through WASM,
a browser runtime, and a reference chat. Earlier architecture wording treated
Rust/OpenMLS and the chat PWA as a single canonical product stack. The approved
Vision instead defines Styx as a platform-neutral secure application substrate
whose first vertical is Flegias.

Leaving both descriptions normative would make protocol decisions ambiguous:
an implementation could become authoritative merely because it currently
generates vectors or ships in the browser. This ADR reconciles the historical
records with the approved direction. It changes no runtime behavior or format.

## Decision

### 1. Styx application protocol

The language-neutral application-protocol specification, state-transition
rules, adversarial scenarios, error rules, wire definitions and conformance
corpus are the application-layer authority. Divergences are resolved through
that authority and reviewed evidence, never by declaring Dart, JavaScript,
Rust, a browser, or a native client canonical.

The application protocol owns durable application objects, causality,
evidence, retention, pruning and conformance. It must not depend on a UI
toolkit, browser API, transport provider or a particular secure-session engine.

### 2. Application implementations

`styx-js/src/ledger/**` and `styx-js/src/facade/**` are the currently active
browser implementation of the application protocol. This is an implementation
role, not normative authority. Its remote-admission path remains deliberately
contained, and the ledger is not yet integrated into a supported end-to-end
product pipeline.

`packages/**` is an independently developed Dart reference and regression
oracle. Its behaviors and edge cases are to be extracted once into the
language-neutral conformance work before the Dart feature line is frozen. Dart
does not become authoritative by generating a vector, and parallel feature
development across Dart and JavaScript remains out of scope.

### 3. Secure-session profile

The secure-session profile is replaceable below the application protocol. It
owns membership, epochs, continuous group key agreement, authenticated
confidential delivery and session convergence within its declared profile.

Rust/OpenMLS remains the selected engine for the bounded profile exercised by
Phase B. Phase B demonstrated only an exact-pin, isolated, synthetic
direct-MLS profile against the recorded OpenMLS, Marmot and MDK revisions. It
did not establish general Marmot conformance, Nostr-envelope interoperability,
product activation, audit coverage, anonymity, metadata privacy or production
readiness. A supported adapter requires a separate versioned and human-gated
contract.

### 4. Runtime profiles

The PWA is the first runtime profile, not the universal architecture. Its
vault, workers, IndexedDB adapters, service worker, notification path and
distribution model implement browser-specific custody and lifecycle concerns.
A future signed desktop or native profile may provide stronger code-provenance
and endpoint properties while implementing the same application protocol.

### 5. Product verticals and reference chat

Product verticals own workflows, roles, policy and user experience. Flegias is
the first intended vertical. The reference chat remains a minimal
interoperability, pairing, persistence and failure-diagnostic surface. It is
not the product authority and does not set the application roadmap.

## Consequences

- Protocol work begins with language-neutral rules and conformance evidence,
  not an implementation port.
- A shared vector is authoritative only through the governed conformance
  corpus and independent consumption, not through the language that generated
  it.
- Secure-session, transport and runtime profiles cannot silently introduce
  application semantics.
- Existing Dart and JavaScript differences remain evidence to characterize;
  this ADR neither resolves nor normalizes them.
- Application formats, causal topology, signature inputs, persistence,
  retention, pruning, remote admission and session binding each remain
  separately gated decisions.

## Non-claims

This decision is architectural governance only. It does not specify a protocol
format, prove interoperability, activate the Phase B profile, freeze Dart,
change product code, amend licensing, complete an audit, or make Styx suitable
for sensitive use.

## Superseded interpretations

The following historical interpretations must not guide new work:

- Rust/OpenMLS as the canonical application protocol;
- the chat PWA as the canonical product or universal client;
- all application features belonging inside the MLS engine;
- Dart-generated vectors making Dart the de facto specification;
- feature parity across two application-ledger implementations.

ADR-0001 remains available as historical provenance for why OpenMLS/Rust was
selected for the secure-session investigation. ADR-0003 remains authoritative
for the bounded Dart reference role as clarified here.
