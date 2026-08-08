---
spec_version: "3.0"
spec_type: "vision"
project: "Styx"
last_updated: "2026-08-08T00:00:00Z"
status: "draft"
---

# Styx — Vision

## Vision statement

Styx is a platform-neutral secure application substrate for applications that
need self-custodied identity, end-to-end-encrypted collaboration, verifiable
state transitions, offline operation, and delivery through infrastructure that
is not trusted with plaintext.

Styx is not a general-purpose messenger. The first product vertical is Themis:
an anonymous case-management system in which a reporter can maintain a
two-way, asynchronous relationship without disclosing an email address, phone
number, or central account. A minimal chat remains useful only as a reference
application, interoperability harness, and diagnostic surface for the secure
runtime.

## Product principles

1. **The protocol is the authority.** No Dart, JavaScript, browser, or future
   native implementation is canonical. The language-neutral event formats,
   state-transition rules, adversarial scenarios, wire formats, and
   conformance vectors are the application-layer authority.
2. **Security properties are profile-specific.** The browser PWA is the first
   runtime profile, not the universal architecture. It deliberately provides
   weaker resistance to an adversary that controls the web origin than a
   future signed native profile can provide.
3. **Application semantics and secure transport are separate.** The Styx
   application protocol owns durable case state, causality, evidence, pruning,
   and convergence. An MLS-over-Nostr profile may provide membership, epochs,
   continuous group key agreement, and delivery without becoming the product.
4. **Compatibility is preferred to gratuitous divergence.** Marmot is the
   preferred compatibility target for the MLS-over-Nostr profile. Compatibility
   requires conformance evidence; reuse of an event kind, tag, or isolated wire
   convention is not compatibility.
5. **Trust limits are explicit.** Relays and push infrastructure must not see
   message plaintext, but they can observe transport metadata unless a specific
   profile proves otherwise. A compromised endpoint, malicious recipient, or
   origin-controlled browser build remains outside the protection supplied by
   E2EE alone.
6. **Current builds are experimental.** They have not received an independent
   security audit and are unsuitable for sensitive, high-risk, or life-critical
   use.

## Product and implementation roles

### Styx Application Protocol

The application protocol defines the durable objects and transitions required
by secure applications: signed event structure, canonical encoding, causal
ordering, deterministic conflict handling, retention and pruning semantics,
and the conformance corpus. It must remain independent of programming language,
UI toolkit, browser APIs, and transport provider.

### Themis

Themis is the first supported product vertical and drives requirements for
anonymous onboarding, durable case state, controlled disclosure, asynchronous
dialogue, notifications, evidence integrity, and operational safety.

### JavaScript ledger

`styx-js/src/ledger/**` and `styx-js/src/facade/**` are the active browser
implementation of the Styx application protocol. They are an implementation,
not a normative source. New application-layer work targets this implementation
only after the relevant protocol rule and conformance evidence exist.

### Dart ledger

`packages/` is an independently developed reference implementation. Before it
is frozen, its behaviors and edge cases must be used once to strengthen the
language-neutral conformance corpus. It is then retained as a reference and
regression oracle, not developed in parallel for feature parity.

### Secure runtime profiles

The PWA vault, crypto worker, IndexedDB adapters, service worker, push path, and
UI shell form the browser runtime profile. Future signed desktop or native
profiles may provide stronger code-provenance and endpoint guarantees while
implementing the same application protocol.

### Reference chat

The chat surface is intentionally minimal. It demonstrates secure-session
round trips, interoperability, pairing, persistence, and notification behavior
needed by real verticals. It does not define the product roadmap.

## Strategic objectives

1. Specify one language-neutral Styx application protocol and conformance
   corpus before extending either ledger implementation.
2. Extract independent Dart behavior into that corpus, then freeze the Dart
   stack as a reference.
3. Establish a secure-session compatibility profile, preferring Marmot where a
   bounded and reviewable implementation can conform.
4. Build Themis on the application protocol and reusable runtime profiles.
5. Keep cryptographic artifacts pinned, reproducible, independently reviewed,
   and separated from product policy.
6. Keep documentation English-canonical and security claims evidence-based.

## Explicit non-goals

- Competing with Signal or another general-purpose messenger.
- Chat feature parity with Marmot or any consumer messenger.
- Parallel feature development across the Dart and JavaScript ledgers.
- Treating the PWA, IndexedDB, service workers, or Web Workers as universal
  platform requirements.
- Claiming that current builds provide production security, complete metadata
  anonymity,
  origin independence, or anonymity against a compromised endpoint.
- Inventing a Styx-specific MLS wire protocol when a compatible, reviewed
  profile is feasible.

## Normative direction

This document supersedes the prior product framing that treated the chat PWA as
the active product. Existing chat, vault, push, and security documents remain
valuable implementation evidence and constraints, but they do not override the
product boundaries above. New implementation work requires an approved Issue,
applicable human gates, and conformance evidence.
