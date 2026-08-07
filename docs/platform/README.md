<!-- styx-canonical:v1 mirror="docs/platform/README_IT.md" -->
# Styx as an application platform

[Italian mirror](README_IT.md)

> **Status:** exploratory, non-normative proposal
> **Code snapshot:** `main @ d90931a3f59ce89c1594cad64ce385d58857b305`
> **Issue:** [#110](https://github.com/styx-secure/styx/issues/110)
> **Language:** English; technical identifiers remain in English.

This directory describes how Styx could evolve from a messaging product into a
reusable application platform for use cases that share three needs:

1. data readable only by authorized endpoints;
2. local and asynchronous operation without depending on a single operator;
3. security properties stated against a threat model, without absolute
   promises.

These documents do not authorize code changes and do not replace specifications,
ADRs, contractual Issues, audits, or legal advice. In case of conflict,
`AGENTS.md`, approved Issues, and the repository's normative sources prevail.

## Documents

| Document | Purpose |
|---|---|
| [Application capability model](application-capability-model.md) | Defines general application capabilities, trust boundaries, identity profiles, and assurance levels. |
| [Integration roadmap](integration-roadmap.md) | Compares requirements with the active JavaScript stack and the Dart reference stack, identifying gaps and possible increments. |
| [Anonymous bidirectional dialogue](use-cases/anonymous-dialogue.md) | Applies the model to reports that must receive replies without requiring personal contact details. |

## Architectural idea

The proposed direction is not to add every function to the chat. It is to
separate four layers:

```text
Applications
  chat | shared accounting | reporting | casework | surveys
       │
Application profiles and policies
  identities | roles | retention | data schema | threat model
       │
Styx Application Core
  E2EE objects | sessions | sync | reliability | vault | recovery
       │
Infrastructure adapters
  Nostr relays | onion service | push | local storage | native client
```

The application decides what the data means. The core provides verifiable
primitives. Adapters carry blobs and signals without becoming authorities over
identity or content. A security profile combines primitives, but cannot promise
more than implementation, tests, and operations can demonstrate.

## Candidate application families

### Private communication

Individual or small-group chats, association coordination, and document
exchange. This is the use case closest to the current JavaScript product, but
storage and metadata blockers still need to be closed before sensitive use.

### Shared records without a central operator

Household accounting, a group of friends' common fund, inventories, shifts,
decisions, and shared expenses. Events must be authenticated, synchronized
offline, idempotent, and resolved according to explicit application rules. A
tamper-evident chain can help detect changes, but does not make false data
entered by a participant true.

### Anonymous or pseudonymous dialogue

Abuse reports, whistleblowing where applicable, listening services,
journalistic sources, and requests for help. This requires one-time per-case
identities, no mandatory account, a return capability, network protection, and
a competent organizational procedure. Content encryption alone does not
provide anonymity.

### Confidential casework

Relationships between a client and an NGO, lawyer, trade union, or caseworker.
This may require case assignment, role separation, escalation, shared key
custody, controlled exports, and limited retention.

### Data collection and surveys

Private questionnaires, field surveys, and consultations. Response secrecy,
voter eligibility authentication, vote uniqueness, and anonymity must be kept
distinct: they are different properties that may conflict. Styx must not be
presented as a verifiable voting system without a dedicated process.

### Evidence and attestations

Collection of statements, photographs, or documents with verifiable provenance
and chronology. Signatures and hashes can prove the integrity of observed
bytes, not the material authenticity of the represented event or a complete
legal chain of custody.

## Rules for security claims

This area adopts the following terminology rules:

- **E2EE** means that content is encrypted between authorized endpoints; it
  does not imply anonymity, availability, or endpoint security.
- **Confidential** does not mean **anonymous**.
- **Pseudonymous** does not mean **unidentifiable**.
- **Tamper-evident** does not mean immutable, true, or legally
  non-repudiable.
- **Federated** does not mean free of servers.
- **Tor-capable** does not mean that all traffic has passed through Tor or that
  global correlation is impossible.
- **Logically deleted** does not mean physically unrecoverable from every
  medium, replica, or backup.
- No configuration may be described as universally anonymous, free of
  metadata, unable to learn any information, or production-ready without
  specific and current evidence.

## How to use this documentation

A new application should:

1. select the relevant assets and adversaries;
2. choose an identity profile and an assurance profile;
3. state which metadata remains visible to relays, operators, and peers;
4. map every requirement to core capabilities;
5. treat missing capabilities as blocking dependencies;
6. open separate Issues for cryptographic decisions, persisted formats,
   migrations, and vault changes;
7. run independent tests and reviews on the complete product, not only on its
   primitives.

## Status relative to the current product

The canonical stack remains Rust/OpenMLS through WASM, with a JavaScript PWA,
as established by `docs/architecture/decisions/ADR-0001-canonical-product-stack.md`.
The Dart stack remains a reference implementation under ADR-0003 and does not
become a second product core. Ideas present in Dart may become requirements and
tests; they must not be imported implicitly into the active product.

At the current snapshot:

- the 1:1 MLS chat and Nostr transport provide useful primitives;
- the IndexedDB vault is still canary-only and contains no product data;
- the chat transport does not wait for a real delivery ACK;
- transport identities are durable and correlatable;
- relays and observers see structural and network metadata;
- remote pairing, product groups, and multi-device support are incomplete;
- an application SDK contract independent of the chat is missing.

The [roadmap](integration-roadmap.md) turns these differences into possible
increments without pre-empting sensitive decisions.
