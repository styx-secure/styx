---
spec_version: "3.0"
spec_type: "tech-spec"
project: "Styx"
last_updated: "2026-08-17T00:00:00Z"
status: "draft"
---

# Styx — Technical Specification (synthesis)

## Architecture

Styx is organized by protocol authority and runtime responsibility, not by the
current monorepo directory layout.

| Layer | Responsibility | Current realization |
|---|---|---|
| Product vertical | Workflows, policy, roles, UX | Themis first; reference chat minimal |
| Styx application protocol | Events, state transitions, causality, evidence, pruning, conformance | JS active browser implementation; Dart independent reference |
| Secure-session profile | Membership, epochs, CGKA, convergence, confidential delivery | Bounded exact-pin direct-MLS proof complete; supported adapter and Nostr-envelope integration remain future work |
| Runtime profile | Key custody, storage, workers, notifications, platform integration | Browser PWA first; signed native profiles future |

No implementation is the canonical application authority. The canonical
contract is the language-neutral specification plus conformance corpus.

## Application implementation roles

- `styx-js/src/ledger/**` and `styx-js/src/facade/**` are the supported browser
  implementation of the application protocol.
- `packages/` Dart is an independently developed reference. Its behavioral
  edge cases must be captured as conformance vectors before the implementation
  is frozen.
- Parallel feature development across the two implementations is forbidden by
  product direction; divergence is resolved in the specification and vectors,
  not by declaring either implementation authoritative.

## Secure-session boundary

The secure-session layer is replaceable below the application protocol. The
current JavaScript path uses vendored OpenMLS WASM and Nostr transport. Marmot
is the preferred target for MLS-over-Nostr compatibility. Phase B produced a
bounded GO against exact pinned OpenMLS, Marmot and MDK revisions for an
isolated synthetic direct-MLS profile: durable Welcome join, bidirectional
application traffic, sequential self-update, the five-past-epoch delivery
boundary and exactly two depth-one same-parent candidates. This is not general
Marmot conformance, Nostr-envelope interoperability or product activation. See
the [final Phase B verdict](../docs/architecture/spikes/2026-08-17-marmot-openmls-phase-b-verdict.md).

Marmot compatibility requires, at minimum, its mandatory ciphersuite, current
account-to-leaf identity proof, capability negotiation, compliant KeyPackages,
staged Commit policy, publish-before-apply, convergence, and transport envelope
rules. Reusing kind `445`, an ephemeral key, or an `h` tag in isolation is not
an acceptable partial implementation.

## Runtime profiles

### Browser PWA

The browser profile includes:

- the encrypted vault and versioned local-state envelopes;
- the crypto worker and vendored WASM boundaries;
- IndexedDB adapters and browser concurrency controls;
- service-worker and push-notification integration;
- the reusable React application shell.

This profile cannot make an adversary-controlled origin trustworthy. CSP,
Trusted Types, reproducible builds, integrity checks, and code transparency can
raise the cost and improve detection, but do not give a web load the same
code-provenance property as an independently installed, signed native build.

### Signed native profiles

A future desktop or native profile may strengthen code provenance and local
secret handling while preserving the same application and secure-session wire
contracts. Browser-specific APIs must not leak into those contracts.

## Security and persistence boundaries

1. **Vendored cryptographic artifacts are pinned boundaries.** Changes to
   `openmls-wasm` or `styx-kdf-wasm`, their features, wrapper, build inputs, or
   artifacts require reproducible rebuilds and explicit human review.
2. **Persisted security state is fail-closed.** Unknown formats, failed writes,
   or partially applied epoch transitions must block affected operations rather
   than continue with ambiguous state.
3. **Commit policy precedes merge.** Any future secure-session implementation
   must allow inbound Commit inspection before merge and local
   publish-before-apply with explicit confirm/discard behavior.
4. **Transport is not identity.** Application identity, MLS leaf signing keys,
   and delivery addresses have separate roles and require explicit bindings.
5. **Audits do not transfer.** An audit of OpenMLS, MDK, Marmot, or another
   client is evidence for test design, not an audit of Styx or its browser
   profile.

## Services and applications

- `styx-js/apps/chat/` is the reusable PWA shell plus a minimal reference chat;
  it is not the product authority.
- `push_bridge/` and `push_bridge_server/` are notification delivery
  components and deliberate metadata boundaries.
- Themis is the first product vertical and must consume the application
  protocol through explicit interfaces rather than importing chat semantics.

## Governance constraints

- Crypto, WASM, persisted formats, migrations, runtime manifests, licensing,
  workflows, and governance remain human-gated.
- The completed Phase B result is evidence only for its exact isolated profile.
  Any supported application adapter, pin change, transport integration,
  retention policy or persisted product format needs a new approved contract,
  adversarial tests and independent evidence.
- The existing OpenMLS pin must not be moved backward to a release tag that
  predates its security and storage changes.
- Current builds remain experimental and unsuitable for sensitive use.

## Normative references

| Subject | Authority |
|---|---|
| Product direction | `specs/01-vision.md` |
| Licensing | `LICENSING.md`, `REUSE.toml` |
| Repository governance | `AGENTS.md` |
| Existing vault and MLS-state constraints | `docs/superpowers/specs/**` |
| Current security findings | `docs/security/2026-07-10-styx-chat-security-report.md` |

The existing ADRs record historical decisions. Any ADR that treats the chat as
the canonical product must be reconciled by a separate, human-approved task;
this synthesis does not silently amend it.
