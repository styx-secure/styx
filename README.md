# 🏛️ Styx

**Secure infrastructure for sensitive work.**

Styx is an experimental SDK being developed for confidential workflows under declared protocol, runtime, transport and operational conditions. Current builds are not qualified for live sensitive use. Flegias is a synthetic-data reference demonstration, not an operational reporting service.

> ⚠️ **Experimental software.** Styx is under active development and has **not** completed an
> independent security audit. Do not use current builds for sensitive, high-risk, or life-critical use.

## Latest progress — November 2026

▶ The 100-second [October recording](https://styxsecure.org/#progress) shows the earlier test
harness ([MP4](docs/media/2026-10-m3-test-run.mp4), 2.9 MB, synthetic data).

In October our delivery work ran inside a prototype test harness. It now runs through the Styx SDK
client, the library an application calls:

- **The SDK client is built.** The [Milestone 3](https://github.com/styx-secure/styx/issues/400)
  SDK client ([#498](https://github.com/styx-secure/styx/pull/498)) is integrated on its branch,
  together with per-relay recovery after a stall
  ([#512](https://github.com/styx-secure/styx/pull/512)), a bounded shutdown that still sends owed
  receipts ([#510](https://github.com/styx-secure/styx/pull/510)), public relays used only when the
  calling application allows them ([#524](https://github.com/styx-secure/styx/pull/524)), MLS invitations over
  Nostr ([#527](https://github.com/styx-secure/styx/pull/527)) and a synthetic-data Flegias preview
  ([#521](https://github.com/styx-secure/styx/pull/521)).
- **Two machines join a group and talk through the SDK.** On two machines on different networks,
  over three public Nostr relays (`relay.nostr.net`, `relay.primal.net`, `offchain.pub`), one side
  published a signed MLS KeyPackage, the other sent the Welcome inside an encrypted NIP-59 gift
  wrap, and both joined the same group. No private key or MLS state was copied between the machines.
  In three complete runs, 18 of 18 messages came back with the recipient's receipt.
- **Delivery that survives failures, now inside the SDK.** In every run we cut one relay off for
  the sender and then stalled its other two connections. The SDK retried, and the stalled message
  was confirmed on its second attempt; a reply sent during the stall arrived exactly once after the
  network came back. With our own TLS keys removed, message content on the wire is MLS ciphertext.
- **An outside attacker still got nothing through.** A scripted attacker on a separate cloud
  worker, reading the public relays but holding no group key, replayed a message, tampered with
  one, injected one of her own and forged a delivery receipt, in three runs against the SDK client.
  No foreign message reached the application, and the forged receipt confirmed nothing: the sender
  kept waiting until the genuine receipt arrived.
- **Milestone 2 keeps moving.** On the integration branch of
  [Milestone 2](https://github.com/styx-secure/styx/issues/313), all 2,379 tests of its 20 suites
  pass, now including the fix for a reproduced transaction-recovery defect and a single-tab lock
  for the planned controlled beta. Milestone 1 is [complete](https://github.com/styx-secure/styx/pull/303).

**Why it matters:** whistleblowers, journalists and the people who handle their cases need to work
over infrastructure that anyone can run, without trusting whoever runs it with their words. With
the SDK, an application reaches this delivery layer through one interface; Flegias is the
synthetic-data reference demonstration of that integration, not an operational reporting service.

*Limits: synthetic data, short-lived identities and one pair of participants; experimental Nostr
event kinds; metadata and KeyPackages stay public; on the public relays the relays themselves
filtered the replayed copies, so the replay defence was checked separately with local test relays
that forward every duplicate (each message still reached the application once); the SDK reports a
rejected event without its id, so rejections were matched to attacks by their timing in the log; pre-audit
code, not yet on `main`.*

The historical public-relay invitation tests used public KeyPackages and an encrypted Welcome. They do not implement or qualify the isolated-case out-of-band invitation design, private KeyPackage delivery or its recovery profile.
The target design keeps KeyPackage and Welcome in the private channel.

## Mission

Styx is an open-source, platform-neutral secure application substrate for sensitive workflows over
infrastructure that must not be trusted with plaintext. Styx is being designed to combine self-custodied per-case keys, end-to-end-encrypted collaboration, authenticated state transitions, offline archive reading, bounded queuing within a continuously live session, and multi-relay retry.
It is not a general-purpose messenger or a replacement for Signal.

It is intended for human-rights and civil-society teams, journalists, safeguarding organizations,
trusted intermediaries, and developers building casework, evidence, coordination, or other
sensitive applications.

Styx delivers an experimental **SDK**. **Flegias** is its synthetic-data reference demonstration
for confidential case intake and return dialogue without an email address, phone number, or
ordinary account, not a managed casework product. Organizations build and operate their own
applications and infrastructure; the SDK does not replace trained handlers, legal and privacy
review, safeguarding procedures, or emergency channels.

In the target isolated-case design, a reporter first obtains a single-use secret out-of-band invitation, then establishes a per-case encrypted context without an ordinary account. Returning to archived history does not guarantee the ability to send new replies.

Offline capability is bounded: archive reading and transient-disconnect queuing within the same eligible live session are distinct from reopening persistent state. New replies after reopening require successful authenticated reattachment. A finite active-case window, epoch-history limits, invitation expiry, relay retention and recovery availability can cause permanent message loss; neither uninterrupted return access nor delivery is guaranteed.

## Where the project stands

- **Built and tested foundations:** an independent Dart ledger and an active JavaScript browser
  stack with a reference MLS chat, Nostr transport, encrypted IndexedDB vault, crypto-worker
  lifecycle, pinned WASM artifacts, fail-closed storage work, and isolated synthetic
  secure-session evidence through the completed Phase B exact-pin proof.
- **Application-protocol evidence now on `main`:** a fully synthetic, transcript-only C0.3
  [conformance corpus](conformance/application-protocol/c03/manifest.json), independent Python and
  JavaScript replay through the [reproduction tooling](tools/causal-flow-simulator/c03/README.md),
  and a closed adversarial mutation registry. This completes corpus construction only. It does not
  establish implementation conformance, protocol completion, or product readiness; C0.3 remains
  `NO-GO` for implementation alignment, demo, product, and sensitive use.
- **Now being built:** authenticated persistence of the MLS session in the encrypted browser vault
  ([Milestone 2](https://github.com/styx-secure/styx/issues/313): 31 of 41 tasks complete or
  approved, including all seven design contracts; on the `m2/integration` branch all 2,379 tests
  of its 20 suites pass; browser and fault-injection testing and a closing security review with
  fixes and re-run remain), and the SDK and reliable-delivery layer
  ([Milestone 3 early lane](https://github.com/styx-secure/styx/issues/400): SDK, delivery and
  preview contracts ratified; the SDK client, with its queue, retry, multi-relay, receipt,
  recovery and invitation modules and a synthetic-data Flegias preview, integrated on
  `m3/integration` and run between two machines over public relays). Neither branch is on `main`
  yet, and integrating the vault into the main application is still to come.
- **Not yet a complete product:** completion and ratification of the language-neutral application
  protocol, an SDK release on `main` with persistent identity and session state,
  metadata-minimizing case routing, an accountless return channel, organizational workflow,
  distribution assurance, a targeted independent review of a bounded high-risk scope, and any
  synthetic-data validation remain future work.
- **Historical exact-pin evidence:** at the exact OpenMLS, Marmot and MDK revisions recorded in the
  final Phase B report, Styx interoperated with the pinned MDK peer in an isolated synthetic
  direct-MLS profile through durable Welcome join, bidirectional application traffic, sequential
  self-update, the five-past-epoch delivery boundary and bounded two-candidate same-parent
  convergence. This is not general Marmot conformance or product activation. The chat is a
  minimal reference application and interoperability harness, not the product roadmap.

The proposed engineering programme preserves the completed bounded secure-session evidence and takes
the project through a conformance-backed Styx application protocol, a supported session adapter,
a reusable SDK and reliable delivery, a text-first Flegias reference demonstration, stronger distribution assurance,
a targeted review of a contractually bounded high-risk scope with remediation and retest, and a
separately gated synthetic-data validation. This is an engineering plan, not a statement of
awarded funding. See the
[project brief](docs/PROJECT_BRIEF.md) for the mission,
evidence, milestones, measurable outcomes, and explicit non-claims. The
[public identity guide](docs/BRAND_IDENTITY.md) defines naming and claim boundaries; the
[dependency-free landing-page source](website/README.md) turns that identity into a reviewable
public surface without deploying it.

This programme description is not a promise of a complete-product audit or authorization for a
live high-risk pilot.

Conforming endpoints encrypt application plaintext before relay delivery; relay operators are not given application decryption keys. Relays can still observe IP addresses, timing, sizes, transport keys or identifiers, routing metadata and within-case activity. Authorized recipients, compromised endpoints and code delivered by a hostile application origin can disclose plaintext.
No current build offers a universal anonymity guarantee.

The isolated-case target design requires a single-use secret invitation delivered through an authenticated out-of-band channel and kept confidential from relays. The invitation is a bearer capability, not a public reusable QR code. That channel authenticates the complete invitation object and the selected organization; a compromised channel can substitute recipient keys and actively intercept content.

Knowledge of the invitation secret removes the design's claimed initial-carrier privacy under the supported malicious-key model. It does not, by itself, imply passive decryption of every initial flight for an independently generated recipient key or of later MLS application traffic without the corresponding private keys or an active key-substitution attack.

First-contact unlinkability does not hold when invitation distributors and relay operators combine assignment, portal, socket, IP-address or timing records. Honest endpoints must generate independent per-case keys. No unlinkability is claimed against an authorized peer that reveals its transcript, plaintext, keys or key reuse to a relay.

> *In Greek mythology, the River Styx marked a boundary and the gods swore solemn oaths upon its waters. The project uses that image to represent explicit trust boundaries in digital systems—not a promise of invulnerability.*

### Persistence, recovery and browser limits

Authenticated storage and signed transitions do not prove freshness. An old authentic snapshot of one case, or an entire profile with its local witnesses, may remain undetected. Rollback can re-expose previously removed or revoked history. Reattachment is not proof that the local archive contains every latest event.
An old authentic snapshot of one case may remain undetected alongside current cases.
Restoring an entire profile, including its local witnesses, may also remain undetected.
Cross-case witnesses can only detect regressions relative to facts they have already incorporated;
this is not a claim of an implemented multi-case rollback detector.

The required recovery policy treats every reopening of persisted secure-session state as untrusted: no new application, invitation, outer-transport, receipt or old-session protocol output is allowed from the reopened state; archive reads and byte-identical replay of independently verified, eligible committed output are the only exceptions. A separate fresh recovery subsystem may attempt authenticated reattachment without using the restored ratchet.

The current candidate requires a counterparty instance that retains the same exclusive volatile capability and one exclusive, non-rolled-back case signing journal. Focus changes, network reconnects or screen suspension do not by themselves constitute reopening while that capability remains live; a new worker, tab or process that imports persisted state does.

A peer being offline prevents completion. If both sides have reopened, the current baseline cannot resume case transmission. This is not a claim that every separately qualified future recovery design is impossible. No automatic new-case fallback is provided. Reattachment authenticates case-recovery authority and the new cutover; it does not prove that the restored archive contains every latest event. This is a design requirement, not a qualified SDK guarantee; key/nonce reuse protection and consumed invitation-key handling still require verification on the actual engine.
Authenticated reattachment is itself not yet qualified. Completing it is not sufficient
to resume sending until the actual engine has been qualified to prevent key/nonce reuse and the
reuse or resurrection of consumed invitation keys.

Old backups containing per-case recovery signing keys and recovery secrets retain case-recovery authority. Possession alone does not decrypt all subsequent MLS traffic. If an eligible live peer accepts a recovery flow, the holder can impersonate that case role, cause denial of service and gain access to subsequent case content after cutover. Session ratchets do not physically revoke these recovery credentials. This limits the post-compromise security of the composed recovery design; it is not a universal break of MLS post-compromise security.

The archive-only capability policy does not contain independent raw-engine imports, old binaries, forked clones, concurrent copies, or whole-runtime, VM or RNG rollback.

The design targets a finite simultaneous active-case window, not continuous reception for every
resident case or a measured capacity. Dormant-case recovery depends on epoch/history limits,
invitation expiry and relay retention; messages may be lost. Chromium and Firefox are browser qualification targets, not a general support guarantee. Safari/WebKit is not claimed as supported. Runtime-specific storage, locking and lifecycle behavior remains part of security qualification.

## Dart reference quick start

The following example exercises the independent Dart reference implementation. Current
application-layer work treats the language-neutral protocol and conformance corpus as the
cross-runtime authority before either implementation is extended. This quick start demonstrates
the Dart API; it is not evidence that the Dart stack implements C0.3 end to end.

```dart
import 'dart:convert';
import 'package:styx/styx.dart';

// 1. Create the ledger
final styx = SovereignLedger(
  identity: identity,
  config: const LedgerConfig(
    relayUrls: ['wss://relay.damus.io'],
  ),
  ledgerStore: ledgerStore,
  transport: transport,
  trustStore: trustStore,
  qrPairing: qrPairing,
  remotePairing: remotePairing,
  reKeyProtocol: reKeyProtocol,
  migrationService: migrationService,
  backupService: backupService,
  retentionManager: retentionManager,
  pruneProtocol: pruneProtocol,
  keyPair: keyPair,
);

// 2. Initialize
await styx.initialize();

// 3. Pair via QR
final qr = styx.generatePairingQr();
// ... show QR to peer, scan theirs ...

// 4. Send a transaction
await styx.sendTransaction(
  Uint8List.fromList(utf8.encode('{"amount": 42.50, "desc": "Cena"}')),
);

// 5. Read history
final history = await styx.getHistory();

// 6. Logical pruning (not proof of legal compliance or physical erasure)
await styx.requestPrune(targetEventId: history.last.eventId);

// 7. Backup identity (Shamir 2-of-3)
final shares = styx.createIdentityBackup();

// 8. Shutdown
await styx.shutdown();
```

## Dart reference architecture

Styx is structured as a monorepo of composable packages, layered bottom-up:

```
┌─────────────────────────────────────────────────────────┐
│                    styx (façade)                        │
│  SovereignLedger · Pairing · Migration · Backup         │
├──────────────┬──────────────┬───────────────────────────┤
│  transport   │ push_bridge  │      ledger_engine        │
│  Nostr·Email │ FCM/APNs     │  Hash chain · HLC · Merge │
│  Tor·Outbox  │ Privacy      │  Pruning · VectorClock    │
├──────────────┴──────────────┴───────────────────────────┤
│                     storage                             │
│              Drift + SQLCipher (AES-256)                │
├─────────────────────────────────────────────────────────┤
│                    crypto_core                          │
│  Ed25519 · X25519 · SPAKE2 · SHA-256 · BIP-39 · Shamir│
└─────────────────────────────────────────────────────────┘
```

| Package | Description |
|---------|-------------|
| `styx` | Public façade — single entry point with `SovereignLedger` |
| `crypto_core` | Ed25519/X25519 keys, SPAKE2, SHA-256, BIP-39, Shamir SSS |
| `storage` | Drift + SQLCipher encrypted database engine |
| `ledger_engine` | Append-only hash chain, HLC, vector clocks, merge, pruning |
| `transport` | Nostr (primary), Email/IMAP (fallback), Tor (overlay), failover engine |
| `push_bridge_client` | FCM/APNs wake-up with 3 privacy profiles |
| `push_bridge_server` | Stateless Go microservice for push notification bridging |

Current test results and path-aware coverage gates are reported by GitHub Actions; fixed totals are
not used here because the suites change as the protocol and reference implementations evolve.

## Dart reference capabilities

### Pairing
- **QR Pairing** — Direct public key exchange with anti-replay nonces
- **Remote Pairing** — BIP-39 mnemonic → SPAKE2 key exchange → 6-digit Double Check code for MITM detection

### Transactions
- Append-only event chain with SHA-256 hashes and Ed25519 signatures
- Event types: `transaction`, `message`, `config`, `sos`, `rekey`, `merge`, `pruneRequest`, `pruneAck`
- Hybrid Logical Clocks (HLC) for causal ordering across peers

### Offline & Sync
- Bounded offline queueing in the reference outbox; no post-reopen sending guarantee
- Deterministic merge on reconnect (order by vector clock sum, then lexicographic pubkey)
- Failover transport: Nostr → Email/IMAP → optional Tor overlay

### Privacy and retention
- Three push notification profiles: **Balanced** (no dummies), **Private** (Poisson-distributed dummy pushes), **Paranoid** (dummy pushes with real relay connections)
- Bilateral pruning protocol: `PRUNE_REQUEST` → `PRUNE_ACK` → payload removed, hash preserved
- Application-directed removal; no guarantee of physical erasure from backups, replicas, restored snapshots or copies held by recipients
- Configurable retention policies with automatic expiration

The SDK provides mechanisms for signed state transitions and application-directed retention. It does not establish GDPR compliance or guarantee erasure from backups, replicas, restored snapshots or copies held by recipients.

### Device Migration
- **Re-keying** via Blessing Events (old device signs the new device's public key)
- **Shamir backup** (2-of-3 by default) for identity recovery without re-keying

## Principles

- **No central server of record** — peers hold the authoritative event chain; messages are
  E2E-encrypted and routed by federated relays that cannot read content but do observe some
  transport metadata (not a zero-metadata or "serverless" system)
- **Cryptographic Trust** — Events are signed, hashed, and chained; authenticated storage and signed transitions do not prove freshness
- **Sovereign Identity** — Keys are generated locally; storage protections depend on the selected runtime profile
- **Retention controls** — Application-directed retention and bilateral payload removal with hash persistence; no legal-compliance or physical-erasure claim
- **Offline-First** — Bounded local queueing and deterministic merge in tested cases; no general availability, automatic-resume, or post-reopen sending guarantee

## Development

### Prerequisites

- Dart SDK ≥ 3.10.0 (the locked dependency graph requires it; see `pubspec.yaml`)
- Melos (`dart pub global activate melos`)
- Go 1.21+ (for `push_bridge_server` only)

### Setup

```bash
git clone https://github.com/styx-secure/styx.git
cd styx
melos bootstrap
```

### Commands

```bash
melos run test:all        # Run all tests across all packages
melos run analyze         # Static analysis
melos run format:check    # Check formatting
melos run ci              # Full CI pipeline locally
melos run coverage:check  # Enforce the per-package coverage baseline (90% is a target, not yet met everywhere)

# Single package
cd packages/styx && dart test                    # All tests in one package
cd packages/styx && dart test test/some_test.dart # Single test file
```

### Project Structure

```
styx/
├── packages/
│   ├── crypto_core/           # Identity & cryptography primitives
│   ├── storage/               # Encrypted persistence (Drift + SQLCipher)
│   ├── ledger_engine/         # Event chain, clocks, merge, pruning
│   ├── transport/             # Nostr, Email, Tor, failover, outbox
│   ├── push_bridge_client/    # Flutter push notification client
│   └── styx/                  # Public façade (SovereignLedger)
├── push_bridge_server/        # Go microservice for push bridging
├── test_integration/          # Cross-package integration tests
└── docs/                      # Architecture, security, API, and historical records
```

## License

Styx is **open source**. The licensing model, approved in
[ADR-0004](docs/architecture/decisions/ADR-0004-licensing-strategy.md) and mapped exactly in
[`LICENSING.md`](LICENSING.md) and [`REUSE.toml`](REUSE.toml), is:

- **Original Styx software and documentation:** [`AGPL-3.0-or-later`](LICENSE).
- **Eighteen exact synthetic data paths** (six interoperability vectors from Issue #41, six
  C0.3 transcript-corpus paths approved by Issue #253 and populated by Issue #264, and six SS-0
  corpus paths approved by Issue #291 and populated by Issue #293, all listed in `LICENSING.md`):
  `Apache-2.0`. Only fully synthetic Styx-generated data with no upstream bytes is authorized.
  SS-CORPUS-0 establishes bounded synthetic replay and mutation evidence only; it does not
  authorize an adapter, persistence, SDK, transport, product, demo, deployment or sensitive use.
- **Third-party and vendored material** keeps its upstream licenses and attribution — notably the
  OpenMLS-derived material in `styx-js/vendor/openmls-wasm/` (MIT; that directory also contains
  Styx-authored AGPL scripts and a Styx-modified MIT derivative, classified path by path). See
  [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
- **Trademarks are separate:** the Styx and Styx Secure names and logos are not granted by the
  software licenses ([`TRADEMARKS.md`](TRADEMARKS.md)).
- **External code contributions remain paused** until separate contributor terms are approved
  ([`CONTRIBUTING.md`](CONTRIBUTING.md)); issues and feedback are welcome.
- Separate commercial terms may be available from the copyright holder; the public AGPL edition
  stays in place regardless.
