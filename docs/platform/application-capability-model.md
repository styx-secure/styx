<!-- styx-canonical:v1 mirror="docs/platform/application-capability-model_IT.md" -->
# Styx application capability model

[Italian mirror](application-capability-model_IT.md)

> **Status:** exploratory, non-normative proposal
> **Snapshot:** `main @ d90931a3f59ce89c1594cad64ce385d58857b305`
> Component and API examples are illustrative and do not freeze interfaces,
> cryptographic primitives, or persisted formats.

## 1. Objective

This model establishes which properties Styx should be able to offer so that
different applications can share secure infrastructure without necessarily
sharing identities, data schemas, or policies.

Composition is the guiding principle: an application selects capabilities and
policies; it does not automatically inherit every promise made by the chat.
Every capability must have:

- an observable contract;
- a threat model;
- a versioned representation when it crosses network or storage boundaries;
- fail-closed errors;
- positive, negative, crash, and interoperability tests where applicable;
- a statement of residual risks.

## 2. Vocabulary

| Term | Meaning in this model |
|---|---|
| **Civil identity** | Information connecting a person to a real-world name, contact detail, or role. It must not be confused with a key. |
| **Cryptographic identity** | A key or credential set used to authenticate actions. It may be persistent, device-bound, application-specific, or ephemeral. |
| **Anonymity** | The defined adversary cannot link an action to a real person within the stated model. It is not an absolute property. |
| **Confidentiality** | Unauthorized parties cannot read content. The operator may still know the identity. |
| **Pseudonymity** | Actions are linked to a stable pseudonym, not necessarily to a civil identity. |
| **Unlinkability** | The adversary cannot establish that two actions, cases, or identities belong to the same subject. |
| **Capability** | An unforgeable secret or token whose possession authorizes an operation, such as reopening an anonymous case. |
| **Application context** | A logical domain separating one application's keys, identifiers, data, and policies from others. |
| **Case context** | A one-time subdomain, or one limited to a case, conversation, or group. |
| **E2EE object** | An encrypted and authenticated object for explicit recipients, with an application schema and version. |
| **Tamper-evident** | A later modification can be detected under stated invariants. It does not prove the original data was true. |
| **Assurance profile** | A verifiable set of capabilities, configuration, clients, and operational requirements. |

## 3. Actors and trust boundaries

The model does not assume a single “bad server.” It separates at least:

- **user and device**: generate input, hold keys, and display plaintext;
- **application**: interprets schemas, roles, and workflows;
- **Styx core**: encrypts, authenticates, persists, and synchronizes;
- **relay or store-and-forward provider**: observes connections and stores blobs;
- **push provider**: observes endpoints, timing, and wake-ups;
- **client publisher**: distributes HTML, JavaScript, WASM, or binaries;
- **organizational operator**: manages cases, groups, roles, or infrastructure;
- **authorized peer**: reads data but may copy or disclose it;
- **network observer**: sees origins, destinations, timing, and volumes;
- **device administrator**: may control the browser, extensions, input, screen,
  and memory;
- **backup or operating-system provider**: may retain replicas invisible to the
  application.

A property must identify the actors against which it holds. “The relay does
not read the message” is compatible with “the relay sees the IP address and
routing tag.”

## 4. Proposed logical architecture

### 4.1 Application layer

Contains UI, workflow, semantic schema, domain validation, and organizational
rules. It does not receive raw keys when it can request operations from the
core, and it does not select cryptographic primitives.

### 4.2 Policy and capability layer

Translates the threat model into policy: identity type, recipients, retention,
recovery, relay count, routing, notifications, attachments, and audit level. It
rejects combinations that do not meet the required profile.

### 4.3 Secure object and session layer

Manages E2EE sessions, versioned application objects, membership, rotation,
authentication, sequences, and cryptographic state. MLS is the canonical
product core, but not every application can automatically be modeled as chat
messages.

### 4.4 Reliability and synchronization layer

Manages a persistent outbox, retry, ACK, deduplication, idempotency, ordering,
replay, and conflict policies. It distinguishes “published to a relay,”
“received by a device,” and “read by a person.”

### 4.5 Privacy transport layer

Selects relays, routes, onion endpoints, mailbox keys, padding, batching, and
notifications. Content encryption does not replace this layer.

### 4.6 Local custody layer

The vault confines keys and plaintext and applies lock/unlock, transactions,
reset, migrations, and recovery. The page consumes a closed data protocol; it
does not receive the Root Key, KEK, `CryptoKey`, or WASM handles.

### 4.7 Distribution and operations layer

Makes builds, updates, configuration, and operational continuity verifiable.
It includes separation of duties, administrative audit, infrastructure backup,
and observability without sensitive data.

## 5. Required capabilities

### 5.1 Application context and domain separation

Every application needs an unambiguous context identifier used in key
derivation, AAD, schemas, and policies. Two applications on the same device
must not automatically reuse:

- identity or mailbox keys;
- vault namespaces;
- group identifiers;
- counters, nonces, or sequences;
- push endpoints;
- aliases and contact graphs;
- recovery secrets.

A `case context` must provide further separation. An anonymous report and a
second report from the same browser must not be linkable through a persistent
protocol identifier.

**Minimum evidence:** cross-context tests proving different keys/AAD and
rejection of ciphertext moved between contexts.

### 5.2 Identity profiles

The core should support distinct profiles rather than simulate them with one
durable account:

| Profile | Lifetime and use |
|---|---|
| `persistent-personal` | Self-custodied, verifiable identity for durable relationships. |
| `device` | Revocable credential for one device, subordinate to a relationship or account. |
| `application` | Identity separated for one application and not reused elsewhere. |
| `case-ephemeral` | Random identity for one case or group, without reuse. |
| `anonymous-capability` | No account; a high-entropy capability allows return to the case. |
| `organization-role` | Credential bound to an operational role and rotatable independently of the person. |

Generation, rotation, revocation, expiry, and export must be explicit. A public
key must not be described as anonymous merely because it contains no name.

### 5.3 Unlinkability

Cryptographic separation is insufficient if network, push, and storage use
stable handles. The profile must jointly assess:

- external event keys;
- routing tags and mailboxes;
- relay sets;
- push endpoints;
- timing and size;
- client fingerprints;
- recovery and backup;
- key names and local namespaces.

Unlinkability must be tested as a negative property: no common field and no
mapping accessible to the declared adversary. Statistical and timing
correlation remain possible against a global observer.

### 5.4 E2EE objects and application schema

Applications must be able to define encrypted objects other than text messages:
accounting operations, assignments, forms, receipts, comments, and workflow
states. Every object requires at least:

- `application context` and schema version;
- a random identifier and idempotency key;
- cryptographic author and recipients or group;
- policy type and version;
- logical timestamp and, where needed, causal dependencies;
- a bounded payload with a closed grammar;
- evolution rules and handling of unknown versions.

The concrete format is a separate decision. The core must not deserialize
application objects into executable forms, accept callbacks, or permit
unvalidated dynamic access.

### 5.5 Conversations, groups, and membership

Primitives are needed for:

- 1:1 sessions;
- groups with distinct members and devices;
- out-of-band invitation and verification;
- addition, removal, and suspension;
- rotation after compromise;
- authorization of membership changes;
- pending commits, ACKs, and forks;
- minimally sensitive state export for debugging.

MLS provides useful primitives, but the product must define the Authentication
Service, Delivery Service, membership policy, and recovery. Forward secrecy and
post-compromise security also depend on rotation and material deletion, not
only on selecting MLS.

### 5.6 Authorization, roles, and delegation

A key able to decrypt should not automatically be able to administer. The
model must distinguish:

- reading, writing, and commenting;
- inviting or removing members;
- case assignment;
- export and deletion;
- retention and policy changes;
- administrative log access;
- rotation and recovery.

Roles, delegations, and revocations must be authenticated, versioned, and
evaluated locally. High-impact operations may require multi-person or threshold
authorization, but the concrete technique requires a separate design.

### 5.7 Local vault and secret confinement

The application vault must:

- encrypt records and manifests before persistence;
- derive and separate keys by namespace and purpose;
- perform KDF, unwrap, and sensitive operations in a dedicated worker;
- expose a closed protocol with bounded payloads;
- serialize mutations and use atomic transactions;
- close deterministically on lock, timeout, reset, and crash;
- prevent return of keys, plaintext, and sensitive stacks;
- distinguish logical deletion from unprovable physical erasure;
- handle migrations without destroying original data before verification.

The password remains a JavaScript string that cannot be reliably zeroed. A
compromised browser or operating system while the vault is unlocked remains
outside the protection offered by the vault alone.

### 5.8 Transports and relay federation

The core should depend on a transport contract, not a specific relay. An
adapter declares:

- publication and confirmation semantics;
- persistence or ephemerality;
- limits and quotas;
- information visible to the operator;
- authentication and replay protection;
- behavior under duplication, reordering, and loss;
- deletion capability, if any;
- direct, federated, or onion mode.

Multiple relays improve availability but may increase the observation surface.
Replication must not be confused with consensus: the application must know
whether one publication, a relay quorum, or a recipient ACK is sufficient.

### 5.9 Reliability and store-and-forward

Every outgoing mutation passes through a persistent outbox before sending. The
model distinguishes states such as:

```text
queued → published → device-acknowledged → application-acknowledged
                         ↘ expired / rejected / conflicted
```

The names are illustrative. Essential requirements are:

- retry with backoff and jitter;
- a stable idempotency key for the operation;
- persistent deduplication, not only in memory;
- authenticated and encrypted ACKs;
- post-crash reconciliation between local commit and response;
- attempt limits, expiry, and a dead-letter state;
- clear semantics for ephemeral messages;
- no “sent” state derived only from calling `publish()`.

### 5.10 Ordering, synchronization, and conflicts

Chat can tolerate ordering different from accounting. The core supplies
primitives while the application declares its policy:

- per-author or per-device sequence;
- causal dependencies;
- gap, replay, and fork detection;
- commutative merge where semantically valid;
- rejection or human review for non-composable conflicts;
- verifiable snapshots and compaction;
- rollback detection within declared limits.

There is no universal merge. Adding two expenses may be correct; accepting two
incompatible assignments of the same case may not be.

### 5.11 Metadata protection

A metadata-minimizing profile must consider at least:

- an ephemeral or non-identifying external key;
- a rotatable mailbox key distinct from identity;
- outer-envelope encryption;
- obscured timestamps;
- bucket padding with a minimum floor;
- optional batching or delays;
- relay choice and rotation;
- Tor/onion routing;
- disabling typing, presence, and read receipts;
- notifications without a direct identity mapping;
- dummy-traffic policy, cost, battery, and latency.

NIP-59/NIP-44 are options to evaluate, not decisions made by this document.
Even a gift wrap may expose a recipient or stable handle; the threat model must
verify the concrete variant.

### 5.12 Attachments and complex content

Attachments add risks independent of encryption:

- EXIF, author, path, history, and document metadata;
- watermarks, canaries, and invisible identifiers;
- malware and vulnerable parsers on the receiving device;
- size and statistical signature;
- previews or scans entrusted to third parties;
- persistence in caches and external applications;
- hash deduplication linking different cases.

The core should provide encrypted streaming, authenticated chunks, limits,
padding, and integrity. Sanitization, conversion, and warnings belong in an
isolated service or the application. An anonymous profile may start `text-only`
and prohibit attachments until the path is verified.

### 5.13 Multi-device, rotation, and compromise response

Every device needs a distinct credential, state, and revocation. The model
must cover:

- verified addition of a device;
- a user-comprehensible device list;
- revocation with group rotation;
- loss, theft, and compromise;
- selective history synchronization;
- recovery without indefinitely cloning a personal key;
- monotonic epoch/generation and rollback detection;
- an emergency procedure that does not conceal compromise.

Backing up a key and supporting multiple devices are not the same. Restoring a
durable key may preserve identity, but does not solve revocation and MLS state.

### 5.14 Recovery and capability custody

Recovery must state what it recovers: identity, case access, data, or
membership. Possible models include a single secret, multiple shares, another
device, or organizational custody; the choice requires separate analysis.

An `anonymous capability` must have sufficient entropy, be generated locally,
and not be derived from personal data. The interface may represent it as a QR
code or words, but must protect against:

- screenshots and automatic cloud backup;
- physical theft;
- phishing and online brute force;
- permanent loss;
- reuse across cases;
- technical support asking for the secret.

The server must not be able to regenerate the capability. Loss may
intentionally make the case impossible to reopen.

### 5.15 Retention, redaction, deletion, and export

Every data class needs an independent policy:

- operational duration;
- basis and reason for retention;
- expiry and legal hold;
- local deletion and requests to peers;
- payload redaction, with or without sequence evidence;
- removal of indexes, caches, notifications, and backups;
- encrypted or cleartext export with consent and audit;
- behavior offline and on devices no longer reachable.

A hash chain may preserve fingerprints of deleted data. The design must assess
whether the fingerprint is itself personal or correlatable. Styx cannot ensure
that a recipient deletes a copy or screenshot.

### 5.16 Audit, receipts, and evidence

Distinct records are needed:

- local **security audit log**: access and sensitive operations;
- **shared event history**: authenticated application events;
- **operator audit**: assignment, export, retention, and administration;
- **delivery evidence**: publication and authenticated ACKs.

Logs must minimize content and identifiers, have separate access, and not
become a new social graph. A signature, local timestamp, and hash chain do not
automatically provide a qualified timestamp, civil identity, truthful content,
or legal admissibility. Those properties require separate processes and
services.

### 5.17 Application SDK and capability discovery

The SDK should expose stable application concepts without handing out secrets:

- opening an `application context`;
- creating or importing an identity profile;
- managing sessions and encrypted objects;
- querying capabilities and versions;
- subscribing to typed, bounded events;
- data-only transactional operations;
- explicit handling of offline, lock, and recovery states;
- statically registered transport and storage adapters;
- typed errors without sensitive payloads or stacks.

Version negotiation must fail closed on incompatible formats. Feature flags
and capability discovery must not permit silent downgrade.

### 5.18 Authentic distribution and updates

An encrypted PWA is not secure if the first response can deliver malicious
JavaScript that exfiltrates plaintext before encryption. Complementary layers
are required:

- reproducible builds and verifiable artifacts;
- dependency provenance and pinning;
- CSP and absence of third-party resources;
- a service worker with update and rollback policy;
- artifact signatures or transparency where supported;
- distribution from independent origins or installed clients;
- a verification channel external to the compromisable server;
- a signed native client for higher-assurance profiles.

A hash communicated by the same server does not authenticate that server.
Cross-client verification can help only if it has a trust root and resists
Sybil, rollback, and eclipse attacks; the concrete protocol is a separate
decision.

### 5.19 Privacy-safe observability and continuity

The operator needs indicators without recording users or content:

- relay availability and latency;
- aggregated errors with bounded cardinality;
- minimized client-version and compatibility data;
- quota and queue saturation without record keys;
- administrative audit separated from telemetry;
- opt-in, local, redacted diagnostic logs;
- runbooks for loss of relays, keys, and providers.

Analytics, crash reporters, CDNs, fonts, and third-party scripts must be
forbidden in sensitive profiles or explicitly evaluated. Geographic redundancy
improves continuity but requires key management, patching, monitoring, and
restore tests.

### 5.20 Organizational custody and separation of duties

Applications managed by organizations require:

- role keys separated from personal identities;
- case assignment and reassignment;
- least privilege;
- immediate operator revocation;
- dual authorization for export, destruction, or policy changes;
- continuity when a person leaves a role;
- declared and audited emergency access;
- no silent universal key.

An organizational master key simplifies recovery but dramatically increases
the impact of compromise and insider abuse. Threshold schemes, multi-recipient
encryption, or escrow are alternatives for separate design and review, not
choices made by this model.

### 5.21 Compliance hooks

The core can facilitate a regulated process through:

- configurable retention;
- data minimization;
- roles and audit;
- export and legal hold;
- versioned notices and consent where relevant;
- deadlines, reminders, and workflow states;
- recording the applicable basis/policy;
- separation between channels governed by different regimes.

It cannot autonomously determine applicable law, classify a report, ensure the
handler's independence, prevent retaliation, or confer certifications. DPIAs,
procedures, training, and human oversight remain the organization's
responsibility.

### 5.22 Abuse resistance and safety

Anonymity can be used for spam, threats, and illegal material. Without
identifying the reporter, an application must be able to apply:

- limits per capability, time window, and cost;
- accessible proof-of-work or challenges after risk analysis;
- quarantine queues and isolated local scanning;
- blocking one case without blocking all users;
- separation between channel abuse and the merits of a report;
- escalation for immediate danger;
- protection of operators from traumatic content;
- controlled preservation of evidence where required.

Per-IP rate limits can harm users behind Tor or NAT and create identifying
logs. Every mitigation must be assessed in the threat model.

## 6. Assurance profiles

The following names describe objectives, not certifications.

### `content-confidential`

E2EE, peer verification, protected storage, and an untrusted relay. Transport
metadata remains visible and a compromised endpoint remains unprotected.

### `resilient-collaboration`

Adds a persistent outbox, ACKs, idempotency, multiple relays, recovery, and
conflict policies. It targets continuity and consistency, not anonymity.

### `metadata-minimizing`

Adds application identities, rotatable mailboxes, a protected outer envelope,
padding, notification policies, and Tor/onion options. It reduces observability
but does not eliminate global correlation.

### `anonymous-dialogue`

Adds per-case identity, a return capability, no mandatory contact detail,
no cross-case linking, and an operator workflow. Anonymity holds only against
the declared adversaries and under the stated conditions.

### `native-high-assurance`

Requires a signed native client, secure hardware where available, verifiable
updates, a specific threat model, and a separate audit. It does not follow
automatically from the PWA.

## 7. Cross-cutting invariants

Every future implementation should preserve:

1. no secret crosses unnecessary boundaries;
2. no network input selects code or dynamic access;
3. namespace, schema, and version are authenticated;
4. a persistence error is not presented as success;
5. publication does not equal delivery;
6. a key does not equal a civil identity;
7. multiple relays do not equal anonymity;
8. deletion does not promise physical erasure;
9. a recovery path does not bypass revocation and audit;
10. a feature is unavailable until tests, CI, and documentation cover it in
    the product that uses it.

## 8. Readiness criterion for a new application

Before a pilot, the application must produce:

- a threat model with actors, assets, and assumptions;
- a data-flow diagram showing visible metadata;
- a capability and dependency matrix;
- approved schema/version policy;
- a plan for loss, crash, rollback, and recovery;
- attachment, retention, and export policy;
- end-to-end tests on real clients and infrastructure;
- an independent review and residual-risk list;
- UI copy that does not exceed demonstrated guarantees;
- an organizational procedure and emergency contacts, where applicable.

The presence of primitives in the repository is insufficient: the property
must be demonstrated across the application's complete path.
