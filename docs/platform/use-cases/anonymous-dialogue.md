# Anonymous bidirectional dialogue

Status: design exploration, non-normative. This document does not define a
production protocol, provide legal advice, or establish compliance with any
law, standard, certification scheme, or organizational procedure.

## 1. Purpose

This use case describes how a future application built on Styx could let a
person submit a report and continue a private conversation without giving the
organization an email address, telephone number, ordinary chat identity, or
other stable contact identifier.

The target is a **bidirectional pseudonymous case mailbox** that can offer
anonymity relative to the receiving organization under an explicit threat
model. It is not a promise of absolute or universal anonymity.

The same primitive could support ethics hotlines, safeguarding channels,
source-and-journalist contact, sensitive research intake, and similar casework.
Each application remains responsible for its own legal basis, governance,
retention, escalation, and safeguarding procedures.

## 2. Terms and required properties

- **Confidentiality** means unauthorized parties cannot read protected content.
- **Pseudonymity** means a case-specific identifier is used instead of a civil
  identity.
- **Anonymity relative to an observer** means that observer cannot reasonably
  connect the case to a person within the stated assumptions.
- **Return capability** is a high-entropy secret that authorizes access to one
  case mailbox. It is not a username or a reusable identity.

A conforming design should provide:

1. end-to-end confidentiality and integrity between the reporter's client and
   authorized case handlers;
2. a fresh, unlinkable cryptographic context for every case;
3. asynchronous replies without collecting conventional contact details;
4. explicit receipt and status semantics rather than assuming relay acceptance
   means organizational receipt;
5. minimal and documented metadata exposure;
6. role-based organizational custody, handler rotation, and revocation;
7. bounded retention and auditable actions without a plaintext audit trail;
8. safe export and handover procedures where the applicable process requires
   them.

## 3. Non-goals

This capability does not by itself:

- prove that a report is true or that a reporter is acting in good faith;
- hide network origin, timing, device fingerprint, message size, writing style,
  facts known to few people, or attachment metadata merely because content is
  encrypted;
- protect a person using a compromised device or a hostile browser while the
  case is open;
- make an employer-controlled device or network safe;
- decide whether a report is legally protected whistleblowing;
- replace an organization's trained handlers, investigation process, emergency
  procedures, or data-protection duties;
- guarantee delivery, availability, or deletion through cryptography alone.

The ordinary long-lived Nostr or Styx chat identity must not be reused. Doing so
would make otherwise separate reports linkable and could expose the reporter's
social graph.

## 4. Legal-routing boundary in Italy

The application must distinguish the purpose of a reporting channel from the
legal route assigned to an individual report.

UNI/PdR 125:2022 is a voluntary reference practice for gender-equality
management systems, not a national statute. Section 6.3.2.6 asks organizations
to provide an anonymous reporting methodology for physical, verbal, or digital
abuse and harassment. That requirement and its organizational context must not
be presented as if every report were a whistleblowing report.

Legislative Decree 24/2023 governs protected whistleblowing within its defined
subjective and objective scope. For internal channels it requires, among other
things, confidentiality of identities, content, and documents; autonomous and
specifically trained management; written or oral reporting; acknowledgement
within seven days; dialogue and diligent follow-up; and feedback normally
within three months. Its privacy, retention, and protection rules apply when
the report is within that scope.

Not every allegation of abuse, harassment, discrimination, employment conflict,
or individual grievance falls within Legislative Decree 24/2023. In particular,
reports concerning only the reporter's individual employment relationship or
relationships with hierarchical superiors may be excluded from its scope. A
trained human or an approved organizational rule must route the report; the
protocol must not silently make that legal determination.

The interface should therefore:

- describe available routes in plain language without requiring the reporter to
  classify the law correctly;
- accept a report before requesting optional identifying information;
- make clear which organization or independent office receives each route;
- record the applicable policy and retention schedule selected by an authorized
  handler;
- support transfer only through an explicit, auditable handover that preserves
  confidentiality and informs the reporter when permitted;
- expose emergency and immediate-danger instructions outside the asynchronous
  mailbox flow.

Legal counsel, the data-protection officer where applicable, worker
representatives, safeguarding experts, and the responsible organizational
functions must validate a real deployment.

## 5. Actors, assets, and trust boundaries

### Actors

- **Reporter:** creates and later reopens a case without a normal account.
- **Reporter client:** trusted temporarily with plaintext and case secrets.
- **Intake service/relay:** stores and forwards opaque envelopes; it is not
  trusted with plaintext or reporter identity.
- **Case handler:** an authorized and trained person who reads and replies.
- **Organization custodian:** provisions role keys, rotates handlers, and
  administers retention without gaining unrestricted plaintext access by
  default.
- **Independent recipient:** an external office or professional used when the
  organization's conflict-of-interest policy requires it.
- **Auditor:** verifies authorized workflow events and policy conformance without
  automatically receiving report content.
- **Adversary:** may operate infrastructure, observe networks, submit abusive
  traffic, compromise an endpoint, correlate timing, or collude across some of
  these positions.

### Protected assets

- report and reply plaintext;
- case existence and status;
- the reporter's identity and network origin;
- the return capability and local case keys;
- handler identities where policy requires confidentiality;
- attachments and their metadata;
- routing, retention, export, and audit records.

### Trust boundaries

1. **Reporter boundary:** device, operating system, browser, extensions,
   clipboard, screen, and local storage.
2. **Distribution boundary:** the code delivered to the reporter must be the
   reviewed application, not a targeted malicious version.
3. **Network boundary:** access provider, DNS, proxies, firewalls, Tor entry and
   exit observations, and relay connections can expose metadata.
4. **Infrastructure boundary:** relay and hosting administrators can inspect,
   delay, replay, delete, or selectively serve data even when they cannot
   decrypt it.
5. **Organization boundary:** custodians, handlers, auditors, investigators, and
   downstream recipients have different legitimate powers and conflicts.
6. **Human boundary:** a recipient can copy plaintext, take screenshots, or infer
   identity from content.

## 6. Threat model

The baseline attacker can operate one or more relays, observe an ordinary
network path, enumerate public protocol events, replay valid ciphertext, and
submit many reports. A stronger attacker may control the web origin or one
organizational administrator, correlate multiple network vantage points, or
compromise a reporter or handler endpoint.

The design should tolerate a malicious relay for content confidentiality and
integrity, and should use independent infrastructure to reduce single-provider
availability risk. It cannot claim traffic-analysis resistance unless the
chosen transport, padding, batching, polling, and deployment are tested against
the stated observer. Multiple public relays can improve availability while also
giving more parties metadata to observe.

Endpoint compromise, targeted delivery of modified web code, coercion, and
content-based identification remain residual risks. A higher-assurance profile
may therefore require a signed native client, reproducible artifacts, Tor or an
onion service, and an independently verifiable release channel. These are
separate design and deployment decisions.

## 7. Conceptual architecture

```text
reporter client
  -> fresh per-case cryptographic context
  -> encrypted case envelope
  -> metadata-minimizing transport adapter
  -> one or more untrusted store-and-forward services
  -> organizational intake adapter
  -> authorized handler workspace

authorized handler reply
  -> encrypted case envelope
  -> store-and-forward services
  -> capability-based polling by the reporter client
```

The application profile sits above the Styx application core. It defines case
states, receipts, routing, retention, roles, and user experience. The core
provides versioned encrypted objects, replay protection, delivery state,
capability handling, and transport abstraction. Nostr, HTTPS drop boxes, Tor
onion services, or offline carriers are adapters; none should define the case
identity or plaintext data model.

The exact cipher suite, envelope format, recipient-key construction,
multi-recipient method, padding scheme, and capability encoding require a
separate approved cryptographic and persisted-format design. This document does
not select them.

## 8. End-to-end data flow

### 8.1 Safe entry

The landing page explains, before data entry, that a work device or work network
may be monitored. A high-assurance deployment provides a separately verifiable
client and a metadata-protecting access path. Ordinary email, SMS, analytics,
third-party fonts, advertising scripts, remote error-reporting payloads, and
identity-linked push notifications are excluded from the reporting flow.

### 8.2 Case creation

The reporter client generates a fresh case context and high-entropy return
capability locally. No normal Styx account, Nostr public key, address-book entry,
or pre-existing chat session is consulted. Domain separation prevents keys or
signatures from being reused in another application or case.

The client obtains an authenticated organizational intake descriptor containing
the intended recipient role, supported protocol versions, expiry, transport
options, and release identity. Trusting that descriptor and its distribution
path is a deployment decision that the interface must make visible.

### 8.3 Submission

The client encrypts a versioned case object for the approved intake role,
applies the selected metadata-minimization policy, and submits redundant opaque
envelopes. Local acceptance, relay storage, cryptographic handler receipt, and
human acknowledgement are distinct states. The interface must not label the
case "received by the organization" after only a relay acknowledgement.

### 8.4 Return capability

After a durable local write, the client displays the return capability once in
a human-manageable export such as a recovery sheet or QR representation. The
encoding and backup method are separate design decisions, but the underlying
secret must have sufficient entropy to resist online and offline guessing.

The capability authorizes only one case. It must not be placed in a URL query,
logs, browser history, telemetry, crash reports, referrer headers, or server-side
account table. A weak phrase, case number, email address, or hash of guessable
data is not an acceptable capability.

The server cannot recover a lost capability without introducing an identity or
an escrow power. The product must state this before the reporter leaves the
creation flow.

### 8.5 Dialogue

The reporter returns through the safe entry point and presents the capability
locally. The client derives or unlocks the case context, polls using an
unlinkability-aware transport token, verifies the complete encrypted history,
and submits replies as new case objects. Manual polling is the privacy-preserving
default; notifications are optional only when their identity and metadata
leakage is explained.

The protocol needs idempotency, authenticated ordering, duplicate suppression,
and explicit gap handling. A valid historical object replayed by a hostile
service must not silently replace the current case state.

### 8.6 Optional identity disclosure

Identity disclosure is a separate, explicit action. The UI previews the exact
fields and recipients, and the resulting object records consent and purpose.
The core never treats later disclosure as permission to retroactively link
other cases.

## 9. Recovery-secret handling

The reporter client should:

- create the capability with a cryptographically secure random source;
- keep it out of DOM attributes, URLs, logs, telemetry, and persistent clipboard
  history where the platform permits;
- store it only in the encrypted local vault when the reporter explicitly opts
  in;
- encourage a private offline copy and explain that screenshots or cloud-backed
  photo libraries may leak it;
- use rate-limited, privacy-preserving retrieval that does not turn the service
  into a capability-guessing oracle;
- make failed lookup responses and timing difficult to use for case enumeration;
- support explicit local removal without claiming guaranteed physical erasure
  from browser storage, flash memory, backups, or synchronized profiles.

A split or delegated recovery design might reduce accidental loss, but it also
creates new correlation and custody powers. It must be evaluated separately and
must never be enabled invisibly.

## 10. Operator workflow

An organizational deployment needs more than a recipient key. At minimum it
defines:

1. intake ownership and conflict-of-interest routing;
2. trained primary and backup handlers with least-privilege access;
3. acknowledgement, follow-up, and feedback deadlines for each applicable legal
   or organizational route;
4. a case-state model such as submitted, technically received, acknowledged,
   under assessment, awaiting reporter, routed, closed, and retained;
5. controlled requests for clarification that do not pressure the reporter to
   identify themselves;
6. escalation for immediate danger, safeguarding, evidence preservation, and
   mandatory external reporting;
7. handler replacement, key rotation, absence cover, and recovery from loss of
   organizational custody;
8. documented export, disclosure, redaction, and deletion authorization;
9. a way to disclose service incidents and missed deadlines to the reporter;
10. periodic independent review of access, routing, retention, and availability.

Where Legislative Decree 24/2023 applies, the workflow must be configured and
validated for its acknowledgement and feedback obligations. Other channels may
have different deadlines. A single generic timer is unsafe.

Organizational keys should represent a role and approved policy, not an
individual employee's normal chat identity. Access changes produce auditable
key events and must not require re-encrypting plaintext through the relay.
Whether decryption uses a dedicated recipient, multiple recipients, threshold
custody, or a hardware-backed service is a separate security decision.

## 11. Metadata protection

Content encryption is necessary but insufficient. The profile should minimize:

- source IP and network path, using a validated anonymity transport where the
  threat model requires it;
- stable relay account, public key, or client identifier;
- exact submission and polling times through batching, delay, and cover traffic
  where justified;
- event and attachment sizes through bounded padding classes;
- unique client fingerprints and third-party requests;
- public recipient tags and organization-specific routing markers;
- server-visible case existence, status, and access frequency;
- logs linking administrator actions to a reporter network session.

Padding, batching, and cover traffic consume bandwidth and can reduce usability.
Their precise policy belongs to an assurance profile and must be measured.
Encryption alone does not hide these properties.

Employer proxies and firewalls are particularly important: even a well-designed
platform cannot make access from a logged corporate network unobservable to
that network. Deployment guidance must explicitly address this risk.

## 12. Attachments and content safety

An initial high-assurance profile should prefer structured text and disable
attachments until a reviewed pipeline exists. Attachments can contain author
names, device identifiers, location, timestamps, revision history, thumbnails,
malware, active content, and visually identifying details.

If enabled, attachment handling needs local metadata inspection and removal,
safe format conversion, size padding, malware isolation, encrypted chunking,
authenticated manifests, resumable delivery, and a warning that sanitization
cannot remove identity clues in the visible content. Originals and sanitized
copies require explicit retention and evidentiary rules.

Free text can itself identify a reporter through facts, vocabulary, or writing
style. The UI may warn and offer a local preview, but automatic rewriting must
not silently alter evidence.

## 13. Abuse resistance

An anonymous intake channel can be spammed, flooded, probed, or used to deliver
malware and harassment. Controls must not quietly recreate identity tracking.
Candidate controls include:

- bounded message and attachment sizes;
- per-capability quotas and state-dependent rate limits;
- privacy-preserving proof-of-work or anonymous rate-limit credentials;
- coarse ingress limits applied before expensive cryptography;
- queue isolation, backpressure, and storage budgets;
- local and operator-side content safety measures;
- revocable case capabilities with a documented appeal or reopening policy;
- multi-provider failover without publishing a global blocklist of reporters.

CAPTCHAs, telephone verification, stable cookies, IP reputation, and commercial
fraud services can undermine anonymity and accessibility. Any use requires a
specific privacy and availability assessment. Abuse controls must be tested for
denial of service against legitimate reporters, including users of Tor and
assistive technology.

## 14. Retention, audit, and export

Retention is assigned by the validated legal or organizational route and starts
from a defined event. Encrypted storage is still personal-data processing when
it relates to an identifiable person. The system should support automatic
expiry, legal holds with explicit authority, reporter-visible closure where
appropriate, and deletion of redundant transport copies without claiming
physical erasure that the storage medium cannot prove.

Audit records should demonstrate events such as descriptor publication, role
changes, handler access, acknowledgement, routing, export, and retention-policy
changes. They should avoid report plaintext, capability material, exact source
metadata, and unnecessary stable identifiers. Tamper evidence can show that a
record changed; it cannot prove that the recorded human action was proper or
that a concealed action never occurred.

Exports need an authenticated manifest, redaction workflow, recipient and
purpose record, integrity verification, and an expiry policy. A plaintext PDF
download is not a complete secure handover design.

## 15. Availability and continuity

The transport should tolerate one unavailable or censoring relay, reconcile
duplicate envelopes, and distinguish temporary delay from confirmed handler
receipt. The organization needs monitored backup intake, tested key recovery,
handler absence cover, and a public incident channel that does not expose active
reporters.

Federation and multiple relays reduce some single points of failure but do not
remove servers, operators, capacity planning, denial-of-service risk, or common
software failures. Recovery drills must include loss of one relay, one region,
one handler, and one organizational key custodian.

## 16. Fit with the current Styx repository

The current repository contains useful building blocks, but it is not yet an
anonymous reporting product:

- the active JavaScript stack provides encrypted sessions, Nostr transport, and
  an emerging local vault;
- the present chat flow and its long-lived identity model are intentionally
  unsuitable for anonymous case creation;
- relay publication is not yet an end-to-end receipt from an authorized human;
- remote pairing, durable delivery state, application-domain separation,
  multi-device recovery, metadata-minimizing routing, and organizational role
  custody remain incomplete or separate design decisions;
- the current PWA distribution and first-load trust model does not alone resist
  a targeted malicious origin;
- the Dart stack is a reference implementation and must not be treated as the
  active product path.

Implementation should follow the capability and integration documents in this
directory. In particular, the vault lifecycle can be a canary for sensitive
state handling, but completing it does not satisfy this use case on its own.

## 17. Proposed staged validation

### Stage A: protocol and governance design

- approve the threat model and assurance profile;
- define versioned case objects, state transitions, receipts, replay rules, and
  domain separation;
- complete cryptographic and persisted-format review;
- map routing, retention, roles, incidents, and legal responsibilities with
  qualified humans;
- perform a data-protection impact assessment where required.

### Stage B: text-only technical pilot

- use a fresh case identity and return capability with no normal account;
- support encrypted submission, acknowledgement, clarification, reply, and
  closure;
- implement durable outbox/inbox state, duplicate and replay handling, relay
  failover, bounded padding, and privacy-safe logs;
- use manual polling and exclude attachments, analytics, and third-party code;
- provide handler rotation and an independent recipient route.

### Stage C: adversarial assurance

- review protocol, client, operator workspace, and deployment independently;
- test malicious relays, replay, rollback, enumeration, spam, queue exhaustion,
  handler revocation, and regional outage;
- measure metadata visible to relays, hosting providers, corporate networks, and
  colluding observers;
- test targeted client delivery and artifact-verification controls;
- run usability and accessibility studies covering capability backup, lost
  access, misleading receipt states, and high-stress reporting.

### Stage D: limited organizational pilot

- deploy only for an explicitly bounded route and population;
- train handlers and test deadlines, escalation, absence, and incident response;
- publish limitations and a safe alternative channel;
- collect aggregate operational measures that cannot identify reporters;
- obtain a go/no-go decision from security, privacy, legal, safeguarding, and
  organizational owners before expanding scope.

## 18. Acceptance evidence for a future implementation

A production claim requires evidence that:

- two cases from one clean client are not linkable through protocol identifiers;
- no ordinary chat or Nostr identity is read or emitted during case creation;
- relay, origin, and database compromise do not reveal protected plaintext;
- altered, reordered, duplicated, missing, and rolled-back case objects fail
  closed or produce an explicit recovery state;
- relay storage and human acknowledgement are never conflated;
- loss and revocation of handler access behave according to the approved custody
  model;
- capability enumeration and online guessing meet defined resistance targets;
- the declared network observer sees only the metadata allowed by the selected
  assurance profile;
- retention and export follow the selected route and produce privacy-minimized
  audit evidence;
- browser, native, mobile, offline, recovery, and accessibility behavior is
  tested for every supported client;
- independent reviewers reproduce the tests from clean environments.

Passing these tests supports only the stated profile and deployment. It does not
justify an unqualified claim of anonymity or legal compliance.

## 19. Residual risks

Even after the proposed work, the following risks remain:

- compromised reporter or handler endpoints, malicious extensions, keyloggers,
  screenshots, shoulder surfing, and coerced disclosure;
- targeted or first-load delivery of modified web code unless a stronger
  distribution mechanism is deployed and used correctly;
- traffic correlation by sufficiently capable or colluding observers;
- organization or relay denial of service, selective delay, and deletion;
- identification through report facts, writing style, visible attachment
  content, or a very small anonymity set;
- reporter mistakes such as using a monitored network, reusing text, sharing the
  capability, or storing it in a synchronized account;
- recipient copying, unauthorized downstream disclosure, and procedural abuse;
- inability to recover a genuinely lost non-escrowed capability;
- incomplete physical deletion from devices, backups, IndexedDB, and relay
  storage;
- legal or policy changes and incorrect human routing decisions.

These risks must be shown to reporters and operators in language appropriate to
their decisions, not hidden in a technical appendix.

## 20. Official references

The following sources were retrieved on 2026-08-06. They are provided for
design context; qualified professionals must verify the current text and its
application to a real deployment.

- [UNI/PdR 125:2022, Guidelines on the management system for gender equality](https://certificazione.pariopportunita.gov.it/public/dist/resources/prassi-di-riferimento-unipdr-pdr100866103.pdf), especially section 6.3.2.6.
- [Legislative Decree 24/2023, Article 4 — internal reporting channels](https://www.gazzettaufficiale.it/atto/serie_generale/caricaArticolo?art.codiceRedazionale=23G00032&art.dataPubblicazioneGazzetta=2023-03-15&art.flagTipoArticolo=0&art.idArticolo=4&art.idGruppo=2&art.idSottoArticolo=1&art.idSottoArticolo1=10&art.progressivo=0&art.versione=1).
- [Legislative Decree 24/2023, Article 5 — management of the internal channel](https://www.gazzettaufficiale.it/atto/serie_generale/caricaArticolo?art.codiceRedazionale=23G00032&art.dataPubblicazioneGazzetta=2023-03-15&art.flagTipoArticolo=0&art.idArticolo=5&art.idGruppo=2&art.idSottoArticolo=1&art.idSottoArticolo1=10&art.progressivo=0&art.versione=1).
- [ANAC, Whistleblowing](https://www.anticorruzione.it/-/whistleblowing), including the current guidance and institutional materials.
- [ANAC, reports excluded from the objective scope of Legislative Decree 24/2023](https://www.anticorruzione.it/documents/91439/146849359/7.%2BApprofondimenti%2Bambito%2Boggettivo%2B%E2%80%93%2BLe%2Bsegnalazioni%2Bescluse%2Bdall%E2%80%99applicazione%2Bdella%2Bnormativa%2B%C2%A7%2B2.1.1.pdf/8d2cdc24-20bf-1c72-c73b-e72adf5efaae?t=1689329633903).
- [Italian Data Protection Authority, opinion on the 2025 ANAC internal-channel guidelines](https://www.garanteprivacy.it/home/docweb/-/docweb-display/docweb/10184673), including privacy by design, impact assessment, retention, encryption, email-log, and workplace-network observations.
