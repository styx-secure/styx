<!-- styx-canonical:v1 mirror="docs/platform/use-cases/anonymous-dialogue_IT.md" -->
# Anonymous bidirectional dialogue

[Italian mirror](anonymous-dialogue_IT.md)

> **Status:** exploratory, non-normative proposal.
>
> This document does not define a production protocol, provide legal advice,
> or demonstrate compliance with laws, practices, certifications, or
> organizational procedures.

## 1. Purpose

This use case describes how a future application built on Styx could let a
person submit a report and continue the dialogue without providing an email
address, telephone number, ordinary chat identity, or other stable contact.

The objective is a **bidirectional, pseudonymous case mailbox** that can offer
anonymity from the receiving organization under a declared threat model. It is
not a universal guarantee of anonymity.

The same capability could support ethics channels, safeguarding, contacts
between sources and journalists, collection of sensitive testimony, and other
casework workflows. Every application remains responsible for legal basis,
governance, retention, escalation, and protection of people.

## 2. Terms and required properties

- **Confidentiality:** unauthorized parties cannot read protected content.
- **Pseudonymity:** a case-specific identifier replaces civil identity, while
  actions within the same case remain linkable.
- **Anonymity from an observer:** that observer cannot reasonably link the case
  to a person under the stated assumptions.
- **Unlinkability:** the observer cannot link distinct cases to the same person.
- **Return capability:** a high-entropy secret authorizing access to exactly
  one mailbox. It is neither a username nor a reusable identity.

A conforming profile should provide:

1. end-to-end confidentiality and integrity between the reporter's client and
   authorized operators;
2. a fresh, unlinkable cryptographic context for each case;
3. asynchronous replies without conventional contact details;
4. explicit receipts distinguishing relay storage, cryptographic receipt,
   human assignment, and reading;
5. minimal, declared, and measurable metadata exposure;
6. role-based organizational custody, rotation, and operator revocation;
7. limited retention and audit without a cleartext register;
8. controlled export and handover when required.

## 3. Non-goals

The capability does not:

- prove a report is true or that a reporter acts in good faith;
- automatically hide source IP, timing, fingerprints, size, writing style,
  facts known to few people, or attachment metadata;
- protect a compromised device, browser, or operator while the case is open;
- make a device or network controlled by an employer safe;
- decide whether a report falls within protected whistleblowing;
- replace trained operators, investigations, emergency procedures, or data
  protection duties;
- ensure availability, delivery, or deletion through cryptography alone.

The ordinary, durable Nostr or Styx chat identity must not be reused. Reuse
would link separate cases and could expose the reporter's social graph.

## 4. Regulatory boundary and routing in Italy

The technical channel and the legal classification of an individual case are
separate matters.

UNI/PdR 125:2022 is a voluntary reference practice for gender-equality
management systems, not national legislation. Section 6.3.2.6 calls for an
anonymous reporting method for physical, verbal, or digital abuse and
harassment. This does not make every report a whistleblowing case.

Legislative Decree 24/2023 governs whistleblowing within its subjective and
objective scope. For internal channels it requires, among other things:

- confidentiality of identities, content, and documents;
- autonomous handling by specifically trained people or offices;
- written or oral reports;
- acknowledgement of receipt within seven days;
- continued dialogue and diligent follow-up;
- feedback normally within three months.

Not every abuse, harassment, discrimination, workplace conflict, or individual
dispute falls under Legislative Decree 24/2023. Objections relating solely to
an individual employment relationship or relationships with supervisors may
be excluded. Classification must be performed by competent people or approved
organizational rules, not inferred automatically by the protocol.

The interface should therefore:

- explain available routes without expecting the reporter to classify the law
  correctly;
- accept the report before requesting optional identifying data;
- show which organization or independent office receives each route;
- associate retention and policy only through an authorized action;
- transfer a case through an explicit, confidential, verifiable handover;
- present instructions for emergencies and immediate danger outside the
  asynchronous flow.

A real deployment requires validation by legal advisers, a DPO where
applicable, worker representatives, safeguarding experts, and responsible
organizational functions.

## 5. Actors

- **Reporter:** creates and reopens a case without an ordinary account.
- **Reporter client:** temporarily holds plaintext and case secrets.
- **Relay or intake service:** stores and forwards opaque envelopes; it is not
  trusted for content or identity.
- **Case operator:** an authorized, trained person who reads and replies.
- **Organizational custodian:** manages role keys, rotations, and retention
  without obtaining unlimited plaintext access by default.
- **Independent recipient:** an external office or professional used when a
  conflict of interest exists.
- **Auditor:** verifies workflow and policy events without automatically
  receiving content.
- **Adversary:** may operate infrastructure, observe networks, send abusive
  traffic, compromise endpoints, or correlate multiple observation points.

## 6. Assets and trust boundaries

### Protected assets

- report and reply text;
- case existence, state, and history;
- reporter identity and network origin;
- return capability and local keys;
- operator identities where policy requires protection;
- attachments and metadata;
- routing, retention, export, and audit information.

### Boundaries

1. **Reporter endpoint:** device, operating system, browser, extensions,
   clipboard, screen, and local storage.
2. **Distribution:** received code must match the verified release rather than
   a targeted malicious version.
3. **Network:** ISP, DNS, proxies, firewalls, and Tor observers may see metadata.
4. **Infrastructure:** relay and hosting administrators may observe, delay,
   replay, delete, or selectively serve encrypted data.
5. **Organization:** custodians, operators, auditors, and investigators have
   different legitimate powers and potential conflicts.
6. **People:** a recipient can copy plaintext, take screenshots, or infer
   identity from content.

## 7. Threat model

The baseline adversary may operate one or more relays, observe a normal network
path, enumerate public events, replay valid ciphertext, and submit many
reports. A stronger adversary may control the web origin or an organizational
administrator, correlate multiple networks, or compromise an endpoint.

Content confidentiality and integrity must withstand a malicious relay.
Independent infrastructure reduces some availability risks. Resistance to
traffic analysis may be claimed only when transport, padding, batching,
polling, and deployment have been tested against the specified observer.
Multiple relays may improve continuity while increasing the observer set.

Endpoint compromise, targeted distribution of altered code, coercion, and
identification from content remain residual risks. A stronger profile may
require a signed native client, reproducible builds, Tor/onion, and an
independent release-verification channel. These are separate decisions.

## 8. Conceptual architecture

```text
reporter client
  -> fresh per-case cryptographic context
  -> encrypted case envelope
  -> metadata-minimizing transport adapter
  -> one or more untrusted store-and-forward services
  -> organizational intake adapter
  -> authorized operator workspace

operator reply
  -> encrypted case envelope
  -> store-and-forward services
  -> capability-based client polling
```

The application profile defines states, receipts, routing, roles, retention,
and UX. The Styx core supplies versioned encrypted objects, replay protection,
delivery state, capability management, and transport abstraction. Nostr, an
HTTPS dropbox, an onion service, and offline media are adapters; none should
define case identity or the plaintext schema.

Cipher, envelope, recipient-key construction, multi-recipient encryption,
padding, and capability encoding require separate approved cryptographic and
persisted-format processes. This document does not select them.

## 9. End-to-end flow

### 9.1 Safe access

Before input, the client warns that workplace devices and networks may be
monitored. A high-assurance deployment offers a separately verifiable client
and a network path suitable for the threat model.

Email, SMS, analytics, third-party fonts, advertising, remote payload
telemetry, and identity-linked push notifications are excluded from the
default flow.

### 9.2 Creation

The client locally generates:

- a fresh case context;
- a random high-entropy return capability;
- material needed to protect the dialogue.

It does not consult Styx accounts, Nostr keys, the address book, or previous
chat sessions. Domain separation prevents reuse of keys, signatures, and
identifiers across applications or cases.

The client obtains an authenticated intake descriptor naming the recipient
role, supported versions, expiry, transports, and release identity. Trust in
the descriptor and its distribution channel must be visible and documented.

### 9.3 Submission

The client encrypts a versioned case object for the authorized role, applies
the minimization policy, and sends redundant opaque envelopes.

The states must remain distinct:

1. durable local storage;
2. relay acceptance;
3. cryptographic receipt by the workspace;
4. human assignment;
5. reading or reply.

The interface cannot display “received by the organization” after relay
acceptance alone.

### 9.4 Return capability

After durable local storage, the client displays the capability once in a
manageable form such as a recovery card or QR code. Encoding and backup are
separate decisions; the underlying secret must resist online and offline
attempts.

The capability:

- authorizes only one case;
- does not appear in URL queries, logs, history, telemetry, crash reports,
  referrers, or server-side account tables;
- is not derived from a weak phrase, case number, email, or hash of guessable
  data;
- is not correlated with a durable identity.

Without escrow or identification, the server cannot recover a lost capability.
The product must say so before the reporter leaves the flow.

### 9.5 Dialogue

The reporter returns through safe access and presents the capability locally.
The client reopens the context, polls using an unlinkable transport token,
verifies history, and sends new replies.

Manual polling is the most cautious default. Notifications are optional only
after explaining correlation and metadata. The protocol requires idempotency,
authenticated ordering, deduplication, and explicit gap handling. An old valid
object replayed by the relay must not silently replace current state.

### 9.6 Optional identity disclosure

Identity disclosure is a distinct, explicit action. The UI shows the exact
fields and recipients; the resulting object records purpose and consent. Later
disclosure does not authorize retroactive linkage of other cases.

## 10. Recovery-secret handling

The client should:

- generate the capability from a cryptographically secure random source;
- keep it out of persistent DOM, URLs, logs, telemetry, and the clipboard where
  possible;
- store it in the encrypted local vault only after an explicit choice;
- suggest a private offline copy while warning about screenshots and cloud
  photo backup;
- apply rate limits and responses that do not become an enumeration oracle;
- reduce content and timing differences between valid and invalid lookups;
- offer local removal without promising physical deletion from flash, backups,
  synchronized profiles, or IndexedDB.

Split or delegated recovery may reduce loss but creates new correlation and
custody powers. It requires a separate decision and cannot be enabled
invisibly.

## 11. Operator workflow

An organizational deployment defines at least:

1. intake ownership and routing for conflicts of interest;
2. trained primary and substitute operators with least privilege;
3. receipt, follow-up, and feedback deadlines for each route;
4. states such as submitted, technically received, assigned, under assessment,
   pending, transferred, closed, and retained;
5. clarification requests that do not induce identification;
6. escalation for danger, safeguarding, evidence preservation, and external
   duties;
7. operator substitution, key rotation, and absence coverage;
8. authorization of export, redaction, disclosure, and deletion;
9. notification to the reporter of incidents and missed deadlines;
10. periodic independent verification of access, routing, retention, and
    continuity.

Where Legislative Decree 24/2023 applies, the workflow must be configured and
validated against its time limits. Other channels may have different
deadlines; one generic timer would be misleading.

Organizational keys represent a role and policy, not an employee's ordinary
chat identity. Rotations and revocations produce verifiable events. A dedicated
recipient, multi-recipient encryption, threshold custody, and HSMs are
alternatives to decide separately.

## 12. Metadata minimization

The profile jointly considers:

- IP address and network path;
- relay account, public key, or stable client identifier;
- submission and polling times;
- event and attachment sizes;
- fingerprints and third-party requests;
- recipient tags and organizational markers;
- case existence, status, and access frequency;
- logs linking administration to a reporter session.

Tor/onion, batching, delays, padding classes, and cover traffic can reduce some
exposures but have costs and limitations. Content encryption does not hide
them.

A logged corporate proxy or firewall may observe access to the platform. No
client makes access through that network invisible to it.

## 13. Attachments and content safety

The first high-assurance profile should be text-only. Attachments may contain
author, device, location, timestamp, history, thumbnails, malware, active
content, and identifying visual details.

Before enabling them, the following are needed:

- local inspection and metadata removal;
- conversion into safe formats and malware isolation;
- encrypted chunks, an authenticated manifest, and resumable uploads;
- size-class padding;
- separate policies for the original and sanitized copy;
- a warning that sanitization does not remove visible clues.

Free text can also identify through facts, vocabulary, or style. The client may
offer warnings and local preview, but must not silently rewrite possible
evidence.

## 14. Abuse resistance

An anonymous channel may receive spam, floods, probes, malware, and harassment.
Controls must not recreate identity tracking. Candidates include:

- message and attachment limits;
- per-capability quotas and state-dependent rate limits;
- proof-of-work or anonymous rate-limiting credentials;
- coarse limits before expensive cryptographic operations;
- queue isolation, backpressure, and storage budgets;
- local and operator-side safety controls;
- a revocable capability with reopening policy;
- failover without a global reporter blocklist.

CAPTCHAs, telephone verification, stable cookies, IP reputation, and commercial
anti-fraud services may harm anonymity and accessibility. Each use requires a
specific assessment and denial-of-service tests for legitimate users,
including Tor and assistive technologies.

## 15. Retention, audit, and export

Retention depends on the validated route and starts from a defined event.
Encrypted data relating to people may still be personal data. The system
should support automatic expiry, authorized legal hold, visible closure where
appropriate, and replica removal without promising unprovable physical
deletion.

The audit may record descriptor publication, role changes, access, assignment,
routing, export, and policy changes. It must avoid plaintext, capabilities,
source metadata, and unnecessary stable identifiers. Tamper evidence detects
some alterations but does not prove that a human action was correct or that no
action was hidden.

Exports require an authenticated manifest, redaction, recipient, purpose,
integrity verification, and expiry. A cleartext PDF alone is not a secure
handover.

## 16. Availability and continuity

Transport should tolerate an unavailable or censoring relay, reconcile
duplicates, and distinguish delay from confirmed receipt. The organization
needs monitored backup intake, tested key recovery, absence coverage, and an
incident channel that does not expose active cases.

Federation and multiple relays reduce some single points of failure but do not
eliminate servers, operators, capacity planning, denial of service, or common
software defects. Drills must include loss of a relay, region, operator, and
key custodian.

## 17. Relationship to the current repository

The repository contains useful primitives, but not an anonymous-reporting
product:

- the active JavaScript stack provides encrypted sessions, Nostr transport,
  and a local vault still under development;
- current chat and durable identity are unsuitable for anonymous creation;
- relay publication does not equal end-to-end receipt;
- remote pairing, durable outbox, application domain separation, multi-device,
  metadata-minimizing routing, and role custody are incomplete or require
  separate decisions;
- first-load trust in the PWA does not by itself withstand a targeted malicious
  origin;
- the Dart stack is a reference implementation, not the product path.

The vault can act as a canary for local custody, but completing it alone does
not satisfy this use case.

## 18. Phased validation

### Phase A — Protocol and governance

- approve the threat model and assurance profile;
- define objects, states, receipts, replay, and domain separation;
- complete cryptographic and format review;
- map roles, routing, retention, incidents, and responsibilities;
- perform a DPIA where required.

### Phase B — Text-only technical pilot

- fresh per-case identity and an accountless capability;
- encrypted submission, assignment, clarification, reply, and closure;
- durable outbox/inbox, replay handling, deduplication, failover, and limited
  padding;
- manual polling without attachments, analytics, or third-party code;
- operator rotation and a route to an independent recipient.

### Phase C — Adversarial verification

- independent review of protocol, client, workspace, and deployment;
- tests for a malicious relay, rollback, enumeration, spam, queue exhaustion,
  revocation, and regional outage;
- measurement of metadata visible to relays, hosting, corporate networks, and
  colluding observers;
- tests of targeted distribution and artifact verification;
- usability and accessibility studies under stress.

### Phase D — Limited organizational pilot

- explicitly limited route and population;
- training and tests for deadlines, escalation, absences, and incident response;
- publication of limitations and a secure alternative channel;
- only aggregate, non-identifying metrics;
- a joint decision by security, privacy, legal, safeguarding, and responsible
  organizational functions before expansion.

## 19. Future acceptance evidence

An implementation should prove that:

- two cases from the same clean client share no protocol identifiers;
- creation neither reads nor emits ordinary chat or Nostr identities;
- compromise of relay, origin, and database does not reveal protected
  plaintext;
- altered, reordered, duplicated, missing, or rolled-back objects fail closed
  or produce an explicit state;
- relay storage and human assignment are not confused;
- operator loss and revocation follow the custody model;
- capability enumeration and guessing meet measured objectives;
- the declared observer sees only metadata permitted by the profile;
- retention and export produce a minimized audit;
- every supported client covers offline operation, recovery, and accessibility;
- independent reviewers reproduce the tests in clean environments.

Passing applies only to the reviewed profile and deployment and does not
authorize generic anonymity or compliance claims.

## 20. Residual risks

The following remain:

- compromised endpoints, malicious extensions, keyloggers, screenshots,
  shoulder surfing, and coercion;
- targeted first-load distribution of modified code;
- timing and traffic correlation by capable or colluding observers;
- censorship, delay, and deletion by relays or the organization;
- identification through facts, style, attachments, or a small anonymity set;
- use of a monitored network, text reuse, sharing the capability, or saving it
  in a synchronized account;
- unauthorized copying and disclosure by recipients;
- inability to recover a truly lost, non-escrowed capability;
- incomplete physical deletion from devices, backups, IndexedDB, and relays;
- regulatory change and incorrect human routing decisions.

These risks must be communicated to reporters and operators at the moment of
decision, not hidden in a technical appendix.

## 21. Official sources

Sources accessed on **2026-08-06**. They are contextual references: qualified
professionals must verify their current text and application to a deployment.

- [UNI/PdR 125:2022, Guidelines on the gender-equality management system](https://certificazione.pariopportunita.gov.it/public/dist/resources/prassi-di-riferimento-unipdr-pdr100866103.pdf), especially §6.3.2.6.
- [Legislative Decree 24/2023, Article 4 — internal reporting channels](https://www.gazzettaufficiale.it/atto/serie_generale/caricaArticolo?art.codiceRedazionale=23G00032&art.dataPubblicazioneGazzetta=2023-03-15&art.flagTipoArticolo=0&art.idArticolo=4&art.idGruppo=2&art.idSottoArticolo=1&art.idSottoArticolo1=10&art.progressivo=0&art.versione=1).
- [Legislative Decree 24/2023, Article 5 — internal channel management](https://www.gazzettaufficiale.it/atto/serie_generale/caricaArticolo?art.codiceRedazionale=23G00032&art.dataPubblicazioneGazzetta=2023-03-15&art.flagTipoArticolo=0&art.idArticolo=5&art.idGruppo=2&art.idSottoArticolo=1&art.idSottoArticolo1=10&art.progressivo=0&art.versione=1).
- [ANAC, Whistleblowing](https://www.anticorruzione.it/-/whistleblowing).
- [ANAC, reports excluded from the objective scope of Legislative Decree 24/2023](https://www.anticorruzione.it/documents/91439/146849359/7.%2BApprofondimenti%2Bambito%2Boggettivo%2B%E2%80%93%2BLe%2Bsegnalazioni%2Bescluse%2Bdall%E2%80%99applicazione%2Bdella%2Bnormativa%2B%C2%A7%2B2.1.1.pdf/8d2cdc24-20bf-1c72-c73b-e72adf5efaae?t=1689329633903).
- [Italian Data Protection Authority, opinion on the 2025 ANAC guidelines](https://www.garanteprivacy.it/home/docweb/-/docweb-display/docweb/10184673), including observations on privacy by design, DPIAs, retention, encryption, email logs, and workplace networks.
