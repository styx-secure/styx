# Styx public identity

> **Status:** approved-direction brand and messaging guide, 17 August 2026.
>
> This guide controls public naming, positioning, visual direction, and claim
> boundaries. It does not change the product specification, licensing,
> trademark policy, threat model, or implementation status. The
> [approved vision](../specs/01-vision.md) and evidence cited below remain the
> authority when a short public description and a technical source differ.

## 1. Brand idea

**Styx — Secure infrastructure for sensitive work.**

Styx helps developers build confidential, resilient applications over
infrastructure that must not be trusted with plaintext.

The name refers to a boundary, not a fortress. In the visual and verbal system,
the river represents a deliberate trust boundary: sensitive content stays on
the protected side while encrypted state can cross infrastructure operated by
others. The metaphor must never imply invulnerability, perfect anonymity, or a
cryptographic property that has not been demonstrated.

### One-sentence description

Styx is an open-source secure application substrate for sensitive workflows,
combining self-custodied identity, end-to-end-encrypted collaboration,
verifiable state transitions, offline operation, and redundant delivery.

### One-paragraph description

Styx is an open-source, platform-neutral substrate for applications that need
to collaborate over infrastructure not trusted with plaintext. It separates
application state, secure sessions, runtime custody, and product policy so that
casework, evidence, coordination, and other sensitive workflows do not have to
be reduced to chat. The first planned product is Flegias, an accountless
confidential case-management experience. Current builds are experimental,
unaudited foundations—not a deployable high-risk system.

### Short descriptor

Use **secure application substrate** when the audience understands technical
platforms. Use **secure infrastructure for sensitive work** everywhere else.
Do not use “messenger,” “anonymous messenger,” or “blockchain.”

## 2. Brand architecture

### Styx

**Role:** the open-source application substrate and primary project identity.

Styx owns the language-neutral application protocol, conformance work, secure
session profiles, runtime profiles, reusable SDK direction, and shared
assurance boundaries. It is not a consumer messenger and is not synonymous
with the current browser chat.

Preferred first reference: **Styx**. Use **the Styx project** where a noun is
needed. Use **Styx Secure** only for the project organization or an official
publisher identity, never as a separate product tier.

### Flegias by Styx

**Role:** the planned first product vertical, not yet an implemented product.

Flegias is intended to support confidential case intake and two-way,
asynchronous follow-up without requiring a reporter to provide an email
address, phone number, or ordinary account. It is driven by the needs of
reporters, human-rights and civil-society organizations, safeguarding teams,
trusted intermediaries, and trained case handlers.

Until its implementation and validation milestones are complete, always pair
Flegias with **planned**, **proposed**, **intended**, or **in development**.
Never describe it as available, anonymous by default, compliant, certified, or
safe for live reporting.

Preferred public name: **Flegias by Styx** on first reference, then **Flegias**.
The former-name mapping and compatibility impact are recorded in the
[naming migration](brand/THEMIS_TO_FLEGIAS_MIGRATION.md).

### Styx Reference Chat

**Role:** a minimal technical harness.

The reference chat exercises pairing, encrypted sessions, persistence,
delivery, interoperability, and diagnostics. It is evidence about individual
technical foundations; it is not the product, a Signal replacement, or a
public promise of messenger feature parity.

Preferred name: **Styx Reference Chat**. Never shorten it to “Styx Chat” in
public positioning where that could redefine the project as a messenger.

### Runtime profiles

Use **Styx browser profile** for the current PWA runtime boundary. It has weaker
resistance to an adversary controlling the origin than a signed native profile
could provide. Use **future signed native profile** only for proposed work; do
not imply that one exists.

## 3. Positioning

### Primary positioning statement

For teams building software around sensitive relationships and durable
workflows, Styx is an open-source secure application substrate that keeps
plaintext and authoritative application state out of delivery infrastructure.
Unlike a chat-only interface or a conventional central database, Styx is being
designed around verifiable state, offline continuity, explicit trust profiles,
and reusable product semantics. Current implementations are experimental and
remain subject to conformance, interoperability, distribution, and bounded
assurance gates, with any exercise or pilot decision gated separately.

### What Styx is not

- not a general-purpose messenger or Signal competitor;
- not a Bitcoin, Lightning, wallet, payment, custody, or consensus product;
- not a claim of universal anonymity or metadata elimination;
- not a substitute for operational security, trained handlers, legal review,
  safeguarding, or emergency services;
- not a hosted service, production deployment, audited release, or completed
  Flegias application;
- not tied to JavaScript, Dart, a browser, Nostr, or any one implementation as
  its normative application protocol.

### Differentiation

Styx focuses on the space between encryption primitives and a safe product:
versioned application objects, causality, evidence, retention, delivery states,
offline recovery, role-aware workflows, and explicit runtime limitations. It
prefers compatible secure-session standards over inventing a private wire
format, while keeping application semantics separate from transport.

## 4. Audiences and messages

### People responsible for sensitive work

**Audience:** civil-society groups, human-rights defenders, journalists,
safeguarding teams, trusted intermediaries, and organizations receiving
sensitive reports.

**Message:** Styx is building the foundations for confidential continuity—not
just one-way submission—while treating process, metadata, endpoints, and human
operations as part of the safety boundary.

**Required caveat:** Flegias is planned; current builds must not receive real
sensitive reports.

### Developers and security engineers

**Message:** Styx separates a language-neutral application protocol from
secure-session and runtime profiles, with public conformance evidence intended
to keep independent implementations honest.

**Call to action:** inspect the evidence, reproduce tests, report flaws
privately, or discuss bounded design questions. External code contributions
remain paused under the current contribution policy.

### Funders and research partners

**Message:** tested foundations exist, but the requested programme is the work
needed to turn them into a conformance-backed substrate, a text-first Flegias
alpha, stronger distribution assurance, a targeted independent review of a
contractually bounded high-risk scope with remediation and retest, and a
separately gated synthetic or non-sensitive organizational exercise or later
controlled-pilot decision.

**Required caveat:** screening, consideration, discussion, or an application
does not mean funding, selection, endorsement, partnership, or a grant.

### Contributors and independent reviewers

**Message:** the most valuable current contributions are reproducible review,
threat-model critique, conformance discussion, accessibility feedback, and
private vulnerability reports. Follow the repository contribution and
security policies; do not submit unsolicited code while contributions are
paused.

## 5. Voice and writing

### Character

- **Calm:** no fear-based sales language or adversary theatre.
- **Precise:** distinguish content confidentiality, metadata, availability,
  identity, endpoint safety, and organizational process.
- **Candid:** place material limitations next to the claim they constrain.
- **Human:** start from people and work, then explain the mechanism.
- **Evidence-led:** label built, draft, planned, and unknown states explicitly.
- **Resolute:** explain the ambition without pretending the hard work is done.

### Style rules

- Write in international English; English is canonical.
- Prefer short, concrete sentences and active voice.
- Use sentence case for headings.
- Expand end-to-end encryption before using **E2EE** in non-technical copy.
- Use **application substrate** or **infrastructure**, not “ecosystem.”
- Use **person who reports** or **reporter**, not “anonymous user.”
- Use **organization** or the precise operator role, not “administrator.”
- State who observes what. Avoid standalone claims such as “private” or
  “secure” without scope.
- Link claims about current capability to repository evidence.

## 6. Approved terminology

| Prefer | Avoid | Reason |
|---|---|---|
| secure infrastructure for sensitive work | unbreakable security | Security is conditional. |
| infrastructure not trusted with plaintext | trustless infrastructure | Trust remains in endpoints, code, people, and profiles. |
| accountless return capability | anonymous inbox | Anonymity depends on the observer and operating conditions. |
| current browser profile | the Styx architecture | The browser is one profile, not the universal design. |
| federated or independently operated relays | serverless | Relays and other services still exist. |
| metadata-minimizing, when evidenced | do not claim zero metadata | Timing, size, routing, and relationships may remain visible. |
| experimental and unaudited | military-grade | The phrase has no useful assurance meaning. |
| planned Flegias alpha | anonymous reporting platform | The product and anonymity evidence do not yet exist. |
| interoperated with the exact pinned MDK peer for the operations in the Phase B report | Marmot-compatible | The completed evidence is revision- and operation-bounded, not general conformance. |
| verifiable state transitions | immutable records | Retention and pruning are intentional; physical deletion is limited. |
| open source under AGPL-3.0-or-later | free of restrictions | The licence has obligations and trademarks are separate. |

## 7. Claims ladder

Every public statement must identify its rung.

1. **Implemented evidence:** present tense only when a merged path and test or
   reproducible artifact can be linked. Example: “The repository contains a
   tested Dart reference ledger.”
2. **Bounded result:** name the exact scope. Example: “At the OpenMLS, Marmot
   and MDK revisions recorded in the final Phase B report, Styx interoperated
   with the pinned MDK peer in an isolated synthetic direct-MLS profile through
   durable Welcome join, bidirectional traffic, sequential self-update, the
   five-past-epoch delivery boundary and bounded two-candidate same-parent
   convergence.”
3. **Draft candidate:** say **Draft PR** or **candidate** and do not count it as
   current capability.
4. **Approved direction:** use **is designed to**, **targets**, or **preferred**.
5. **Proposed work:** use **planned**, **intended**, **would**, or **depends on**.
6. **Prohibited implication:** never convert an upstream audit, primitive test,
   funder screening, relay count, test count, or polished interface into proof
   of product security, anonymity, adoption, or institutional approval.

### Mandatory security boundaries

When space is limited, preserve these facts before adding detail:

- current builds are experimental, unaudited, and not suitable for sensitive,
  high-risk, or life-critical use;
- the browser profile is weaker against an adversary controlling the origin;
- current transports expose routing, timing, size, and relationship metadata;
- end-to-end encryption does not protect a compromised endpoint or prevent a
  recipient from copying content;
- Flegias, general Marmot conformance, product integration of the isolated
  profile, native distribution, a targeted
  independent review with remediation/retest, and any separately approved
  organizational exercise or pilot are future work;
- deletion cannot guarantee physical erasure from every device, backup, or
  third-party copy.

## 8. Calls to action

Use calls to action that match current maturity:

- **Explore the architecture** → approved vision or public project brief.
- **Inspect the evidence** → repository, tests, and bounded reports.
- **Review the roadmap** → funded milestones in the project brief.
- **Discuss a use case** → a GitHub Issue without sensitive information.
- **Report a vulnerability privately** → GitHub private vulnerability
  reporting.

Do not use **Start reporting**, **Deploy now**, **Create an anonymous case**,
**Try the secure messenger**, **Join the network**, or **Become a partner**.

## 9. Visual identity

### Mark

The primary mark is a vertical boundary crossed by a continuous river path.
The boundary is stable but not sealed; the river crosses it without exposing
what it carries. A small offset node suggests a verifiable transition rather
than surveillance or custody.

The mark must remain geometric and open. Never place it inside a shield, lock,
chat bubble, coin, hexagonal blockchain motif, government seal, or anonymous
mask. Do not animate it as flowing data in security-critical interfaces.

Clear space around the mark should be at least one quarter of its width. At
small sizes, use the mark without the wordmark. Do not rotate, stretch, add a
drop shadow, recolor individual segments, or place it on a visually noisy
background.

### Palette

| Token | Value | Purpose |
|---|---|---|
| Obsidian | `#101A18` | Primary dark field and body text |
| Deep current | `#173F3A` | Panels, rules, and strong accents |
| River | `#39C6B0` | Primary interactive accent on dark fields |
| River dark | `#11675E` | Links and accents on light fields |
| Mineral | `#E9E4D8` | Warm page background |
| Foam | `#F7F5EF` | Raised light surfaces |
| Ember | `#E87955` | Sparse status or roadmap emphasis |
| Mist | `#AABDB6` | Secondary copy on dark fields |

Contrast must be checked for the actual foreground/background pair. River is
not body text on Mineral or Foam; River dark is used there. Ember communicates
emphasis, never success or safety.

### Typography

Use a sober humanist sans-serif system stack for body text and a restrained
serif system stack for display headings. The contrast expresses human purpose
and technical structure without an external font dependency. Monospace is
reserved for protocol tokens, status labels, and evidence identifiers.

### Layout and spacing

Use generous negative space, fine boundary lines, and asymmetric river-like
paths. Prefer a twelve-column desktop grid that collapses cleanly to one
column. Body lines should stay near 65–72 characters. Use an 8 px base spacing
rhythm with larger 24, 40, 64, and 96 px intervals.

### Diagrams and screenshots

- Diagram the four layers as related responsibilities, not as a security
  hierarchy with an “unbreakable” outer wall.
- Label implemented, planned, and future elements directly.
- Screenshots must show the experimental state when they depict current
  builds.
- Do not use stock images of hooded figures, fingerprints, padlocks, glowing
  code, server rooms, cryptocurrency, or surveillance cameras.

### Motion

Motion is optional and must never be necessary to understand state. Respect
`prefers-reduced-motion`. Avoid flowing-packet animations, pulsing “secure”
indicators, or motion that implies live network assurance. The initial static
site uses no JavaScript and no essential animation.

## 10. Accessibility

- Target WCAG 2.2 AA contrast and interaction principles; do not claim
  conformance before an accessibility review.
- Preserve semantic heading order, landmarks, visible keyboard focus, and a
  skip link.
- Do not encode maturity or security state by color alone.
- Keep warnings in selectable text, not images.
- Support 200% zoom, narrow screens, reduced motion, and forced-color modes.
- Use descriptive link labels; avoid repeated “learn more.”

## 11. Examples

### Use

> Styx is building secure infrastructure for applications that coordinate
> sensitive work over services not trusted with plaintext. Current builds are
> experimental and not ready for live high-risk use.

> Flegias by Styx is the planned first vertical: confidential case intake and
> follow-up without requiring a conventional contact identifier.

> At the OpenMLS, Marmot and MDK revisions recorded in the final Phase B
> report, Styx interoperated with the pinned MDK peer in an isolated synthetic
> direct-MLS profile through durable Welcome join, bidirectional traffic,
> sequential self-update, the five-past-epoch delivery boundary and bounded
> two-candidate same-parent convergence. This is not general Marmot conformance
> or product activation.

### Avoid

> Styx is an anonymous, serverless messenger that makes reports untraceable.

> Military-grade cryptography guarantees that nobody can read your data.

> Flegias is an HRF-backed reporting platform.

> Styx is the decentralized Signal for Bitcoin.

> Styx is Marmot-compatible.

## 12. Source hierarchy and maintenance

Before publishing new copy, check sources in this order:

1. [approved vision](../specs/01-vision.md);
2. [project brief](PROJECT_BRIEF.md);
3. normative specifications and accepted architecture decisions;
4. merged implementation and reproducible test evidence;
5. this guide for expression and visual consistency.

Licensing is defined by [`LICENSING.md`](../LICENSING.md), attribution by
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md), contribution status by
[`CONTRIBUTING.md`](../CONTRIBUTING.md), and trademarks by
[`TRADEMARKS.md`](../TRADEMARKS.md). This guide does not amend them.

Review this guide whenever the product vision, Flegias status, audit status,
compatibility evidence, runtime profiles, licensing, or public deployment
changes. A wording refresh must never silently promote planned work to current
capability.
