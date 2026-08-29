# Themis to Flegias naming migration

Date: 2026-08-29

## Decision

The planned first Styx product vertical is renamed from **Themis** to
**Flegias**. Current public material uses **Flegias by Styx** on first
reference and **Flegias** thereafter.

The unpublished, standalone Flutter survey package is renamed at the same time:

| Before | After |
| --- | --- |
| `packages/themis_survey/` | `packages/flegias_survey/` |
| `themis_survey` | `flegias_survey` |
| `package:themis_survey/themis_survey.dart` | `package:flegias_survey/flegias_survey.dart` |

The package remains a decoupled survey engine and optional consumer. Renaming
it does not turn it into a complete Flegias product and does not change survey
behavior, application-protocol semantics or the injected `SurveyStyxBridge`
boundary.

## Current and historical references

Current public, normative and technical surfaces use the new name. Historical
records under `docs/archive/`, the dated Phase A spike, and the 2026-07-12
licensing inventory retain their original wording because rewriting them would
misrepresent the evidence available when they were produced. ADR-0003 keeps one
explicit former-package-name note so old references remain understandable.

Repository history is not rewritten. Unpublished consumers outside this
repository that import the former package URI must migrate explicitly.

## Naming risk acknowledged

At ratification time, Lian Security publicly described a security-industry
product named **Flegias** at <https://www.liansecurity.com/en/product/4/info>.
The maintainer acknowledged this collision before authorizing the technical
rename. This record is not trademark, domain, jurisdictional or commercial-name
clearance and does not claim affiliation with or endorsement by Lian Security.

## Security and attribution boundaries

The rename changes no security property and strengthens no maturity claim.
Flegias remains planned and unavailable for live reporting. Styx remains
experimental, unaudited and unsuitable for sensitive, high-risk or
life-critical use.

The Styx Reference Chat remains Styx-authored. OpenMLS, Marmot and MDK remain
external protocol and implementation dependencies with their existing exact
pins, upstream licences, provenance and audit-scope boundaries. The Flegias
name does not imply upstream endorsement or extend upstream audit coverage to
Styx-authored code.
