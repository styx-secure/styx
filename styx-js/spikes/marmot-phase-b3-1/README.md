# Marmot Phase B3.1 — isolated `0x8001` capability closure

This directory belongs to the bounded interoperability experiment authorized by
Issue #167. It is not a product runtime and does not establish Marmot
compatibility.

Stage 1 freezes a synthetic state fixture written by the outgoing
`ed5e740d…` artifact, implements a strict independent codec for
`marmot.group.profile.v1`, and prepares an isolated B3.1 KeyPackage that
advertises `[0x8001, 0x8003, 0x8009, 0x800c]`. All existing `PhaseB2*`
component sets, readers, group validation and persisted state remain unchanged.

The candidate generated artifact is built twice outside the repository. It is
not installed until the Issue body records its exact five-file tuple, generated
surface and source head/tree and the product owner approves the Stage 2
amendment.

The expected result after Stage 2 is still a typed NO-GO at the next honest
Welcome/RatchetTree boundary. Clearing MDK's missing-`0x8001` rejection will
prove only that the exact KeyPackage advertisement was accepted. It will not
prove full profile processing, wire interoperability or product readiness.

`b3-1-canonical.mjs` is the Styx-authored byte-exact JavaScript codec used to
verify MDK's eventual `0x8001` conformance projection against the independently
implemented Rust codec. `generate-b2-7-legacy-fixture.mjs` is one-shot and must
never overwrite its checked-in synthetic fixture.
