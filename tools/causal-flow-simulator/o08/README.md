# O-08 bounded resource-envelope evidence

This isolated package implements the transcript-only C0.3 resource-envelope
decision owned by Issue #250. It is conformance evidence, not product runtime
code and not a wire, storage, authorization, checkpoint, recovery or transport
format.

The package keeps five classes distinct: 46 semantic maxima, five abstract
activation-capability inputs, two explicit zero/unsupported dimensions, eleven
post-C0.3 profile dimensions and three evidence-only dimensions. The complete
67-dimension source inventory remains visible even though only 53 dimensions
participate in the C0.3 entry envelope.

`resource-envelope.candidates.json` is non-authoritative. The selected
`resource-envelope.candidate.json` may be created only after the six measurement
reports and deterministic comparison have been accepted through the external
human selection gate. Every final semantic report is host-independent canonical
JSON; host measurements remain non-normative and are never compared bytewise
across machines.

The reference model rejects limits before protected work and never mutates
authoritative state on failure. The Node oracle is dependency-independent. The
final gate regenerates all eight report families in two distinct clean checkouts
and requires pairwise byte equality.

Non-claims include production ceremony, persistence, physical eviction,
recovery, freshness, rollback detection, delivery, secure-session behavior,
transport behavior, browser/mobile suitability and any stable O-10 code.
