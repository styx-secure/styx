"""Bounded symbolic payload-state model for the Styx C0.2f gate.

The model consumes only already validated causal events.  Commitments are
symbolic ideal terms, not cryptographic bytes, and observations are explicit
per-replica inputs.  Nothing in this module selects an O-06 algorithm, wire
encoding, checkpoint authority, or irreversible storage effect.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Mapping, Sequence

from model import Evaluation, ModelInputError, affected_replay_boundary


class ContentClass(str, Enum):
    NONE = "NONE"
    REQUIRED = "REQUIRED"
    DETACHABLE = "DETACHABLE"


class CommitmentShape(str, Enum):
    NONE = "NONE"
    SINGLE = "SINGLE"
    CHUNKED = "CHUNKED"


class Availability(str, Enum):
    ABSENT = "ABSENT"
    PARTIAL = "PARTIAL"
    PRESENT = "PRESENT"


class BindingObservation(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_CHECKED = "NOT_CHECKED"
    VERIFIED = "VERIFIED"
    OPENING_MISSING = "OPENING_MISSING"
    LENGTH_MISMATCH = "LENGTH_MISMATCH"
    COMMITMENT_MISMATCH = "COMMITMENT_MISMATCH"


class RetentionState(str, Enum):
    ACTIVE = "ACTIVE"
    LOGICALLY_REMOVED = "LOGICALLY_REMOVED"


class ReplayReadiness(str, Enum):
    READY = "READY"
    CONTENT_DEFERRED = "CONTENT_DEFERRED"
    STALE_EVIDENCE = "STALE_EVIDENCE"


class PresentationState(str, Enum):
    NO_CONTENT = "NO_CONTENT"
    UNEXPECTED_CONTENT_REJECTED = "UNEXPECTED_CONTENT_REJECTED"
    ACTIVE_VERIFIED = "ACTIVE_VERIFIED"
    ACTIVE_UNAVAILABLE = "ACTIVE_UNAVAILABLE"
    ACTIVE_UNVERIFIABLE = "ACTIVE_UNVERIFIABLE"
    ACTIVE_SUBSTITUTED_REJECTED = "ACTIVE_SUBSTITUTED_REJECTED"
    REMOVED = "REMOVED"
    REMOVED_PRESENTED_VERIFIED = "REMOVED_PRESENTED_VERIFIED"
    REMOVED_PRESENTED_UNVERIFIABLE = "REMOVED_PRESENTED_UNVERIFIABLE"
    REMOVED_SUBSTITUTED_REJECTED = "REMOVED_SUBSTITUTED_REJECTED"
    DEFERRED = "DEFERRED"


class DirectiveOutcome(str, Enum):
    APPLIED = "APPLIED"
    UNAUTHORIZED = "UNAUTHORIZED"
    INAPPLICABLE_CLASS = "INAPPLICABLE_CLASS"
    TARGET_COMMITMENT_MISMATCH = "TARGET_COMMITMENT_MISMATCH"
    ALREADY_REMOVED = "ALREADY_REMOVED"
    DEFERRED_BY_REQUIRED_SUFFIX = "DEFERRED_BY_REQUIRED_SUFFIX"
    DEFERRED_BY_STALE_EVIDENCE = "DEFERRED_BY_STALE_EVIDENCE"


class CheckpointDisposition(str, Enum):
    UNAVAILABLE = "UNAVAILABLE"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    CONFLICTING = "CONFLICTING"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    PRODUCER_INELIGIBLE = "PRODUCER_INELIGIBLE"
    EMITTABLE = "EMITTABLE"


@dataclass(frozen=True)
class ChunkGeometry:
    chunk_size: int
    chunk_count: int
    final_chunk_length: int


@dataclass(frozen=True)
class ContentDescriptor:
    content_class: ContentClass
    content_type_id: str
    exact_content_length: int
    commitment_suite_id: str
    commitment_shape: CommitmentShape
    commitment_value: bytes
    chunk_geometry: ChunkGeometry | None = None

    @classmethod
    def none(cls) -> "ContentDescriptor":
        return cls(ContentClass.NONE, "", 0, "", CommitmentShape.NONE, b"")


@dataclass(frozen=True)
class RemovalClaim:
    target_reference: bytes
    target_commitment: bytes


@dataclass(frozen=True)
class PayloadRecord:
    reference: bytes
    descriptor: ContentDescriptor
    removal: RemovalClaim | None = None


@dataclass(frozen=True)
class PayloadObservation:
    availability: Availability
    binding: BindingObservation


@dataclass(frozen=True)
class PayloadCheckpoint:
    horizon_refs: tuple[bytes, ...]
    available: bool = True
    authenticated: bool = True
    conflicting: bool = False


@dataclass(frozen=True)
class PayloadProfile:
    max_records: int = 9
    max_directives: int = 4
    max_content_length: int = 1024
    max_chunk_size: int = 256
    max_chunks: int = 8
    max_commitment_bytes: int = 64
    max_randomizer_bytes: int = 64
    max_symbol_bytes: int = 64
    max_text_bytes: int = 64
    max_checkpoint_refs: int = 9
    max_input_bytes: int = 8192
    max_exploration_cases: int = 512

    def validate(self) -> None:
        values = (
            self.max_records,
            self.max_directives,
            self.max_content_length,
            self.max_chunk_size,
            self.max_chunks,
            self.max_commitment_bytes,
            self.max_randomizer_bytes,
            self.max_symbol_bytes,
            self.max_text_bytes,
            self.max_checkpoint_refs,
            self.max_input_bytes,
            self.max_exploration_cases,
        )
        if any(type(value) is not int or value < 1 for value in values):
            raise ModelInputError("payload profile limits must be positive integers")


@dataclass(frozen=True)
class SymbolicCommitmentVector:
    context_token: tuple[str, str, str, bytes]
    suite_id: str
    content_type_id: str
    exact_content_length: int
    shape: CommitmentShape
    chunk_geometry: ChunkGeometry | None
    part_symbols: tuple[bytes, ...]
    part_lengths: tuple[int, ...]
    randomizer: bytes


@dataclass(frozen=True)
class PayloadState:
    content_class: ContentClass
    availability: Availability
    binding: BindingObservation
    retention: RetentionState
    readiness: ReplayReadiness
    presentation: PresentationState


@dataclass(frozen=True)
class PayloadSnapshot:
    reference: bytes
    states: tuple[tuple[bytes, PayloadState], ...]
    directive_outcomes: tuple[tuple[bytes, DirectiveOutcome], ...]
    applied_order: tuple[bytes, ...]
    halted_at: bytes | None


@dataclass(frozen=True)
class CheckpointAssessment:
    disposition: CheckpointDisposition
    contents: tuple[tuple[object, ...], ...]
    producer_eligible: bool
    consumer_substitution: bool = False


@dataclass(frozen=True)
class PayloadEvaluation:
    states: Mapping[bytes, PayloadState]
    directive_outcomes: Mapping[bytes, DirectiveOutcome]
    applied_order: tuple[bytes, ...]
    halted_at: bytes | None
    stale_dependencies: tuple[bytes, ...]
    snapshots: tuple[PayloadSnapshot, ...]
    checkpoint: CheckpointAssessment | None


def _bounded_bytes(value: object, maximum: int) -> bool:
    return isinstance(value, bytes) and 0 < len(value) <= maximum


def _bounded_text(value: object, maximum: int) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        return len(value.encode("utf-8")) <= maximum
    except UnicodeEncodeError:
        return False


def _descriptor_term(descriptor: ContentDescriptor) -> tuple[object, ...]:
    geometry = descriptor.chunk_geometry
    return (
        descriptor.content_class.value,
        descriptor.content_type_id,
        descriptor.exact_content_length,
        descriptor.commitment_suite_id,
        descriptor.commitment_shape.value,
        descriptor.commitment_value.hex(),
        None
        if geometry is None
        else (geometry.chunk_size, geometry.chunk_count, geometry.final_chunk_length),
    )


def _record_term(record: PayloadRecord) -> tuple[object, ...]:
    removal = record.removal
    return (
        *_descriptor_term(record.descriptor),
        None
        if removal is None
        else (
            "removal",
            removal.target_reference.hex(),
            removal.target_commitment.hex(),
        ),
    )


def symbolic_commitment_term(
    vector: SymbolicCommitmentVector,
    profile: PayloadProfile | None = None,
) -> tuple[object, ...]:
    """Return an ideal symbolic term, never normative commitment bytes."""

    selected = PayloadProfile() if profile is None else profile
    _validate_symbolic_vector(vector, selected)
    return (
        "styx.model.payload-commitment",
        vector.suite_id,
        vector.context_token,
        vector.content_type_id,
        vector.exact_content_length,
        vector.shape.value,
        None
        if vector.chunk_geometry is None
        else (
            vector.chunk_geometry.chunk_size,
            vector.chunk_geometry.chunk_count,
            vector.chunk_geometry.final_chunk_length,
        ),
        vector.part_symbols,
        vector.part_lengths,
        vector.randomizer,
    )


def symbolic_chunk_terms(
    vector: SymbolicCommitmentVector,
    profile: PayloadProfile | None = None,
) -> tuple[tuple[object, ...], ...]:
    """Return ideal leaf terms binding ordinal, length and event randomizer."""

    selected = PayloadProfile() if profile is None else profile
    _validate_symbolic_vector(vector, selected)
    if vector.shape is not CommitmentShape.CHUNKED:
        raise ModelInputError("symbolic leaf terms require chunked shape")
    return tuple(
        (
            "styx.model.payload-leaf",
            vector.suite_id,
            vector.context_token,
            vector.content_type_id,
            index,
            length,
            symbol,
            vector.randomizer,
        )
        for index, (symbol, length) in enumerate(
            zip(vector.part_symbols, vector.part_lengths, strict=True)
        )
    )


def _validate_symbolic_vector(
    vector: SymbolicCommitmentVector, profile: PayloadProfile
) -> None:
    profile.validate()
    if not isinstance(vector, SymbolicCommitmentVector):
        raise ModelInputError("commitment vector type is invalid")
    if not _bounded_text(vector.suite_id, profile.max_text_bytes):
        raise ModelInputError("commitment vector suite is invalid")
    if not _bounded_text(vector.content_type_id, profile.max_text_bytes):
        raise ModelInputError("commitment vector content type is invalid")
    if (
        type(vector.exact_content_length) is not int
        or not 0 <= vector.exact_content_length <= profile.max_content_length
    ):
        raise ModelInputError("commitment vector length exceeds profile")
    if not _bounded_bytes(vector.randomizer, profile.max_randomizer_bytes):
        raise ModelInputError("commitment vector randomizer is invalid")
    if len(vector.part_symbols) > profile.max_chunks:
        raise ModelInputError("commitment vector part count exceeds profile")
    if len(vector.part_symbols) != len(vector.part_lengths):
        raise ModelInputError("commitment vector part lengths differ")
    if any(not _bounded_bytes(item, profile.max_symbol_bytes) for item in vector.part_symbols):
        raise ModelInputError("commitment vector symbol is invalid")
    if any(type(item) is not int or item < 0 for item in vector.part_lengths):
        raise ModelInputError("commitment vector part length is invalid")
    if sum(vector.part_lengths) != vector.exact_content_length:
        raise ModelInputError("commitment vector total length differs")
    _validate_shape(
        vector.shape,
        vector.chunk_geometry,
        vector.exact_content_length,
        len(vector.part_symbols),
        vector.part_lengths,
        profile,
    )


def _validate_shape(
    shape: CommitmentShape,
    geometry: ChunkGeometry | None,
    exact_length: int,
    part_count: int,
    part_lengths: Sequence[int] | None,
    profile: PayloadProfile,
) -> None:
    if shape is CommitmentShape.SINGLE:
        if geometry is not None or part_count != 1:
            raise ModelInputError("single commitment geometry is invalid")
        if part_lengths is not None and tuple(part_lengths) != (exact_length,):
            raise ModelInputError("single commitment length is invalid")
        return
    if shape is not CommitmentShape.CHUNKED or not isinstance(geometry, ChunkGeometry):
        raise ModelInputError("content-bearing commitment shape is invalid")
    values = (geometry.chunk_size, geometry.chunk_count, geometry.final_chunk_length)
    if any(type(value) is not int for value in values):
        raise ModelInputError("chunk geometry types are invalid")
    if exact_length == 0:
        raise ModelInputError("zero-length content must use single commitment")
    if not 1 <= geometry.chunk_size <= profile.max_chunk_size:
        raise ModelInputError("chunk size exceeds profile")
    if not 1 <= geometry.chunk_count <= profile.max_chunks:
        raise ModelInputError("chunk count exceeds profile")
    if geometry.chunk_count != part_count:
        raise ModelInputError("chunk count differs from supplied parts")
    expected_count = (exact_length + geometry.chunk_size - 1) // geometry.chunk_size
    expected_final = exact_length - geometry.chunk_size * (expected_count - 1)
    if geometry.chunk_count != expected_count or geometry.final_chunk_length != expected_final:
        raise ModelInputError("chunk geometry does not match exact length")
    if part_lengths is not None:
        expected = (geometry.chunk_size,) * (geometry.chunk_count - 1) + (
            geometry.final_chunk_length,
        )
        if tuple(part_lengths) != expected:
            raise ModelInputError("chunk part lengths do not match geometry")


class PayloadModel:
    """Fold authenticated payload records over one validated causal order."""

    def __init__(self, profile: PayloadProfile | None = None) -> None:
        self.profile = PayloadProfile() if profile is None else profile
        self.profile.validate()

    def evaluate(
        self,
        causal: Evaluation,
        records: Sequence[PayloadRecord],
        observations: Mapping[bytes, PayloadObservation],
        authorizations: Mapping[bytes, bool],
        checkpoint: PayloadCheckpoint | None = None,
    ) -> PayloadEvaluation:
        record_map = self._validate_inputs(
            causal, records, observations, authorizations, checkpoint
        )
        return self._project(
            causal,
            record_map,
            observations,
            authorizations,
            checkpoint,
            boundary=0,
            prefix=(),
        )

    def incremental(
        self,
        old_causal: Evaluation,
        new_causal: Evaluation,
        old_payload: PayloadEvaluation,
        old_records: Sequence[PayloadRecord],
        new_records: Sequence[PayloadRecord],
        old_observations: Mapping[bytes, PayloadObservation],
        new_observations: Mapping[bytes, PayloadObservation],
        old_authorizations: Mapping[bytes, bool],
        new_authorizations: Mapping[bytes, bool],
        checkpoint: PayloadCheckpoint | None = None,
    ) -> tuple[int, PayloadEvaluation]:
        old_map = self._validate_inputs(
            old_causal, old_records, old_observations, old_authorizations, checkpoint
        )
        expected_old = self._project(
            old_causal,
            old_map,
            old_observations,
            old_authorizations,
            checkpoint,
            boundary=0,
            prefix=(),
        )
        if old_payload != expected_old:
            raise ModelInputError("old payload evaluation does not match validated inputs")
        new_map = self._validate_inputs(
            new_causal, new_records, new_observations, new_authorizations, checkpoint
        )
        boundary = affected_replay_boundary(old_causal.order, new_causal.order)
        if self._compacted_dependencies(old_causal) != self._compacted_dependencies(
            new_causal
        ):
            boundary = 0
        shared = min(boundary, len(old_causal.order), len(new_causal.order))
        for index in range(shared):
            reference = new_causal.order[index]
            if (
                old_map[reference] != new_map[reference]
                or old_observations[reference] != new_observations[reference]
                or old_authorizations.get(reference) != new_authorizations.get(reference)
            ):
                boundary = index
                break
        prefix = old_payload.snapshots[:boundary]
        result = self._project(
            new_causal,
            new_map,
            new_observations,
            new_authorizations,
            checkpoint,
            boundary=boundary,
            prefix=prefix,
        )
        return boundary, result

    def _validate_inputs(
        self,
        causal: Evaluation,
        records: Sequence[PayloadRecord],
        observations: Mapping[bytes, PayloadObservation],
        authorizations: Mapping[bytes, bool],
        checkpoint: PayloadCheckpoint | None,
    ) -> dict[bytes, PayloadRecord]:
        if len(records) > self.profile.max_records:
            raise ModelInputError("payload record bound exceeded")
        record_map: dict[bytes, PayloadRecord] = {}
        directives = 0
        input_bytes = 0
        for record in records:
            if not isinstance(record, PayloadRecord):
                raise ModelInputError("payload record type is invalid")
            if record.reference in record_map:
                raise ModelInputError("duplicate payload record")
            self._validate_descriptor(record.descriptor)
            input_bytes += self._record_input_size(record)
            if record.removal is not None:
                directives += 1
                if not isinstance(record.removal, RemovalClaim):
                    raise ModelInputError("removal claim type is invalid")
                if not _bounded_bytes(record.removal.target_reference, self.profile.max_commitment_bytes):
                    raise ModelInputError("removal target reference is invalid")
                if not _bounded_bytes(record.removal.target_commitment, self.profile.max_commitment_bytes):
                    raise ModelInputError("removal target commitment is invalid")
            record_map[record.reference] = record
        if directives > self.profile.max_directives:
            raise ModelInputError("removal directive bound exceeded")
        expected = set(causal.order)
        if set(record_map) != expected:
            raise ModelInputError("payload records must match validated causal order")
        if set(observations) != expected:
            raise ModelInputError("payload observations must match validated causal order")
        for reference, observation in observations.items():
            if not isinstance(observation, PayloadObservation):
                raise ModelInputError("payload observation type is invalid")
            self._validate_axis_combination(record_map[reference].descriptor, observation)
            input_bytes += len(reference) + 2
        removal_refs = {record.reference for record in records if record.removal is not None}
        if set(authorizations) != removal_refs:
            raise ModelInputError("removal authorizations must match directives")
        if any(type(value) is not bool for value in authorizations.values()):
            raise ModelInputError("removal authorization must be boolean")
        for record in records:
            if record.removal is None:
                continue
            target = record.removal.target_reference
            if target not in record_map:
                raise ModelInputError("retained removal target is unavailable")
            if not self._reachable(record.reference, target, causal.graph):
                raise ModelInputError("removal target is not a causal ancestor")
        if checkpoint is not None:
            self._validate_checkpoint(checkpoint)
            input_bytes += sum(len(reference) for reference in checkpoint.horizon_refs)
        if input_bytes > self.profile.max_input_bytes:
            raise ModelInputError("payload input byte bound exceeded")
        return record_map

    def _validate_descriptor(self, descriptor: ContentDescriptor) -> None:
        if not isinstance(descriptor, ContentDescriptor):
            raise ModelInputError("content descriptor type is invalid")
        if descriptor.content_class is ContentClass.NONE:
            if descriptor != ContentDescriptor.none():
                raise ModelInputError("NONE descriptor is not canonical")
            return
        if descriptor.content_class not in (ContentClass.REQUIRED, ContentClass.DETACHABLE):
            raise ModelInputError("content class is invalid")
        if not _bounded_text(descriptor.content_type_id, self.profile.max_text_bytes):
            raise ModelInputError("content type identifier is invalid")
        if not _bounded_text(descriptor.commitment_suite_id, self.profile.max_text_bytes):
            raise ModelInputError("commitment suite identifier is invalid")
        if (
            type(descriptor.exact_content_length) is not int
            or not 0 <= descriptor.exact_content_length <= self.profile.max_content_length
        ):
            raise ModelInputError("declared content length exceeds profile")
        if not _bounded_bytes(descriptor.commitment_value, self.profile.max_commitment_bytes):
            raise ModelInputError("commitment value is invalid")
        parts = 1 if descriptor.commitment_shape is CommitmentShape.SINGLE else (
            descriptor.chunk_geometry.chunk_count
            if isinstance(descriptor.chunk_geometry, ChunkGeometry)
            and type(descriptor.chunk_geometry.chunk_count) is int
            and 0 <= descriptor.chunk_geometry.chunk_count <= self.profile.max_chunks
            else 0
        )
        _validate_shape(
            descriptor.commitment_shape,
            descriptor.chunk_geometry,
            descriptor.exact_content_length,
            parts,
            None,
            self.profile,
        )

    @staticmethod
    def _validate_axis_combination(
        descriptor: ContentDescriptor, observation: PayloadObservation
    ) -> None:
        availability = observation.availability
        binding = observation.binding
        if not isinstance(availability, Availability) or not isinstance(
            binding, BindingObservation
        ):
            raise ModelInputError("payload observation axis type is invalid")
        if descriptor.content_class is ContentClass.NONE:
            if binding is not BindingObservation.NOT_APPLICABLE or availability not in (
                Availability.ABSENT,
                Availability.PRESENT,
            ):
                raise ModelInputError("NONE event has impossible payload observation")
            return
        legal = {
            Availability.ABSENT: {BindingObservation.NOT_CHECKED},
            Availability.PARTIAL: {BindingObservation.NOT_CHECKED},
            Availability.PRESENT: {
                BindingObservation.NOT_CHECKED,
                BindingObservation.VERIFIED,
                BindingObservation.OPENING_MISSING,
                BindingObservation.LENGTH_MISMATCH,
                BindingObservation.COMMITMENT_MISMATCH,
            },
        }
        if binding not in legal[availability]:
            raise ModelInputError("content-bearing event has impossible payload observation")

    def _validate_checkpoint(self, checkpoint: PayloadCheckpoint) -> None:
        if not isinstance(checkpoint, PayloadCheckpoint):
            raise ModelInputError("payload checkpoint type is invalid")
        if len(checkpoint.horizon_refs) > self.profile.max_checkpoint_refs:
            raise ModelInputError("payload checkpoint reference bound exceeded")
        if checkpoint.horizon_refs != tuple(sorted(set(checkpoint.horizon_refs))):
            raise ModelInputError("payload checkpoint horizon is not canonical")
        if any(not _bounded_bytes(item, self.profile.max_commitment_bytes) for item in checkpoint.horizon_refs):
            raise ModelInputError("payload checkpoint reference is invalid")
        if any(type(value) is not bool for value in (checkpoint.available, checkpoint.authenticated, checkpoint.conflicting)):
            raise ModelInputError("payload checkpoint flags must be boolean")

    def _record_input_size(self, record: PayloadRecord) -> int:
        descriptor = record.descriptor
        size = len(record.reference) + len(descriptor.commitment_value) + 8
        size += len(descriptor.content_type_id.encode("utf-8"))
        size += len(descriptor.commitment_suite_id.encode("utf-8"))
        if descriptor.chunk_geometry is not None:
            size += 24
        if record.removal is not None:
            size += len(record.removal.target_reference) + len(record.removal.target_commitment)
        return size

    @staticmethod
    def _reachable(
        start: bytes, target: bytes, graph: Mapping[bytes, tuple[bytes, ...]]
    ) -> bool:
        pending = list(graph.get(start, ()))
        seen: set[bytes] = set()
        while pending:
            candidate = pending.pop()
            if candidate == target:
                return True
            if candidate in seen:
                continue
            seen.add(candidate)
            pending.extend(graph.get(candidate, ()))
        return False

    def _project(
        self,
        causal: Evaluation,
        records: Mapping[bytes, PayloadRecord],
        observations: Mapping[bytes, PayloadObservation],
        authorizations: Mapping[bytes, bool],
        checkpoint: PayloadCheckpoint | None,
        *,
        boundary: int,
        prefix: Sequence[PayloadSnapshot],
    ) -> PayloadEvaluation:
        stale_dependencies = self._compacted_dependencies(causal)
        if stale_dependencies:
            return self._stale_projection(
                causal,
                records,
                observations,
                checkpoint,
                stale_dependencies,
            )
        if boundary:
            if len(prefix) != boundary:
                raise ModelInputError("incremental payload prefix is incomplete")
            prior = prefix[-1]
            states = dict(prior.states)
            outcomes = dict(prior.directive_outcomes)
            applied = list(prior.applied_order)
            halted_at = prior.halted_at
            snapshots = list(prefix)
        else:
            states: dict[bytes, PayloadState] = {}
            outcomes: dict[bytes, DirectiveOutcome] = {}
            applied: list[bytes] = []
            halted_at: bytes | None = None
            snapshots: list[PayloadSnapshot] = []

        for reference in causal.order[boundary:]:
            record = records[reference]
            observation = observations[reference]
            state = self._active_state(record.descriptor, observation)
            if halted_at is not None:
                state = replace(
                    state,
                    readiness=ReplayReadiness.CONTENT_DEFERRED,
                    presentation=PresentationState.DEFERRED,
                )
            elif (
                record.descriptor.content_class is ContentClass.REQUIRED
                and observation.binding is not BindingObservation.VERIFIED
            ):
                halted_at = reference
                state = replace(
                    state,
                    readiness=ReplayReadiness.CONTENT_DEFERRED,
                    presentation=PresentationState.DEFERRED,
                )
            else:
                applied.append(reference)
            states[reference] = state

            if record.removal is not None:
                if halted_at is not None and reference not in applied:
                    outcome = DirectiveOutcome.DEFERRED_BY_REQUIRED_SUFFIX
                else:
                    outcome = self._apply_removal(
                        record,
                        bool(authorizations[reference]),
                        records,
                        observations,
                        states,
                    )
                outcomes[reference] = outcome

            snapshots.append(
                PayloadSnapshot(
                    reference,
                    tuple(sorted(states.items())),
                    tuple(sorted(outcomes.items())),
                    tuple(applied),
                    halted_at,
                )
            )

        assessment = None
        if checkpoint is not None:
            assessment = self._assess_checkpoint(records, observations, checkpoint)
        return PayloadEvaluation(
            states=dict(sorted(states.items())),
            directive_outcomes=dict(sorted(outcomes.items())),
            applied_order=tuple(applied),
            halted_at=halted_at,
            stale_dependencies=(),
            snapshots=tuple(snapshots),
            checkpoint=assessment,
        )

    @staticmethod
    def _compacted_dependencies(causal: Evaluation) -> tuple[bytes, ...]:
        """Return non-authority dependencies represented only by causal evidence.

        C0.2f v0 cannot infer the absent dependency's payload class or reconstruct
        its AP contribution.  It therefore treats every such dependency as stale
        rather than allowing checkpoint evidence to substitute for payload state.
        """

        current = set(causal.decisions)
        authority_refs = {handoff.grant_ref for handoff in causal.handoffs}
        compacted: set[bytes] = set()
        for handoff in causal.handoffs:
            dependencies = handoff.causal_parents
            if handoff.author_predecessor is not None:
                dependencies = (handoff.author_predecessor, *dependencies)
            compacted.update(
                dependency
                for dependency in dependencies
                if dependency not in current and dependency not in authority_refs
            )
        return tuple(sorted(compacted))

    def _stale_projection(
        self,
        causal: Evaluation,
        records: Mapping[bytes, PayloadRecord],
        observations: Mapping[bytes, PayloadObservation],
        checkpoint: PayloadCheckpoint | None,
        stale_dependencies: tuple[bytes, ...],
    ) -> PayloadEvaluation:
        states: dict[bytes, PayloadState] = {}
        outcomes: dict[bytes, DirectiveOutcome] = {}
        snapshots: list[PayloadSnapshot] = []
        halted_at = stale_dependencies[0]
        for reference in causal.order:
            record = records[reference]
            state = replace(
                self._active_state(record.descriptor, observations[reference]),
                readiness=ReplayReadiness.STALE_EVIDENCE,
                presentation=PresentationState.DEFERRED,
            )
            states[reference] = state
            if record.removal is not None:
                outcomes[reference] = DirectiveOutcome.DEFERRED_BY_STALE_EVIDENCE
            snapshots.append(
                PayloadSnapshot(
                    reference,
                    tuple(sorted(states.items())),
                    tuple(sorted(outcomes.items())),
                    (),
                    halted_at,
                )
            )
        assessment = (
            None
            if checkpoint is None
            else self._assess_checkpoint(records, observations, checkpoint)
        )
        if assessment is not None:
            assessment = replace(
                assessment,
                disposition=CheckpointDisposition.STALE_EVIDENCE,
                producer_eligible=False,
                consumer_substitution=False,
            )
        return PayloadEvaluation(
            states=dict(sorted(states.items())),
            directive_outcomes=dict(sorted(outcomes.items())),
            applied_order=(),
            halted_at=halted_at,
            stale_dependencies=stale_dependencies,
            snapshots=tuple(snapshots),
            checkpoint=assessment,
        )

    @staticmethod
    def _active_state(
        descriptor: ContentDescriptor, observation: PayloadObservation
    ) -> PayloadState:
        if descriptor.content_class is ContentClass.NONE:
            presentation = (
                PresentationState.NO_CONTENT
                if observation.availability is Availability.ABSENT
                else PresentationState.UNEXPECTED_CONTENT_REJECTED
            )
        elif observation.binding is BindingObservation.VERIFIED:
            presentation = PresentationState.ACTIVE_VERIFIED
        elif observation.availability in (Availability.ABSENT, Availability.PARTIAL):
            presentation = PresentationState.ACTIVE_UNAVAILABLE
        elif observation.binding in (
            BindingObservation.LENGTH_MISMATCH,
            BindingObservation.COMMITMENT_MISMATCH,
        ):
            presentation = PresentationState.ACTIVE_SUBSTITUTED_REJECTED
        else:
            presentation = PresentationState.ACTIVE_UNVERIFIABLE
        return PayloadState(
            descriptor.content_class,
            observation.availability,
            observation.binding,
            RetentionState.ACTIVE,
            ReplayReadiness.READY,
            presentation,
        )

    @staticmethod
    def _apply_removal(
        record: PayloadRecord,
        authorized: bool,
        records: Mapping[bytes, PayloadRecord],
        observations: Mapping[bytes, PayloadObservation],
        states: dict[bytes, PayloadState],
    ) -> DirectiveOutcome:
        assert record.removal is not None
        target = record.removal.target_reference
        target_record = records[target]
        target_state = states[target]
        if not authorized:
            return DirectiveOutcome.UNAUTHORIZED
        if target_record.descriptor.content_class is not ContentClass.DETACHABLE:
            return DirectiveOutcome.INAPPLICABLE_CLASS
        if record.removal.target_commitment != target_record.descriptor.commitment_value:
            return DirectiveOutcome.TARGET_COMMITMENT_MISMATCH
        if target_state.retention is RetentionState.LOGICALLY_REMOVED:
            return DirectiveOutcome.ALREADY_REMOVED
        observation = observations[target]
        if observation.availability is Availability.ABSENT:
            presentation = PresentationState.REMOVED
        elif observation.binding is BindingObservation.VERIFIED:
            presentation = PresentationState.REMOVED_PRESENTED_VERIFIED
        elif observation.binding in (
            BindingObservation.LENGTH_MISMATCH,
            BindingObservation.COMMITMENT_MISMATCH,
        ):
            presentation = PresentationState.REMOVED_SUBSTITUTED_REJECTED
        else:
            presentation = PresentationState.REMOVED_PRESENTED_UNVERIFIABLE
        states[target] = replace(
            target_state,
            retention=RetentionState.LOGICALLY_REMOVED,
            presentation=presentation,
        )
        return DirectiveOutcome.APPLIED

    def _assess_checkpoint(
        self,
        records: Mapping[bytes, PayloadRecord],
        observations: Mapping[bytes, PayloadObservation],
        checkpoint: PayloadCheckpoint,
    ) -> CheckpointAssessment:
        known = all(reference in records for reference in checkpoint.horizon_refs)
        contents = tuple(
            (reference.hex(), *_record_term(records[reference]))
            for reference in checkpoint.horizon_refs
            if reference in records
        )
        eligible = known and all(
            records[reference].descriptor.content_class is not ContentClass.REQUIRED
            or observations[reference].binding is BindingObservation.VERIFIED
            for reference in checkpoint.horizon_refs
        )
        if not checkpoint.available:
            disposition = CheckpointDisposition.UNAVAILABLE
        elif not checkpoint.authenticated:
            disposition = CheckpointDisposition.UNAUTHENTICATED
        elif checkpoint.conflicting:
            disposition = CheckpointDisposition.CONFLICTING
        elif not known:
            disposition = CheckpointDisposition.STALE_EVIDENCE
        elif not eligible:
            disposition = CheckpointDisposition.PRODUCER_INELIGIBLE
        else:
            disposition = CheckpointDisposition.EMITTABLE
        return CheckpointAssessment(disposition, contents, eligible, False)


def payload_state_json(state: PayloadState) -> dict[str, str]:
    return {
        "content_class": state.content_class.value,
        "availability": state.availability.value,
        "binding": state.binding.value,
        "retention": state.retention.value,
        "readiness": state.readiness.value,
        "presentation": state.presentation.value,
    }


def payload_evaluation_json(evaluation: PayloadEvaluation) -> dict[str, object]:
    checkpoint = None
    if evaluation.checkpoint is not None:
        checkpoint = {
            "disposition": evaluation.checkpoint.disposition.value,
            "contents": evaluation.checkpoint.contents,
            "producer_eligible": evaluation.checkpoint.producer_eligible,
            "consumer_substitution": evaluation.checkpoint.consumer_substitution,
        }
    return {
        "states": {
            reference.hex(): payload_state_json(evaluation.states[reference])
            for reference in sorted(evaluation.states)
        },
        "directive_outcomes": {
            reference.hex(): evaluation.directive_outcomes[reference].value
            for reference in sorted(evaluation.directive_outcomes)
        },
        "applied_order": [reference.hex() for reference in evaluation.applied_order],
        "halted_at": None if evaluation.halted_at is None else evaluation.halted_at.hex(),
        "stale_dependencies": [
            reference.hex() for reference in evaluation.stale_dependencies
        ],
        "checkpoint": checkpoint,
    }
