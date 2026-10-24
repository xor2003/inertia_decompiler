"""Six-stage function evidence readiness governance.

Layer: Pipeline governance.
Responsibility: consumes the IR-owned function lifecycle, checks dependent-stage
invalidation, and reports typed verdicts to the same owner real consumers consult. Readiness
is evidence currency: a stage is CURRENT only while its recorded evidence stays
bound to the live source generation and to the upstream evidence inputs it was
recorded against. Absent evidence is UNTTRACKED — independent producer routes
keep their own proofs; this owner never guesses unsupported functions valid and
never fabricates readiness. Provably dead evidence is STALE and consumers must
refuse it.

Do not recover semantic facts here. Do not perform IR, alias, widening,
lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting
work here.
Owns runtime ordering, invariant checks, hard failures, and final emission gates
Do not recover semantic facts or perform IR, alias, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import Enum
from os import getpid
from typing import Protocol, cast

from inertia.ir.core import IRCallStackEffect8616, IRValue
from inertia.ir.function_artifact import IRFunctionArtifact
from inertia.ir.function_ir_registry import registered_function_ir_artifact_8616
from inertia.ir.function_lifecycle import (
    FunctionStageEvidence8616,
    FunctionStageFailure8616,
    FunctionStageInput8616,
    FunctionStageReadiness8616,
    FunctionStageVerdict8616,
    existing_function_lifecycle_state_8616,
    function_lifecycle_state_8616,
    function_stage_outputs_digest_8616,
)
from inertia.ir.function_readiness_contracts import (
    FUNCTION_LIFECYCLE_STAGES_8616,
    FunctionLifecycleStage8616,
    FunctionSourceRevision8616,
    function_artifact_body_digest_8616,
    observed_function_source_revision_8616,
    reobserve_function_source_revision_8616,
    requires_function_source_observation_8616,
)
from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    registered_function_ssa_artifact_8616,
)
from inertia.ir.source_graph_binding import (
    SourceGraphSerializationError8616,
    canonical_call_stack_effect_8616,
)
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.pipeline.structured_ast_output import (
    StructuredASTPublication8616,
    StructuredASTPublicationOwnership8616,
    observe_structured_ast_output_8616,
    publish_structured_ast_output_8616,
)

from .errors import PipelineHardError

__all__ = [
    "assert_function_ast_consumer_ready_8616",
    "assert_function_stage_ready_8616",
    "drop_function_stage_evidence_8616",
    "function_render_required_stage_8616",
    "function_rewrite_production_scope_8616",
    "function_stage_evidence_map_8616",
    "function_stage_readiness_8616",
    "function_structuring_production_scope_8616",
    "handoff_function_ast_to_rewrite_8616",
    "record_function_ast_stage_evidence_8616",
    "record_function_rewrite_completion_8616",
    "record_function_stage_evidence_8616",
]


@dataclass(slots=True)
class _EvidenceFingerprintWalk8616:
    """Track active paths and memoized content within one observation only.

    Object identities detect cycles and shared references; they never enter the
    emitted fingerprint. Retained objects prevent identity reuse during a walk.
    No memo survives a new observation of potentially mutable evidence.
    """

    active: set[int] = field(default_factory=set)
    memo: dict[int, tuple[object, str | None]] = field(default_factory=dict)
    outputs: dict[int, tuple[object, str | None]] = field(default_factory=dict)


def _scalar_fingerprint_8616(value: object) -> str | None:
    """Encode plain scalar leaves while retaining enum type identity separately."""
    if isinstance(value, Enum):
        return None
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return f"atom:{value!r}"
    return None


def _sequence_fingerprint_8616(
    values: Iterable[object], walk: _EvidenceFingerprintWalk8616, *, unordered: bool,
) -> str | None:
    """Encode complete ordered or unordered container contents."""
    parts = tuple(_structural_fingerprint_8616(item, walk) for item in values)
    if any(part is None for part in parts):
        return None
    complete = cast(tuple[str, ...], parts)
    if unordered:
        return "set:{" + ",".join(sorted(complete)) + "}"
    return "seq:(" + ",".join(complete) + ")"


def _compound_fingerprint_8616(value: object, walk: _EvidenceFingerprintWalk8616) -> str | None:
    """Dispatch structured evidence without treating implementation identity as content."""
    if isinstance(value, StructuredASTPublication8616):
        snapshot = value.current_snapshot()
        return None if snapshot is None else f"structured_ast:{snapshot.function_addr}:{snapshot.digest}"
    if isinstance(value, (IRFunctionArtifact, SSAFunctionArtifact, IRValue, IRCallStackEffect8616, Enum)):
        return _typed_evidence_fingerprint_8616(value, walk)
    if isinstance(value, (tuple, list)):
        return _sequence_fingerprint_8616(value, walk, unordered=False)
    if isinstance(value, (set, frozenset)):
        return _sequence_fingerprint_8616(value, walk, unordered=True)
    if isinstance(value, Mapping):
        return _mapping_fingerprint_8616(value, walk)
    return _members_fingerprint_8616(value, walk)


def _typed_evidence_fingerprint_8616(
    value: IRFunctionArtifact | SSAFunctionArtifact | IRValue | IRCallStackEffect8616 | Enum,
    walk: _EvidenceFingerprintWalk8616,
) -> str | None:
    """Use owned body and enum encodings without traversing implementation state."""
    if isinstance(value, IRCallStackEffect8616):
        try:
            encoded = canonical_call_stack_effect_8616(value)
        except SourceGraphSerializationError8616:
            return None
        return f"call_stack_effect:{encoded}"
    if isinstance(value, (IRFunctionArtifact, SSAFunctionArtifact)):
        digest = function_artifact_body_digest_8616(value)
        return None if digest is None else f"ir:{type(value).__qualname__}:{digest}"
    if isinstance(value, IRValue):
        try:
            encoded = json.dumps(value.to_dict(), sort_keys=True, allow_nan=False)
        except (TypeError, ValueError):
            return None
        return "value:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    payload = _structural_fingerprint_8616(value.value, walk)
    if payload is None:
        return None
    kind = type(value)
    return f"enum:{kind.__module__}.{kind.__qualname__}:{value.name}:{payload}"


def _mapping_fingerprint_8616[KeyT](
    value: Mapping[KeyT, object], walk: _EvidenceFingerprintWalk8616,
) -> str | None:
    """Encode every mapping key and value with deterministic ordering."""
    parts: list[tuple[str, str]] = []
    for key, item in value.items():
        key_fp = _structural_fingerprint_8616(key, walk)
        item_fp = _structural_fingerprint_8616(item, walk)
        if key_fp is None or item_fp is None:
            return None
        parts.append((key_fp, item_fp))
    return "map:{" + ",".join(sorted(f"{key}={item}" for key, item in parts)) + "}"


def _structural_fingerprint_8616(
    value: object, walk: _EvidenceFingerprintWalk8616 | None = None,
) -> str | None:
    """Encode evidence content, refusing cycles without truncating finite provenance."""
    scalar = _scalar_fingerprint_8616(value)
    if scalar is not None:
        return scalar
    state = _EvidenceFingerprintWalk8616() if walk is None else walk
    marker = id(value)
    cached = state.memo.get(marker)
    if cached is not None:
        return cached[1]
    if marker in state.active:
        return None
    state.active.add(marker)
    try:
        encoded = _compound_fingerprint_8616(value, state)
    finally:
        state.active.remove(marker)
    state.memo[marker] = (value, encoded)
    return encoded


class _SlottedEvidenceType8616(Protocol):
    """Describe slot declarations supplied by native codegen evidence types."""

    __slots__: str | Iterable[str]


def _slotted_evidence_members_8616(value: object) -> dict[str, object]:
    """Collect native carrier slots, including their inherited declarations."""
    members: dict[str, object] = {}
    for owner in type(value).__mro__:
        try:
            slots = cast(_SlottedEvidenceType8616, owner).__slots__
        except AttributeError:
            continue
        names = (slots,) if isinstance(slots, str) else slots
        for name in names:
            if name in {"__dict__", "__weakref__"}:
                continue
            try:
                # Dynamic codegen/plugin boundary: carriers declare field names at runtime.
                members[name] = getattr(value, name)
            except AttributeError:
                continue
    return members


def _members_fingerprint_8616(value: object, walk: _EvidenceFingerprintWalk8616) -> str | None:
    """Fingerprint dynamic boundary members without counting an artificial mapping level."""
    try:
        members = dict(vars(value))
    except TypeError:
        members = _slotted_evidence_members_8616(value)
    if not members:
        return None
    encoded = _mapping_fingerprint_8616(members, walk)
    if encoded is None:
        return None
    return f"obj:{type(value).__qualname__}:[{encoded}]"


def _evidence_fingerprint_8616(
    value: object, walk: _EvidenceFingerprintWalk8616 | None = None,
) -> str | None:
    """Observe each live output once within one caller-owned observation."""
    state = _EvidenceFingerprintWalk8616() if walk is None else walk
    marker = id(value)
    cached = state.outputs.get(marker)
    if cached is not None:
        return cached[1]
    fingerprint = _encode_evidence_fingerprint_8616(value, state)
    state.outputs[marker] = (value, fingerprint)
    return fingerprint


def _encode_evidence_fingerprint_8616(
    value: object, walk: _EvidenceFingerprintWalk8616,
) -> str | None:
    """Fingerprint the content of one real evidence object, never its identity.

    Owned contracts contribute their ``to_dict`` projection; mutable
    third-party objects contribute a deep structural encoding of their field
    values, so in-place mutation is visible. Unsupported evidence yields
    ``None`` — a typed non-result, never a guessed fingerprint.
    """
    if isinstance(value, StructuredASTPublication8616):
        # Diagnostics describe the receipt; only the version contract observes
        # the live output. Never fingerprint its diagnostic serialization.
        structural = _structural_fingerprint_8616(value, walk)
        return None if structural is None else hashlib.sha256(structural.encode("utf-8")).hexdigest()
    to_dict = getattr(value, "to_dict", None)  # Dynamic third-party boundary.
    if callable(to_dict):
        try:
            payload = to_dict()
            if isinstance(payload, dict):
                payload = dict(payload)
                payload.pop("source_revision", None)
                payload.pop("lifecycle_stage", None)
                payload.pop("lifecycle", None)
            encoded = json.dumps(payload, sort_keys=True, allow_nan=False)
        except (AttributeError, TypeError, ValueError):
            encoded = ""
        if encoded:
            return "dict:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    structural = _structural_fingerprint_8616(value, walk)
    if structural is None:
        return None
    return hashlib.sha256(structural.encode("utf-8")).hexdigest()


def _current_function_source_revision_8616(
    project: object,
    function_addr: int,
) -> FunctionSourceRevision8616 | None:
    """Resolve one coherent live source scope from the authoritative IR bodies."""
    raw = registered_function_ir_artifact_8616(project, function_addr)
    ssa = registered_function_ssa_artifact_8616(project, function_addr)
    return _registered_bodies_source_revision_8616(
        project, function_addr, (raw.artifact, ssa.artifact)
    )


def _registered_bodies_source_revision_8616(
    project: object,
    function_addr: int,
    bodies: tuple[IRFunctionArtifact | SSAFunctionArtifact | None, ...],
) -> FunctionSourceRevision8616 | None:
    """Reobserve coherent source scopes from bodies resolved in this observation."""
    revisions = tuple(
        artifact.source_revision
        for artifact in bodies
        if artifact is not None and artifact.source_revision is not None
    )
    if not revisions:
        return observed_function_source_revision_8616(project, function_addr)
    source = revisions[0]
    if any(revision != source for revision in revisions[1:]):
        return None
    return reobserve_function_source_revision_8616(project, source)


def record_function_stage_evidence_8616(
    project: object,
    function_addr: int,
    stage: FunctionLifecycleStage8616,
    *,
    producer: str,
    source_revision: FunctionSourceRevision8616 | None = None,
    upstream: Iterable[tuple[FunctionLifecycleStage8616, object]] = (),
    outputs: Iterable[object] = (),
) -> FunctionStageEvidence8616:
    """Record that one stage consumed bound inputs and produced typed evidence.

    ``source_revision=None`` records an unverifiable environment honestly; the
    revision defaults to the current observation when omitted. ``upstream``
    pairs each consumed input with the lifecycle stage that produced it;
    ``outputs`` are the actual evidence objects this stage produced, so later
    replacement of those objects invalidates every recorded dependent.
    """
    if stage not in FUNCTION_LIFECYCLE_STAGES_8616:
        raise TypeError(f"unknown function lifecycle stage: {stage!r}")
    state = function_lifecycle_state_8616(project, function_addr)
    evidence_map = state.publications
    if source_revision is None:
        source_revision = _current_function_source_revision_8616(project, function_addr)
    output_items = tuple(outputs)
    output_fingerprints = tuple(
        fingerprint
        for item in output_items
        if (fingerprint := _evidence_fingerprint_8616(item)) is not None
    )
    unsupported = len(output_fingerprints) != len(output_items)
    # Every recorded earlier stage is a bound input: its aggregate output
    # fingerprint is captured, so replacing or dropping that evidence
    # invalidates this record even under an unchanged source generation.
    inputs: dict[FunctionLifecycleStage8616, FunctionStageInput8616] = {
        prior: FunctionStageInput8616(prior, prior_evidence.outputs_digest)
        for prior, prior_evidence in evidence_map.items()
        if prior in FUNCTION_LIFECYCLE_STAGES_8616
        and FUNCTION_LIFECYCLE_STAGES_8616.index(prior)
        < FUNCTION_LIFECYCLE_STAGES_8616.index(stage)
    }
    for input_stage, item in upstream:
        fingerprint = _evidence_fingerprint_8616(item)
        if fingerprint is None:
            unsupported = True
            continue
        declared = inputs.get(input_stage)
        if declared is None:
            inputs[input_stage] = FunctionStageInput8616(
                input_stage, "", (fingerprint,)
            )
        else:
            inputs[input_stage] = FunctionStageInput8616(
                input_stage, declared.digest, (*declared.items, fingerprint)
            )
    evidence = FunctionStageEvidence8616(
        stage=stage,
        source_revision=source_revision,
        outputs=() if unsupported else output_fingerprints,
        inputs=tuple(inputs.values()),
        producer=producer,
        live_outputs=output_items,
        failure=(FunctionStageFailure8616.EVIDENCE_NOT_REPRESENTABLE if unsupported else None),
        ast_outputs=tuple(item for item in output_items if isinstance(item, StructuredASTPublication8616)),
    )
    state.record(evidence)
    return evidence


def record_function_ast_stage_evidence_8616(
    project: object,
    function_addr: int,
    stage: FunctionLifecycleStage8616,
    codegen: object,
    *,
    producer: str,
    outputs: Iterable[object] = (),
) -> FunctionStageEvidence8616:
    """Publish the actual final AST version with its producer's other evidence."""
    if stage not in {FunctionLifecycleStage8616.STRUCTURING, FunctionLifecycleStage8616.REWRITE}:
        raise ValueError("only Structuring and Rewrite publish structured AST versions")
    publication = publish_structured_ast_output_8616(codegen)
    snapshot = publication.observation.snapshot
    if snapshot is not None and snapshot.function_addr != function_addr:
        raise PipelineHardError(
            "AST publication belongs to another function",
            layer=producer,
            function_addr=function_addr,
            details={"observed_function_addr": snapshot.function_addr},
        )
    return record_function_stage_evidence_8616(
        project, function_addr, stage, producer=producer,
        outputs=(publication, *outputs),
    )


def handoff_function_ast_to_rewrite_8616(
    project: object, function_addr: int, codegen: object,
) -> None:
    """Validate the actual Structuring output before Rewrite takes ownership."""
    assert_function_stage_ready_8616(
        project, function_addr, FunctionLifecycleStage8616.STRUCTURING,
        layer="postprocess_codegen:structuring_handoff",
    )
    if not requires_function_source_observation_8616(project):
        return
    evidence = function_stage_evidence_map_8616(project, function_addr).get(
        FunctionLifecycleStage8616.STRUCTURING,
    )
    publications = () if evidence is None else tuple(
        item for item in evidence.live_outputs if isinstance(item, StructuredASTPublication8616)
    )
    if len(publications) != 1:
        raise PipelineHardError(
            "Structuring did not publish one actual AST output",
            layer="postprocess_codegen:structuring_handoff",
            function_addr=function_addr,
            details={"failure": FunctionStageFailure8616.AST_PUBLICATION_UNAVAILABLE.value},
        )
    failure = publications[0].handoff_to_rewrite(codegen)
    if failure is not None:
        refusal = FunctionStageReadiness8616(
            function_addr, FunctionLifecycleStage8616.REWRITE,
            FunctionStageVerdict8616.UNKNOWN_REFUSE,
            blocking_stage=FunctionLifecycleStage8616.STRUCTURING,
            failure=FunctionStageFailure8616.AST_HANDOFF_REFUSED,
        )
        _observe_function_readiness_8616(project, refusal)
        raise PipelineHardError(
            "Structuring AST handoff refused",
            layer="postprocess_codegen:structuring_handoff",
            function_addr=function_addr,
            details={
                "failure": FunctionStageFailure8616.AST_HANDOFF_REFUSED.value,
                "ast_failure": failure.value,
            },
        )
    drop_function_stage_evidence_8616(project, function_addr, FunctionLifecycleStage8616.REWRITE)


def drop_function_stage_evidence_8616(
    project: object,
    function_addr: int,
    stage: FunctionLifecycleStage8616 | None = None,
) -> None:
    """Drop recorded evidence for one stage, or all stages when omitted.

    Dropping earlier-stage evidence changes every dependent's upstream digest,
    which revokes their CURRENT verdict without deleting their records.
    """
    state = existing_function_lifecycle_state_8616(project, function_addr)
    if state is not None:
        state.drop(stage)


def function_stage_evidence_map_8616(
    project: object,
    function_addr: int,
) -> Mapping[FunctionLifecycleStage8616, FunctionStageEvidence8616]:
    """Return a read-only view of recorded stage evidence for one function."""
    state = existing_function_lifecycle_state_8616(project, function_addr)
    return {} if state is None else dict(state.publications)


def _live_fingerprints_8616(
    evidence: FunctionStageEvidence8616,
    walk: _EvidenceFingerprintWalk8616 | None = None,
) -> tuple[str, ...] | None:
    """Re-fingerprint recorded live outputs to catch in-place mutation."""
    state = _EvidenceFingerprintWalk8616() if walk is None else walk
    live: list[str] = []
    for item in evidence.live_outputs:
        fingerprint = _evidence_fingerprint_8616(item, state)
        if fingerprint is None:
            return None
        live.append(fingerprint)
    return tuple(live)


@dataclass(slots=True)
class _StageOutputObservation8616:
    """Share one output snapshot across dependencies in one readiness call."""

    walk: _EvidenceFingerprintWalk8616 = field(default_factory=_EvidenceFingerprintWalk8616)
    outputs: dict[FunctionLifecycleStage8616, tuple[str, ...] | None] = field(default_factory=dict)

    def observe(self, evidence: FunctionStageEvidence8616) -> tuple[str, ...] | None:
        """Observe shared bodies once; retain no state for the next admission."""
        if evidence.stage not in self.outputs:
            self.outputs[evidence.stage] = _live_fingerprints_8616(evidence, self.walk)
        return self.outputs[evidence.stage]


def _ir_authority_alive_8616(
    bodies: tuple[IRFunctionArtifact | SSAFunctionArtifact | None, ...],
    items: Iterable[str],
    walk: _EvidenceFingerprintWalk8616,
) -> bool:
    """Match declared IR inputs against bodies resolved in this observation.

    The registered IR/SSA artifacts are the real IR-stage evidence; no
    synthetic ledger record is required for them.
    """
    authority: list[str] = []
    for artifact in bodies:
        if artifact is None:
            continue
        fingerprint = _evidence_fingerprint_8616(artifact, walk)
        if fingerprint is not None:
            authority.append(fingerprint)
    return bool(authority) and all(item in authority for item in items)


@dataclass(frozen=True, slots=True)
class _PriorBlock8616:
    """One dead prior-stage outcome for the readiness loop."""

    verdict: FunctionStageVerdict8616
    failure: FunctionStageFailure8616 | None


def _prior_evidence_block_8616(
    evidence: FunctionStageEvidence8616,
    prior: FunctionLifecycleStage8616,
    current: FunctionSourceRevision8616 | None,
    input_alive: Callable[[FunctionStageInput8616], bool],
    observe_outputs: Callable[[FunctionStageEvidence8616], tuple[str, ...] | None],
) -> _PriorBlock8616 | None:
    """Evaluate one recorded prior stage; ``None`` means it stays alive.

    Unverifiable source binding is UNKNOWN_REFUSE; a lost live observation is
    SOURCE_UNAVAILABLE; a changed generation, mutated live output, or dead
    upstream input is STALE. ``input_alive`` verifies each declared upstream
    binding against the producer's live fingerprints.
    """
    if evidence.source_revision is None:
        return _PriorBlock8616(FunctionStageVerdict8616.UNKNOWN_REFUSE, None)
    if current is None:
        return _PriorBlock8616(
            FunctionStageVerdict8616.UNKNOWN_REFUSE,
            FunctionStageFailure8616.SOURCE_UNAVAILABLE,
        )
    if evidence.source_revision != current:
        return _PriorBlock8616(
            FunctionStageVerdict8616.STALE,
            FunctionStageFailure8616.SOURCE_REVISION_CHANGED,
        )
    if evidence.failure is not None:
        return _PriorBlock8616(FunctionStageVerdict8616.UNKNOWN_REFUSE, evidence.failure)
    live = observe_outputs(evidence)
    if live is None:
        return _PriorBlock8616(
            FunctionStageVerdict8616.UNKNOWN_REFUSE,
            FunctionStageFailure8616.EVIDENCE_NOT_REPRESENTABLE,
        )
    if live != evidence.outputs:
        return _PriorBlock8616(
            FunctionStageVerdict8616.STALE,
            FunctionStageFailure8616.UPSTREAM_EVIDENCE_CHANGED,
        )
    for declared in evidence.inputs:
        if not input_alive(declared):
            return _PriorBlock8616(
                FunctionStageVerdict8616.STALE,
                FunctionStageFailure8616.UPSTREAM_EVIDENCE_CHANGED,
            )
    return None


def _unrecorded_stage_readiness_8616(
    function_addr: int,
    stage: FunctionLifecycleStage8616,
    current: FunctionSourceRevision8616 | None,
    bodies: tuple[IRFunctionArtifact | SSAFunctionArtifact | None, ...],
) -> FunctionStageReadiness8616:
    """Recognize the actual IR registries without inventing later producers."""
    if (
        stage is FunctionLifecycleStage8616.IR
        and current is not None
        and any(artifact is not None for artifact in bodies)
    ):
        return FunctionStageReadiness8616(
            function_addr, stage, FunctionStageVerdict8616.CURRENT,
        )
    return FunctionStageReadiness8616(
        function_addr, stage, FunctionStageVerdict8616.UNTRACKED,
    )


def _evaluate_function_stage_readiness_8616(
    project: object,
    function_addr: int,
    stage: FunctionLifecycleStage8616,
) -> FunctionStageReadiness8616:
    """Evaluate one stage's readiness from recorded evidence only.

    STALE wins over everything: the first stage in canonical order whose
    recorded evidence is dead blocks every dependent stage. A stage with no
    recorded evidence is UNTTRACKED — never promoted, never refused.
    """
    evidence_map = function_stage_evidence_map_8616(project, function_addr)
    # The SSA registry binding is the authoritative IR-stage evidence: its
    # typed stale refusal invalidates every recorded dependent stage.
    ssa_resolution = registered_function_ssa_artifact_8616(project, function_addr)
    if ssa_resolution.failure is FunctionSSAArtifactFailure8616.SOURCE_REVISION_CHANGED:
        return FunctionStageReadiness8616(
            function_addr,
            stage,
            FunctionStageVerdict8616.STALE,
            blocking_stage=FunctionLifecycleStage8616.IR,
            failure=FunctionStageFailure8616.SOURCE_REVISION_CHANGED,
        )
    raw_resolution = registered_function_ir_artifact_8616(project, function_addr)
    bodies = (raw_resolution.artifact, ssa_resolution.artifact)
    current = _registered_bodies_source_revision_8616(project, function_addr, bodies)
    target_index = FUNCTION_LIFECYCLE_STAGES_8616.index(stage)
    observation = _StageOutputObservation8616()

    def _input_stage_alive_8616(
        declared: FunctionStageInput8616,
    ) -> bool:
        """Verify one declared upstream binding against live producer truth."""
        input_evidence = evidence_map.get(declared.stage)
        live_fingerprints = (
            None
            if input_evidence is None
            else observation.observe(input_evidence)
        )
        if (
            input_evidence is None
            and declared.stage is FunctionLifecycleStage8616.IR
        ):
            return _ir_authority_alive_8616(bodies, declared.items, observation.walk)
        if input_evidence is None or live_fingerprints is None:
            return False
        if declared.digest and declared.digest != function_stage_outputs_digest_8616(
            live_fingerprints
        ):
            return False
        return all(item in live_fingerprints for item in declared.items)

    for prior in FUNCTION_LIFECYCLE_STAGES_8616[: target_index + 1]:
        evidence = evidence_map.get(prior)
        if evidence is None:
            continue
        blocked = _prior_evidence_block_8616(
            evidence, prior, current, _input_stage_alive_8616, observation.observe
        )
        if blocked is not None:
            return FunctionStageReadiness8616(
                function_addr,
                stage,
                blocked.verdict,
                blocking_stage=prior,
                failure=blocked.failure,
            )
    own = evidence_map.get(stage)
    if own is None:
        return _unrecorded_stage_readiness_8616(function_addr, stage, current, bodies)
    return FunctionStageReadiness8616(
        function_addr,
        stage,
        FunctionStageVerdict8616.CURRENT,
    )


def _observe_function_readiness_8616(project: object, readiness: FunctionStageReadiness8616) -> None:
    """Transport checked currency or refusal into the canonical function state."""
    state = existing_function_lifecycle_state_8616(project, readiness.function_addr)
    if state is not None:
        state.observe(readiness)


def function_stage_readiness_8616(
    project: object, function_addr: int, stage: FunctionLifecycleStage8616,
) -> FunctionStageReadiness8616:
    """Observe producer currency; diagnostics alone cannot promote native maturity."""
    readiness = _evaluate_function_stage_readiness_8616(project, function_addr, stage)
    if readiness.verdict is not FunctionStageVerdict8616.CURRENT:
        _observe_function_readiness_8616(project, readiness)
    return readiness


def _native_ast_publication_failure_8616(
    project: object,
    function_addr: int,
    required: FunctionLifecycleStage8616,
    target: FunctionLifecycleStage8616,
) -> FunctionStageFailure8616 | None:
    """Require one correctly bound AST version and the producer/consumer handoff."""
    evidence = function_stage_evidence_map_8616(project, function_addr).get(required)
    publications = () if evidence is None else tuple(
        item for item in evidence.live_outputs if isinstance(item, StructuredASTPublication8616)
    )
    if len(publications) != 1:
        return FunctionStageFailure8616.AST_PUBLICATION_UNAVAILABLE
    publication = publications[0]
    snapshot = publication.observation.snapshot
    if snapshot is None or snapshot.function_addr != function_addr:
        return FunctionStageFailure8616.AST_PUBLICATION_UNAVAILABLE
    if (
        required is FunctionLifecycleStage8616.REWRITE
        and publication.ownership is not StructuredASTPublicationOwnership8616.LIVE
    ):
        return FunctionStageFailure8616.AST_PUBLICATION_UNAVAILABLE
    if (
        target is FunctionLifecycleStage8616.REWRITE
        and required is FunctionLifecycleStage8616.STRUCTURING
        and publication.ownership is not StructuredASTPublicationOwnership8616.HANDED_TO_REWRITE
    ):
        return FunctionStageFailure8616.AST_HANDOFF_REFUSED
    return None


def _native_stage_admission_8616(
    project: object,
    function_addr: int,
    stage: FunctionLifecycleStage8616,
) -> FunctionStageReadiness8616:
    """Require completed native producers in the canonical dependency order."""
    target = function_stage_readiness_8616(project, function_addr, stage)
    if target.verdict is FunctionStageVerdict8616.STALE:
        return target
    target_index = FUNCTION_LIFECYCLE_STAGES_8616.index(stage)
    for required in FUNCTION_LIFECYCLE_STAGES_8616[: target_index + 1]:
        readiness = function_stage_readiness_8616(project, function_addr, required)
        if readiness.verdict is FunctionStageVerdict8616.UNTRACKED:
            return FunctionStageReadiness8616(
                function_addr, stage, FunctionStageVerdict8616.UNKNOWN_REFUSE,
                blocking_stage=required,
                failure=FunctionStageFailure8616.STAGE_NOT_PRODUCED,
            )
        if readiness.verdict is not FunctionStageVerdict8616.CURRENT:
            return FunctionStageReadiness8616(
                function_addr, stage, readiness.verdict,
                blocking_stage=readiness.blocking_stage or required,
                failure=readiness.failure,
            )
        if required in {FunctionLifecycleStage8616.STRUCTURING, FunctionLifecycleStage8616.REWRITE}:
            failure = _native_ast_publication_failure_8616(project, function_addr, required, stage)
            if failure is not None:
                return FunctionStageReadiness8616(
                    function_addr, stage, FunctionStageVerdict8616.UNKNOWN_REFUSE,
                    blocking_stage=required, failure=failure,
                )
        _observe_function_readiness_8616(project, readiness)
    return function_stage_readiness_8616(project, function_addr, stage)


def assert_function_ast_consumer_ready_8616(
    project: object,
    function_addr: int,
    stage: FunctionLifecycleStage8616,
    codegen: object,
    *,
    layer: str,
) -> FunctionStageReadiness8616:
    """Check producer currency and the actual AST this consumer will use."""
    readiness = assert_function_stage_ready_8616(project, function_addr, stage, layer=layer)
    if not requires_function_source_observation_8616(project) or stage not in {
        FunctionLifecycleStage8616.STRUCTURING, FunctionLifecycleStage8616.REWRITE,
    }:
        return readiness
    evidence = function_stage_evidence_map_8616(project, function_addr)[stage]
    publications = tuple(
        item for item in evidence.live_outputs if isinstance(item, StructuredASTPublication8616)
    )
    # Native admission above requires exactly one actual AST publication.
    publication = publications[0]
    current = observe_structured_ast_output_8616(codegen)
    if not current.complete or current.snapshot != publication.observation.snapshot:
        refusal = FunctionStageReadiness8616(
            function_addr, stage, FunctionStageVerdict8616.UNKNOWN_REFUSE,
            blocking_stage=stage, failure=FunctionStageFailure8616.AST_CONSUMER_CHANGED,
        )
        _observe_function_readiness_8616(project, refusal)
        raise PipelineHardError(
            "consumer AST differs from the published function output",
            layer=layer,
            function_addr=function_addr,
            details={
                "failure": FunctionStageFailure8616.AST_CONSUMER_CHANGED.value,
                "stage": stage.value,
                "ast_failure": None if current.failure is None else current.failure.value,
            },
        )
    return readiness


def assert_function_stage_ready_8616(
    project: object,
    function_addr: int,
    stage: FunctionLifecycleStage8616,
    *,
    layer: str,
) -> FunctionStageReadiness8616:
    """Require native stage producers; preserve independent model obligations.

    Native projects must have every prerequisite and the consumed stage
    completed. Model-only clients retain their independent proof paths, while
    stale or unverifiable recorded evidence refuses in every scope.
    """
    readiness = (
        _native_stage_admission_8616(project, function_addr, stage)
        if requires_function_source_observation_8616(project)
        else function_stage_readiness_8616(project, function_addr, stage)
    )
    _observe_function_readiness_8616(project, readiness)
    if readiness.verdict in {
        FunctionStageVerdict8616.STALE,
        FunctionStageVerdict8616.UNKNOWN_REFUSE,
    }:
        raise PipelineHardError(
            f"function {function_addr:#x} {stage.value} consumption refused: "
            f"{readiness.blocking_stage} evidence is {readiness.verdict.value}",
            layer=layer,
            function_addr=function_addr,
            details=readiness.to_dict(),
        )
    return readiness


@dataclass(frozen=True, slots=True)
class _RewriteCompletionRequest8616:
    """Retain one producer's completion evidence until its actual output exists."""

    producer: str
    outputs: tuple[object, ...]


@dataclass(slots=True)
class _FunctionProductionScope8616:
    """Temporary, process-local authority to render one producer's pending AST."""

    project: object
    function_addr: int
    codegen: object
    source_evidence: FunctionStageEvidence8616 | None
    input_stage: FunctionLifecycleStage8616
    process_id: int
    active: bool = True
    completion: _RewriteCompletionRequest8616 | None = None


class _RewriteFunctionAddress8616(Protocol):
    """Third-party generated function coordinate used by the rendering boundary."""

    addr: int


class _RewriteFunctionCodegen8616(Protocol):
    """Third-party generator surface needed to match an active producer."""

    cfunc: _RewriteFunctionAddress8616


_ACTIVE_FUNCTION_PRODUCTION_8616: ContextVar[_FunctionProductionScope8616 | None] = ContextVar(
    "inertia_active_function_production_8616", default=None,
)


def record_function_rewrite_completion_8616(
    project: object, function_addr: int, codegen: object, *,
    producer: str, outputs: Iterable[object] = (),
) -> None:
    """Record standalone output or defer it until the matching producer finishes.

    The active Rewrite producer still owns naming, regeneration and final
    validation after its inner cleanup completes. Its output cannot be consumed
    until normal scope exit rechecks the consumed input and snapshots the final
    AST. An exception discards the request. A foreign, inherited, inactive or
    duplicate completion request is an API error, never publication authority.
    """
    scope = _ACTIVE_FUNCTION_PRODUCTION_8616.get()
    if scope is None:
        record_function_ast_stage_evidence_8616(
            project, function_addr, FunctionLifecycleStage8616.REWRITE, codegen,
            producer=producer, outputs=outputs,
        )
        return
    if (
        not scope.active or scope.process_id != getpid()
        or scope.project is not project or scope.function_addr != function_addr
        or scope.codegen is not codegen
    ):
        raise ValueError("Rewrite completion does not belong to the active producer")
    if scope.input_stage is not FunctionLifecycleStage8616.STRUCTURING:
        raise ValueError("Rewrite completion requires a Rewrite production scope")
    if scope.completion is not None:
        raise ValueError("Rewrite producer already requested completion")
    scope.completion = _RewriteCompletionRequest8616(producer, tuple(outputs))


def _commit_function_rewrite_completion_8616(scope: _FunctionProductionScope8616) -> None:
    """Seal requested output only while its identical consumed input is current."""
    request = scope.completion
    if request is None:
        return
    if not scope.active or scope.process_id != getpid():
        raise ValueError("Rewrite completion requires its live producing process")
    current = function_stage_evidence_map_8616(scope.project, scope.function_addr).get(scope.input_stage)
    if current is not scope.source_evidence:
        raise PipelineHardError(
            "Rewrite consumed input was replaced before completion",
            layer="pipeline_contract:rewrite_completion", function_addr=scope.function_addr,
            details={"failure": FunctionStageFailure8616.UPSTREAM_EVIDENCE_CHANGED.value,
                     "blocking_stage": scope.input_stage.value},
        )
    assert_function_stage_ready_8616(
        scope.project, scope.function_addr, scope.input_stage,
        layer="pipeline_contract:rewrite_completion",
    )
    record_function_ast_stage_evidence_8616(
        scope.project, scope.function_addr, FunctionLifecycleStage8616.REWRITE, scope.codegen,
        producer=request.producer, outputs=request.outputs,
    )


@contextmanager
def function_rewrite_production_scope_8616(
    project: object, function_addr: int, codegen: object,
) -> Iterator[None]:
    """Own pending Rewrite output after a checked Structuring handoff.

    Internal rendering consumes the completed input stage while this producer
    is running. An explicit completion request publishes its actual final AST
    only after successful scope exit and a fresh input check. No request or an
    exception publishes nothing. Closing revokes copied contexts as well as
    restoring any enclosing producer; publication supplies no semantic verdict.
    Final consumers still require the actual completed Rewrite publication.
    """
    handoff_function_ast_to_rewrite_8616(project, function_addr, codegen)
    evidence = function_stage_evidence_map_8616(project, function_addr).get(
        FunctionLifecycleStage8616.STRUCTURING,
    )
    scope = _FunctionProductionScope8616(
        project, function_addr, codegen, evidence, FunctionLifecycleStage8616.STRUCTURING, getpid(),
    )
    token = _ACTIVE_FUNCTION_PRODUCTION_8616.set(scope)
    try:
        yield
        _commit_function_rewrite_completion_8616(scope)
    finally:
        scope.active = False
        scope.completion = None
        _ACTIVE_FUNCTION_PRODUCTION_8616.reset(token)


@contextmanager
def function_structuring_production_scope_8616(
    project: object, function_addr: int, codegen: object,
) -> Iterator[None]:
    """Render pending Structuring output from the exact checked Types input.

    This lease grants no completed Structuring or Rewrite evidence. It expires
    on exit and rejects replaced input evidence, foreign generators and forks.
    """
    assert_function_stage_ready_8616(
        project, function_addr, FunctionLifecycleStage8616.TYPES,
        layer="pipeline_contract:structuring_internal_render",
    )
    evidence = function_stage_evidence_map_8616(project, function_addr).get(
        FunctionLifecycleStage8616.TYPES,
    )
    scope = _FunctionProductionScope8616(
        project, function_addr, codegen, evidence, FunctionLifecycleStage8616.TYPES, getpid(),
    )
    token = _ACTIVE_FUNCTION_PRODUCTION_8616.set(scope)
    try:
        yield
    finally:
        scope.active = False
        _ACTIVE_FUNCTION_PRODUCTION_8616.reset(token)


def function_render_required_stage_8616(
    project: object, codegen: object,
) -> FunctionLifecycleStage8616:
    """Select checked input only for an exact live producer's internal rendering.

    Foreign generators, changed input versions, expired or inherited process
    contexts and final rendering all retain the full Rewrite requirement.
    """
    scope = _ACTIVE_FUNCTION_PRODUCTION_8616.get()
    if (
        scope is None or not scope.active or scope.process_id != getpid()
        or scope.project is not project or scope.codegen is not codegen
    ):
        return FunctionLifecycleStage8616.REWRITE
    try:
        addr = cast(_RewriteFunctionCodegen8616, codegen).cfunc.addr
    except AttributeError:
        return FunctionLifecycleStage8616.REWRITE
    if addr != scope.function_addr:
        return FunctionLifecycleStage8616.REWRITE
    current = function_stage_evidence_map_8616(project, addr).get(
        scope.input_stage,
    )
    if current is not scope.source_evidence:
        return FunctionLifecycleStage8616.REWRITE
    assert_function_stage_ready_8616(
        project, addr, scope.input_stage,
        layer="pipeline_contract:producer_internal_render",
    )
    # The retained producer input describes consumed evidence. Rendering
    # the producer's pending AST checks Types contracts without comparing that
    # changing output to the immutable input snapshot; the full input prefix
    # has just been checked above.
    return FunctionLifecycleStage8616.TYPES
