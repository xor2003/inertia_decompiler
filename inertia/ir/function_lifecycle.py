"""Function-owned lifecycle evidence, observations and projection handles.

Layer: IR.
Responsibility: own typed producer publications, validated maturity and refusal
state shared by raw IR, SSA and later projections. These are evidence contracts;
this module neither recovers semantics nor observes mutable backend objects.
Pipeline consumers evaluate currency and report their observations here.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, cast

from .function_readiness_contracts import (
    FUNCTION_LIFECYCLE_STAGES_8616,
    FunctionLifecycleStage8616,
    FunctionSourceRevision8616,
)

__all__ = [
    "FunctionLifecycle8616",
    "FunctionLifecycleState8616",
    "FunctionOutputDiagnostics8616",
    "FunctionStageEvidence8616",
    "FunctionStageFailure8616",
    "FunctionStageInput8616",
    "FunctionStageReadiness8616",
    "FunctionStageVerdict8616",
    "bind_function_lifecycle_8616",
    "bind_function_lifecycle_source_8616",
    "existing_function_lifecycle_state_8616",
    "function_lifecycle_state_8616",
    "function_stage_outputs_digest_8616",
    "observe_function_source_refusal_8616",
]


class FunctionOutputDiagnostics8616(Protocol):
    """Diagnostic projection of a live producer publication owned elsewhere."""

    def to_dict(self) -> dict[str, object]:
        """Describe the publication without serializing its runtime objects."""
        ...


def function_stage_outputs_digest_8616(fingerprints: Iterable[str]) -> str:
    """Aggregate canonical per-item output fingerprints without runtime identity."""
    return hashlib.sha256("\x00".join(sorted(fingerprints)).encode("utf-8")).hexdigest()


class FunctionStageVerdict8616(StrEnum):
    """Typed verdict of one function-stage readiness evaluation."""

    CURRENT = "current"
    STALE = "stale"
    UNKNOWN_REFUSE = "unknown_refuse"
    UNTRACKED = "untracked"


class FunctionStageFailure8616(StrEnum):
    """Typed refusal cause for missing, unsupported or stale stage evidence."""

    SOURCE_REVISION_CHANGED = "source_revision_changed"
    SOURCE_UNAVAILABLE = "source_unavailable"
    SOURCE_REVISION_CONFLICT = "source_revision_conflict"
    STAGE_NOT_PRODUCED = "stage_not_produced"
    UPSTREAM_EVIDENCE_CHANGED = "upstream_evidence_changed"
    EVIDENCE_NOT_REPRESENTABLE = "evidence_not_representable"
    AST_PUBLICATION_UNAVAILABLE = "ast_publication_unavailable"
    AST_HANDOFF_REFUSED = "ast_handoff_refused"
    AST_CONSUMER_CHANGED = "ast_consumer_changed"


@dataclass(frozen=True, slots=True)
class FunctionStageInput8616:
    """One declared upstream consumption inside recorded stage evidence.

    ``items`` carries the content fingerprints of the particular producer
    outputs consumed; an empty tuple binds the whole recorded output set of
    that stage via its aggregate ``digest``.
    """

    stage: FunctionLifecycleStage8616
    digest: str
    items: tuple[str, ...] = ()

    def to_dict(self) -> list[object]:
        """Serialize this input binding for diagnostics."""
        return [self.stage.value, self.digest, list(self.items)]


@dataclass(frozen=True, slots=True)
class FunctionStageEvidence8616:
    """Recorded evidence that one lifecycle stage consumed bound inputs.

    ``source_revision`` binds the observation to a source generation when the
    boundary was observable; ``None`` records an unverifiable environment
    honestly. ``outputs`` are the per-item content fingerprints of the actual
    produced evidence; ``live_outputs`` retains the produced objects so
    in-place mutation without re-recording invalidates dependents at
    evaluation time. ``inputs`` binds each consumed upstream stage to the
    same canonical fingerprints the producer recorded. ``failure`` preserves
    unsupported publication as a typed non-result; partial outputs prove no
    completed stage even if a later mutation becomes representable.
    """

    stage: FunctionLifecycleStage8616
    source_revision: FunctionSourceRevision8616 | None
    outputs: tuple[str, ...]
    inputs: tuple[FunctionStageInput8616, ...]
    producer: str
    live_outputs: tuple[object, ...] = ()
    failure: FunctionStageFailure8616 | None = None
    ast_outputs: tuple[FunctionOutputDiagnostics8616, ...] = ()

    @property
    def outputs_digest(self) -> str:
        """Aggregate digest over this record's per-item output fingerprints."""
        return function_stage_outputs_digest_8616(self.outputs)

    def to_dict(self) -> dict[str, object]:
        """Serialize this stage evidence record for diagnostics."""
        return {
            "stage": self.stage.value,
            "source_revision": (
                None if self.source_revision is None else self.source_revision.to_dict()
            ),
            "outputs": list(self.outputs),
            "outputs_digest": self.outputs_digest,
            "inputs": [entry.to_dict() for entry in self.inputs],
            "producer": self.producer,
            "failure": None if self.failure is None else self.failure.value,
            "ast_outputs": [
                item.to_dict() for item in self.ast_outputs
            ],
        }


@dataclass(frozen=True, slots=True)
class FunctionStageReadiness8616:
    """One evaluated stage readiness with the first blocking stage, if any."""

    function_addr: int
    stage: FunctionLifecycleStage8616
    verdict: FunctionStageVerdict8616
    blocking_stage: FunctionLifecycleStage8616 | None = None
    failure: FunctionStageFailure8616 | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this readiness verdict for diagnostics."""
        return {
            "function_addr": self.function_addr,
            "stage": self.stage.value,
            "verdict": self.verdict.value,
            "blocking_stage": None if self.blocking_stage is None else self.blocking_stage.value,
            "failure": None if self.failure is None else self.failure.value,
        }


@dataclass(slots=True)
class FunctionLifecycleState8616:
    """Canonical producer evidence and the last checked prefix for one function.

    Cached observations describe the last successful check, never permission to
    skip live consumer checks. Recording or removing a producer invalidates its
    dependent observations. A refusal invalidates its blocking stage and later
    stages so projections cannot retain a successful descendant verdict.
    """

    publications: dict[FunctionLifecycleStage8616, FunctionStageEvidence8616] = field(default_factory=dict)
    evaluations: dict[FunctionLifecycleStage8616, FunctionStageReadiness8616] = field(default_factory=dict)
    source_revision: FunctionSourceRevision8616 | None = None
    ir_body_digest: str | None = None

    def bind_source(self, revision: FunctionSourceRevision8616 | None, body_digest: str) -> None:
        """Bind one state to one immutable accepted raw-IR generation."""
        if self.ir_body_digest is not None and (
            self.source_revision != revision or self.ir_body_digest != body_digest
        ):
            raise ValueError("a lifecycle state cannot change its raw IR generation")
        elif self.ir_body_digest is None:
            self.evaluations.clear()
        self.source_revision = revision
        self.ir_body_digest = body_digest

    @property
    def maturity(self) -> FunctionLifecycleStage8616 | None:
        """Return the contiguous prefix most recently validated by consumers."""
        result = None
        for stage in FUNCTION_LIFECYCLE_STAGES_8616:
            readiness = self.evaluations.get(stage)
            if readiness is None or readiness.verdict is not FunctionStageVerdict8616.CURRENT:
                break
            result = stage
        return result

    def invalidate_from(self, stage: FunctionLifecycleStage8616) -> None:
        """Remove cached readiness for a changed producer and its dependents."""
        index = FUNCTION_LIFECYCLE_STAGES_8616.index(stage)
        for dependent in FUNCTION_LIFECYCLE_STAGES_8616[index:]:
            self.evaluations.pop(dependent, None)

    def record(self, evidence: FunctionStageEvidence8616) -> None:
        """Retain actual producer evidence and revoke dependent cached verdicts."""
        self.invalidate_from(evidence.stage)
        self.publications[evidence.stage] = evidence

    def drop(self, stage: FunctionLifecycleStage8616 | None = None) -> None:
        """Remove a producer or all producers without retaining later maturity."""
        if stage is None:
            self.publications.clear()
            self.evaluations.clear()
        else:
            self.publications.pop(stage, None)
            self.invalidate_from(stage)

    def observe(self, readiness: FunctionStageReadiness8616) -> None:
        """Transport a consumer's checked verdict and typed refusal to all views."""
        if readiness.verdict is not FunctionStageVerdict8616.CURRENT:
            self.invalidate_from(readiness.blocking_stage or readiness.stage)
        self.evaluations[readiness.stage] = readiness

    def to_dict(self) -> dict[str, object]:
        """Serialize observations for diagnostics, without granting restore authority."""
        maturity = self.maturity
        return {
            "maturity": None if maturity is None else maturity.value,
            "source_revision": None if self.source_revision is None else self.source_revision.to_dict(),
            "ir_body_digest": self.ir_body_digest,
            "publications": {
                stage.value: self.publications[stage].to_dict()
                for stage in FUNCTION_LIFECYCLE_STAGES_8616 if stage in self.publications
            },
            "evaluations": {
                stage.value: self.evaluations[stage].to_dict()
                for stage in FUNCTION_LIFECYCLE_STAGES_8616 if stage in self.evaluations
            },
        }


@dataclass(slots=True)
class FunctionLifecycle8616:
    """Projection handle bound to the one function-owned lifecycle state."""

    state: FunctionLifecycleState8616 = field(default_factory=FunctionLifecycleState8616)
    function_addr: int | None = None

    def require_owner(self, function_addr: int) -> None:
        """Reject cross-function handles before creating or changing any state."""
        if self.function_addr is not None and self.function_addr != function_addr:
            raise ValueError("a function lifecycle projection cannot change its owning function")

    def bind(self, state: FunctionLifecycleState8616, function_addr: int) -> None:
        """Attach this projection to canonical runtime state after publication checks."""
        self.require_owner(function_addr)
        if self.function_addr is not None and self.state is not state:
            raise ValueError("a bound lifecycle projection cannot change its source generation")
        self.function_addr = function_addr
        self.state = state

    def to_dict(self) -> dict[str, object]:
        """Expose the same typed lifecycle through every bound projection."""
        return self.state.to_dict()


class _FunctionLifecycleRegistrySurface8616(Protocol):
    """IR-owned function state registry on the third-party project extension."""

    _inertia_function_lifecycle_states_8616: dict[int, FunctionLifecycleState8616]


def _existing_registry_8616(project: object) -> dict[int, FunctionLifecycleState8616] | None:
    """Read canonical state without creating anything during observation."""
    surface = cast(_FunctionLifecycleRegistrySurface8616, project)
    try:
        registry = surface._inertia_function_lifecycle_states_8616
    except AttributeError:
        return None
    if not isinstance(registry, dict):
        raise TypeError("function lifecycle registry must be a dict")
    return registry


def existing_function_lifecycle_state_8616(
    project: object, function_addr: int,
) -> FunctionLifecycleState8616 | None:
    """Look up one function's authoritative state without building IR or SSA."""
    registry = _existing_registry_8616(project)
    return None if registry is None else registry.get(function_addr)


def observe_function_source_refusal_8616(
    project: object, function_addr: int, failure: FunctionStageFailure8616,
) -> None:
    """Revoke retained views when their canonical registry observes no source proof.

    Observation does not create state or publish a new generation. Existing
    handles retain their original state and its explicit IR-stage refusal.
    """
    if failure not in {
        FunctionStageFailure8616.SOURCE_REVISION_CHANGED,
        FunctionStageFailure8616.SOURCE_UNAVAILABLE,
        FunctionStageFailure8616.SOURCE_REVISION_CONFLICT,
    }:
        raise ValueError("registry source observation requires a source refusal")
    state = existing_function_lifecycle_state_8616(project, function_addr)
    if state is not None:
        state.observe(FunctionStageReadiness8616(
            function_addr, FunctionLifecycleStage8616.IR,
            FunctionStageVerdict8616.STALE
            if failure is FunctionStageFailure8616.SOURCE_REVISION_CHANGED
            else FunctionStageVerdict8616.UNKNOWN_REFUSE,
            FunctionLifecycleStage8616.IR, failure,
        ))


def function_lifecycle_state_8616(project: object, function_addr: int) -> FunctionLifecycleState8616:
    """Create canonical state only for a producer or an accepted publication."""
    registry = _existing_registry_8616(project)
    if registry is None:
        registry = {}
        cast(_FunctionLifecycleRegistrySurface8616, project)._inertia_function_lifecycle_states_8616 = registry
    state = registry.get(function_addr)
    if state is None:
        state = FunctionLifecycleState8616()
        registry[function_addr] = state
    return state


def bind_function_lifecycle_8616(
    project: object, function_addr: int, lifecycle: FunctionLifecycle8616,
) -> None:
    """Bind accepted IR/SSA projections; detached serialized claims are ignored."""
    lifecycle.require_owner(function_addr)
    lifecycle.bind(function_lifecycle_state_8616(project, function_addr), function_addr)


def bind_function_lifecycle_source_8616(
    project: object,
    function_addr: int,
    lifecycle: FunctionLifecycle8616,
    revision: FunctionSourceRevision8616 | None,
    body_digest: str,
) -> None:
    """Publish a new source state while old projections retain an explicit refusal."""
    lifecycle.require_owner(function_addr)
    state = function_lifecycle_state_8616(project, function_addr)
    changed = state.ir_body_digest is not None and (
        state.source_revision != revision or state.ir_body_digest != body_digest
    )
    if changed:
        if lifecycle.function_addr is not None:
            raise ValueError("a new raw IR generation requires a fresh lifecycle projection")
        failure = (
            FunctionStageFailure8616.SOURCE_REVISION_CHANGED
            if state.source_revision != revision
            else FunctionStageFailure8616.UPSTREAM_EVIDENCE_CHANGED
        )
        state.observe(FunctionStageReadiness8616(
            function_addr, FunctionLifecycleStage8616.REWRITE, FunctionStageVerdict8616.STALE,
            FunctionLifecycleStage8616.IR, failure,
        ))
        state = FunctionLifecycleState8616()
        registry = _existing_registry_8616(project)
        assert registry is not None
        registry[function_addr] = state
    state.bind_source(revision, body_digest)
    lifecycle.bind(state, function_addr)
