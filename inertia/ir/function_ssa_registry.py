"""Cache exact function SSA artifacts on one analysis project.

Layer: IR.
Responsibility: build and retain one typed ``SSAFunctionArtifact`` for an exact
function boundary so later Alias and Types/Lowering consumers share the same
program-owned dataflow truth.
This module does not classify interfaces or mutate codegen.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol, cast

from .function_artifact import IRFunctionArtifact
from .function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from .function_lifecycle import (
    FunctionStageFailure8616,
    bind_function_lifecycle_8616,
    observe_function_source_refusal_8616,
)
from .function_readiness_contracts import (
    FunctionSourceBinding8616,
    FunctionSourceBindingProvenance8616,
    FunctionSourceRevision8616,
    function_artifact_body_digest_8616,
    function_build_attestation_8616,
    function_source_boundary_8616,
    observed_function_artifact_source_revision_8616,
    observed_function_source_revision_8616,
    record_function_build_attestation_8616,
    requires_function_source_observation_8616,
)
from .ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from .vex_import import build_x86_16_ir_function_artifact

__all__ = [
    "FunctionSSAArtifactFailure8616",
    "FunctionSSAArtifactResolution8616",
    "FunctionSSAArtifactStage8616",
    "FunctionSSAArtifactVerdict8616",
    "function_boundary_at_address_8616",
    "function_ssa_artifact_at_address_8616",
    "function_ssa_artifact_for_boundary_8616",
    "publish_function_ssa_artifact_8616",
    "registered_function_ssa_artifact_8616",
]


class FunctionSSAArtifactVerdict8616(StrEnum):
    """Typed outcome of one program-owned SSA lookup."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class FunctionSSAArtifactStage8616(StrEnum):
    """Earliest pipeline stage whose facts are present in one SSA artifact."""

    IR = "ir"
    SEMANTIC = "semantic"


class FunctionSSAArtifactFailure8616(StrEnum):
    """Stable reasons why one exact caller SSA artifact is unavailable."""

    FUNCTION_NOT_FOUND = "function_not_found"
    FUNCTION_BOUNDARY_CONFLICT = "function_boundary_conflict"
    IR_BUILD_FAILED = "ir_build_failed"
    IR_BUILD_REFUSED = "ir_build_refused"
    SEMANTIC_BUILD_FAILED = "semantic_build_failed"
    ARTIFACT_NOT_REGISTERED = "artifact_not_registered"
    ARTIFACT_CONFLICT = "artifact_conflict"
    SOURCE_REVISION_CHANGED = "source_revision_changed"
    SOURCE_REVISION_CONFLICT = "source_revision_conflict"
    SOURCE_UNAVAILABLE = "source_unavailable"


_SSA_ARTIFACT_PRODUCER_8616 = "x86_16_function_ssa"


@dataclass(frozen=True, slots=True)
class FunctionSSAArtifactResolution8616:
    """One exact function SSA artifact or a typed refusal."""

    function_addr: int
    verdict: FunctionSSAArtifactVerdict8616
    artifact: SSAFunctionArtifact | None
    failure: FunctionSSAArtifactFailure8616 | None
    stage: FunctionSSAArtifactStage8616 | None


class _FunctionManager8616(Protocol):
    """Third-party function-manager surface used for exact lookup."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return an existing function without inventing a boundary."""
        ...


class _FunctionBoundary8616(Protocol):
    """Third-party function boundary with one canonical entry address."""

    addr: object


class _KnowledgeBase8616(Protocol):
    """Third-party knowledge-base surface used by this IR owner."""

    functions: _FunctionManager8616


class _ProjectSSARegistrySurface8616(Protocol):
    """angr project plus the owned typed SSA registry extension."""

    kb: _KnowledgeBase8616
    _inertia_caller_function_ranges_8616: tuple[tuple[int, int], ...]
    _inertia_function_ssa_artifacts_8616: dict[int, SSAFunctionArtifact]
    _inertia_function_ssa_stages_8616: dict[int, FunctionSSAArtifactStage8616]
    _inertia_function_ssa_source_bindings_8616: dict[int, FunctionSourceBinding8616]


def _registry_8616(project: object) -> dict[int, SSAFunctionArtifact]:
    """Return the validated project-owned SSA artifact registry."""
    surface = cast(_ProjectSSARegistrySurface8616, project)
    try:
        registry = surface._inertia_function_ssa_artifacts_8616
    except AttributeError:
        registry = {}
        surface._inertia_function_ssa_artifacts_8616 = registry
    if not isinstance(registry, dict):
        raise TypeError("function SSA artifact registry must be a dict")
    return registry


def _stage_registry_8616(
    project: object,
) -> dict[int, FunctionSSAArtifactStage8616]:
    """Return the project-owned readiness stage for every cached SSA artifact."""
    surface = cast(_ProjectSSARegistrySurface8616, project)
    try:
        registry = surface._inertia_function_ssa_stages_8616
    except AttributeError:
        registry = {}
        surface._inertia_function_ssa_stages_8616 = registry
    if not isinstance(registry, dict):
        raise TypeError("function SSA stage registry must be a dict")
    return registry


def _source_bindings_8616(project: object) -> dict[int, FunctionSourceBinding8616]:
    """Return the project-owned SSA source-binding ledger, creating it if absent."""
    surface = cast(_ProjectSSARegistrySurface8616, project)
    try:
        bindings = surface._inertia_function_ssa_source_bindings_8616
    except AttributeError:
        bindings = {}
        surface._inertia_function_ssa_source_bindings_8616 = bindings
    if not isinstance(bindings, dict):
        raise TypeError("function SSA source binding ledger must be a dict")
    return bindings


def _binding_stale_8616(
    binding: FunctionSourceBinding8616 | None,
    observed: FunctionSourceRevision8616 | None,
) -> bool:
    """Return whether a recorded binding is provably older than current source."""
    return (
        binding is not None
        and observed is not None
        and binding.revision != observed
    )


def _refuse_8616(
    function_addr: int,
    failure: FunctionSSAArtifactFailure8616,
    stage: FunctionSSAArtifactStage8616 | None = None,
) -> FunctionSSAArtifactResolution8616:
    """Build one typed refusal without leaking the stale artifact."""
    return FunctionSSAArtifactResolution8616(
        function_addr,
        FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
        None,
        failure,
        stage,
    )


def _proven_8616(
    function_addr: int,
    artifact: SSAFunctionArtifact,
    stage: FunctionSSAArtifactStage8616,
) -> FunctionSSAArtifactResolution8616:
    """Build one proven resolution for a live registered artifact."""
    return FunctionSSAArtifactResolution8616(
        function_addr,
        FunctionSSAArtifactVerdict8616.PROVEN,
        artifact,
        None,
        stage,
    )


def _verify_ssa_attestation_8616(
    project: object,
    function_addr: int,
    artifact: SSAFunctionArtifact,
    observed: FunctionSourceRevision8616 | None,
) -> bool:
    """Authenticate one SSA body by its own derivation record.

    A copied revision value or an authentic parent digest is never enough:
    this exact body's own build attestation must exist in this project's
    ledger, bound to the live generation, and its declared parent digest
    must be one of the exact consumed inputs recorded at derivation time.
    """
    if observed is None:
        return False
    attested = artifact.source_revision
    if attested is not None and attested != observed:
        return False
    body_digest = function_artifact_body_digest_8616(artifact)
    if body_digest is None:
        return False
    direct = function_build_attestation_8616(project, function_addr, body_digest)
    if direct is None or direct.revision != observed:
        return False
    parent = artifact.parent_digest
    if parent is None:
        return True
    if parent not in direct.inputs:
        return False
    lineage = function_build_attestation_8616(project, function_addr, parent)
    return lineage is not None and lineage.revision == observed


def _record_source_binding_8616(
    bindings: dict[int, FunctionSourceBinding8616],
    function_addr: int,
    observed: FunctionSourceRevision8616 | None,
    artifact: SSAFunctionArtifact,
) -> None:
    """Bind a published SSA artifact to its observed or attested generation."""
    if observed is None:
        return
    bindings[function_addr] = FunctionSourceBinding8616(
        revision=observed,
        provenance=(
            FunctionSourceBindingProvenance8616.ATTESTED
            if artifact.source_revision is not None
            else FunctionSourceBindingProvenance8616.OBSERVED
        ),
        producer=_SSA_ARTIFACT_PRODUCER_8616,
    )


def function_boundary_at_address_8616(
    project: object,
    function_addr: int,
) -> object | None:
    """Return an exact CFG function or an independently framed range boundary."""
    return function_source_boundary_8616(project, function_addr)


def registered_function_ssa_artifact_8616(
    project: object,
    function_addr: int,
) -> FunctionSSAArtifactResolution8616:
    """Return one registered artifact and its readiness without rebuilding it.

    A registered artifact whose recorded source binding is provably stale
    refuses with ``SOURCE_REVISION_CHANGED`` and never leaks the stale
    artifact to consumers.
    """
    cached = _registry_8616(project).get(function_addr)
    if cached is None:
        return _refuse_8616(
            function_addr,
            FunctionSSAArtifactFailure8616.ARTIFACT_NOT_REGISTERED,
        )
    if not isinstance(cached, SSAFunctionArtifact) or cached.function_addr != function_addr:
        return _refuse_8616(
            function_addr,
            FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT,
        )
    stages = _stage_registry_8616(project)
    stage = stages.get(function_addr, FunctionSSAArtifactStage8616.IR)
    if not isinstance(stage, FunctionSSAArtifactStage8616):
        return _refuse_8616(
            function_addr,
            FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT,
        )
    stages[function_addr] = stage
    binding = _source_bindings_8616(project).get(function_addr)
    observed = observed_function_artifact_source_revision_8616(project, function_addr, cached)
    if binding is None and (
        observed is not None or requires_function_source_observation_8616(project)
    ):
        source_failure = (
            FunctionSSAArtifactFailure8616.SOURCE_UNAVAILABLE
            if observed is None
            else FunctionSSAArtifactFailure8616.SOURCE_REVISION_CONFLICT
        )
        observe_function_source_refusal_8616(
            project, function_addr,
            FunctionStageFailure8616.SOURCE_UNAVAILABLE if observed is None
            else FunctionStageFailure8616.SOURCE_REVISION_CONFLICT,
        )
        return _refuse_8616(function_addr, source_failure, stage)
    if binding is not None:
        if observed is None:
            observe_function_source_refusal_8616(
                project, function_addr, FunctionStageFailure8616.SOURCE_UNAVAILABLE,
            )
            return _refuse_8616(
                function_addr,
                FunctionSSAArtifactFailure8616.SOURCE_UNAVAILABLE,
                stage,
            )
        if _binding_stale_8616(binding, observed):
            observe_function_source_refusal_8616(
                project, function_addr, FunctionStageFailure8616.SOURCE_REVISION_CHANGED,
            )
            return _refuse_8616(
                function_addr,
                FunctionSSAArtifactFailure8616.SOURCE_REVISION_CHANGED,
                stage,
            )
    return _proven_8616(function_addr, cached, stage)


def _publication_source_failure_8616(
    project: object,
    function_addr: int,
    artifact: SSAFunctionArtifact,
    observed: FunctionSourceRevision8616 | None,
) -> FunctionSSAArtifactFailure8616 | None:
    """Require native source and authenticate the exact published SSA body."""
    if observed is None:
        if requires_function_source_observation_8616(project):
            return FunctionSSAArtifactFailure8616.SOURCE_UNAVAILABLE
        return None
    if not _verify_ssa_attestation_8616(project, function_addr, artifact, observed):
        return FunctionSSAArtifactFailure8616.SOURCE_REVISION_CONFLICT
    return None


def _published_ssa_8616(
    project: object,
    function_addr: int,
    artifact: SSAFunctionArtifact,
    stage: FunctionSSAArtifactStage8616,
) -> FunctionSSAArtifactResolution8616:
    """Return accepted SSA attached to the same canonical function lifecycle."""
    bind_function_lifecycle_8616(project, function_addr, artifact.lifecycle)
    return _proven_8616(function_addr, artifact, stage)


def publish_function_ssa_artifact_8616(
    project: object,
    artifact: SSAFunctionArtifact,
    stage: FunctionSSAArtifactStage8616,
) -> FunctionSSAArtifactResolution8616:
    """Publish one exact artifact bound to its observed source generation.

    Preserves the IR-to-Semantics upgrade discipline for live registrations.
    A stored artifact whose binding is provably stale is dead evidence: it may
    be superseded only by different content bound to the current generation,
    and republishing the identical stale artifact refuses with
    ``SOURCE_REVISION_CONFLICT``.
    """
    function_addr = artifact.function_addr
    observed = observed_function_artifact_source_revision_8616(project, function_addr, artifact)
    source_failure = _publication_source_failure_8616(
        project, function_addr, artifact, observed
    )
    if source_failure is not None:
        return _refuse_8616(function_addr, source_failure, stage)
    artifacts = _registry_8616(project)
    stages = _stage_registry_8616(project)
    bindings = _source_bindings_8616(project)
    stored = artifacts.get(function_addr)
    if stored is not None and (
        not isinstance(stored, SSAFunctionArtifact) or stored.function_addr != function_addr
    ):
        return _refuse_8616(
            function_addr,
            FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT,
            stages.get(function_addr),
        )
    if stored is not None and _binding_stale_8616(bindings.get(function_addr), observed):
        if stored == artifact:
            return _refuse_8616(
                function_addr,
                FunctionSSAArtifactFailure8616.SOURCE_REVISION_CONFLICT,
                stages.get(function_addr),
            )
        artifacts[function_addr] = artifact
        stages[function_addr] = stage
        _record_source_binding_8616(bindings, function_addr, observed, artifact)
        return _published_ssa_8616(project, function_addr, artifact, stage)
    if stored is None:
        artifacts[function_addr] = artifact
        stages[function_addr] = stage
        _record_source_binding_8616(bindings, function_addr, observed, artifact)
        return _published_ssa_8616(project, function_addr, artifact, stage)
    current_stage = stages.get(function_addr, FunctionSSAArtifactStage8616.IR)
    if current_stage is FunctionSSAArtifactStage8616.SEMANTIC:
        if stage is FunctionSSAArtifactStage8616.IR or stored == artifact:
            return _published_ssa_8616(project, function_addr, stored, current_stage)
        return _refuse_8616(
            function_addr,
            FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT,
            current_stage,
        )
    if stage is FunctionSSAArtifactStage8616.IR:
        if stored == artifact:
            return _published_ssa_8616(project, function_addr, stored, current_stage)
        return _refuse_8616(
            function_addr,
            FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT,
            current_stage,
        )
    artifacts[function_addr] = artifact
    stages[function_addr] = stage
    _record_source_binding_8616(bindings, function_addr, observed, artifact)
    return _published_ssa_8616(project, function_addr, artifact, stage)


def function_ssa_artifact_at_address_8616(
    project: object,
    function_addr: int,
) -> FunctionSSAArtifactResolution8616:
    """Build or return one exact caller SSA artifact without guessing gaps."""
    registered = registered_function_ssa_artifact_8616(project, function_addr)
    if registered.verdict is FunctionSSAArtifactVerdict8616.PROVEN:
        return registered
    if registered.failure is FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT:
        return registered
    function = function_boundary_at_address_8616(project, function_addr)
    if function is None:
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.FUNCTION_NOT_FOUND,
            None,
        )
    return function_ssa_artifact_for_boundary_8616(
        project,
        function_addr,
        function,
    )


def _attest_ssa_derivation_8616(
    project: object,
    function_addr: int,
    function_ssa: SSAFunctionArtifact,
    ir_artifact: object,
    revision: FunctionSourceRevision8616 | None,
) -> None:
    """Attest the actual derivation: this exact SSA body consumed this exact
    IR body under the same generation, so neither a copied revision nor an
    authentic-but-unrelated parent digest can confer proof later."""
    if revision is None:
        return
    ssa_body_digest = function_artifact_body_digest_8616(function_ssa)
    ir_body_digest = function_artifact_body_digest_8616(ir_artifact)
    if ssa_body_digest is not None:
        record_function_build_attestation_8616(
            project,
            function_addr,
            ssa_body_digest,
            revision,
            _SSA_ARTIFACT_PRODUCER_8616,
            inputs=() if ir_body_digest is None else (ir_body_digest,),
        )


def _canonical_registered_ir_artifact_8616(
    project: object,
    function_addr: int,
    ir_artifact: IRFunctionArtifact,
) -> IRFunctionArtifact:
    """Reuse the registered IR object when the rebuild is content-identical.

    Republishing an equal but distinct object must supersede the stored one so
    identity-checking consumers observe revocation. Re-deriving the same IR
    during SSA resolution is not a republication decision, though: adopting the
    canonical registered object keeps registry identity stable while retaining
    the latest-wins store for genuine republishers.
    """
    registered_ir = registered_function_ir_artifact_8616(project, function_addr)
    artifact = registered_ir.artifact
    if (
        registered_ir.verdict is FunctionIRArtifactVerdict8616.PROVEN
        and artifact is not None
        and artifact == ir_artifact
    ):
        return artifact
    return ir_artifact


def function_ssa_artifact_for_boundary_8616(
    project: object,
    function_addr: int,
    function: object,
) -> FunctionSSAArtifactResolution8616:
    """Build or return one exact SSA artifact from a supplied boundary."""
    try:
        boundary_addr = cast(_FunctionBoundary8616, function).addr
    except AttributeError:
        boundary_addr = None
    if boundary_addr != function_addr:
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.FUNCTION_BOUNDARY_CONFLICT,
            None,
        )
    registered = registered_function_ssa_artifact_8616(project, function_addr)
    if (
        registered.verdict is FunctionSSAArtifactVerdict8616.PROVEN
        and registered.artifact is not None
        and registered.artifact.source_revision == observed_function_source_revision_8616(
            project, function_addr, boundary=function,
        )
    ):
        return registered
    if registered.failure is FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT:
        return registered
    try:
        ir_artifact = build_x86_16_ir_function_artifact(project, function)
    except (AttributeError, KeyError, TypeError, ValueError):
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.IR_BUILD_FAILED,
            None,
        )
    if ir_artifact.refusals:
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.IR_BUILD_REFUSED,
            None,
        )
    # Bind builder output to builder input: the boundary observed immediately
    # after import is the exact generation this artifact was lifted from.
    revision = observed_function_source_revision_8616(
        project,
        function_addr,
        boundary=function,
    )
    if revision is not None:
        ir_artifact = replace(ir_artifact, source_revision=revision)
    ir_artifact = _canonical_registered_ir_artifact_8616(project, function_addr, ir_artifact)
    try:
        function_ssa = build_x86_16_function_ssa(ir_artifact)
    except (AttributeError, KeyError, TypeError, ValueError):
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.IR_BUILD_FAILED,
            None,
        )
    _attest_ssa_derivation_8616(
        project,
        function_addr,
        function_ssa,
        ir_artifact,
        revision,
    )
    ir_publication = publish_function_ir_artifact_8616(project, ir_artifact)
    if ir_publication.verdict is not FunctionIRArtifactVerdict8616.PROVEN:
        return FunctionSSAArtifactResolution8616(
            function_addr,
            FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionSSAArtifactFailure8616.ARTIFACT_CONFLICT,
            None,
        )
    return publish_function_ssa_artifact_8616(
        project,
        function_ssa,
        FunctionSSAArtifactStage8616.IR,
    )
