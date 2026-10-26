"""Retain exact raw function IR artifacts for downstream IR consumers.

Layer: IR.
Responsibility: publish and resolve one immutable binary-derived IR artifact per
function address without rebuilding VEX, SSA, Alias, or semantic projections.

Owns typed Value, Address, Condition, instruction facts, and lossless
normalization. Do not perform alias-state ownership, widening,
lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from .function_artifact import IRFunctionArtifact
from .function_lifecycle import (
    FunctionStageFailure8616,
    bind_function_lifecycle_8616,
    bind_function_lifecycle_source_8616,
    observe_function_source_refusal_8616,
)
from .function_readiness_contracts import (
    FunctionSourceBinding8616,
    FunctionSourceBindingProvenance8616,
    FunctionSourceRevision8616,
    function_artifact_body_digest_8616,
    function_build_attestation_8616,
    observed_function_artifact_source_revision_8616,
    requires_function_source_observation_8616,
)

__all__ = [
    "FunctionIRArtifactFailure8616",
    "FunctionIRArtifactResolution8616",
    "FunctionIRArtifactVerdict8616",
    "publish_function_ir_artifact_8616",
    "registered_function_ir_artifact_8616",
]

_IR_ARTIFACT_PRODUCER_8616 = "x86_16_vex_ir"


class FunctionIRArtifactVerdict8616(StrEnum):
    """Typed result of one exact raw-IR registry operation."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class FunctionIRArtifactFailure8616(StrEnum):
    """Reason one complete raw function artifact is unavailable."""

    NOT_REGISTERED = "not_registered"
    ARTIFACT_REFUSED = "artifact_refused"
    ARTIFACT_CONFLICT = "artifact_conflict"
    SOURCE_REVISION_CHANGED = "source_revision_changed"
    SOURCE_REVISION_CONFLICT = "source_revision_conflict"
    SOURCE_UNAVAILABLE = "source_unavailable"


@dataclass(frozen=True, slots=True)
class FunctionIRArtifactResolution8616:
    """One exact raw artifact or a typed registry refusal."""

    function_addr: int
    verdict: FunctionIRArtifactVerdict8616
    artifact: IRFunctionArtifact | None
    failure: FunctionIRArtifactFailure8616 | None


class _FunctionIRRegistrySurface8616(Protocol):
    """Project-owned immutable raw-IR registry extension."""

    _inertia_function_ir_artifacts_8616: dict[int, IRFunctionArtifact]
    _inertia_function_ir_source_bindings_8616: dict[int, FunctionSourceBinding8616]


def _existing_registry_8616(
    project: object,
) -> dict[int, IRFunctionArtifact] | None:
    """Return the validated project-owned registry without creating it.

    Resolving must not mutate the project: an absent attribute yields ``None``
    so the caller can refuse, while a malformed attribute stays loud.
    """
    surface = cast(_FunctionIRRegistrySurface8616, project)
    try:
        registry = surface._inertia_function_ir_artifacts_8616
    except AttributeError:
        return None
    if not isinstance(registry, dict):
        raise TypeError("function IR artifact registry must be a dict")
    return registry


def _registry_8616(project: object) -> dict[int, IRFunctionArtifact]:
    """Return the validated registry, creating it for publication only."""
    surface = cast(_FunctionIRRegistrySurface8616, project)
    registry = _existing_registry_8616(project)
    if registry is None:
        registry = {}
        surface._inertia_function_ir_artifacts_8616 = registry
    return registry


def _existing_source_bindings_8616(
    project: object,
) -> dict[int, FunctionSourceBinding8616] | None:
    """Return the validated binding ledger without creating it on lookup."""
    surface = cast(_FunctionIRRegistrySurface8616, project)
    try:
        bindings = surface._inertia_function_ir_source_bindings_8616
    except AttributeError:
        return None
    if not isinstance(bindings, dict):
        raise TypeError("function IR source binding ledger must be a dict")
    return bindings


def _source_bindings_8616(project: object) -> dict[int, FunctionSourceBinding8616]:
    """Return the validated binding ledger, creating it for publication only."""
    surface = cast(_FunctionIRRegistrySurface8616, project)
    bindings = _existing_source_bindings_8616(project)
    if bindings is None:
        bindings = {}
        surface._inertia_function_ir_source_bindings_8616 = bindings
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
    failure: FunctionIRArtifactFailure8616,
) -> FunctionIRArtifactResolution8616:
    """Build one typed refusal without leaking the stale artifact."""
    return FunctionIRArtifactResolution8616(
        function_addr,
        FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE,
        None,
        failure,
    )


def registered_function_ir_artifact_8616(
    project: object,
    function_addr: int,
) -> FunctionIRArtifactResolution8616:
    """Return one exact registered raw artifact without creating state."""
    registry = _existing_registry_8616(project)
    artifact = registry.get(function_addr) if registry is not None else None
    if artifact is None:
        return FunctionIRArtifactResolution8616(
            function_addr,
            FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionIRArtifactFailure8616.NOT_REGISTERED,
        )
    if (
        not isinstance(artifact, IRFunctionArtifact)
        or artifact.function_addr != function_addr
        or artifact.refusals
    ):
        return FunctionIRArtifactResolution8616(
            function_addr,
            FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionIRArtifactFailure8616.ARTIFACT_CONFLICT,
        )
    bindings = _existing_source_bindings_8616(project)
    binding = bindings.get(function_addr) if bindings is not None else None
    observed = observed_function_artifact_source_revision_8616(project, function_addr, artifact)
    if binding is None and (
        observed is not None or requires_function_source_observation_8616(project)
    ):
        source_failure = (
            FunctionIRArtifactFailure8616.SOURCE_UNAVAILABLE
            if observed is None
            else FunctionIRArtifactFailure8616.SOURCE_REVISION_CONFLICT
        )
        observe_function_source_refusal_8616(
            project, function_addr,
            FunctionStageFailure8616.SOURCE_UNAVAILABLE if observed is None
            else FunctionStageFailure8616.SOURCE_REVISION_CONFLICT,
        )
        return _refuse_8616(function_addr, source_failure)
    if binding is not None:
        if observed is None:
            observe_function_source_refusal_8616(
                project, function_addr, FunctionStageFailure8616.SOURCE_UNAVAILABLE,
            )
            return _refuse_8616(
                function_addr,
                FunctionIRArtifactFailure8616.SOURCE_UNAVAILABLE,
            )
        if _binding_stale_8616(binding, observed):
            observe_function_source_refusal_8616(
                project, function_addr, FunctionStageFailure8616.SOURCE_REVISION_CHANGED,
            )
            return _refuse_8616(
                function_addr,
                FunctionIRArtifactFailure8616.SOURCE_REVISION_CHANGED,
            )
    return FunctionIRArtifactResolution8616(
        function_addr,
        FunctionIRArtifactVerdict8616.PROVEN,
        artifact,
        None,
    )


def _bind_accepted_ir_lifecycle_8616(
    project: object, artifact: IRFunctionArtifact, revision: FunctionSourceRevision8616 | None,
) -> None:
    """Attach accepted raw IR to canonical state and revoke older generations."""
    digest = function_artifact_body_digest_8616(artifact)
    if digest is None:
        bind_function_lifecycle_8616(project, artifact.function_addr, artifact.lifecycle)
    else:
        bind_function_lifecycle_source_8616(
            project, artifact.function_addr, artifact.lifecycle, revision, digest,
        )


def publish_function_ir_artifact_8616(
    project: object,
    artifact: IRFunctionArtifact,
) -> FunctionIRArtifactResolution8616:
    """Publish one complete raw artifact bound to its observed source.

    A builder-attested ``source_revision`` must match the currently observed
    generation; attesting an old generation onto current bytes refuses as a
    ``SOURCE_REVISION_CONFLICT``. Stored artifacts whose recorded binding is
    provably stale may be superseded only by different content bound to the
    current generation; republishing the identical stale artifact refuses.
    """
    function_addr = artifact.function_addr
    if function_addr < 0 or artifact.refusals:
        return _refuse_8616(
            function_addr,
            FunctionIRArtifactFailure8616.ARTIFACT_REFUSED,
        )
    observed = observed_function_artifact_source_revision_8616(project, function_addr, artifact)
    if observed is None and requires_function_source_observation_8616(project):
        return _refuse_8616(
            function_addr,
            FunctionIRArtifactFailure8616.SOURCE_UNAVAILABLE,
        )
    attested = artifact.source_revision
    if observed is not None:
        body_digest = function_artifact_body_digest_8616(artifact)
        record = (
            None
            if body_digest is None
            else function_build_attestation_8616(project, function_addr, body_digest)
        )
        # Only an owned build attestation proves this exact body was lifted
        # from the current generation; a bare or copied revision value, or
        # an unstamped foreign body, mints nothing.
        if (
            record is None
            or record.revision != observed
            or (attested is not None and attested != observed)
        ):
            return _refuse_8616(
                function_addr,
                FunctionIRArtifactFailure8616.SOURCE_REVISION_CONFLICT,
            )
    registry = _registry_8616(project)
    bindings = _source_bindings_8616(project)
    existing = registry.get(function_addr)
    if existing is not None:
        stale = _binding_stale_8616(bindings.get(function_addr), observed)
        if existing == artifact:
            if stale:
                return _refuse_8616(
                    function_addr,
                    FunctionIRArtifactFailure8616.SOURCE_REVISION_CONFLICT,
                )
            registry[function_addr] = artifact
            _bind_accepted_ir_lifecycle_8616(project, artifact, observed)
            return FunctionIRArtifactResolution8616(
                function_addr,
                FunctionIRArtifactVerdict8616.PROVEN,
                artifact,
                None,
            )
        if not stale:
            return _refuse_8616(
                function_addr,
                FunctionIRArtifactFailure8616.ARTIFACT_CONFLICT,
            )
    _bind_accepted_ir_lifecycle_8616(project, artifact, observed)
    registry[function_addr] = artifact
    if observed is not None:
        provenance = (
            FunctionSourceBindingProvenance8616.ATTESTED
            if attested is not None
            else FunctionSourceBindingProvenance8616.OBSERVED
        )
        bindings[function_addr] = FunctionSourceBinding8616(
            revision=observed,
            provenance=provenance,
            producer=_IR_ARTIFACT_PRODUCER_8616,
        )
    return FunctionIRArtifactResolution8616(
        function_addr,
        FunctionIRArtifactVerdict8616.PROVEN,
        artifact,
        None,
    )
