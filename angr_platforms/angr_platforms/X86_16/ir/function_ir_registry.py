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

from .core import IRFunctionArtifact

__all__ = [
    "FunctionIRArtifactFailure8616",
    "FunctionIRArtifactResolution8616",
    "FunctionIRArtifactVerdict8616",
    "publish_function_ir_artifact_8616",
    "registered_function_ir_artifact_8616",
]


class FunctionIRArtifactVerdict8616(StrEnum):
    """Typed result of one exact raw-IR registry operation."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class FunctionIRArtifactFailure8616(StrEnum):
    """Reason one complete raw function artifact is unavailable."""

    NOT_REGISTERED = "not_registered"
    ARTIFACT_REFUSED = "artifact_refused"
    ARTIFACT_CONFLICT = "artifact_conflict"


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
    return FunctionIRArtifactResolution8616(
        function_addr,
        FunctionIRArtifactVerdict8616.PROVEN,
        artifact,
        None,
    )


def publish_function_ir_artifact_8616(
    project: object,
    artifact: IRFunctionArtifact,
) -> FunctionIRArtifactResolution8616:
    """Publish one complete raw artifact, refusing address conflicts."""
    function_addr = artifact.function_addr
    if function_addr < 0 or artifact.refusals:
        return FunctionIRArtifactResolution8616(
            function_addr,
            FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionIRArtifactFailure8616.ARTIFACT_REFUSED,
        )
    registry = _registry_8616(project)
    existing = registry.get(function_addr)
    if existing is not None and existing != artifact:
        return FunctionIRArtifactResolution8616(
            function_addr,
            FunctionIRArtifactVerdict8616.UNKNOWN_REFUSE,
            None,
            FunctionIRArtifactFailure8616.ARTIFACT_CONFLICT,
        )
    registry[function_addr] = artifact
    return FunctionIRArtifactResolution8616(
        function_addr,
        FunctionIRArtifactVerdict8616.PROVEN,
        artifact,
        None,
    )
