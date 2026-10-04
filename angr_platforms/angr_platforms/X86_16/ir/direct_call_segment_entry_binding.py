"""Bind one direct-call segment-entry candidate to its registered IR lineage.

Layer: IR.
Responsibility: enforce in-process object identity between the raw IR artifact
a ``DirectCallSegmentEntryCandidate8616`` proves, the artifact registered on
the candidate's own project, and the exact IR artifact its Alias
``SegmentRestoreSource`` was built from. Consumes only the project-owned raw
IR registry and the typed source owner field. Never publishes IR, never runs
Alias, and never treats equal content, matching addresses, or serialized
diagnostics as lineage.
"""

from __future__ import annotations

from enum import StrEnum

from .core import IRFunctionArtifact
from .function_ir_registry import (
    FunctionIRArtifactFailure8616,
    FunctionIRArtifactVerdict8616,
    registered_function_ir_artifact_8616,
)
from .segment_state_transfer import SegmentRestoreSource

__all__ = [
    "DirectCallSegmentEntryBindingFailure8616",
    "segment_entry_lineage_refusal_8616",
]


class DirectCallSegmentEntryBindingFailure8616(StrEnum):
    """Typed reason a candidate's IR/Alias lineage cannot be bound."""

    IR_NOT_REGISTERED = "ir_not_registered"
    IR_REGISTRY_REFUSED = "ir_registry_refused"
    IR_NOT_PROJECT_OWNED = "ir_not_project_owned"
    ALIAS_SOURCE_UNBOUND = "alias_source_unbound"
    ALIAS_SOURCE_FOREIGN = "alias_source_foreign"


def segment_entry_lineage_refusal_8616(
    project: object,
    artifact: IRFunctionArtifact,
    source: SegmentRestoreSource,
) -> DirectCallSegmentEntryBindingFailure8616 | None:
    """Require the proven artifact and its Alias source to share one object.

    The project-owned registry is the sole authority for raw IR identity: its
    registered object must be the artifact under proof, not an equal-content
    one, and the Alias source must name that identical object as its owner.
    A malformed project registry raises the registry contract's own
    ``TypeError``; an absent or refused registration refuses without creating
    registry state.
    """
    resolution = registered_function_ir_artifact_8616(project, artifact.function_addr)
    if resolution.verdict is not FunctionIRArtifactVerdict8616.PROVEN:
        if resolution.failure is FunctionIRArtifactFailure8616.NOT_REGISTERED:
            return DirectCallSegmentEntryBindingFailure8616.IR_NOT_REGISTERED
        return DirectCallSegmentEntryBindingFailure8616.IR_REGISTRY_REFUSED
    if resolution.artifact is not artifact:
        return DirectCallSegmentEntryBindingFailure8616.IR_NOT_PROJECT_OWNED
    owner = source.source_artifact
    if owner is None:
        return DirectCallSegmentEntryBindingFailure8616.ALIAS_SOURCE_UNBOUND
    if owner is not resolution.artifact:
        return DirectCallSegmentEntryBindingFailure8616.ALIAS_SOURCE_FOREIGN
    return None
