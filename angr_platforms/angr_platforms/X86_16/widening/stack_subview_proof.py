"""Resolve structured stack views against the current Widening artifact.

Layer: Widening.
Responsibility: bind one third-party structured-C stack variable to the unique
Alias-derived stack-object candidate that owns its exact byte range. This
module proves storage identity only; C expression materialization remains in
``stack_subview_projection``.
Consumes alias-proven storage identity through the typed object artifact.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.

Missing syntax is not a candidate. A range covered by a refused, ambiguous,
stale, incomplete, or cross-function artifact is never accepted. Do not infer
ownership from names, rendered C, assembly text, or numeric proximity alone.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..alias.stack_coordinate_projection import (
    project_stack_offset_to_machine_bp_8616,
)
from ..alias.stack_memory_ssa_contracts import StackMemorySSAAliasArtifact8616
from ..analysis.stack_frame_ir import FrameAccessArtifact
from ..ir.core import IRAddress, MemSpace
from ..ir.logical_memory_contracts import IRMemoryAccessKind8616
from ..pipeline.errors import PipelineHardError
from .stack_memory_objects_contracts import (
    StackMemoryObjectWideningArtifact8616,
    StackMemoryObjectWideningCandidate8616,
)
from .stack_subview_coordinates import published_stack_variable_range_8616, stack_variable_range_8616


class StackObjectViewResolutionKind8616(Enum):
    """Typed outcome of resolving one structured stack variable."""

    NOT_CANDIDATE = "not_candidate"
    ACCEPTED = "accepted"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class StackObjectViewProof8616:
    """One Alias-width view and its unique materialized object owner."""

    view: structured_c.CVariable
    owner: structured_c.CVariable
    source: StackMemoryObjectWideningCandidate8616
    relative_offset: int
    view_size: int
    owner_size: int
    syntax_size: int

    @property
    def has_widened_syntax(self) -> bool:
        """Return whether structured C widened the proven memory-read width."""
        return self.syntax_size > self.view_size


@dataclass(frozen=True, slots=True)
class StackObjectViewResolution8616:
    """Accepted proof, explicit refusal, or unrelated structured variable."""

    kind: StackObjectViewResolutionKind8616
    proof: StackObjectViewProof8616 | None = None
    reason: str | None = None


class _CodegenBoundary8616(Protocol):
    """Owned proof artifacts carried on the dynamic angr codegen boundary."""

    _inertia_stack_memory_ssa_alias_artifact: StackMemorySSAAliasArtifact8616
    _inertia_stack_memory_object_widening_artifact: StackMemoryObjectWideningArtifact8616
    _inertia_vex_ir_frame: FrameAccessArtifact


class _CFunctionBoundary8616(Protocol):
    """Minimal third-party structured function surface used for projection."""

    addr: int
    variables_in_use: dict[object, object]


def current_stack_object_widening_8616(
    codegen: object,
) -> StackMemoryObjectWideningArtifact8616 | None:
    """Return the current complete object proof or reject a layer bypass."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        source = boundary._inertia_stack_memory_ssa_alias_artifact
    except AttributeError:
        source = None
    try:
        artifact = boundary._inertia_stack_memory_object_widening_artifact
    except AttributeError:
        artifact = None
    if source is None and artifact is None:
        return None
    if (
        not isinstance(source, StackMemorySSAAliasArtifact8616)
        or not isinstance(artifact, StackMemoryObjectWideningArtifact8616)
        or artifact.source_alias is not source
        or not artifact.complete
    ):
        raise PipelineHardError(
            "stack subview projection does not consume the current complete Widening artifact",
            layer="widening",
        )
    return artifact


def _address_range_8616(address: IRAddress) -> tuple[int, int] | None:
    """Return one exact SS:BP range from a Widening address."""
    if address.space is not MemSpace.SS or address.base != ("bp",) or address.size <= 0:
        return None
    return address.offset, address.size


def _owner_cvariable_8616(
    codegen: object,
    cfunc: _CFunctionBoundary8616,
    source_alias: StackMemorySSAAliasArtifact8616,
    candidate: StackMemoryObjectWideningCandidate8616,
    function_addr: int,
) -> structured_c.CVariable | None:
    """Return the unique C variable that represents one proven owner range."""
    owner_range = _address_range_8616(candidate.address)
    if owner_range is None:
        return None
    try:
        frame = cast(_CodegenBoundary8616, codegen)._inertia_vex_ir_frame
    except AttributeError:
        frame = None
    owners: list[structured_c.CVariable] = []
    for variable, cvar in cfunc.variables_in_use.items():
        raw_range = stack_variable_range_8616(variable, function_addr)
        if raw_range is None or not isinstance(cvar, structured_c.CVariable):
            continue
        bound_range = published_stack_variable_range_8616(codegen, variable, function_addr)
        if bound_range is not None:
            if bound_range == owner_range:
                owners.append(cvar)
            continue
        projection = project_stack_offset_to_machine_bp_8616(
            source_alias,
            frame,
            raw_range[0],
            raw_range[1],
        )
        if projection.bp_offset is not None and (projection.bp_offset, raw_range[1]) == owner_range:
            owners.append(cvar)
    unique = {id(owner): owner for owner in owners}
    return next(iter(unique.values())) if len(unique) == 1 else None


def _resolve_exact_view_range_8616(
    codegen: object,
    function: _CFunctionBoundary8616,
    artifact: StackMemoryObjectWideningArtifact8616,
    view: structured_c.CVariable,
    view_range: tuple[int, int],
    *,
    syntax_size: int,
) -> StackObjectViewResolution8616:
    """Resolve one Alias-proven view range to its unique Widening owner."""
    matching_candidates: list[StackMemoryObjectWideningCandidate8616] = []
    for candidate in artifact.candidates:
        owner_range = _address_range_8616(candidate.address)
        covered_ranges = {
            address_range
            for address in candidate.covered_addresses
            if (address_range := _address_range_8616(address)) is not None
        }
        if owner_range != view_range and view_range in covered_ranges:
            matching_candidates.append(candidate)
    refused = any(
        view_range
        in {
            address_range
            for address in refusal.addresses
            if (address_range := _address_range_8616(address)) is not None
        }
        for refusal in artifact.refusals
    )
    if refused or len(matching_candidates) > 1:
        return StackObjectViewResolution8616(
            StackObjectViewResolutionKind8616.REFUSED,
            reason="stack byte view belongs to a refused or ambiguous object component",
        )
    if not matching_candidates:
        return StackObjectViewResolution8616(StackObjectViewResolutionKind8616.NOT_CANDIDATE)

    candidate = matching_candidates[0]
    owner_range = _address_range_8616(candidate.address)
    if owner_range is None:
        return StackObjectViewResolution8616(
            StackObjectViewResolutionKind8616.REFUSED,
            reason="stack object owner is not an exact SS:BP range",
        )
    try:
        owner = _owner_cvariable_8616(
            codegen,
            function,
            artifact.source_alias,
            candidate,
            artifact.function_addr,
        )
    except AttributeError:
        owner = None
    if owner is None:
        return StackObjectViewResolution8616(
            StackObjectViewResolutionKind8616.REFUSED,
            reason="stack object owner has no unique structured-C variable",
        )
    relative_offset = view_range[0] - owner_range[0]
    if relative_offset < 0 or relative_offset + view_range[1] > owner_range[1]:
        return StackObjectViewResolution8616(
            StackObjectViewResolutionKind8616.REFUSED,
            reason="stack byte view falls outside its accepted object owner",
        )
    return StackObjectViewResolution8616(
        StackObjectViewResolutionKind8616.ACCEPTED,
        StackObjectViewProof8616(
            view=view,
            owner=owner,
            source=candidate,
            relative_offset=relative_offset,
            view_size=view_range[1],
            owner_size=owner_range[1],
            syntax_size=syntax_size,
        ),
    )


def _validated_function_8616(
    cfunc: object,
    artifact: StackMemoryObjectWideningArtifact8616,
) -> _CFunctionBoundary8616:
    """Bind one structured function to the current Widening artifact."""
    function = cast(_CFunctionBoundary8616, cfunc)
    try:
        function_addr = function.addr
    except AttributeError as ex:
        raise PipelineHardError(
            "stack subview projection has no exact structured function identity",
            layer="widening",
        ) from ex
    if not isinstance(function_addr, int) or function_addr != artifact.function_addr:
        raise PipelineHardError(
            "stack subview projection received a Widening artifact for another function",
            layer="widening",
        )
    return function


def resolve_stack_object_view_8616(
    codegen: object,
    cfunc: object,
    artifact: StackMemoryObjectWideningArtifact8616 | None,
    view: structured_c.CVariable,
) -> StackObjectViewResolution8616:
    """Resolve one exact contained C variable through the typed object proof."""
    if artifact is None:
        return StackObjectViewResolution8616(StackObjectViewResolutionKind8616.NOT_CANDIDATE)
    function = _validated_function_8616(cfunc, artifact)
    function_addr = artifact.function_addr
    view_range = stack_variable_range_8616(view.variable, function_addr, codegen=codegen)
    if view_range is None:
        return StackObjectViewResolution8616(StackObjectViewResolutionKind8616.NOT_CANDIDATE)
    return _resolve_exact_view_range_8616(
        codegen,
        function,
        artifact,
        view,
        view_range,
        syntax_size=view_range[1],
    )


def resolve_widened_stack_object_read_8616(
    codegen: object,
    cfunc: object,
    artifact: StackMemoryObjectWideningArtifact8616 | None,
    view: structured_c.CVariable,
) -> StackObjectViewResolution8616:
    """Resolve a wider C carrier from one unique narrower logical read."""
    if artifact is None:
        return StackObjectViewResolution8616(StackObjectViewResolutionKind8616.NOT_CANDIDATE)
    function = _validated_function_8616(cfunc, artifact)
    syntax_range = stack_variable_range_8616(view.variable, artifact.function_addr, codegen=codegen)
    if syntax_range is None:
        return StackObjectViewResolution8616(StackObjectViewResolutionKind8616.NOT_CANDIDATE)
    logical_read_ranges = {
        address_range
        for identity in artifact.source_alias.logical_storage_identities
        if identity.source.kind is IRMemoryAccessKind8616.READ
        and (address_range := _address_range_8616(identity.source.address)) is not None
        and address_range[0] == syntax_range[0]
    }
    if syntax_range in logical_read_ranges:
        return (
            StackObjectViewResolution8616(
                StackObjectViewResolutionKind8616.REFUSED,
                reason="wide C carrier also has an exact logical read",
            )
            if len(logical_read_ranges) > 1
            else StackObjectViewResolution8616(StackObjectViewResolutionKind8616.NOT_CANDIDATE)
        )
    narrower_ranges = {
        address_range
        for address_range in logical_read_ranges
        if 0 < address_range[1] < syntax_range[1]
    }
    if len(narrower_ranges) != 1:
        return (
            StackObjectViewResolution8616(StackObjectViewResolutionKind8616.NOT_CANDIDATE)
            if not narrower_ranges
            else StackObjectViewResolution8616(
                StackObjectViewResolutionKind8616.REFUSED,
                reason="wide C carrier has ambiguous logical read widths",
            )
        )
    return _resolve_exact_view_range_8616(
        codegen,
        function,
        artifact,
        view,
        next(iter(narrower_ranges)),
        syntax_size=syntax_range[1],
    )


__all__ = [
    "StackObjectViewProof8616",
    "StackObjectViewResolution8616",
    "StackObjectViewResolutionKind8616",
    "current_stack_object_widening_8616",
    "resolve_stack_object_view_8616",
    "resolve_widened_stack_object_read_8616",
    "stack_variable_range_8616",
]
