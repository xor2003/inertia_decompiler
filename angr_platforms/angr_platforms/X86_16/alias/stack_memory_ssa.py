"""Project exact stack-memory SSA facts into Alias storage identities.

Layer: Alias.
Responsibility: classify versioned `SS:BP+offset` IR accesses and memory phi
nodes through the canonical Alias model while preserving typed refusals.
Owns storage identity only. Do not infer C locals or types, widen adjacent
ranges, structure control flow, rewrite generated C, or inspect rendered text.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import replace
from typing import Protocol, cast

from ..ir.core import IRAddress, IRInstr, IRRefusal, MemSpace
from ..ir.ssa_function import SSAFunctionArtifact
from ..ir.ssa_memory_contracts import SSAMemoryOverlap8616, SSAMemoryOverlapRelation8616
from ..ir.ssa_memory_ranges import stack_coordinate_agreement_8616
from ..ir.stack_extent_evidence import build_stack_extent_evidence_8616
from ..pipeline.errors import PipelineHardError
from .alias_model_impl import AliasStorageFacts
from .logical_stack_memory_projection import project_logical_stack_memory_alias_8616
from .logical_stack_storage_identity import (
    project_logical_stack_storage_identities_8616,
)
from .private_stack_writes import classify_private_stack_writes_8616
from .stack_address_escape import classify_function_stack_address_escape_8616
from .stack_memory_access_projection import (
    alias_stack_memory_storage_8616,
    project_stack_memory_access_8616,
    project_stack_memory_phi_8616,
)
from .stack_memory_ssa_contracts import (
    StackMemoryAliasFactKind8616,
    StackMemoryAliasRefusal8616,
    StackMemoryAliasRefusalKind8616,
    StackMemoryAliasStats8616,
    StackMemorySSAAliasAccess8616,
    StackMemorySSAAliasAccessSlice8616,
    StackMemorySSAAliasArtifact8616,
    StackMemorySSAAliasFact8616,
    StackMemorySSAAliasOverlap8616,
)

__all__ = [
    "StackMemoryAliasFactKind8616",
    "StackMemoryAliasRefusal8616",
    "StackMemoryAliasRefusalKind8616",
    "StackMemoryAliasStats8616",
    "StackMemorySSAAliasAccess8616",
    "StackMemorySSAAliasAccessSlice8616",
    "StackMemorySSAAliasArtifact8616",
    "StackMemorySSAAliasFact8616",
    "StackMemorySSAAliasOverlap8616",
    "apply_x86_16_stack_memory_ssa_alias_artifact",
    "build_x86_16_stack_memory_ssa_alias_artifact",
]


class _CodegenBoundary8616(Protocol):
    """Typed artifacts carried across the dynamic angr codegen boundary."""

    _inertia_vex_ir_function_ssa: object
    _inertia_stack_memory_ssa_alias_artifact: StackMemorySSAAliasArtifact8616


def _stack_access_8616(instruction: IRInstr) -> IRAddress | None:
    """Return one typed SS load/store address."""
    if instruction.op not in {"LOAD", "STORE"} or not instruction.args:
        return None
    address = instruction.args[0]
    return address if isinstance(address, IRAddress) and address.space is MemSpace.SS else None


def _alias_overlap_8616(
    overlap: SSAMemoryOverlap8616,
) -> StackMemorySSAAliasOverlap8616 | StackMemoryAliasRefusal8616:
    """Project and verify one IR byte-overlap relation through Alias."""
    addresses = (overlap.left, overlap.right, overlap.intersection)
    storages = tuple(alias_stack_memory_storage_8616(address) for address in addresses)
    accepted: list[AliasStorageFacts] = []
    for address, storage in zip(addresses, storages, strict=True):
        if isinstance(storage, tuple):
            return StackMemoryAliasRefusal8616(storage[0], None, None, storage[1], address)
        accepted.append(storage)
    left, right, intersection = accepted
    left_contains_right = left.contains(right)
    right_contains_left = right.contains(left)
    if overlap.relation is SSAMemoryOverlapRelation8616.LEFT_CONTAINS_RIGHT:
        relation_consistent = left_contains_right and not right_contains_left
    elif overlap.relation is SSAMemoryOverlapRelation8616.RIGHT_CONTAINS_LEFT:
        relation_consistent = right_contains_left and not left_contains_right
    else:
        relation_consistent = not left_contains_right and not right_contains_left
    if not left.contains(intersection) or not right.contains(intersection) or not relation_consistent:
        return StackMemoryAliasRefusal8616(
            StackMemoryAliasRefusalKind8616.INCONSISTENT_OVERLAP_STORAGE,
            None,
            None,
            "IR overlap relation disagrees with canonical Alias storage containment",
            overlap.intersection,
        )
    return StackMemorySSAAliasOverlap8616(overlap, left, right, intersection)


def _incomplete_upstream_artifact_8616(
    function_ssa: SSAFunctionArtifact,
    accesses: tuple[tuple[int, int, IRAddress], ...],
) -> StackMemorySSAAliasArtifact8616:
    """Refuse every candidate when upstream memory-SSA accounting is open."""
    access_refusals = tuple(
        StackMemoryAliasRefusal8616(
            StackMemoryAliasRefusalKind8616.UPSTREAM_INCOMPLETE,
            block_addr,
            instr_index,
            "stack-memory SSA evidence accounting is incomplete",
            address,
        )
        for block_addr, instr_index, address in accesses
    )
    phi_refusals = tuple(
        StackMemoryAliasRefusal8616(
            StackMemoryAliasRefusalKind8616.UPSTREAM_INCOMPLETE,
            phi.block_addr,
            None,
            "stack-memory SSA evidence accounting is incomplete",
            phi.target,
        )
        for phi in function_ssa.memory_phi_nodes
    )
    overlap_refusals = tuple(
        StackMemoryAliasRefusal8616(
            StackMemoryAliasRefusalKind8616.UPSTREAM_INCOMPLETE,
            None,
            None,
            "stack-memory SSA evidence accounting is incomplete",
            overlap.intersection,
        )
        for overlap in function_ssa.memory_overlaps
    )
    refusals = access_refusals + phi_refusals + overlap_refusals
    logical = project_logical_stack_memory_alias_8616(function_ssa, (), ())
    logical_storage = project_logical_stack_storage_identities_8616(
        function_ssa.function_addr,
        function_ssa.logical_memory,
        coordinate_agreement=stack_coordinate_agreement_8616(function_ssa.blocks),
    )
    return StackMemorySSAAliasArtifact8616(
        function_addr=function_ssa.function_addr,
        source_ssa=function_ssa,
        refusals=refusals,
        source_refusals=function_ssa.memory_refusals,
        call_effects=function_ssa.memory_call_effects,
        stats=StackMemoryAliasStats8616(
            raw_fact_count=len(refusals),
            failure_count=len(refusals),
        ),
        upstream_complete=False,
        logical_accesses=logical.accesses,
        logical_refusals=logical.refusals,
        logical_stats=logical.stats,
        logical_storage_identities=logical_storage.identities,
        logical_storage_refusals=logical_storage.refusals,
        logical_storage_stats=logical_storage.stats,
    )


def _upstream_refusals_by_block_8616(refusals: tuple[IRRefusal, ...]) -> dict[int | None, list[IRRefusal]]:
    """Index mutable refusal queues without changing source order or ownership."""
    grouped: dict[int | None, list[IRRefusal]] = {}
    for refusal in refusals:
        grouped.setdefault(refusal.block_addr, []).append(refusal)
    return grouped


def _unprojected_access_refusals_8616(
    raw_accesses: tuple[tuple[int, int, IRAddress], ...],
    accepted_positions: set[tuple[int, int]],
    upstream_by_block: dict[int | None, list[IRRefusal]],
) -> list[StackMemoryAliasRefusal8616]:
    """Pair unmatched accesses with ordered refusals, retaining orphan evidence."""
    refusals: list[StackMemoryAliasRefusal8616] = []
    for block_addr, instr_index, address in raw_accesses:
        if (block_addr, instr_index) in accepted_positions:
            continue
        upstream = upstream_by_block.get(block_addr, [])
        source = upstream.pop(0) if upstream else None
        refusals.append(
            StackMemoryAliasRefusal8616(
                StackMemoryAliasRefusalKind8616.UPSTREAM_MEMORY_REFUSAL
                if source is not None
                else StackMemoryAliasRefusalKind8616.UNVERSIONED_ADDRESS,
                block_addr,
                instr_index,
                source.detail
                if source is not None
                else "stack access has no authoritative memory-SSA access",
                address,
            )
        )
    return refusals


def build_x86_16_stack_memory_ssa_alias_artifact(
    function_ssa: SSAFunctionArtifact,
) -> StackMemorySSAAliasArtifact8616:
    """Project all function stack-memory SSA inputs into exact Alias facts."""
    raw_accesses = tuple(
        (block.addr, instr_index, address)
        for block in sorted(function_ssa.blocks, key=lambda item: item.addr)
        for instr_index, instruction in enumerate(block.instrs)
        if (address := _stack_access_8616(instruction)) is not None
    )
    if not function_ssa.memory_stats.complete:
        return _incomplete_upstream_artifact_8616(function_ssa, raw_accesses)

    upstream_by_block = _upstream_refusals_by_block_8616(function_ssa.memory_refusals)
    facts: list[StackMemorySSAAliasFact8616] = []
    composed_accesses: list[StackMemorySSAAliasAccess8616] = []
    overlaps: list[StackMemorySSAAliasOverlap8616] = []
    refusals: list[StackMemoryAliasRefusal8616] = []

    accepted_positions = {
        (access.block_addr, access.instr_index) for access in function_ssa.memory_accesses
    }
    for access in function_ssa.memory_accesses:
        projected_access = project_stack_memory_access_8616(access)
        if isinstance(projected_access, StackMemoryAliasRefusal8616):
            refusals.append(projected_access)
        elif isinstance(projected_access, StackMemorySSAAliasAccess8616):
            composed_accesses.append(projected_access)
        else:
            facts.append(projected_access)

    refusals.extend(_unprojected_access_refusals_8616(raw_accesses, accepted_positions, upstream_by_block))

    for overlap in function_ssa.memory_overlaps:
        projected_overlap = _alias_overlap_8616(overlap)
        if isinstance(projected_overlap, StackMemoryAliasRefusal8616):
            refusals.append(projected_overlap)
        else:
            overlaps.append(projected_overlap)

    for phi in function_ssa.memory_phi_nodes:
        projected_phi = project_stack_memory_phi_8616(phi)
        if isinstance(projected_phi, StackMemoryAliasRefusal8616):
            refusals.append(projected_phi)
        else:
            facts.append(projected_phi)

    for source_refusals in upstream_by_block.values():
        refusals.extend(
            StackMemoryAliasRefusal8616(
                StackMemoryAliasRefusalKind8616.ORPHAN_UPSTREAM_REFUSAL,
                source.block_addr,
                None,
                source.detail,
            )
            for source in source_refusals
        )
    materialized_count = len(facts) + len(composed_accesses) + len(overlaps)
    raw_count = materialized_count + len(refusals)
    stats = StackMemoryAliasStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=materialized_count,
        classified_fact_count=materialized_count,
        materialized_count=materialized_count,
        failure_count=len(refusals),
    )
    logical = project_logical_stack_memory_alias_8616(
        function_ssa,
        tuple(facts),
        tuple(composed_accesses),
    )
    logical_storage = project_logical_stack_storage_identities_8616(
        function_ssa.function_addr,
        function_ssa.logical_memory,
        coordinate_agreement=stack_coordinate_agreement_8616(function_ssa.blocks),
    )
    artifact = StackMemorySSAAliasArtifact8616(
        function_addr=function_ssa.function_addr,
        source_ssa=function_ssa,
        facts=tuple(facts),
        accesses=tuple(composed_accesses),
        overlaps=tuple(overlaps),
        refusals=tuple(refusals),
        source_refusals=function_ssa.memory_refusals,
        call_effects=function_ssa.memory_call_effects,
        stats=stats,
        logical_accesses=logical.accesses,
        logical_refusals=logical.refusals,
        logical_stats=logical.stats,
        logical_storage_identities=logical_storage.identities,
        logical_storage_refusals=logical_storage.refusals,
        logical_storage_stats=logical_storage.stats,
        stack_extent_evidence=tuple(
            build_stack_extent_evidence_8616(block)
            for block in sorted(function_ssa.blocks, key=lambda item: item.addr)
        ),
    )
    artifact = replace(artifact, frame_address_escape=classify_function_stack_address_escape_8616(
        function_ssa, artifact.stack_extent_evidence,
    ))
    return replace(artifact, private_write_decisions=classify_private_stack_writes_8616(artifact))


def apply_x86_16_stack_memory_ssa_alias_artifact(_project: object, codegen: object) -> bool:
    """Attach the Alias projection immediately after typed function SSA exists."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        function_ssa = boundary._inertia_vex_ir_function_ssa
    except AttributeError:
        return False
    if not isinstance(function_ssa, SSAFunctionArtifact):
        return False
    try:
        existing = boundary._inertia_stack_memory_ssa_alias_artifact
    except AttributeError:
        existing = None
    if isinstance(existing, StackMemorySSAAliasArtifact8616) and existing.source_ssa is function_ssa:
        if not existing.complete:
            raise PipelineHardError(
                "cached stack-memory SSA Alias evidence is incomplete",
                layer="alias",
                details=existing.to_dict(),
            )
        return False
    artifact = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)
    if not artifact.complete:
        raise PipelineHardError(
            "stack-memory SSA Alias projection has incomplete evidence accounting",
            layer="alias",
        )
    boundary._inertia_stack_memory_ssa_alias_artifact = artifact
    return False
