"""Attach indexed segmented-address evidence immediately after function SSA.

Layer: IR.
Responsibility: collect and publish the closed indexed DS/ES address artifact
from the authoritative function SSA. This module does not infer aliases,
bounds, objects, C types, or rendered expressions.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import Protocol, cast

from inertia.pipeline.errors import PipelineHardError

from .indexed_address_contracts import IndexedAddressEvidence8616
from .indexed_address_copy_contracts import IndexedAddressCopyEvidence8616
from .indexed_address_copy_evidence import collect_indexed_address_copy_evidence_8616
from .indexed_address_evidence import collect_indexed_address_evidence_8616
from .indexed_address_range_candidates import (
    collect_indexed_loop_ranges_from_ssa_8616,
)
from .indexed_address_range_contracts import IndexedLoopRangeEvidence8616
from .ssa_function import SSAFunctionArtifact


class _CodegenBoundary8616(Protocol):
    """Typed IR artifacts carried on the dynamic angr codegen boundary."""

    _inertia_vex_ir_function_ssa: object
    _inertia_indexed_address_evidence_8616: IndexedAddressEvidence8616
    _inertia_indexed_address_copy_evidence_8616: IndexedAddressCopyEvidence8616
    _inertia_indexed_loop_range_evidence_8616: IndexedLoopRangeEvidence8616


def apply_x86_16_indexed_address_evidence_8616(
    project: object,
    codegen: object,
) -> bool:
    """Publish closed indexed-address evidence after function SSA exists."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        function_ssa = boundary._inertia_vex_ir_function_ssa
    except AttributeError:
        return False
    if not isinstance(function_ssa, SSAFunctionArtifact):
        return False
    try:
        existing = boundary._inertia_indexed_address_evidence_8616
    except AttributeError:
        existing = None
    if not (
        isinstance(existing, IndexedAddressEvidence8616)
        and existing.function_addr == function_ssa.function_addr
    ):
        existing = collect_indexed_address_evidence_8616(function_ssa)
        if not existing.closed:
            raise PipelineHardError(
                "indexed-address IR evidence has incomplete accounting",
                layer="ir",
            )
        boundary._inertia_indexed_address_evidence_8616 = existing
    try:
        copy_evidence = boundary._inertia_indexed_address_copy_evidence_8616
    except AttributeError:
        copy_evidence = None
    if not (
        isinstance(copy_evidence, IndexedAddressCopyEvidence8616)
        and copy_evidence.source == existing
    ):
        copy_evidence = collect_indexed_address_copy_evidence_8616(
            function_ssa,
            existing,
        )
        if not copy_evidence.closed:
            raise PipelineHardError(
                "indexed-address copy evidence has incomplete accounting",
                layer="ir",
            )
        boundary._inertia_indexed_address_copy_evidence_8616 = copy_evidence
    range_evidence = collect_indexed_loop_ranges_from_ssa_8616(
        function_ssa,
        existing,
    )
    if not range_evidence.closed:
        raise PipelineHardError(
            "indexed loop-range IR evidence has incomplete accounting",
            layer="ir",
        )
    boundary._inertia_indexed_loop_range_evidence_8616 = range_evidence
    return False


__all__ = ["apply_x86_16_indexed_address_evidence_8616"]
