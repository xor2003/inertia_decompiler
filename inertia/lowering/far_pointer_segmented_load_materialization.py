"""Materialize typed far-pointer segmented-load evidence in generated C.

Layer: Types/Lowering.
Responsibility: replace only structural dereference nodes carrying an exact
LES/LDS-backed load-site address. Stack identities come from typed lowering
facts; this module never parses source, COD, assembly, or rendered C text.
Consumes alias, widening, and typed facts; it does not invent them.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.analyses.decompiler.structured_codegen.c import CExpression
from angr.sim_type import SimTypeShort

from inertia.lowering.c_ast_utils import _replace_c_children_8616

from .far_pointer_segmented_load_evidence import FarPointerSegmentedLoadEvidence8616
from .segment_access_policy import instruction_addrs_from_node_8616
from .stack_frame_projection import entry_sp_offset_for_machine_bp_range_8616
from .stack_lowering_from_facts import materialize_stack_cvar_at_offset_from_facts_8616
from .stack_variable_coordinates import stack_cvar_for_machine_bp_range_8616


class _CFunctionBoundary8616(Protocol):
    """Owned fields used from the dynamic angr C-function boundary."""

    statements: object


class _CodegenBoundary8616(Protocol):
    """Owned fields used from the dynamic angr codegen boundary."""

    cfunc: _CFunctionBoundary8616 | None


@dataclass(frozen=True, slots=True)
class FarPointerSegmentedLoadStats8616:
    """Closed evidence loop for far-pointer segmented-load materialization."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class FarPointerSegmentedLoadResult8616:
    """Materialization result and its closed evidence counters."""

    changed: bool
    stats: FarPointerSegmentedLoadStats8616


def _stack_cvar_for_machine_bp_fact_8616(
    codegen: object,
    bp_offset: int,
    size: int,
) -> CExpression | None:
    """Resolve one machine-BP fact without treating it as an entry-SP offset."""
    existing = stack_cvar_for_machine_bp_range_8616(codegen, bp_offset, size)
    if isinstance(existing, CExpression):
        return existing
    entry_sp_offset = entry_sp_offset_for_machine_bp_range_8616(
        codegen,
        bp_offset,
        size,
    )
    if entry_sp_offset is None:
        return None
    materialized = materialize_stack_cvar_at_offset_from_facts_8616(
        codegen,
        entry_sp_offset,
        size,
        machine_bp_offset=bp_offset,
    )
    return materialized if isinstance(materialized, CExpression) else None


def _materialized_offset_expr_8616(
    codegen: object,
    fact: FarPointerSegmentedLoadEvidence8616,
) -> tuple[CExpression, CExpression] | None:
    """Build exact segment and offset expressions from stack facts."""
    segment_source = fact.pointer_source.segment_value_source
    segment_stack_offset = (
        segment_source.stack_offset
        if segment_source is not None and segment_source.width == 2
        else fact.pointer_source.segment_stack_offset
    )
    segment = _stack_cvar_for_machine_bp_fact_8616(
        codegen,
        segment_stack_offset,
        2,
    )
    offset_constant = fact.pointer_source.offset_constant
    offset = (
        structured_c.CConstant(
            offset_constant,
            SimTypeShort(False),
            codegen=codegen,
        )
        if offset_constant is not None
        else _stack_cvar_for_machine_bp_fact_8616(
            codegen,
            fact.pointer_source.offset_stack_offset,
            2,
        )
    )
    if not isinstance(segment, CExpression) or not isinstance(offset, CExpression):
        return None
    result: CExpression = offset
    if fact.index_stack_offset is not None:
        index = _stack_cvar_for_machine_bp_fact_8616(
            codegen,
            fact.index_stack_offset,
            fact.index_stack_width,
        )
        if not isinstance(index, CExpression):
            return None
        if fact.index_shift:
            index = structured_c.CBinaryOp(
                "Shl",
                index,
                structured_c.CConstant(fact.index_shift, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )
        result = structured_c.CBinaryOp("Add", result, index, codegen=codegen)
    if fact.displacement:
        result = structured_c.CBinaryOp(
            "Add" if fact.displacement > 0 else "Sub",
            result,
            structured_c.CConstant(abs(fact.displacement), SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    return segment, result


def _is_materializable_load_shape_8616(node: object, width: int) -> bool:
    """Accept only structural dereference shapes for the binary-proven width."""
    if isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference":
        return True
    if width != 2 or not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return False

    def _is_byte_load(candidate: object) -> bool:
        """Recognize one direct byte-load arm through scalar casts only."""
        while isinstance(candidate, structured_c.CTypeCast):
            candidate = candidate.expr
        return isinstance(candidate, structured_c.CUnaryOp) and candidate.op == "Dereference"

    def _is_high_byte(candidate: object) -> bool:
        """Recognize the exact high-byte load shifted into a 16-bit word."""
        while isinstance(candidate, structured_c.CTypeCast):
            candidate = candidate.expr
        if not isinstance(candidate, structured_c.CBinaryOp) or candidate.op != "Shl":
            return False
        shift = candidate.rhs
        return (
            _is_byte_load(candidate.lhs)
            and isinstance(shift, structured_c.CConstant)
            and shift.value == 8
        )

    return (_is_byte_load(node.lhs) and _is_high_byte(node.rhs)) or (
        _is_high_byte(node.lhs) and _is_byte_load(node.rhs)
    )


def materialize_far_pointer_segmented_loads_8616(
    codegen: object,
    evidence: tuple[FarPointerSegmentedLoadEvidence8616, ...],
) -> FarPointerSegmentedLoadResult8616:
    """Materialize exact LES/LDS-backed loads on the current structured C AST."""
    typed_codegen = cast(_CodegenBoundary8616, codegen)
    cfunc = typed_codegen.cfunc
    root = cfunc.statements if cfunc is not None else None
    if cfunc is None or root is None or not evidence:
        stats = FarPointerSegmentedLoadStats8616(len(evidence), len(evidence), 0, 0, 0)
        return FarPointerSegmentedLoadResult8616(False, stats)
    by_address = {fact.ins_addr: fact for fact in evidence}
    classified: set[int] = set()
    materialized: set[int] = set()
    failures: set[int] = set()
    changed = False

    def transform(node: object) -> object:
        """Replace one exact structural load node and refuse all ambiguity."""
        nonlocal changed
        addresses = instruction_addrs_from_node_8616(node) & by_address.keys()
        if len(addresses) != 1:
            return node
        address = next(iter(addresses))
        fact = by_address[address]
        if isinstance(node, structured_c.CFunctionCall):
            if node.tags.get("inertia_x86_16_far_pointer_segmented_load") == address:
                classified.add(address)
                materialized.add(address)
            return node
        if not _is_materializable_load_shape_8616(node, fact.width):
            return node
        classified.add(address)
        expressions = _materialized_offset_expr_8616(codegen, fact)
        helper = {1: "SEG_U8", 2: "SEG_U16", 4: "SEG_U32"}.get(fact.width)
        if expressions is None or helper is None:
            failures.add(address)
            return node
        segment, offset = expressions
        materialized.add(address)
        changed = True
        return structured_c.CFunctionCall(
            helper,
            None,
            [segment, offset],
            codegen=codegen,
            tags={
                "inertia_source_instruction_addrs": (address,),
                "inertia_x86_16_far_pointer_segmented_load": address,
            },
        )

    new_root = transform(root)
    if new_root is not root:
        cfunc.statements = new_root
        root = new_root
    if _replace_c_children_8616(root, transform):
        changed = True
    stats = FarPointerSegmentedLoadStats8616(
        raw_fact_count=len(evidence),
        normalized_fact_count=len(evidence),
        classified_fact_count=len(classified),
        materialized_count=len(materialized),
        failure_count=len(failures),
    )
    return FarPointerSegmentedLoadResult8616(changed, stats)
