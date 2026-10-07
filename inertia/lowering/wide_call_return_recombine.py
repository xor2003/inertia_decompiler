"""Canonicalize typed DX:AX call-return stores after global-object lowering.

Layer: Types/Lowering.
Responsibility: Consumes alias, widening, and typed facts. Consume an exact
machine call/store proof after its destination has become a typed global object,
replacing only the redundant DX:AX carrier recomposition with the original call
expression.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CVariable,
)
from angr.sim_variable import SimMemoryVariable

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.pipeline.errors import PipelineHardError

from .physical_registers import physical_register_view_8616

DIRECT_CALL_RETURN_STORE_EVIDENCE_TAG_8616: str = "inertia_x86_16_direct_call_return_store_evidence"


class WideCallReturnStoreEvidence8616(Protocol):
    """Read-only view of the authoritative immutable call/store proof."""

    @property
    def offset(self) -> int:
        """Return the proven destination offset."""
        ...

    @property
    def width(self) -> int:
        """Return the proven destination width in bytes."""
        ...

    @property
    def source_call_name(self) -> str:
        """Return the recorded call label."""
        ...

    @property
    def source_call_target(self) -> int | None:
        """Return the target address when known."""
        ...

    @property
    def source_call_ins_addr(self) -> int:
        """Return the instruction address identifying the source call."""
        ...


@dataclass(frozen=True, slots=True)
class WideCallReturnFoldReport8616:
    """Closed evidence loop for one wide call-return canonicalization run."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    already_materialized_count: int
    failure_count: int

    @property
    def changed(self) -> bool:
        """Return whether this run changed the structured C tree."""
        return self.materialized_count > 0


def _assignment_8616(node: object) -> CAssignment | None:
    """Return an assignment from the two supported angr statement wrappers."""
    if isinstance(node, CAssignment):
        return node
    if isinstance(node, CExpressionStatement) and isinstance(node.expr, CAssignment):
        return node.expr
    return None


def _global_identity_8616(node: object) -> tuple[int, int] | None:
    """Return the exact address and width of one materialized global object."""
    if not isinstance(node, CVariable) or not isinstance(node.variable, SimMemoryVariable):
        return None
    variable = node.variable
    if not isinstance(variable.addr, int) or not isinstance(variable.size, int):
        return None
    return variable.addr & 0xFFFF, variable.size


def _constant_8616(node: object) -> int | None:
    """Return one literal C integer without interpreting rendered text."""
    return node.value if isinstance(node, CConstant) and isinstance(node.value, int) else None


def _normalized_call_name_8616(call: CFunctionCall) -> str | None:
    """Read a call name at the dynamic third-party codegen boundary."""
    raw_name = call.callee_target
    if not isinstance(raw_name, str):
        callee = call.callee_func
        if callee is None:
            return None
        try:
            raw_name = callee.name
        except AttributeError:
            return None
    name = raw_name.strip().lstrip("_")
    return name or None


def _call_matches_evidence_8616(
    call: CFunctionCall,
    evidence: WideCallReturnStoreEvidence8616,
) -> bool:
    """Match the typed target identity, using its name only when no address exists."""
    target = call.callee_target
    if isinstance(target, int):
        return evidence.source_call_target is not None and target == evidence.source_call_target
    expected_name = evidence.source_call_name.strip().lstrip("_")
    return _normalized_call_name_8616(call) == expected_name


def _is_dx_word_shift_16_8616(node: object) -> bool:
    """Recognize the exact high word of a 16-bit DX:AX return value."""
    if not isinstance(node, CBinaryOp) or node.op not in {"Shl", "LShift"}:
        return False
    if _constant_8616(node.rhs) != 16:
        return False
    view = physical_register_view_8616(node.lhs)
    return view is not None and view.reg_offset == 8 and view.width == 2


def _nested_call_8616(
    rhs: object,
    evidence: WideCallReturnStoreEvidence8616,
) -> tuple[CFunctionCall | None, bool]:
    """Return a nested proven call and whether its DX half is exact."""
    if not isinstance(rhs, CBinaryOp) or rhs.op != "Or":
        return None, False
    for call_side, high_side in ((rhs.lhs, rhs.rhs), (rhs.rhs, rhs.lhs)):
        if isinstance(call_side, CFunctionCall) and _call_matches_evidence_8616(call_side, evidence):
            return call_side, _is_dx_word_shift_16_8616(high_side)
    return None, False


def fold_tagged_wide_call_return_stores_8616(
    root: object,
    evidence_items: tuple[WideCallReturnStoreEvidence8616, ...],
) -> WideCallReturnFoldReport8616:
    """Fold exact tagged ``global = call() | (DX << 16)`` assignments.

    The evidence tag, destination identity, call identity, and physical DX
    view must all agree. A tagged candidate with a mismatched high half is a
    projection-coherence failure and stops the pipeline instead of guessing.
    """
    normalized = tuple(
        {
            (
                item.offset & 0xFFFF,
                item.width,
                item.source_call_ins_addr,
                item.source_call_target,
                item.source_call_name,
            ): item
            for item in evidence_items
            if item.width == 4
        }.values()
    )
    classified = materialized = already_materialized = failures = 0
    for node in _iter_c_nodes_deep_8616(root):
        assignment = _assignment_8616(node)
        if assignment is None:
            continue
        identity = _global_identity_8616(assignment.lhs)
        if identity is None:
            continue
        tagged = assignment.tags.get(DIRECT_CALL_RETURN_STORE_EVIDENCE_TAG_8616)
        matches = tuple(item for item in normalized if tagged == item and identity == (item.offset & 0xFFFF, 4))
        if len(matches) != 1:
            continue
        evidence = matches[0]
        if isinstance(assignment.rhs, CFunctionCall):
            if _call_matches_evidence_8616(assignment.rhs, evidence):
                classified += 1
                already_materialized += 1
            continue
        call, high_half_matches = _nested_call_8616(assignment.rhs, evidence)
        if call is None:
            continue
        classified += 1
        if not high_half_matches:
            failures += 1
            continue
        assignment.rhs = call
        materialized += 1
    if failures:
        raise PipelineHardError(
            "typed wide call-return store could not materialize its exact DX high-half carrier"
        )
    return WideCallReturnFoldReport8616(
        raw_fact_count=len(evidence_items),
        normalized_fact_count=len(normalized),
        classified_fact_count=classified,
        materialized_count=materialized,
        already_materialized_count=already_materialized,
        failure_count=failures,
    )
