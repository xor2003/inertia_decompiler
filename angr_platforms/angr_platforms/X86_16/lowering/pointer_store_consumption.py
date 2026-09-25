"""Prove complete consumption before removing a pointer-store carrier.

Layer: Types/Lowering.
Responsibility: separate source-preservation evidence for a proven store
projection from whole-function register-use evidence for setup deletion. This is not general
DCE: unrelated writes, opaque effects, cycles, and shared occurrences refuse.
Consumes alias, widening, and typed facts; never infers storage from names.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CDirtyExpression,
    CFunctionCall,
    CVariable,
)

from ..c_ast_utils import (
    _c_ast_cycle_path_8616,
    _iter_c_node_occurrences_8616,
    _same_c_expression_8616,
)
from .physical_registers import PhysicalRegisterView8616, physical_register_view_8616


class PointerStoreConsumptionVerdict8616(StrEnum):
    """Distinguish a preserved store source from a fully consumed setup."""

    PROVEN_CONSUMED = "proven_consumed"
    PROVEN_SOURCE_PRESERVED = "proven_source_preserved"
    UNKNOWN_REFUSE = "unknown_refuse"


class PointerStoreConsumptionFailure8616(StrEnum):
    """Stable reasons to preserve the original pointer-store statements."""

    UNKNOWN_CARRIER = "unknown_carrier"
    SOURCE_CHANGED = "source_changed"
    OPAQUE_EFFECT = "opaque_effect"
    CYCLIC_AST = "cyclic_ast"
    INCOMPLETE_PLACEMENT = "incomplete_placement"
    UNCONSUMED_REGISTER = "unconsumed_register"


@dataclass(frozen=True, slots=True)
class PointerStoreConsumptionEvidence8616:
    """One materialized guard decision, not a claim that C was mutated."""

    verdict: PointerStoreConsumptionVerdict8616
    failure: PointerStoreConsumptionFailure8616 | None = None
    raw_fact_count: int = 1
    normalized_fact_count: int = 1
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 1

    @property
    def complete(self) -> bool:
        """Require a closed consumption proof before removing the setup."""
        return (
            self.verdict is PointerStoreConsumptionVerdict8616.PROVEN_CONSUMED
            and self.source_preserved
        )

    @property
    def source_preserved(self) -> bool:
        """Authorize only value substitution; this alone never permits DCE."""
        return (
            self.verdict in {
                PointerStoreConsumptionVerdict8616.PROVEN_CONSUMED,
                PointerStoreConsumptionVerdict8616.PROVEN_SOURCE_PRESERVED,
            }
            and self.failure is None
            and self.raw_fact_count == self.normalized_fact_count
            == self.classified_fact_count == self.materialized_count == 1
            and self.failure_count == 0
        )


def _refuse(failure: PointerStoreConsumptionFailure8616) -> PointerStoreConsumptionEvidence8616:
    """Publish an atomic refusal without claiming consumed statements."""
    return PointerStoreConsumptionEvidence8616(
        PointerStoreConsumptionVerdict8616.UNKNOWN_REFUSE, failure,
    )


def _register_occurrences(nodes: Iterable[object], carrier: PhysicalRegisterView8616) -> int:
    """Count AST edges with overlapping physical bytes, including subregisters."""
    return sum(
        1
        for node in nodes
        if (view := physical_register_view_8616(node)) is not None
        and view.reg_offset < carrier.reg_offset + carrier.width
        and carrier.reg_offset < view.reg_offset + view.width
    )


def prove_pointer_store_source_preservation_8616(
    carrier: object,
    pointer: object,
    stores: tuple[CAssignment, ...],
    intervening: tuple[object, ...],
) -> PointerStoreConsumptionEvidence8616:
    """Prove an unchanged pointer source across a straight-line store interval."""
    view = physical_register_view_8616(carrier)
    if view is None or not stores:
        return _refuse(PointerStoreConsumptionFailure8616.UNKNOWN_CARRIER)
    for statement in intervening:
        if any(statement is store for store in stores):
            continue
        if (
            not isinstance(statement, CAssignment)
            or not isinstance(statement.lhs, CVariable)
            or _same_c_expression_8616(statement.lhs, pointer)
            or _register_occurrences(_iter_c_node_occurrences_8616(statement.lhs), view)
        ):
            return _refuse(PointerStoreConsumptionFailure8616.SOURCE_CHANGED)
        if any(
            isinstance(node, (CFunctionCall, CDirtyExpression))
            for node in _iter_c_node_occurrences_8616(statement.rhs)
        ):
            return _refuse(PointerStoreConsumptionFailure8616.OPAQUE_EFFECT)
    if any(
        isinstance(node, (CFunctionCall, CDirtyExpression))
        for store in stores
        for node in _iter_c_node_occurrences_8616(store.rhs)
    ):
        return _refuse(PointerStoreConsumptionFailure8616.OPAQUE_EFFECT)
    if any(_register_occurrences(_iter_c_node_occurrences_8616(store.rhs), view) for store in stores):
        return _refuse(PointerStoreConsumptionFailure8616.UNCONSUMED_REGISTER)
    return PointerStoreConsumptionEvidence8616(
        PointerStoreConsumptionVerdict8616.PROVEN_SOURCE_PRESERVED,
        classified_fact_count=1, materialized_count=1, failure_count=0,
    )


def _root_consumption_verdict_8616(
    root: object,
    setup: CAssignment,
    stores: tuple[CAssignment, ...],
    view: PhysicalRegisterView8616,
    expected: int,
) -> PointerStoreConsumptionFailure8616 | bool:
    """Classify one C root: skip, consume, or refuse with a typed failure."""
    if _c_ast_cycle_path_8616(root):
        return PointerStoreConsumptionFailure8616.CYCLIC_AST
    occurrences = tuple(_iter_c_node_occurrences_8616(root))
    if any(
        isinstance(node, CDirtyExpression) and physical_register_view_8616(node) is None
        for node in occurrences
    ):
        return PointerStoreConsumptionFailure8616.OPAQUE_EFFECT
    count = _register_occurrences(occurrences, view)
    if not count:
        return False
    if sum(node is setup for node in occurrences) != 1 or any(
        sum(node is store for node in occurrences) != 1 for store in stores
    ):
        return PointerStoreConsumptionFailure8616.INCOMPLETE_PLACEMENT
    if count != expected:
        return PointerStoreConsumptionFailure8616.UNCONSUMED_REGISTER
    return True


def prove_pointer_store_consumption_8616(
    roots: tuple[object, ...],
    setup: CAssignment,
    carrier: object,
    pointer: object,
    stores: tuple[CAssignment, ...],
    intervening: tuple[object, ...],
) -> PointerStoreConsumptionEvidence8616:
    """Require unchanged source and no carrier occurrence outside consumed LHSs."""
    view = physical_register_view_8616(carrier)
    if view is None or not roots:
        return _refuse(PointerStoreConsumptionFailure8616.UNKNOWN_CARRIER)
    source = prove_pointer_store_source_preservation_8616(carrier, pointer, stores, intervening)
    if not source.source_preserved:
        return source
    expected = _register_occurrences(_iter_c_node_occurrences_8616(setup.lhs), view) + sum(
        _register_occurrences(_iter_c_node_occurrences_8616(store.lhs), view) for store in stores
    )
    if expected < 2:
        return _refuse(PointerStoreConsumptionFailure8616.INCOMPLETE_PLACEMENT)
    found = False
    for root in {id(root): root for root in roots}.values():
        verdict = _root_consumption_verdict_8616(root, setup, stores, view, expected)
        if isinstance(verdict, PointerStoreConsumptionFailure8616):
            return _refuse(verdict)
        found = found or verdict
    if not found:
        return _refuse(PointerStoreConsumptionFailure8616.INCOMPLETE_PLACEMENT)
    return PointerStoreConsumptionEvidence8616(
        PointerStoreConsumptionVerdict8616.PROVEN_CONSUMED,
        classified_fact_count=1, materialized_count=1, failure_count=0,
    )
