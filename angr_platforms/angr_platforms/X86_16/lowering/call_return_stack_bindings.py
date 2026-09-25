"""Bind typed call-return stack stores to canonical stack C variables.

Layer: Types/Lowering.
Responsibility: join an exact typed callsite return-store destination to the
machine-BP/entry-SP coordinate registry after angr has materialized the call.
The existing call expression, arguments, and placement remain unchanged.
Consumes callsite summaries and stack-coordinate projections.
Consumes alias, widening, and typed facts.
Do not discover calls, reconstruct arguments, inspect rendered text, or decide
structured placement here.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable, SimTemporaryVariable

from ..c_ast_utils import _iter_c_node_occurrences_8616
from ..callsite_summary import callsite_summary_inventory_8616
from ..semantics.expression_analysis import describe_virtual_value_identity_8616
from .call_return_stack_stores import (
    CallReturnStackStoreEvidence8616,
    classify_call_return_stack_store_8616,
)
from .stack_frame_projection import entry_sp_offset_for_machine_bp_range_8616
from .stack_lowering_from_facts import materialize_stack_cvar_at_offset_from_facts_8616
from .stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    stack_cvar_for_machine_bp_range_8616,
)


class CallReturnStackBindingStatus8616(Enum):
    """Outcome of one exact call-return stack-assignment binding attempt."""

    NOT_APPLICABLE = "not_applicable"
    NO_PROJECTION = "no_projection"
    ALREADY_BOUND = "already_bound"
    BOUND = "bound"


_CALL_RETURN_STACK_BRIDGE_TAG_8616 = "inertia_call_return_stack_bridge_8616"


class _RegisterArchitecture8616(Protocol):
    """Architecture register map needed at the third-party codegen boundary."""

    registers: Mapping[str, tuple[int, int]]


class _RegisterProject8616(Protocol):
    """Project architecture needed to resolve a physical return register."""

    arch: _RegisterArchitecture8616


class _RegisterCodegen8616(Protocol):
    """Third-party codegen surface carrying the active project."""

    project: _RegisterProject8616


@dataclass(frozen=True, slots=True)
class CallReturnStackBindingResult8616:
    """Typed evidence-loop result for one structured assignment."""

    node: object
    status: CallReturnStackBindingStatus8616
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether the structured assignment identity changed."""
        return self.status is CallReturnStackBindingStatus8616.BOUND


def _direct_call_8616(expr: object) -> structured_c.CFunctionCall | None:
    """Return a direct call beneath only semantics-preserving C casts."""
    while isinstance(expr, structured_c.CTypeCast):
        expr = expr.expr
    return expr if isinstance(expr, structured_c.CFunctionCall) else None


def _signed_stack_offset_8616(offset: int) -> int:
    """Normalize a 16-bit stack displacement to its signed coordinate."""
    return offset - 0x10000 if 0x8000 <= offset <= 0xFFFF else offset


def _call_return_register_source_matches_8616(
    codegen: object,
    variable: object,
    evidence: CallReturnStackStoreEvidence8616,
) -> bool:
    """Match the exact physical register copied into the proven stack store."""
    if not isinstance(variable, SimRegisterVariable):
        return False
    try:
        arch = cast(_RegisterCodegen8616, codegen).project.arch
    except AttributeError:
        return False
    register = arch.registers.get(evidence.source_register_name)
    return (
        register is not None
        and isinstance(variable.reg, int)
        and isinstance(variable.size, int)
        and variable.reg == register[0]
        and variable.size == register[1] == evidence.width
    )


def call_return_stack_destination_matches_8616(
    codegen: object,
    expression: object,
    evidence: CallReturnStackStoreEvidence8616,
) -> bool:
    """Match a return store by canonical machine-BP storage identity."""
    if not isinstance(expression, structured_c.CVariable):
        return False
    variable = expression.variable
    if not isinstance(variable, SimStackVariable) or not isinstance(variable.size, int):
        return False
    bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    return (
        variable.base == "bp"
        and isinstance(bp_offset, int)
        and _signed_stack_offset_8616(bp_offset)
        == _signed_stack_offset_8616(evidence.dst_offset)
        and variable.size == evidence.width
    )


def materialize_call_return_stack_destination_8616(
    codegen: object,
    evidence: CallReturnStackStoreEvidence8616,
    *,
    preferred_name: str | None = None,
) -> structured_c.CVariable | None:
    """Resolve one machine-BP return store to its exact entry-SP C variable."""
    projected = stack_cvar_for_machine_bp_range_8616(
        codegen,
        evidence.dst_offset,
        evidence.width,
    )
    if isinstance(projected, structured_c.CVariable):
        return projected
    entry_sp_offset = entry_sp_offset_for_machine_bp_range_8616(
        codegen,
        evidence.dst_offset,
        evidence.width,
    )
    if entry_sp_offset is None:
        return None
    materialized = materialize_stack_cvar_at_offset_from_facts_8616(
        codegen,
        entry_sp_offset,
        evidence.width,
        machine_bp_offset=evidence.dst_offset,
        preferred_name=preferred_name,
    )
    return materialized if isinstance(materialized, structured_c.CVariable) else None


def _proven_stack_store_evidence_8616(
    node: structured_c.CAssignment,
    codegen: object,
) -> CallReturnStackStoreEvidence8616 | CallReturnStackBindingResult8616:
    """Return the proven stack store evidence or an early binding refusal."""
    call = _direct_call_8616(node.rhs)
    lhs = node.lhs
    if call is None or not isinstance(lhs, structured_c.CVariable):
        return CallReturnStackBindingResult8616(
            node,
            CallReturnStackBindingStatus8616.NOT_APPLICABLE,
        )
    tags = call.tags
    callsite_addr = tags.get("ins_addr") if isinstance(tags, dict) else None
    if not isinstance(callsite_addr, int):
        return CallReturnStackBindingResult8616(
            node,
            CallReturnStackBindingStatus8616.NOT_APPLICABLE,
        )
    summary = callsite_summary_inventory_8616(codegen).get(callsite_addr)
    if summary is None:
        return CallReturnStackBindingResult8616(
            node,
            CallReturnStackBindingStatus8616.NOT_APPLICABLE,
        )
    evidence = classify_call_return_stack_store_8616(summary)
    materialized_evidence = node.tags.get(_CALL_RETURN_STACK_BRIDGE_TAG_8616)
    if isinstance(materialized_evidence, CallReturnStackStoreEvidence8616):
        return CallReturnStackBindingResult8616(
            node,
            CallReturnStackBindingStatus8616.ALREADY_BOUND,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
        )
    variable = lhs.variable
    if evidence is None or not isinstance(
        variable,
        (SimRegisterVariable, SimStackVariable),
    ):
        return CallReturnStackBindingResult8616(
            node,
            CallReturnStackBindingStatus8616.NOT_APPLICABLE,
            raw_fact_count=1,
        )
    if not (
        call_return_stack_destination_matches_8616(codegen, lhs, evidence)
        or _call_return_register_source_matches_8616(codegen, variable, evidence)
    ):
        return CallReturnStackBindingResult8616(
            node,
            CallReturnStackBindingStatus8616.NOT_APPLICABLE,
            raw_fact_count=1,
            normalized_fact_count=1,
        )
    return evidence


def bind_call_return_stack_assignment_8616(
    node: object,
    codegen: object,
) -> CallReturnStackBindingResult8616:
    """Bind one exact stack call-result assignment without rebuilding its call.

    A callsite tag identifies the typed summary. The current left side must be
    either its exact return-register carrier or the proven machine-BP stack
    destination. The call expression and its arguments remain unchanged.
    """
    if not isinstance(node, structured_c.CAssignment):
        return CallReturnStackBindingResult8616(
            node,
            CallReturnStackBindingStatus8616.NOT_APPLICABLE,
        )
    gated = _proven_stack_store_evidence_8616(node, codegen)
    if isinstance(gated, CallReturnStackBindingResult8616):
        return gated
    evidence = gated
    lhs = cast(structured_c.CVariable, node.lhs)
    projected = materialize_call_return_stack_destination_8616(
        codegen,
        evidence,
    )
    if not isinstance(projected, structured_c.CVariable):
        return CallReturnStackBindingResult8616(
            node,
            CallReturnStackBindingStatus8616.NO_PROJECTION,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            failure_count=1,
        )
    if lhs is projected or lhs.variable is projected.variable:
        return CallReturnStackBindingResult8616(
            node,
            CallReturnStackBindingStatus8616.ALREADY_BOUND,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
        )
    call_assignment_tags = dict(node.tags)
    call_assignment_tags[_CALL_RETURN_STACK_BRIDGE_TAG_8616] = evidence
    call_assignment = structured_c.CAssignment(
        lhs,
        node.rhs,
        codegen=node.codegen,
        tags=call_assignment_tags,
    )
    store_tags = dict(node.tags)
    if evidence.store_ins_addr is not None:
        store_tags["ins_addr"] = evidence.store_ins_addr
    store_assignment = structured_c.CAssignment(
        projected,
        lhs,
        codegen=node.codegen,
        tags=store_tags,
    )
    bridge = structured_c.CStatements(
        [call_assignment, store_assignment],
        codegen=node.codegen,
    )
    return CallReturnStackBindingResult8616(
        bridge,
        CallReturnStackBindingStatus8616.BOUND,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
    )


def preserve_word_call_carrier_8616(
    original: object, replacement: structured_c.CAssignment,
) -> structured_c.CAssignment | structured_c.CStatements:
    """Keep an exact word call definition when projecting its result to a local.

    The caller already owns the machine store proof. Equal exact callsites and
    unsigned word storage allow a copy, not another evaluation of the call.
    Retaining the carrier unconditionally preserves all later consumers without
    guessing their liveness. Wider/composite results retain their existing path.
    """
    if not isinstance(original, structured_c.CAssignment):
        return replacement
    if not isinstance(original.rhs, structured_c.CFunctionCall) or not isinstance(replacement.rhs, structured_c.CFunctionCall):
        return replacement
    source, destination = original.lhs, replacement.lhs
    if not isinstance(source, structured_c.CVariable) or not isinstance(destination, structured_c.CVariable):
        return replacement
    if not isinstance(source.variable, (SimTemporaryVariable, SimRegisterVariable)) or not isinstance(destination.variable, SimStackVariable):
        return replacement
    exact_words = all(variable.variable.size == 2 and isinstance(variable.variable_type, SimTypeShort)
                      and variable.variable_type.signed is False for variable in (source, destination))
    callsite = original.rhs.tags.get("ins_addr")
    same_callsite = isinstance(callsite, int) and original.rhs.tags.get("ins_addr") == replacement.rhs.tags.get("ins_addr")
    if not exact_words or not same_callsite:
        return replacement
    replacement.rhs = source
    return structured_c.CStatements([original, replacement], codegen=replacement.codegen)


def call_result_escapes_group_8616(root: object, assignment: object, following: tuple[object, ...]) -> bool:
    """Refuse destination folding when its local census misses any carrier use."""
    if not isinstance(assignment, structured_c.CAssignment):
        return True
    source = (assignment.lhs.variable if isinstance(assignment.lhs, structured_c.CVariable)
              else describe_virtual_value_identity_8616(assignment.lhs))
    if source is None:
        return True

    def occurrences(node: object) -> int:
        """Count shared references by occurrence, not by visited node identity."""
        return sum((child.variable if isinstance(child, structured_c.CVariable)
                    else describe_virtual_value_identity_8616(child)) == source
                   for child in _iter_c_node_occurrences_8616(node))

    inspected = occurrences(assignment) + sum(occurrences(node) for node in following)
    return occurrences(root) != inspected


__all__ = [
    "CallReturnStackBindingResult8616",
    "CallReturnStackBindingStatus8616",
    "bind_call_return_stack_assignment_8616",
    "call_result_escapes_group_8616",
    "call_return_stack_destination_matches_8616",
    "materialize_call_return_stack_destination_8616",
    "preserve_word_call_carrier_8616",
]
