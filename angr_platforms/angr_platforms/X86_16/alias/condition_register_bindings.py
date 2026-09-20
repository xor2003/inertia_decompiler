"""Classify typed condition-producer register bindings.

Layer: Alias.
Responsibility: Translate canonical ConditionIR producer semantics and proven
cross-CFG reaching sources into exact register-to-storage binding facts.
Consumers still decide whether CFG topology permits propagation.
Owns storage identity in segmented address spaces for those proven register bindings.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
This module consumes decoded-fact proofs but does not inspect rendered C, names,
source, COD, or sidecars.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from ..callsite_register_provenance import recover_register_source_before_instruction_8616
from ..ir.condition_ir import (
    ConditionIR,
    ConditionRegisterBindingIR,
    ConditionRegisterUpdateIR,
    condition_sort_key_8616,
)
from ..ir.core import IRBinaryValue, IRValue, MemSpace
from ..pipeline.errors import PipelineHardError
from .condition_register_storage import (
    storage_from_reaching_source_8616 as _storage_from_reaching_source_8616,
)
from .condition_register_storage import (
    zero_extended_register_storage_8616,
)
from .register_reaching_source import RegisterReachingSourceVerdict8616

__all__ = (
    "ConditionRegisterSourceBindingResult8616",
    "ConditionRegisterSourceBindingStats8616",
    "ConditionRegisterSourceBindingVerdict8616",
    "bind_condition_register_sources_8616",
    "condition_operand_storage_binding_8616",
    "condition_self_test_register_binding_8616",
    "condition_self_test_storage_bindings_8616",
    "condition_semantic_register_operands_8616",
)

_BINARY_PRODUCER_ARITY: int = 3
_REGISTER_SUBVIEW_SOURCE_ARITY: int = 7


class ConditionRegisterSourceBindingVerdict8616(StrEnum):
    """Typed outcome of cross-block condition-register binding."""

    MATERIALIZED = "materialized"
    NO_CANDIDATE = "no_candidate"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class ConditionRegisterSourceBindingStats8616:
    """Closed evidence counters for cross-block condition-register binding."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class ConditionRegisterSourceBindingResult8616:
    """Return bound conditions, a typed verdict, and closed evidence counts."""

    conditions: tuple[ConditionIR, ...]
    verdict: ConditionRegisterSourceBindingVerdict8616
    stats: ConditionRegisterSourceBindingStats8616


def condition_self_test_register_binding_8616(
    condition: ConditionIR,
) -> tuple[str, object] | None:
    """Return the register and operand proven by a logical self-test."""
    semantics = condition.producer_semantics
    if (
        not isinstance(semantics, tuple)
        or len(semantics) < _BINARY_PRODUCER_ARITY
        or semantics[0] not in {"and_reg_reg16", "or_reg_reg16"}
    ):
        return None
    if (
        not isinstance(semantics[1], str)
        or not isinstance(semantics[2], str)
        or semantics[1].lower() != semantics[2].lower()
    ):
        return None
    return semantics[1].lower(), condition.lhs


def condition_self_test_storage_bindings_8616(
    condition: ConditionIR,
) -> tuple[tuple[str, object], ...]:
    """Return explicit bindings for the register used by one logical self-test."""
    self_test = condition_self_test_register_binding_8616(condition)
    if self_test is None:
        return ()
    register_name, _operand = self_test
    return tuple(
        (register_name, binding.value)
        for binding in condition.register_bindings
        if binding.register_name.lower() == register_name
    )


def condition_semantic_register_operands_8616(
    condition: ConditionIR,
) -> tuple[tuple[str, object], ...]:
    """Map canonical condition-producer semantics to register operands."""
    self_test = condition_self_test_register_binding_8616(condition)
    if self_test is not None:
        return (self_test,)
    semantics = condition.producer_semantics
    if not isinstance(semantics, tuple) or not semantics:
        return ()
    kind = semantics[0]
    if (
        kind == "loop_counter_predecrement"
        and len(semantics) == _BINARY_PRODUCER_ARITY
        and isinstance(semantics[1], str)
        and semantics[2] == 1
    ):
        return ((semantics[1].lower(), condition.lhs),)
    if kind in {
        "cmp_reg_mem16",
        "cmp_reg_abs16",
        "cmp_reg_imm16",
        "cmp_reg_imm8",
    }:
        return ((str(semantics[1]).lower(), condition.lhs),)
    if kind in {"cmp_mem_reg16", "cmp_abs_reg16"}:
        return ((str(semantics[2]).lower(), condition.rhs),)
    if kind == "cmp_reg_reg16":
        return (
            (str(semantics[1]).lower(), condition.lhs),
            (str(semantics[2]).lower(), condition.rhs),
        )
    return ()


def condition_operand_storage_binding_8616(
    condition: ConditionIR,
    operand: object,
) -> object:
    """Resolve one semantic register operand to its exact Alias storage fact."""
    register_names = tuple(
        register_name
        for register_name, semantic_operand in condition_semantic_register_operands_8616(
            condition
        )
        if semantic_operand is operand
    )
    if len(register_names) != 1:
        return operand
    bindings = tuple(
        binding.value
        for binding in condition.register_bindings
        if binding.register_name.lower() == register_names[0]
    )
    if not bindings or any(binding != bindings[0] for binding in bindings[1:]):
        return operand
    return bindings[0]


def _register_update_binding_from_reaching_source_8616(
    function: object,
    source: tuple[object, ...] | None,
    *,
    width_bits: int,
) -> tuple[IRBinaryValue, ConditionRegisterUpdateIR] | None:
    """Materialize one decoded full-register update and projected condition view."""
    if not source or source[0] != "register_binary_subview" or len(source) != _REGISTER_SUBVIEW_SOURCE_ARITY:
        return None
    op, lhs_name, rhs_name, shift_bits, view_bits, instruction_addr = source[1:]
    width = max(1, (width_bits + 7) // 8)
    if not (
        isinstance(op, str)
        and isinstance(lhs_name, str)
        and isinstance(rhs_name, str)
        and isinstance(shift_bits, int)
        and isinstance(view_bits, int)
        and isinstance(instruction_addr, int)
        and view_bits == width * 8
    ):
        return None
    rhs_reaching = recover_register_source_before_instruction_8616(
        function,
        instruction_addr=instruction_addr,
        register=rhs_name,
    )
    if rhs_reaching.verdict is not RegisterReachingSourceVerdict8616.PROVEN:
        return None
    word_size = 2
    rhs = _storage_from_reaching_source_8616(
        rhs_reaching.source,
        width_bits=word_size * 8,
    )
    if rhs is None:
        return None
    target = IRValue(MemSpace.REG, name=lhs_name, size=word_size)
    updated: IRValue | IRBinaryValue = IRBinaryValue(
        op,
        target,
        rhs,
        size=word_size,
    )
    projected: IRValue | IRBinaryValue = updated
    if shift_bits:
        projected = IRBinaryValue(
            "shr",
            projected,
            IRValue(MemSpace.CONST, const=shift_bits, size=word_size),
            size=word_size,
        )
    value = IRBinaryValue(
        "and",
        projected,
        IRValue(MemSpace.CONST, const=(1 << view_bits) - 1, size=word_size),
        size=width,
    )
    return value, ConditionRegisterUpdateIR(
        instruction_addr=instruction_addr,
        target_register=lhs_name,
        op=op,
        rhs=rhs,
    )


def _with_register_storage_binding_8616(
    condition: ConditionIR,
    *,
    register_name: str,
    storage: IRValue | IRBinaryValue,
    update: ConditionRegisterUpdateIR | None = None,
) -> ConditionIR:
    """Attach one coherent storage binding or fail on competing owned truth."""
    same_register = tuple(
        binding
        for binding in condition.register_bindings
        if binding.register_name.lower() == register_name
    )
    candidate = ConditionRegisterBindingIR(register_name, storage, update)
    if any(binding != candidate for binding in same_register):
        raise PipelineHardError(
            "proven condition-register source conflicts with an existing binding",
            layer="alias",
            details={
                "block_addr": condition.block_addr,
                "producer_insn": condition.producer_insn,
                "register": register_name,
            },
        )
    if same_register:
        return condition
    return replace(
        condition,
        register_bindings=(
            *condition.register_bindings,
            candidate,
        ),
    )


def bind_condition_register_sources_8616(
    function: object,
    conditions: list[ConditionIR] | tuple[ConditionIR, ...],
) -> ConditionRegisterSourceBindingResult8616:
    """Bind semantic register operands to storage proven at their producer."""
    ordered = tuple(sorted(conditions, key=condition_sort_key_8616))
    bound: list[ConditionIR] = []
    normalized = 0
    classified = 0
    materialized = 0
    failures = 0
    for condition in ordered:
        current = condition
        for register_name, operand in condition_semantic_register_operands_8616(condition):
            if (
                not isinstance(operand, IRValue)
                or operand.space is not MemSpace.REG
                or not isinstance(condition.producer_insn, int)
            ):
                continue
            normalized += 1
            reaching = recover_register_source_before_instruction_8616(
                function,
                instruction_addr=condition.producer_insn,
                register=register_name,
            )
            source = reaching.source if reaching.verdict is RegisterReachingSourceVerdict8616.PROVEN else None
            update_binding = _register_update_binding_from_reaching_source_8616(
                function,
                source,
                width_bits=condition.width_bits,
            )
            storage = (
                update_binding[0]
                if update_binding is not None
                else _storage_from_reaching_source_8616(
                    source,
                    width_bits=condition.width_bits,
                )
            )
            if storage is None:
                storage = zero_extended_register_storage_8616(
                    function, instruction_addr=condition.producer_insn,
                    register=register_name, width_bits=condition.width_bits,
                )
            if storage is None:
                failures += 1
                continue
            classified += 1
            current = _with_register_storage_binding_8616(
                current,
                register_name=register_name,
                storage=storage,
                update=update_binding[1] if update_binding is not None else None,
            )
            materialized += 1
        bound.append(current)

    stats = ConditionRegisterSourceBindingStats8616(
        raw_fact_count=len(ordered),
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=failures,
    )
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError(
            "classified condition-register sources were not materialized",
            layer="alias",
        )
    verdict = (
        ConditionRegisterSourceBindingVerdict8616.MATERIALIZED
        if materialized
        else ConditionRegisterSourceBindingVerdict8616.UNKNOWN_REFUSE
        if normalized
        else ConditionRegisterSourceBindingVerdict8616.NO_CANDIDATE
    )
    return ConditionRegisterSourceBindingResult8616(tuple(bound), verdict, stats)
