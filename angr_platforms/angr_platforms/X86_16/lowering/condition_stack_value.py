"""Materialize typed stack condition operands without losing access provenance.

Layer: Types/Lowering.
Responsibility: consume proven stack coordinates and operand-owned load
addresses to build typed C views. Branch and flag-producer addresses are not
memory-access evidence and must not be substituted for missing operand facts.
Sign-only declaration requests must cover a complete storage owner; partial
operand views never authorize resizing that owner.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from angr.analyses.decompiler.structured_codegen.c import CExpression
from angr.sim_variable import SimStackVariable

from ..ir.condition_ir import ConditionIR
from ..ir.core import IRValue, MemSpace
from .condition_stack_operands import materialize_typed_condition_stack_operand_8616
from .stack_variable_binding import StackVariableBinding, stable_stack_binding_tags_8616


def complete_storage_signedness_requests_8616(
    requests: Mapping[int, int], variables: Iterable[SimStackVariable],
) -> dict[int, int]:
    """Keep only whole-owner signedness requests; never infer storage width.

    Offsets use the existing storage inventory's coordinates. A partial view
    cannot type its wider owner, and competing overlapping owners must refuse.
    This proof permits sign interpretation only, not widening or ABI recovery.
    """
    owners = {(variable.offset, variable.size) for variable in variables if variable.base == "bp"}
    accepted: dict[int, int] = {}
    for offset, size in requests.items():
        if size <= 0 or (offset, size) not in owners:
            continue
        conflicting = any(
            (owner_offset, owner_size) != (offset, size)
            and (owner_offset == offset or max(offset, owner_offset) < min(offset + size, owner_offset + owner_size))
            for owner_offset, owner_size in owners
        )
        if not conflicting:
            accepted[offset] = size
    return accepted


def condition_stack_operand_tags_8616(
    operand: IRValue, size: int, *, name: str | None = None,
) -> dict[str, object]:
    """Keep operand-owned load provenance separate from condition-owner tags."""
    binding = StackVariableBinding(int(operand.offset), size, var_name=name)
    tags = {str(key): value for key, value in stable_stack_binding_tags_8616(binding).items()}
    if isinstance(operand.memory_access_insn, int):
        tags["inertia_source_instruction_addrs"] = (operand.memory_access_insn,)
    return tags


def materialize_condition_stack_value_8616(
    operand: IRValue,
    codegen: object,
    *,
    signed: bool = False,
    cond: ConditionIR | None = None,
) -> CExpression | None:
    """Build a stack expression retaining typed width, signedness and provenance."""
    if operand.space != MemSpace.SS:
        return None
    base = operand.name if operand.name in {"bp", "sp"} else "bp"
    offset = int(operand.offset)
    size = int(operand.size or 2)
    if cond is not None and isinstance(cond.width_bits, int) and cond.width_bits > 0:
        condition_size = max(1, (cond.width_bits + 7) // 8)
        if size > condition_size:
            size = condition_size
    prefix = "arg" if base == "bp" and offset > 0 else "local"
    name = f"{prefix}_{abs(offset):x}"
    return materialize_typed_condition_stack_operand_8616(
        codegen,
        base=base,
        offset=offset,
        size=max(size, 1),
        name=name,
        signed=signed,
        prefer_signed_local_storage=signed,
        tags=condition_stack_operand_tags_8616(operand, max(size, 1), name=name),
    )
