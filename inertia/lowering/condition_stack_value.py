# cython: language_level=3, infer_types=True
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
import typing
import cython

from collections.abc import Iterable, Mapping

from angr.analyses.decompiler.structured_codegen.c import CExpression
from angr.sim_variable import SimStackVariable

from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace

from .condition_stack_operands import materialize_typed_condition_stack_operand_8616
from .stack_variable_binding import StackVariableBinding, stable_stack_binding_tags_8616
import operator
import builtins


def complete_storage_signedness_requests_8616(
    requests: Mapping[cython.longlong, cython.longlong], variables: Iterable[SimStackVariable],
) -> object:
    """Keep only whole-owner signedness requests; never infer storage width.

    Offsets use the existing storage inventory's coordinates. A partial view
    cannot type its wider owner, and competing overlapping owners must refuse.
    This proof permits sign interpretation only, not widening or ABI recovery.
    """
    offset: object
    size: object
    owners = {(variable.offset, variable.size) for variable in iter(variables) if variable.base == "bp"}
    accepted: dict[cython.longlong, cython.longlong] = {}
    for offset, size in requests.items():
        if size <= 0 or (offset, size) not in owners:
            continue
        conflicting = any(
            (owner_offset, owner_size) != (offset, size)
            and (owner_offset == offset or max(offset, owner_offset) < min(offset + size, owner_offset + owner_size))
            for owner_offset, owner_size in iter(owners)
        )
        if not conflicting:
            accepted[offset] = size
    return accepted


@cython.ccall
def condition_stack_operand_tags_8616(
    operand: IRValue, size: cython.longlong, *, name: object = None,
) -> object:
    """Keep operand-owned load provenance separate from condition-owner tags."""
    binding = StackVariableBinding(int(operand.offset), size, var_name=name)
    tags = {str(key): value for key, value in builtins.iter(stable_stack_binding_tags_8616(binding).items())}
    if isinstance(operand.memory_access_insn, int):
        tags["inertia_source_instruction_addrs"] = (operand.memory_access_insn,)
    return tags


@cython.ccall
def materialize_condition_stack_value_8616(
    operand: IRValue,
    codegen: object,
    *,
    signed: cython.bint = False,
    cond: ConditionIR | None = None,
) -> CExpression | None:
    """Build a stack expression retaining typed width, signedness and provenance."""
    if operator.ne(operand.space, MemSpace.SS):
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
