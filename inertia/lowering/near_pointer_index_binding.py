"""Bind an unscaled byte index using exact pointer-carrier evidence.

Layer: Types/Lowering.
Responsibility: distinguish pointer base from scalar index in commutative
address additions. Consume decoded pointer facts and existing register/storage
identities; do not infer roles from operand order, names or rendered C.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CExpression, CVariable

from .gp_register_state import runtime_gp_expression_view_8616
from .near_pointer_argument import NearPointerArgumentFact8616
from .physical_registers import physical_register_name_8616


def bind_byte_pointer_index_8616(
    expression: object,
    facts: Sequence[NearPointerArgumentFact8616],
    instruction_addrs: frozenset[int],
    arguments: Sequence[CVariable],
    argument_offset: Callable[[object], int | None],
    *,
    codegen: object,
) -> CBinaryOp | None:
    """Replace only a uniquely proven unchanged carrier, preserving its index."""
    if not isinstance(expression, CBinaryOp) or expression.op != "Add":
        return None
    matches = tuple(fact for fact in facts if fact.access_width_bytes == 1
                    and fact.dereference_ins_addr in instruction_addrs)
    if len(matches) != 1:
        return None
    fact = matches[0]
    if (not fact.carrier_value_is_exact or fact.carrier_register_name is None
            or fact.source_version_delta != 0 or fact.source_update_ins_addrs):
        return None
    indices: list[CExpression] = []
    for base, index in ((expression.lhs, expression.rhs), (expression.rhs, expression.lhs)):
        runtime = runtime_gp_expression_view_8616(base)
        name = runtime.register_name if runtime is not None else physical_register_name_8616(base)
        if name == fact.carrier_register_name and isinstance(index, CExpression):
            indices.append(index)
    if len(indices) != 1:
        return None
    pointers = tuple(argument for argument in arguments
                     if isinstance(argument, CVariable) and argument_offset(argument) == fact.stack_offset)
    if len(pointers) != 1:
        return None
    return CBinaryOp("Add", pointers[0], indices[0], codegen=codegen, tags=dict(expression.tags or {}))
