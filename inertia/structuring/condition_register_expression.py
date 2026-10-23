"""Bind condition register expressions to exact Alias definition proofs.

Layer: Structuring.
Responsibility: select an existing C expression by a proven instruction identity.
CFG joins and storage identity belong to Alias, not this projection consumer.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from inertia.alias.condition_register_definition import resolve_condition_register_definition_8616
from inertia.ir.vex_import import codegen_function_8616
from inertia.semantics import register_source_block_inventory as register_source_block_inventory


def condition_register_expression_8616(
    project: object,
    codegen: object,
    expressions: dict[tuple[int, str, int], object],
    *,
    instruction_addr: int,
    register: str,
    size: int,
) -> object | None:
    """Select only a definition proven to reach this exact condition boundary."""
    try:
        resolved = codegen_function_8616(project, codegen)
    except (AttributeError, TypeError):
        return None
    if resolved is None:
        return None
    function, _ = resolved
    candidates = {
        address: expression
        for (address, name, width), expression in expressions.items()
        if name == register.lower() and width == size
    }
    inventory = register_source_block_inventory.collect_register_source_block_inventory_8616(function)
    proof = resolve_condition_register_definition_8616(
        inventory, instruction_addr=instruction_addr, register=register,
        size=size, candidate_addrs=frozenset(candidates),
    )
    return candidates.get(proof.instruction_addr) if proof.instruction_addr is not None else None
