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

from typing import Protocol, cast

from .. import register_source_block_inventory
from ..alias.condition_register_definition import resolve_condition_register_definition_8616


class _FunctionManager(Protocol):
    """angr function lookup boundary."""

    def function(self, *, addr: int, create: bool) -> object | None:
        """Find an existing function without changing CFG discovery."""


class _KnowledgeBase(Protocol):
    """angr knowledge-base boundary."""

    functions: _FunctionManager


class _Project(Protocol):
    """angr project boundary."""

    kb: _KnowledgeBase


class _CFunction(Protocol):
    """angr structured function coordinate."""

    addr: int


class _Codegen(Protocol):
    """angr codegen boundary for the current function."""

    cfunc: _CFunction


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
        function = cast(_Project, project).kb.functions.function(
            addr=cast(_Codegen, codegen).cfunc.addr, create=False,
        )
    except (AttributeError, TypeError):
        return None
    if function is None:
        return None
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
