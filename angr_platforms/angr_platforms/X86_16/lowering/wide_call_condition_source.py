"""Select a wide call result through Alias reaching-definition evidence.

Layer: Types/Lowering.
Responsibility: require one typed call candidate to supply every register use
in a wide predicate. Alias owns joins, partial writes and clobber semantics.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from typing import Protocol, cast

from .. import register_source_block_inventory
from ..alias.condition_register_definition import resolve_condition_register_definition_8616
from ..ir.condition_ir import ConditionIR
from ..ir.core import IRValue, MemSpace


class _Functions(Protocol):
    """Existing angr function lookup boundary."""

    def function(self, *, addr: int, create: bool) -> object | None:
        """Find a function without changing CFG discovery."""


class _KnowledgeBase(Protocol):
    """angr function inventory boundary."""

    functions: _Functions


class _Project(Protocol):
    """angr project boundary."""

    kb: _KnowledgeBase


class _Function(Protocol):
    """Current generated function coordinate."""

    addr: int


class _Codegen(Protocol):
    """angr codegen boundary for exact binary evidence."""

    project: _Project
    cfunc: _Function


def proven_wide_condition_callsite_8616(
    codegen: object,
    conditions: tuple[ConditionIR, ...],
    candidate_addrs: frozenset[int],
) -> int | None:
    """Require the same candidate at every operand's producer boundary.

    Candidate addresses must already carry a typed DX:AX call-result contract.
    Unknown, partial or conflicting definitions refuse before AST mutation.
    """
    boundary = cast(_Codegen, codegen)
    try:
        function = boundary.project.kb.functions.function(addr=boundary.cfunc.addr, create=False)
    except (AttributeError, TypeError):
        return None
    if function is None or not conditions or not candidate_addrs:
        return None
    inventory = register_source_block_inventory.collect_register_source_block_inventory_8616(function)
    definitions: set[int] = set()
    for condition in conditions:
        operand = condition.lhs
        address = condition.producer_insn if isinstance(condition.producer_insn, int) else condition.src_insn
        if not isinstance(operand, IRValue) or operand.space is not MemSpace.REG:
            return None
        if not isinstance(address, int) or not isinstance(operand.name, str) or operand.size is None:
            return None
        proof = resolve_condition_register_definition_8616(
            inventory, instruction_addr=address, register=operand.name,
            size=operand.size, candidate_addrs=candidate_addrs,
        )
        if proof.instruction_addr is None:
            return None
        definitions.add(proof.instruction_addr)
    return next(iter(definitions)) if len(definitions) == 1 else None
