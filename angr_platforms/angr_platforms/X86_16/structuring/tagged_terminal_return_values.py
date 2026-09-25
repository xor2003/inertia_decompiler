"""Reconcile structured returns with their exact terminal CFG paths.

Layer: Structuring.
Responsibility: consume instruction-origin tags on structured return
expressions and replace each expression only with the value proven by its own
terminal CFG predecessor. Linear whole-function return evidence is explicitly
insufficient when several value-producing predecessors exist.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CExpression, CReturn

from ..c_ast_utils import _iter_c_nodes_deep_8616
from .branch_return_expressions import (
    branch_target_imm_8616,
    recover_branch_target_return_expression_8616,
)
from .return_chains import terminal_value_block_addrs_8616


class _BlockFactory8616(Protocol):
    """Dynamic angr block-factory boundary used by CFG return ownership."""

    def block(self, addr: int, *, opt_level: int = 0) -> object:
        """Return one decoded block at an exact CFG address."""


class _CapstoneInstruction8616(Protocol):
    """Typed view of one third-party Capstone instruction."""

    address: int


class _CapstoneBlock8616(Protocol):
    """Typed view of the third-party Capstone instruction sequence."""

    insns: Iterable[_CapstoneInstruction8616]


class _DecodedBlock8616(Protocol):
    """Typed view of an angr block carrying Capstone instructions."""

    capstone: _CapstoneBlock8616


class _Project8616(Protocol):
    """Dynamic angr project boundary used by CFG return ownership."""

    factory: _BlockFactory8616


class _Function8616(Protocol):
    """Dynamic angr function boundary used by CFG return ownership."""

    block_addrs_set: Iterable[int]


class _CFunction8616(Protocol):
    """Dynamic angr structured-C function boundary."""

    statements: object | None


class _Codegen8616(Protocol):
    """Dynamic angr codegen boundary plus owned result publication."""

    cfunc: _CFunction8616 | None
    _inertia_tagged_terminal_return_value_result_8616: TaggedTerminalReturnValueResult8616


@dataclass(frozen=True, slots=True)
class TaggedTerminalReturnValueResult8616:
    """Closed evidence for path-specific terminal return materialization."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    replacement_count: int

    @property
    def changed(self) -> bool:
        """Return whether at least one stale return expression was replaced."""
        return self.replacement_count > 0


def _instruction_addresses_8616(block: object) -> frozenset[int]:
    """Return decoded instruction addresses at the Capstone boundary."""
    typed_block = cast(_DecodedBlock8616, block)
    try:
        instructions = tuple(typed_block.capstone.insns)
    except (AttributeError, TypeError):
        return frozenset()
    return frozenset(
        int(instruction.address) for instruction in instructions if isinstance(instruction.address, int)
    )


@dataclass(slots=True)
class _TaggedReturnScan8616:
    """Mutable per-return-node materialization scan state."""

    project: object
    codegen: object
    terminal_blocks: tuple[int, ...] | frozenset[int]
    decoded_addresses: dict[int, frozenset[int]]
    expressions_equivalent: Callable[[object, object], bool]
    normalized: int = 0
    classified: int = 0
    materialized: int = 0
    failures: int = 0
    replacements: int = 0

    def process(self, return_node: CReturn) -> None:
        """Materialize one tagged return node's proven value."""
        expression = return_node.retval
        if not isinstance(expression, CExpression):
            return
        tags = expression.tags
        if not isinstance(tags, dict):
            return
        block_addr = tags.get("vex_block_addr")
        instruction_addr = tags.get("ins_addr")
        if not isinstance(block_addr, int) and not isinstance(instruction_addr, int):
            return
        self.normalized += 1
        candidates = {
            candidate
            for candidate in self.terminal_blocks
            if candidate == block_addr
            or (
                isinstance(instruction_addr, int)
                and instruction_addr in self.decoded_addresses.get(candidate, frozenset())
            )
        }
        if len(candidates) != 1:
            self.failures += 1
            return
        candidate = candidates.pop()
        proven = recover_branch_target_return_expression_8616(
            self.project,
            self.codegen,
            candidate,
        )
        if not isinstance(proven, CExpression):
            self.failures += 1
            return
        self.classified += 1
        self.materialized += 1
        if self.expressions_equivalent(expression, proven):
            return
        return_node.retval = proven
        self.replacements += 1


def materialize_tagged_terminal_return_values_8616(
    project: object,
    codegen: object,
    function: object | None,
    *,
    expressions_equivalent: Callable[[object, object], bool],
) -> TaggedTerminalReturnValueResult8616:
    """Materialize each exactly tagged return from its own terminal block."""
    typed_codegen = cast(_Codegen8616, codegen)
    cfunc = typed_codegen.cfunc
    root = cfunc.statements if cfunc is not None else None
    if root is None or function is None:
        result = TaggedTerminalReturnValueResult8616(0, 0, 0, 0, 0, 0)
        typed_codegen._inertia_tagged_terminal_return_value_result_8616 = result
        return result

    typed_project = cast(_Project8616, project)
    typed_function = cast(_Function8616, function)

    def load_block(addr: int) -> object | None:
        """Load one exact block and refuse third-party decode failures."""
        try:
            return typed_project.factory.block(addr, opt_level=0)
        except Exception:
            return None

    terminal_blocks = terminal_value_block_addrs_8616(
        typed_function.block_addrs_set,
        load_block,
        branch_target_imm_8616,
    )
    decoded_addresses = {
        block_addr: _instruction_addresses_8616(block)
        for block_addr in terminal_blocks
        if (block := load_block(block_addr)) is not None
    }
    return_nodes = tuple(
        node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CReturn)
    )
    scan = _TaggedReturnScan8616(
        project,
        codegen,
        terminal_blocks,
        decoded_addresses,
        expressions_equivalent,
    )
    for return_node in return_nodes:
        scan.process(return_node)

    result = TaggedTerminalReturnValueResult8616(
        raw_fact_count=len(return_nodes),
        normalized_fact_count=scan.normalized,
        classified_fact_count=scan.classified,
        materialized_count=scan.materialized,
        failure_count=scan.failures,
        replacement_count=scan.replacements,
    )
    typed_codegen._inertia_tagged_terminal_return_value_result_8616 = result
    if result.classified_fact_count > 0 and result.materialized_count == 0:
        raise RuntimeError(
            "tagged terminal return values were classified without materialization"
        )
    return result


__all__ = [
    "TaggedTerminalReturnValueResult8616",
    "materialize_tagged_terminal_return_values_8616",
]
