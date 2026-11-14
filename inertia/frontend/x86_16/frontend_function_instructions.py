# cython: language_level=3, infer_types=True
"""Collect exact and bounded per-function instruction evidence.

Layer: Frontend.
Responsibility: bind decoded Capstone instructions to one explicit function
entry through CFG-owned blocks or an explicit bounded sequential window,
without assigning semantic effects.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from .frontend_instruction_reachability import decoded_block_instructions_8616
import dataclasses
import operator
import builtins

__all__ = [
    "BoundedLinearInstructionInventory8616",
    "BoundedLinearInstructionStatus8616",
    "FunctionInstructionInventory8616",
    "FunctionInstructionInventoryStatus8616",
    "collect_bounded_linear_instruction_inventory_8616",
    "collect_function_instruction_inventory_8616",
]


class _FunctionBoundary8616(Protocol):
    """angr function fields consumed at the Frontend boundary."""

    block_addrs_set: Iterable[cython.longlong]


class _InstructionBoundary8616(Protocol):
    """Capstone instruction identity consumed at the Frontend boundary."""

    address: cython.longlong
    mnemonic: object
    size: cython.longlong


class _FunctionManagerBoundary8616(Protocol):
    """Narrow angr knowledge-base function lookup boundary."""

    def function(
        self,
        *,
        addr: cython.longlong,
        create: cython.bint = False,
    ) -> _FunctionBoundary8616 | None:
        """Return the function whose entry is ``addr``."""


class _KnowledgeBaseBoundary8616(Protocol):
    """Narrow angr knowledge-base boundary."""

    functions: _FunctionManagerBoundary8616


class _ProjectBoundary8616(Protocol):
    """Narrow angr project boundary used for function instruction lookup."""

    kb: _KnowledgeBaseBoundary8616


class FunctionInstructionInventoryStatus8616(Enum):
    """Typed result of binding decoded instructions to one CFG function."""

    COMPLETE = "complete"
    MISSING_ENTRY = "missing_entry"
    MISSING_FUNCTION = "missing_function"
    MISSING_BLOCKS = "missing_blocks"
    DECODE_REFUSED = "decode_refused"


class BoundedLinearInstructionStatus8616(Enum):
    """Typed termination reason for one bounded sequential decode."""

    TERMINAL_REACHED = "terminal_reached"
    WINDOW_EXHAUSTED = "window_exhausted"
    EXACT_END_REACHED = "exact_end_reached"
    DECODE_REFUSED = "decode_refused"
    INVALID_WIDTH = "invalid_width"
    MISSING_ENTRY = "missing_entry"


@dataclasses.dataclass(frozen=True, )
class BoundedLinearInstructionInventory8616:
    """Immutable bounded instruction evidence merged with exact CFG evidence."""

    function_entry: int | None
    max_bytes: cython.longlong
    exact_end: int | None
    base_surface: object
    instructions: object
    sequential_instructions: object
    status: BoundedLinearInstructionStatus8616
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    @property
    def closed(self) -> cython.bint:
        """Return whether every classified fact materialized or failed."""
        return bool(
            operator.eq(self.raw_fact_count, self.normalized_fact_count)
            and operator.eq(self.normalized_fact_count, self.classified_fact_count)
            and operator.eq(self.classified_fact_count, self.materialized_count + self.failure_count)
        )


@dataclasses.dataclass(frozen=True, )
class FunctionInstructionInventory8616:
    """Instruction evidence owned by one exact CFG function entry."""

    function_entry: int | None
    block_addrs: object
    instructions: object
    status: FunctionInstructionInventoryStatus8616
    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    @property
    def complete(self) -> cython.bint:
        """Return whether every CFG block produced instruction evidence."""
        return (
            self.status is FunctionInstructionInventoryStatus8616.COMPLETE
            and self.raw_fact_count > 0
            and operator.eq(self.raw_fact_count, self.normalized_fact_count)
            and operator.eq(self.normalized_fact_count, self.classified_fact_count)
            and operator.eq(self.classified_fact_count, self.materialized_count + self.failure_count)
            and self.failure_count == 0
            and bool(self.instructions)
        )


@cython.ccall
def _refused_inventory_8616(
    function_entry: int | None,
    status: FunctionInstructionInventoryStatus8616,
) -> FunctionInstructionInventory8616:
    """Build a closed one-fact refusal for missing function identity evidence."""
    return FunctionInstructionInventory8616(
        function_entry=function_entry,
        block_addrs=(),
        instructions=(),
        status=status,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=1,
    )


@cython.ccall
def _decode_function_block_instructions_8616(
    project: object,
    block_addrs: object,
) -> tuple[dict[cython.longlong, object], cython.longlong, cython.longlong]:
    """Decode CFG-owned blocks while retaining one closed failure count."""
    block_addr: object
    instruction: object
    by_addr: dict[cython.longlong, object] = {}
    materialized_count = 0
    failure_count = 0
    for block_addr in block_addrs:
        try:
            decoded = decoded_block_instructions_8616(
                project,
                block_addr,
                opt_level=0,
            )
        except Exception:
            decoded = ()
        if not decoded or operator.ne(int(cast(_InstructionBoundary8616, decoded[0]).address), block_addr):
            failure_count += 1
            continue
        materialized_count += 1
        for instruction in decoded:
            address = int(cast(_InstructionBoundary8616, instruction).address)
            if address >= 0:
                by_addr.setdefault(address, instruction)
    return by_addr, materialized_count, failure_count


def collect_function_instruction_inventory_8616(
    project: object,
    *,
    function_entry: int | None,
) -> FunctionInstructionInventory8616:
    """Decode only blocks owned by the exact current CFG function."""
    function: object
    if not isinstance(function_entry, int):
        return _refused_inventory_8616(
            None,
            FunctionInstructionInventoryStatus8616.MISSING_ENTRY,
        )

    boundary = cast(_ProjectBoundary8616, project)
    try:
        function = boundary.kb.functions.function(
            addr=int(function_entry),
            create=False,
        )
    except Exception:
        function = None
    if function is None:
        return _refused_inventory_8616(
            int(function_entry),
            FunctionInstructionInventoryStatus8616.MISSING_FUNCTION,
        )

    try:
        block_addrs = tuple(sorted({int(addr) for addr in iter(function.block_addrs_set)}))
    except (AttributeError, TypeError, ValueError):
        block_addrs = ()
    if not block_addrs:
        return _refused_inventory_8616(
            int(function_entry),
            FunctionInstructionInventoryStatus8616.MISSING_BLOCKS,
        )

    by_addr, materialized_count, failure_count = _decode_function_block_instructions_8616(
        project,
        block_addrs,
    )

    status = (
        FunctionInstructionInventoryStatus8616.COMPLETE
        if failure_count == 0 and by_addr
        else FunctionInstructionInventoryStatus8616.DECODE_REFUSED
    )
    fact_count = len(block_addrs)
    return FunctionInstructionInventory8616(
        function_entry=int(function_entry),
        block_addrs=block_addrs,
        instructions=tuple(by_addr[address] for address in builtins.iter(sorted(by_addr))),
        status=status,
        raw_fact_count=fact_count,
        normalized_fact_count=fact_count,
        classified_fact_count=fact_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
    )


def _instruction_surface_8616(
    instructions: object,
) -> tuple[tuple[cython.longlong, cython.longlong, str], ...]:
    """Project immutable decode fields used to validate bounded-cache reuse."""
    return tuple(
        (
            int(cast(_InstructionBoundary8616, instruction).address),
            int(cast(_InstructionBoundary8616, instruction).size),
            str(cast(_InstructionBoundary8616, instruction).mnemonic).lower(),
        )
        for instruction in iter(instructions)
    )


def collect_bounded_linear_instruction_inventory_8616(
    project: object,
    *,
    function_entry: int | None,
    base_instructions: object,
    previous: BoundedLinearInstructionInventory8616 | None = None,
    max_bytes: cython.longlong = 0x800,
    exact_end: int | None = None,
) -> BoundedLinearInstructionInventory8616:
    """Decode one bounded sequential stream and merge exact base evidence.

    This Frontend owner records instruction bytes and order only. It does not
    classify control flow, conditions, storage, types, or C-AST semantics.
    """
    instruction: object
    bounded_bytes = max(1, int(max_bytes))
    bounded_exact_end = (
        int(exact_end)
        if isinstance(exact_end, int)
        else (
            int(function_entry) + bounded_bytes
            if isinstance(function_entry, int)
            else None
        )
    )
    if isinstance(exact_end, int) and isinstance(function_entry, int):
        bounded_exact_end = min(exact_end, int(function_entry) + bounded_bytes)
        bounded_bytes = max(1, bounded_exact_end - int(function_entry))
    base_surface = _instruction_surface_8616(base_instructions)
    if (
        previous is not None
        and operator.eq(previous.function_entry, function_entry)
        and operator.eq(previous.max_bytes, bounded_bytes)
        and operator.eq(previous.exact_end, bounded_exact_end)
        and operator.eq(previous.base_surface, base_surface)
    ):
        return previous
    if not isinstance(function_entry, int):
        return BoundedLinearInstructionInventory8616(
            function_entry=None,
            max_bytes=bounded_bytes,
            exact_end=None,
            base_surface=base_surface,
            instructions=base_instructions,
            sequential_instructions=(),
            status=BoundedLinearInstructionStatus8616.MISSING_ENTRY,
            raw_fact_count=len(base_instructions) + 1,
            normalized_fact_count=len(base_instructions) + 1,
            classified_fact_count=len(base_instructions) + 1,
            materialized_count=len(base_instructions),
            failure_count=1,
        )

    sequential: list[object] = []
    address = int(function_entry)
    end_address = (
        int(bounded_exact_end)
        if isinstance(bounded_exact_end, int)
        else address + bounded_bytes
    )
    status = (
        BoundedLinearInstructionStatus8616.EXACT_END_REACHED
        if exact_end is not None
        else BoundedLinearInstructionStatus8616.WINDOW_EXHAUSTED
    )
    while address < end_address:
        try:
            decoded = decoded_block_instructions_8616(
                project,
                address,
                num_inst=1,
                opt_level=0,
            )
        except Exception:
            status = BoundedLinearInstructionStatus8616.DECODE_REFUSED
            break
        if not decoded:
            status = BoundedLinearInstructionStatus8616.DECODE_REFUSED
            break
        instruction = decoded[0]
        sequential.append(instruction)
        boundary = cast(_InstructionBoundary8616, instruction)
        width = int(boundary.size)
        mnemonic = str(boundary.mnemonic).lower()
        if exact_end is None and mnemonic in {"ret", "retf", "iret"}:
            status = BoundedLinearInstructionStatus8616.TERMINAL_REACHED
            break
        if width <= 0:
            status = BoundedLinearInstructionStatus8616.INVALID_WIDTH
            break
        address += width

    by_address = {
        int(cast(_InstructionBoundary8616, instruction).address): instruction
        for instruction in iter(base_instructions)
    }
    for instruction in sequential:
        by_address[int(cast(_InstructionBoundary8616, instruction).address)] = instruction
    instructions = tuple(by_address[item_address] for item_address in builtins.iter(sorted(by_address)))
    failure_count = int(
        status
        in {
            BoundedLinearInstructionStatus8616.DECODE_REFUSED,
            BoundedLinearInstructionStatus8616.INVALID_WIDTH,
        }
    )
    fact_count = len(instructions) + failure_count
    return BoundedLinearInstructionInventory8616(
        function_entry=int(function_entry),
        max_bytes=bounded_bytes,
        exact_end=end_address,
        base_surface=base_surface,
        instructions=instructions,
        sequential_instructions=tuple(sequential),
        status=status,
        raw_fact_count=fact_count,
        normalized_fact_count=fact_count,
        classified_fact_count=fact_count,
        materialized_count=len(instructions),
        failure_count=failure_count,
    )
