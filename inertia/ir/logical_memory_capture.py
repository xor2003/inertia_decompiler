"""Capture typed logical-memory intent while the frontend emits execution IR.

Layer: IR.
Responsibility: transport one function-scoped machine operand from frontend lift
to the IR importer with exact block, instruction, width, and ordinal identity.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

from .core import IRAddress
from .logical_memory_contracts import IRMemoryAccessKind8616


def memory_access_kind_from_mode_8616(mode: int) -> IRMemoryAccessKind8616:
    """Normalize the dynamic frontend mode integer into a typed IR operation."""
    return {
        0: IRMemoryAccessKind8616.READ,
        1: IRMemoryAccessKind8616.WRITE,
        2: IRMemoryAccessKind8616.EXECUTE,
    }.get(mode, IRMemoryAccessKind8616.UNKNOWN)


@dataclass(frozen=True, slots=True)
class IRLogicalMemoryCaptureRecord8616:
    """Raw typed machine-operand evidence captured during one instruction lift."""

    function_addr: int
    block_addr: int | None
    insn_addr: int | None
    access_ordinal: int | None
    kind: IRMemoryAccessKind8616
    address_bits: int | None
    address: IRAddress | None

    @property
    def mode(self) -> int:
        """Expose the legacy frontend mode for compatibility-only consumers."""
        return {
            IRMemoryAccessKind8616.READ: 0,
            IRMemoryAccessKind8616.WRITE: 1,
            IRMemoryAccessKind8616.EXECUTE: 2,
        }.get(self.kind, -1)

    @property
    def addr(self) -> IRAddress | None:
        """Expose the legacy address name for compatibility-only consumers."""
        return self.address


@dataclass(slots=True)
class IRLogicalMemoryCaptureCollection8616:
    """Function-owned logical operands captured during one explicit lift."""

    function_addr: int
    accesses: list[IRLogicalMemoryCaptureRecord8616] = field(default_factory=list)
    next_ordinals: dict[tuple[int, int], int] = field(default_factory=dict)

    def allocate_ordinal(self, block_addr: int | None, insn_addr: int | None) -> int | None:
        """Allocate one deterministic per-instruction access ordinal when possible."""
        if block_addr is None or insn_addr is None:
            return None
        site = (block_addr, insn_addr)
        ordinal = self.next_ordinals.get(site, 0)
        self.next_ordinals[site] = ordinal + 1
        return ordinal


_active_collection: ContextVar[IRLogicalMemoryCaptureCollection8616 | None] = ContextVar(
    "x86_16_active_logical_memory_collection",
    default=None,
)
_active_block_addr: ContextVar[int | None] = ContextVar(
    "x86_16_active_logical_memory_block",
    default=None,
)


@contextmanager
def collect_accesses_for_function(
    function_addr: int,
) -> Iterator[IRLogicalMemoryCaptureCollection8616]:
    """Capture logical accesses for one function without process-global keys."""
    if not isinstance(function_addr, int):
        raise TypeError("function_addr must be an integer")
    collection = IRLogicalMemoryCaptureCollection8616(function_addr=function_addr)
    token = _active_collection.set(collection)
    try:
        yield collection
    finally:
        _active_collection.reset(token)


@contextmanager
def collect_accesses_for_block(block_addr: int) -> Iterator[None]:
    """Attach exact block ownership to accesses emitted by one factory lift."""
    if not isinstance(block_addr, int):
        raise TypeError("block_addr must be an integer")
    token = _active_block_addr.set(block_addr)
    try:
        yield
    finally:
        _active_block_addr.reset(token)


def get_current_function_addr() -> int | None:
    """Return the function owned by the active logical-memory collection."""
    collection = _active_collection.get()
    return collection.function_addr if collection is not None else None


def record_access(
    function_addr: int,
    mode: int,
    addr: object,
    *,
    block_addr: int | None = None,
    insn_addr: int | None = None,
    address_bits: int | None = None,
) -> None:
    """Record one access only when the active collection owns its function."""
    collection = _active_collection.get()
    if collection is None or collection.function_addr != function_addr:
        return
    owned_block_addr = block_addr if block_addr is not None else _active_block_addr.get()
    ordinal = collection.allocate_ordinal(owned_block_addr, insn_addr)
    collection.accesses.append(
        IRLogicalMemoryCaptureRecord8616(
            function_addr=function_addr,
            block_addr=owned_block_addr,
            insn_addr=insn_addr,
            access_ordinal=ordinal,
            kind=memory_access_kind_from_mode_8616(mode),
            address_bits=address_bits,
            address=addr if isinstance(addr, IRAddress) else None,
        )
    )


__all__ = [
    "IRLogicalMemoryCaptureCollection8616",
    "IRLogicalMemoryCaptureRecord8616",
    "collect_accesses_for_block",
    "collect_accesses_for_function",
    "get_current_function_addr",
    "memory_access_kind_from_mode_8616",
    "record_access",
]
