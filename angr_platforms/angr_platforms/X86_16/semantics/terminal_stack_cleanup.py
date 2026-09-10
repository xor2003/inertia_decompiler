"""Recover callee stack cleanup from complete binary terminal paths.

Layer: Semantics.
Responsibility: classify immediate stack cleanup performed by every reachable
return without choosing or mutating a C calling convention.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Forbidden: source/COD/name evidence, rendered-text recovery, or prototype repair.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from typing import Any, Protocol, cast

from angr.errors import SimEngineError, SimTranslationError

from ..frontend_instruction_reachability import (
    collect_instruction_reachability_8616,
    decoded_block_instructions_8616,
)
from .terminal_return_contract import (
    TerminalReturnFrameKind8616,
    TerminalStackCleanupEvidence8616,
    decoded_return_operand_bits_8616,
)

__all__ = [
    "TerminalReturnFrameKind8616",
    "TerminalStackCleanupEvidence8616",
    "collect_terminal_stack_cleanup_evidence_8616",
    "terminal_stack_cleanup_at_address_8616",
]


class _FunctionSurface8616(Protocol):
    """angr function fields consumed by terminal cleanup semantics."""

    addr: int
    block_addrs_set: Collection[int]


class _LoadedObjectSurface8616(Protocol):
    """Loaded-object bounds used for bounded callee reachability."""

    min_addr: int
    max_addr: int


class _LoaderSurface8616(Protocol):
    """Third-party loader lookup needed for bodyless callee recovery."""

    def find_object_containing(self, address: int) -> _LoadedObjectSurface8616 | None:
        """Return the loaded object containing ``address``."""
        ...


class _ProjectLoaderSurface8616(Protocol):
    """Project loader boundary used by terminal cleanup recovery."""

    loader: _LoaderSurface8616


class _ProjectCleanupCacheSurface8616(Protocol):
    """Owned project extension retaining complete immutable cleanup proofs."""

    _inertia_terminal_stack_cleanup_cache_8616: dict[
        int,
        TerminalStackCleanupEvidence8616,
    ]


@dataclass(frozen=True, slots=True)
class _ReachableFunctionSurface8616:
    """Request-local function boundary proven by frontend reachability."""

    addr: int
    block_addrs_set: frozenset[int]


def _terminal_cleanup_cache_8616(
    project: object,
) -> dict[int, TerminalStackCleanupEvidence8616]:
    """Return the project-owned cache of complete callee cleanup proofs."""
    surface = cast(_ProjectCleanupCacheSurface8616, project)
    try:
        cache = surface._inertia_terminal_stack_cleanup_cache_8616
    except AttributeError:
        cache = {}
        surface._inertia_terminal_stack_cleanup_cache_8616 = cache
    if not isinstance(cache, dict):
        raise TypeError("terminal stack cleanup cache must be a dict")
    return cache


def _inner_instruction_8616(insn: object) -> object:
    """Return a dynamic Capstone instruction beneath an optional angr wrapper."""
    try:
        return cast(Any, insn).insn
    except AttributeError:
        return cast(Any, insn)


def _mnemonic_8616(insn: object) -> str:
    """Return a normalized mnemonic across the dynamic Capstone boundary."""
    try:
        return str(cast(Any, insn).mnemonic or "").lower()
    except AttributeError:
        try:
            return str(cast(Any, _inner_instruction_8616(insn)).mnemonic or "").lower()
        except AttributeError:
            return ""


def _fallthrough_8616(insn: object) -> int | None:
    """Return the next instruction address across the Capstone boundary."""
    try:
        address, size = cast(Any, insn).address, cast(Any, insn).size
    except AttributeError:
        inner = cast(Any, _inner_instruction_8616(insn))
        try:
            address, size = inner.address, inner.size
        except AttributeError:
            return None
    return address + size if isinstance(address, int) and isinstance(size, int) and size > 0 else None


def _direct_target_8616(insn: object) -> int | None:
    """Return one direct branch target across the Capstone boundary."""
    inner = cast(Any, _inner_instruction_8616(insn))
    try:
        operands = tuple(inner.operands or ())
    except AttributeError:
        return None
    if len(operands) != 1:
        return None
    operand = cast(Any, operands[0])
    return operand.imm if operand.type == 2 and isinstance(operand.imm, int) else None


def _return_cleanup_8616(insn: object) -> int | None:
    """Return a valid even near/far return immediate, including plain zero."""
    inner = cast(Any, _inner_instruction_8616(insn))
    try:
        operands = tuple(inner.operands or ())
    except AttributeError:
        return None
    if not operands:
        return 0
    if len(operands) != 1:
        return None
    operand = cast(Any, operands[0])
    cleanup = operand.imm if operand.type == 2 else None
    return cleanup if isinstance(cleanup, int) and 0 <= cleanup <= 128 and cleanup % 2 == 0 else None


def _return_frame_kind_8616(insn: object) -> TerminalReturnFrameKind8616 | None:
    """Classify the decoded machine return-frame shape without text rendering."""
    mnemonic = _mnemonic_8616(insn)
    if mnemonic in {"retf", "lret"}:
        return TerminalReturnFrameKind8616.FAR
    if mnemonic == "iret":
        return TerminalReturnFrameKind8616.INTERRUPT
    if mnemonic.startswith("ret"):
        return TerminalReturnFrameKind8616.NEAR
    return None


def _is_conditional_branch_8616(mnemonic: str) -> bool:
    """Return whether a decoded mnemonic has two control-flow successors."""
    return (mnemonic.startswith("j") and mnemonic not in {"jmp", "jmpw"}) or mnemonic.startswith("loop")


def collect_terminal_stack_cleanup_evidence_8616(
    project: object,
    function: object,
) -> TerminalStackCleanupEvidence8616:
    """Collect cleanup amounts along all bounded entry-reachable returns."""
    function_surface = cast(_FunctionSurface8616, function)
    try:
        block_addrs = frozenset(int(addr) for addr in function_surface.block_addrs_set)
        entry_addr = function_surface.addr
    except AttributeError:
        block_addrs, entry_addr = frozenset(), None
    if not isinstance(entry_addr, int) or entry_addr not in block_addrs:
        return TerminalStackCleanupEvidence8616(frozenset(), 1, 0, 0, 0, 1)
    amounts: set[int] = set()
    frame_kinds: set[TerminalReturnFrameKind8616] = set()
    operand_bits: set[int | None] = set()
    counts = [0, 0, 0, 0, 0]

    def record_cleanup(
        cleanup: int,
        frame_kind: TerminalReturnFrameKind8616,
        width: int | None,
    ) -> None:
        """Record one classified terminal cleanup and frame-shape fact."""
        for index in range(4):
            counts[index] += 1
        amounts.add(cleanup)
        frame_kinds.add(frame_kind)
        operand_bits.add(width)

    def record_failure() -> None:
        """Record one terminal/control fact that cannot be classified."""
        counts[0] += 1
        counts[4] += 1

    def scan(block_addr: int, path: frozenset[int]) -> None:
        """Follow one bounded control-flow path to a return."""
        if block_addr in path:
            return
        try:
            insns = decoded_block_instructions_8616(cast(Any, project), block_addr, opt_level=0)
        except (KeyError, SimEngineError, SimTranslationError, ValueError):
            record_failure()
            return
        if not insns:
            record_failure()
            return
        for insn in insns:
            mnemonic = _mnemonic_8616(insn)
            if mnemonic.startswith("ret") or mnemonic == "iret":
                cleanup = _return_cleanup_8616(insn)
                frame_kind = _return_frame_kind_8616(insn)
                if isinstance(cleanup, int) and frame_kind is not None:
                    record_cleanup(cleanup, frame_kind, decoded_return_operand_bits_8616(_inner_instruction_8616(insn)))
                else:
                    record_failure()
                return
            if mnemonic in {"jmp", "jmpw", "ljmp"}:
                target = _direct_target_8616(insn)
                if isinstance(target, int) and target in block_addrs:
                    scan(target, path | {block_addr})
                else:
                    record_failure()
                return
            if _is_conditional_branch_8616(mnemonic):
                for successor in dict.fromkeys((_direct_target_8616(insn), _fallthrough_8616(insn))):
                    if isinstance(successor, int) and successor in block_addrs:
                        scan(successor, path | {block_addr})
                    else:
                        record_failure()
                return
        fallthrough = _fallthrough_8616(insns[-1])
        if isinstance(fallthrough, int) and fallthrough in block_addrs:
            scan(fallthrough, path | {block_addr})
        else:
            record_failure()

    scan(entry_addr, frozenset())
    return TerminalStackCleanupEvidence8616(
        cleanup_amounts=frozenset(amounts),
        raw_fact_count=counts[0],
        normalized_fact_count=counts[1],
        classified_fact_count=counts[2],
        materialized_count=counts[3],
        failure_count=counts[4],
        return_frame_kinds=frozenset(frame_kinds),
        return_operand_bits=frozenset(operand_bits),
    )


def terminal_stack_cleanup_at_address_8616(
    project: object,
    address: int,
) -> TerminalStackCleanupEvidence8616:
    """Collect cleanup from a known or bounded binary-reachable callee body."""
    cache = _terminal_cleanup_cache_8616(project)
    cached = cache.get(address)
    if cached is not None:
        return cached
    try:
        function = cast(Any, project).kb.functions.function(addr=address, create=False)
    except (AttributeError, KeyError):
        function = None
    if function is not None:
        known = collect_terminal_stack_cleanup_evidence_8616(project, function)
        if known.complete:
            cache[address] = known
            return known
    else:
        known = None
    try:
        insns = decoded_block_instructions_8616(cast(Any, project), address, opt_level=0)
    except (KeyError, SimEngineError, SimTranslationError, ValueError):
        insns = ()
    direct_body_is_branched = any(
        _is_conditional_branch_8616(_mnemonic_8616(insn))
        or _mnemonic_8616(insn) in {"jmp", "jmpw", "ljmp"}
        for insn in insns
    )
    terminal = None if not insns or direct_body_is_branched else insns[-1]
    cleanup = (
        _return_cleanup_8616(terminal)
        if terminal is not None and _mnemonic_8616(terminal).startswith("ret")
        else None
    )
    frame_kind = _return_frame_kind_8616(terminal) if terminal is not None else None
    if isinstance(cleanup, int) and frame_kind is not None:
        evidence = TerminalStackCleanupEvidence8616(
            frozenset({cleanup}),
            1,
            1,
            1,
            1,
            0,
            frozenset({frame_kind}),
            frozenset({decoded_return_operand_bits_8616(_inner_instruction_8616(terminal))}),
        )
        cache[address] = evidence
        return evidence

    try:
        loaded = cast(_ProjectLoaderSurface8616, project).loader.find_object_containing(address)
    except (AttributeError, KeyError, TypeError):
        loaded = None
    if loaded is not None and isinstance(loaded.min_addr, int) and isinstance(loaded.max_addr, int):
        reachability = collect_instruction_reachability_8616(
            project,
            entry=address,
            region_start=loaded.min_addr,
            region_end=loaded.max_addr + 1,
        )
        if reachability.complete:
            reachable = _ReachableFunctionSurface8616(
                address,
                frozenset(reachability.reachable_block_addrs),
            )
            evidence = collect_terminal_stack_cleanup_evidence_8616(project, reachable)
            if evidence.complete:
                cache[address] = evidence
                return evidence
    if known is not None:
        return known
    return TerminalStackCleanupEvidence8616(frozenset(), 1, 0, 0, 0, 1)
