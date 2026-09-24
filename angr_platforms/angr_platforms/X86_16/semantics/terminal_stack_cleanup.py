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
from dataclasses import dataclass, field
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

    scan = _CleanupScan8616(project=project, block_addrs=block_addrs)
    scan.follow(entry_addr, frozenset())
    return TerminalStackCleanupEvidence8616(
        cleanup_amounts=frozenset(scan.amounts),
        raw_fact_count=scan.counts[0],
        normalized_fact_count=scan.counts[1],
        classified_fact_count=scan.counts[2],
        materialized_count=scan.counts[3],
        failure_count=scan.counts[4],
        return_frame_kinds=frozenset(scan.frame_kinds),
        return_operand_bits=frozenset(scan.operand_bits),
    )


@dataclass
class _CleanupScan8616:
    """Bounded entry-reachable path walker collecting cleanup evidence."""

    project: object
    block_addrs: frozenset[int]
    amounts: set[int] = field(default_factory=set)
    frame_kinds: set[TerminalReturnFrameKind8616] = field(default_factory=set)
    operand_bits: set[int | None] = field(default_factory=set)
    counts: list[int] = field(default_factory=lambda: [0, 0, 0, 0, 0])

    def record_cleanup(
        self,
        cleanup: int,
        frame_kind: TerminalReturnFrameKind8616,
        width: int | None,
    ) -> None:
        """Record one classified terminal cleanup and frame-shape fact."""
        for index in range(4):
            self.counts[index] += 1
        self.amounts.add(cleanup)
        self.frame_kinds.add(frame_kind)
        self.operand_bits.add(width)

    def record_failure(self) -> None:
        """Record one terminal/control fact that cannot be classified."""
        self.counts[0] += 1
        self.counts[4] += 1

    def follow(self, block_addr: int, path: frozenset[int]) -> None:
        """Follow one bounded control-flow path to a return."""
        if block_addr in path:
            return
        try:
            insns = decoded_block_instructions_8616(cast(Any, self.project), block_addr, opt_level=0)
        except (KeyError, SimEngineError, SimTranslationError, ValueError):
            self.record_failure()
            return
        if not insns:
            self.record_failure()
            return
        for insn in insns:
            if self._follow_insn(insn, block_addr, path):
                return
        fallthrough = _fallthrough_8616(insns[-1])
        if isinstance(fallthrough, int) and fallthrough in self.block_addrs:
            self.follow(fallthrough, path | {block_addr})
        else:
            self.record_failure()

    def _follow_insn(self, insn: object, block_addr: int, path: frozenset[int]) -> bool:
        """Handle one instruction; return True when the path was consumed."""
        mnemonic = _mnemonic_8616(insn)
        if mnemonic.startswith("ret") or mnemonic == "iret":
            cleanup = _return_cleanup_8616(insn)
            frame_kind = _return_frame_kind_8616(insn)
            if isinstance(cleanup, int) and frame_kind is not None:
                self.record_cleanup(
                    cleanup,
                    frame_kind,
                    decoded_return_operand_bits_8616(_inner_instruction_8616(insn)),
                )
            else:
                self.record_failure()
            return True
        if mnemonic in {"jmp", "jmpw", "ljmp"}:
            target = _direct_target_8616(insn)
            if isinstance(target, int) and target in self.block_addrs:
                self.follow(target, path | {block_addr})
            else:
                self.record_failure()
            return True
        if _is_conditional_branch_8616(mnemonic):
            for successor in dict.fromkeys((_direct_target_8616(insn), _fallthrough_8616(insn))):
                if isinstance(successor, int) and successor in self.block_addrs:
                    self.follow(successor, path | {block_addr})
                else:
                    self.record_failure()
            return True
        return False


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
    direct = _direct_body_cleanup_evidence_8616(project, address)
    if direct is not None:
        cache[address] = direct
        return direct
    reachable = _reachable_body_cleanup_evidence_8616(project, address)
    if reachable is not None:
        cache[address] = reachable
        return reachable
    if known is not None:
        return known
    return TerminalStackCleanupEvidence8616(frozenset(), 1, 0, 0, 0, 1)


def _direct_body_cleanup_evidence_8616(
    project: object, address: int
) -> TerminalStackCleanupEvidence8616 | None:
    """Classify cleanup when the callee body is a single unbranched block."""
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
    if not (isinstance(cleanup, int) and frame_kind is not None):
        return None
    return TerminalStackCleanupEvidence8616(
        frozenset({cleanup}),
        1,
        1,
        1,
        1,
        0,
        frozenset({frame_kind}),
        frozenset({decoded_return_operand_bits_8616(_inner_instruction_8616(terminal))}),
    )


def _reachable_body_cleanup_evidence_8616(
    project: object, address: int
) -> TerminalStackCleanupEvidence8616 | None:
    """Classify cleanup over bounded reachable blocks in the containing object."""
    try:
        loaded = cast(_ProjectLoaderSurface8616, project).loader.find_object_containing(address)
    except (AttributeError, KeyError, TypeError):
        return None
    if not (
        loaded is not None and isinstance(loaded.min_addr, int) and isinstance(loaded.max_addr, int)
    ):
        return None
    reachability = collect_instruction_reachability_8616(
        project,
        entry=address,
        region_start=loaded.min_addr,
        region_end=loaded.max_addr + 1,
    )
    if not reachability.complete:
        return None
    reachable = _ReachableFunctionSurface8616(
        address,
        frozenset(reachability.reachable_block_addrs),
    )
    evidence = collect_terminal_stack_cleanup_evidence_8616(project, reachable)
    return evidence if evidence.complete else None
