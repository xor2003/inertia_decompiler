"""Join exact register-source transfers across a function CFG.

Layer: Alias.
Responsibility: prove one register source reaches an exact instruction boundary
across all CFG paths from an exact function entry.
Owns storage identity and cross-block reaching-source joins.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
Widening remains a downstream consumer of this Alias proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .callsite_stack_merge import CallsiteSource8616

__all__ = (
    "RegisterBlockTransfer8616",
    "RegisterBlockTransferKind8616",
    "RegisterReachingSourceResult8616",
    "RegisterReachingSourceVerdict8616",
    "callsite_source_reads_memory_8616",
    "resolve_register_reaching_source_8616",
)


class RegisterBlockTransferKind8616(StrEnum):
    """Effect of one decoded block prefix on a tracked register source."""

    PRESERVE = "preserve"
    REPLACE = "replace"
    KILL = "kill"


@dataclass(frozen=True, slots=True)
class RegisterBlockTransfer8616:
    """One exact block transfer and its complete in-function predecessors."""

    block_addr: int
    predecessor_addrs: tuple[int, ...]
    kind: RegisterBlockTransferKind8616
    source: CallsiteSource8616 | None = None
    clobbers_memory_sources: bool = False

    def is_well_formed(self) -> bool:
        """Return whether the transfer carries a coherent typed payload."""
        return (
            self.block_addr >= 0
            and len(set(self.predecessor_addrs)) == len(self.predecessor_addrs)
            and ((self.kind is RegisterBlockTransferKind8616.REPLACE) == (self.source is not None))
            and isinstance(self.clobbers_memory_sources, bool)
            and (
                not self.clobbers_memory_sources
                or self.kind is RegisterBlockTransferKind8616.PRESERVE
            )
        )


class RegisterReachingSourceVerdict8616(StrEnum):
    """Typed outcome of one cross-CFG register-source proof."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class RegisterReachingSourceResult8616:
    """One reaching source plus the required closed evidence counters."""

    verdict: RegisterReachingSourceVerdict8616
    source: CallsiteSource8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


class _FlowKind8616(StrEnum):
    """Internal monotone lattice state for CFG propagation."""

    BOTTOM = "bottom"
    KNOWN = "known"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class _FlowState8616:
    """One internal reaching-source lattice value."""

    kind: _FlowKind8616
    source: CallsiteSource8616 | None = None


_BOTTOM_8616 = _FlowState8616(_FlowKind8616.BOTTOM)
_UNKNOWN_8616 = _FlowState8616(_FlowKind8616.UNKNOWN)


def callsite_source_reads_memory_8616(source: CallsiteSource8616 | None) -> bool:
    """Find memory reads through source, operation and operand tuple layers.

    Expression operations carry nested sources independently of the base
    source. Their grouping tuples must not hide a mutable-memory dependency.
    Address-only sources remain independent of the pointed-to contents.
    """
    if not source:
        return False
    kind = source[0]
    if kind in {"bp", "global", "global_index", "seg_indirect"}:
        return True
    return any(
        callsite_source_reads_memory_8616(item)
        for item in source
        if isinstance(item, tuple)
    )


def _join_states_8616(states: tuple[_FlowState8616, ...]) -> _FlowState8616:
    """Join reached predecessors; conflicts and unknown paths stay unknown."""
    reached = tuple(state for state in states if state.kind is not _FlowKind8616.BOTTOM)
    if not reached:
        return _BOTTOM_8616
    if any(state.kind is _FlowKind8616.UNKNOWN for state in reached):
        return _UNKNOWN_8616
    first = reached[0].source
    if first is None or any(state.source != first for state in reached[1:]):
        return _UNKNOWN_8616
    return _FlowState8616(_FlowKind8616.KNOWN, first)


def _apply_transfer_8616(
    incoming: _FlowState8616,
    transfer: RegisterBlockTransfer8616,
) -> _FlowState8616:
    """Apply one block transfer to a monotone incoming state."""
    if incoming.kind is _FlowKind8616.BOTTOM:
        return _BOTTOM_8616
    if transfer.kind is RegisterBlockTransferKind8616.KILL:
        return _UNKNOWN_8616
    if transfer.kind is RegisterBlockTransferKind8616.REPLACE:
        return _FlowState8616(_FlowKind8616.KNOWN, transfer.source)
    if transfer.clobbers_memory_sources and callsite_source_reads_memory_8616(incoming.source):
        return _UNKNOWN_8616
    return incoming


def resolve_register_reaching_source_8616(
    transfers: tuple[RegisterBlockTransfer8616, ...],
    *,
    entry_addr: int,
    sink_addr: int,
) -> RegisterReachingSourceResult8616:
    """Prove the same exact register source reaches ``sink_addr`` on all paths."""
    raw_count = len(transfers)
    normalized = tuple(transfer for transfer in transfers if transfer.is_well_formed())
    by_addr = {transfer.block_addr: transfer for transfer in normalized}
    malformed = (
        len(normalized) != raw_count
        or len(by_addr) != len(normalized)
        or entry_addr not in by_addr
        or sink_addr not in by_addr
        or any(pred not in by_addr for transfer in normalized for pred in transfer.predecessor_addrs)
    )
    if malformed:
        return RegisterReachingSourceResult8616(
            RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE,
            None,
            raw_count,
            len(normalized),
            0,
            0,
            1,
        )

    outputs = dict.fromkeys(by_addr, _BOTTOM_8616)
    iteration_limit = max(len(by_addr) * 3, 1)
    for _iteration in range(iteration_limit):
        changed = False
        for block_addr, transfer in sorted(by_addr.items()):
            incoming = (
                _UNKNOWN_8616
                if block_addr == entry_addr
                else _join_states_8616(
                    tuple(outputs[pred] for pred in transfer.predecessor_addrs)
                )
            )
            updated = _apply_transfer_8616(incoming, transfer)
            if updated != outputs[block_addr]:
                outputs[block_addr] = updated
                changed = True
        if not changed:
            break

    sink = outputs[sink_addr]
    if sink.kind is not _FlowKind8616.KNOWN or sink.source is None:
        return RegisterReachingSourceResult8616(
            RegisterReachingSourceVerdict8616.UNKNOWN_REFUSE,
            None,
            raw_count,
            len(normalized),
            0,
            0,
            1,
        )
    return RegisterReachingSourceResult8616(
        RegisterReachingSourceVerdict8616.PROVEN,
        sink.source,
        raw_count,
        len(normalized),
        1,
        1,
        0,
    )
