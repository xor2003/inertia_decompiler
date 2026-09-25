"""Function-level status-flag liveness over typed CFG evidence.

Layer: Semantics.
Responsibility: solve per-bit status-flag liveness across complete CFG edges and
materialize conservative suppression decisions before Lowering or Structuring.
Unknown instructions, missing successors, and incomplete call summaries keep
all status bits live. This module never mutates VEX, AIL, or rendered C.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .status_flag_contracts import (
    STATUS_FLAGS_8616,
    StatusFlag8616,
    StatusFlagEffect8616,
    StatusFlagLivenessStats8616,
    StatusFlagLivenessVerdict8616,
)


@dataclass(frozen=True, slots=True)
class StatusFlagCFGInstruction8616:
    """One decoded instruction projected to a proven or unknown flag effect."""

    address: int
    effect: StatusFlagEffect8616 | None
    suppression_supported: bool = True


@dataclass(frozen=True, slots=True)
class StatusFlagCFGBlock8616:
    """One function-owned block with complete intraprocedural successors."""

    address: int
    instructions: tuple[StatusFlagCFGInstruction8616, ...]
    successor_addresses: tuple[int, ...] = ()
    successors_complete: bool = True


@dataclass(frozen=True, slots=True)
class StatusFlagCFGDecision8616:
    """Per-instruction dead-write decision from the converged CFG solution."""

    block_address: int
    instruction_index: int
    instruction_address: int
    written: StatusFlag8616
    live_after: StatusFlag8616
    dead_writes: StatusFlag8616
    verdict: StatusFlagLivenessVerdict8616
    suppression_supported: bool

    @property
    def suppresses_write(self) -> bool:
        """Return whether every status bit written by this instruction is dead."""
        return bool(
            self.verdict is StatusFlagLivenessVerdict8616.SUPPRESS_DEAD
            and self.suppression_supported
            and int(self.written) != 0
            and self.dead_writes == self.written
        )


@dataclass(frozen=True, slots=True)
class StatusFlagCFGLivenessArtifact8616:
    """Converged liveness maps, decisions, and closed evidence counters."""

    entry_address: int
    live_in_by_block: tuple[tuple[int, StatusFlag8616], ...]
    live_out_by_block: tuple[tuple[int, StatusFlag8616], ...]
    decisions: tuple[StatusFlagCFGDecision8616, ...]
    stats: StatusFlagLivenessStats8616

    def live_at_entry(self) -> StatusFlag8616:
        """Return status bits required at the selected function entry."""
        return dict(self.live_in_by_block).get(self.entry_address, STATUS_FLAGS_8616)

    def suppressed_instruction_addresses(self) -> frozenset[int]:
        """Return addresses whose complete status write is proven dead."""
        return frozenset(
            decision.instruction_address
            for decision in self.decisions
            if decision.suppresses_write
        )


def _transfer_effect_8616(
    effect: StatusFlagEffect8616 | None,
    live_after: StatusFlag8616,
) -> StatusFlag8616:
    """Transfer one instruction backward; unknown effects preserve everything."""
    if effect is None:
        return STATUS_FLAGS_8616
    return effect.reads | (live_after & ~effect.overwrites)


def _block_live_in_8616(
    block: StatusFlagCFGBlock8616,
    live_out: StatusFlag8616,
) -> StatusFlag8616:
    """Transfer one complete block backward from its live-out mask."""
    live = live_out
    for instruction in reversed(block.instructions):
        live = _transfer_effect_8616(instruction.effect, live)
    return live & STATUS_FLAGS_8616


def _block_live_out_8616(
    block: StatusFlagCFGBlock8616,
    live_in: dict[int, StatusFlag8616],
    block_by_addr: dict[int, StatusFlagCFGBlock8616],
    exit_live: StatusFlag8616,
) -> tuple[StatusFlag8616, int]:
    """Join successor live-ins; incomplete edges force full liveness."""
    if not block.successors_complete:
        return STATUS_FLAGS_8616, 1
    if not block.successor_addresses:
        return exit_live & STATUS_FLAGS_8616, 0
    live_out = StatusFlag8616.NONE
    missing = 0
    for successor in block.successor_addresses:
        if successor not in block_by_addr:
            live_out |= STATUS_FLAGS_8616
            missing += 1
        else:
            live_out |= live_in[successor]
    return live_out, missing


def _converged_live_sets_8616(
    blocks: tuple[StatusFlagCFGBlock8616, ...],
    block_by_addr: dict[int, StatusFlagCFGBlock8616],
    exit_live: StatusFlag8616,
) -> tuple[dict[int, StatusFlag8616], dict[int, StatusFlag8616], int]:
    """Solve live-in/live-out to a fixed point over the complete CFG."""
    live_in = {block.address: StatusFlag8616.NONE for block in blocks}
    live_out = {block.address: StatusFlag8616.NONE for block in blocks}
    missing_successor_count = 0
    changed = True
    while changed:
        changed = False
        missing_successor_count = 0
        for block in reversed(blocks):
            block_live_out, missing = _block_live_out_8616(
                block,
                live_in,
                block_by_addr,
                exit_live,
            )
            missing_successor_count += missing
            block_live_in = _block_live_in_8616(block, block_live_out)
            if live_out[block.address] != block_live_out:
                live_out[block.address] = block_live_out
                changed = True
            if live_in[block.address] != block_live_in:
                live_in[block.address] = block_live_in
                changed = True
    return live_in, live_out, missing_successor_count


def _block_decisions_8616(
    block: StatusFlagCFGBlock8616,
    live_after_block: StatusFlag8616,
) -> tuple[list[StatusFlagCFGDecision8616], int]:
    """Materialize per-instruction decisions for one block, backward."""
    live = live_after_block
    reversed_decisions: list[StatusFlagCFGDecision8616] = []
    unknown_count = 0
    for reverse_index, instruction in enumerate(reversed(block.instructions)):
        index = len(block.instructions) - reverse_index - 1
        effect = instruction.effect
        if effect is None:
            unknown_count += 1
            written = StatusFlag8616.NONE
            dead_writes = StatusFlag8616.NONE
            verdict = StatusFlagLivenessVerdict8616.KEEP_UNKNOWN
        else:
            written = effect.overwrites & STATUS_FLAGS_8616
            dead_writes = written & ~live
            verdict = (
                StatusFlagLivenessVerdict8616.SUPPRESS_DEAD
                if int(written) != 0 and dead_writes == written
                else StatusFlagLivenessVerdict8616.KEEP_LIVE
            )
        reversed_decisions.append(
            StatusFlagCFGDecision8616(
                block_address=block.address,
                instruction_index=index,
                instruction_address=instruction.address,
                written=written,
                live_after=live,
                dead_writes=dead_writes,
                verdict=verdict,
                suppression_supported=instruction.suppression_supported,
            )
        )
        live = _transfer_effect_8616(effect, live)
    return list(reversed(reversed_decisions)), unknown_count


def analyze_status_flag_cfg_liveness_8616(
    blocks: tuple[StatusFlagCFGBlock8616, ...],
    *,
    entry_address: int,
    exit_live: StatusFlag8616 = STATUS_FLAGS_8616,
) -> StatusFlagCFGLivenessArtifact8616:
    """Solve per-bit liveness to a fixed point and materialize every decision.

    ``exit_live`` is an owned function-contract input. The conservative default
    preserves all architectural status bits. A caller may pass ``NONE`` only
    after a typed function-output contract proves flags are unobservable.
    """
    block_by_addr = {block.address: block for block in blocks}
    live_in, live_out, missing_successor_count = _converged_live_sets_8616(
        blocks,
        block_by_addr,
        exit_live,
    )

    decisions: list[StatusFlagCFGDecision8616] = []
    unknown_count = 0
    instruction_count = 0
    for block in blocks:
        block_decisions, block_unknown = _block_decisions_8616(
            block,
            live_out[block.address],
        )
        instruction_count += len(block.instructions)
        unknown_count += block_unknown
        decisions.extend(block_decisions)

    failure_count = unknown_count + missing_successor_count
    stats = StatusFlagLivenessStats8616(
        raw_fact_count=instruction_count,
        normalized_fact_count=instruction_count,
        classified_fact_count=instruction_count,
        materialized_count=instruction_count,
        failure_count=failure_count,
    )
    if not stats.closed:
        raise RuntimeError("status-flag CFG liveness evidence did not close")
    return StatusFlagCFGLivenessArtifact8616(
        entry_address=entry_address,
        live_in_by_block=tuple(sorted(live_in.items())),
        live_out_by_block=tuple(sorted(live_out.items())),
        decisions=tuple(
            sorted(
                decisions,
                key=lambda decision: (decision.block_address, decision.instruction_index),
            )
        ),
        stats=stats,
    )


def _closed_block_map_8616(
    blocks: tuple[StatusFlagCFGBlock8616, ...],
    entry_address: int,
) -> dict[int, StatusFlagCFGBlock8616] | None:
    """Return the block map only when the CFG is complete from entry."""
    block_by_addr = {block.address: block for block in blocks}
    if entry_address not in block_by_addr:
        return None
    for block in blocks:
        if not block.successors_complete or any(
            successor not in block_by_addr for successor in block.successor_addresses
        ):
            return None
    return block_by_addr


def _reachable_addresses_8616(
    block_by_addr: dict[int, StatusFlagCFGBlock8616],
    entry_address: int,
) -> set[int]:
    """Return every block reachable from the function entry."""
    reachable = {entry_address}
    pending = [entry_address]
    while pending:
        current = pending.pop()
        for successor in block_by_addr[current].successor_addresses:
            if successor not in reachable:
                reachable.add(successor)
                pending.append(successor)
    return reachable


def _reachable_predecessors_8616(
    block_by_addr: dict[int, StatusFlagCFGBlock8616],
    reachable: set[int],
) -> dict[int, set[int]]:
    """Return the reachable predecessor map over the closed CFG."""
    predecessors: dict[int, set[int]] = {address: set() for address in reachable}
    for address in reachable:
        for successor in block_by_addr[address].successor_addresses:
            if successor in reachable:
                predecessors[successor].add(address)
    return predecessors


def _must_block_in_8616(
    address: int,
    predecessors: dict[int, set[int]],
    must_out: dict[int, StatusFlag8616],
    entry_address: int,
) -> StatusFlag8616:
    """Meet predecessor must-out bits; entry and orphan blocks start empty."""
    if address == entry_address:
        return StatusFlag8616.NONE
    incoming = predecessors[address]
    if not incoming:
        return StatusFlag8616.NONE
    block_in = STATUS_FLAGS_8616
    for predecessor in incoming:
        block_in &= must_out[predecessor]
    return block_in


def _must_block_out_8616(
    block: StatusFlagCFGBlock8616,
    block_in: StatusFlag8616,
) -> StatusFlag8616:
    """Accumulate definite overwrites forward across one block."""
    block_out = block_in
    for instruction in block.instructions:
        if instruction.effect is not None:
            block_out |= instruction.effect.overwrites
    return block_out & STATUS_FLAGS_8616


def _must_overwrite_sets_8616(
    block_by_addr: dict[int, StatusFlagCFGBlock8616],
    reachable: set[int],
    predecessors: dict[int, set[int]],
    entry_address: int,
) -> dict[int, StatusFlag8616]:
    """Solve definite-overwrite must-in/must-out to a fixed point."""
    must_in = {
        address: (
            StatusFlag8616.NONE if address == entry_address else STATUS_FLAGS_8616
        )
        for address in reachable
    }
    must_out = dict(must_in)
    changed = True
    while changed:
        changed = False
        for address in sorted(reachable):
            block_in = _must_block_in_8616(
                address,
                predecessors,
                must_out,
                entry_address,
            )
            block_out = _must_block_out_8616(block_by_addr[address], block_in)
            if must_in[address] != block_in:
                must_in[address] = block_in
                changed = True
            if must_out[address] != block_out:
                must_out[address] = block_out
                changed = True
    return must_out


def _definitely_overwritten_on_all_exits_8616(
    blocks: tuple[StatusFlagCFGBlock8616, ...],
    *,
    entry_address: int,
) -> StatusFlag8616:
    """Return bits overwritten on every complete path from entry to return."""
    block_by_addr = _closed_block_map_8616(blocks, entry_address)
    if block_by_addr is None:
        return StatusFlag8616.NONE
    reachable = _reachable_addresses_8616(block_by_addr, entry_address)
    predecessors = _reachable_predecessors_8616(block_by_addr, reachable)
    must_out = _must_overwrite_sets_8616(
        block_by_addr,
        reachable,
        predecessors,
        entry_address,
    )

    exits = tuple(
        address
        for address in reachable
        if not block_by_addr[address].successor_addresses
    )
    if not exits:
        return StatusFlag8616.NONE
    definitely_overwritten = STATUS_FLAGS_8616
    for address in exits:
        definitely_overwritten &= must_out[address]
    return definitely_overwritten


def summarize_status_flag_cfg_effect_8616(
    blocks: tuple[StatusFlagCFGBlock8616, ...],
    *,
    entry_address: int,
) -> StatusFlagEffect8616:
    """Summarize callee entry reads and all-return definite overwrites."""
    reads_artifact = analyze_status_flag_cfg_liveness_8616(
        blocks,
        entry_address=entry_address,
        exit_live=StatusFlag8616.NONE,
    )
    return StatusFlagEffect8616(
        reads=reads_artifact.live_at_entry(),
        overwrites=_definitely_overwritten_on_all_exits_8616(
            blocks,
            entry_address=entry_address,
        ),
    )


__all__ = [
    "StatusFlagCFGBlock8616",
    "StatusFlagCFGDecision8616",
    "StatusFlagCFGInstruction8616",
    "StatusFlagCFGLivenessArtifact8616",
    "analyze_status_flag_cfg_liveness_8616",
    "summarize_status_flag_cfg_effect_8616",
]
