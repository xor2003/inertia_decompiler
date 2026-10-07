"""Prove incoming BP survives every return of a closed leaf body.

Layer: Alias.
Responsibility: consume binary-owned IR coverage and exact saved-stack-byte
lineage, then close BP effects over all supplied CFG paths. No compiler ABI,
pointer representation, call target or rendered-code inference is performed.
Owns storage identity.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import StrEnum

from inertia.ir.core import IRBlock, IRFunctionArtifact, MemSpace
from inertia.ir.frame_register_reaching_definition import frame_register_family_8616
from inertia.ir.ir_boundary_cfg import IRBoundaryCoverageResult8616

from .saved_stack_store_window import unproved_cross_selector_store_on_restore_path_8616
from .segment_stack_restore import (
    SegmentStackRestoreFact8616,
    SegmentStackRestoreVerdict8616,
    build_x86_16_stack_register_restore_artifact_8616,
)


class BPPreservationFailure8616(StrEnum):
    """Explicit refusal reasons for whole-leaf BP preservation."""

    COVERAGE_INCOMPLETE = "coverage_incomplete"
    EXTERNAL_EFFECT = "external_effect"
    RETURN_UNPROVEN = "return_unproven"
    ENTRY_REENTERED = "entry_reentered"
    BP_CLOBBERED = "bp_clobbered"
    STORE_ALIAS_UNPROVEN = "store_alias_unproven"


@dataclass(frozen=True, slots=True)
class BPPreservationResult8616:
    """Exact retained body coverage and closed one-function proof accounting."""

    coverage: IRBoundaryCoverageResult8616
    failure: BPPreservationFailure8616 | None
    return_block_addrs: tuple[int, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Recheck retained evidence; counters alone never authorize an effect."""
        counts = (self.raw_fact_count, self.normalized_fact_count,
                  self.classified_fact_count, self.materialized_count, self.failure_count)
        if self.failure is not None or counts != (1, 1, 1, 1, 0):
            return False
        if any(type(count) is not int for count in counts):
            return False
        failure, returns = _preservation_evidence_8616(self.coverage)
        return failure is None and returns == self.return_block_addrs


def _return_blocks_8616(artifact: IRFunctionArtifact) -> tuple[IRBlock, ...] | None:
    """Require every terminal block to end with exactly one final RET."""
    exits = tuple(block for block in artifact.blocks if not block.successor_addrs)
    if not exits or any(not block.instrs or block.instrs[-1].op != "RET" for block in exits):
        return None
    for block in artifact.blocks:
        if any(item.op == "RET" for item in block.instrs[:-1]):
            return None
        if block.successor_addrs and block.instrs and block.instrs[-1].op == "RET":
            return None
    return exits


def _block_preserves_8616(
    block: IRBlock, incoming: bool, restores: frozenset[tuple[int, int]],
) -> bool:
    """Transfer exact whole/partial BP writes, consuming proved entry restores."""
    preserved = incoming
    family = frame_register_family_8616("bp")
    for instruction in block.instrs:
        destination = instruction.dst
        if destination is None or destination.space is not MemSpace.REG or destination.name not in family:
            continue
        preserved = bool(
            destination.name == "bp" and destination.size == instruction.size == 2
            and (block.addr, instruction.addr) in restores
        )
    return preserved


def _incoming_bp_save_sites_8616(artifact: IRFunctionArtifact) -> frozenset[int]:
    """Keep entry-prefix sites strictly before any overlapping BP write."""
    entry = next(block for block in artifact.blocks if block.addr == artifact.function_addr)
    sites: set[int] = set()
    family = frame_register_family_8616("bp")
    for instruction in entry.instrs:
        destination = instruction.dst
        if destination is not None and destination.space is MemSpace.REG and destination.name in family:
            if instruction.addr is not None:
                sites.discard(instruction.addr)
            break
        if instruction.addr is not None:
            sites.add(instruction.addr)
    return frozenset(sites)


def _cross_segment_store_reaches_restore_8616(
    artifact: IRFunctionArtifact, fact: SegmentStackRestoreFact8616,
) -> bool:
    """Consume the shared Alias lifetime guard for an incoming-BP restore."""
    if fact.saved_instruction_addr is None:
        return True
    return unproved_cross_selector_store_on_restore_path_8616(
        artifact, (artifact.function_addr, fact.saved_instruction_addr),
        (fact.block_addr, fact.restore_instruction_addr),
    )


def _preservation_evidence_8616(
    coverage: IRBoundaryCoverageResult8616,
) -> tuple[BPPreservationFailure8616 | None, tuple[int, ...]]:
    """Close all reachable leaf paths using Alias-owned restore identity."""
    if not coverage.complete:
        return BPPreservationFailure8616.COVERAGE_INCOMPLETE, ()
    artifact = coverage.artifact
    if any(artifact.function_addr in block.successor_addrs for block in artifact.blocks):
        return BPPreservationFailure8616.ENTRY_REENTERED, ()
    if any(item.op in {"CALL", "INT", "INTERRUPT", "SYSCALL", "IRET"}
           for block in artifact.blocks for item in block.instrs):
        return BPPreservationFailure8616.EXTERNAL_EFFECT, ()
    exits = _return_blocks_8616(artifact)
    if exits is None:
        return BPPreservationFailure8616.RETURN_UNPROVEN, ()
    alias = build_x86_16_stack_register_restore_artifact_8616(artifact, tracked_registers=frozenset({"bp"}))
    assert alias.is_bound_to(artifact)
    incoming_save_sites = _incoming_bp_save_sites_8616(artifact)
    write_counts = Counter(
        (block.addr, item.addr) for block in artifact.blocks for item in block.instrs
        if item.dst is not None and item.dst.space is MemSpace.REG
        and item.dst.name in frame_register_family_8616("bp")
    )
    candidates = tuple(
        fact for fact in alias.facts
        if fact.verdict is SegmentStackRestoreVerdict8616.PROVEN
        and fact.saved_register == fact.restore_register == "bp"
        and fact.saved_instruction_addr in incoming_save_sites
        and fact.constant_value is None
        and write_counts[(fact.block_addr, fact.restore_instruction_addr)] == 1
    )
    refused = tuple(fact for fact in candidates if _cross_segment_store_reaches_restore_8616(artifact, fact))
    restores = frozenset(
        (fact.block_addr, fact.restore_instruction_addr) for fact in candidates if fact not in refused
    )
    predecessors = {block.addr: tuple(source.addr for source in artifact.blocks
                                     if block.addr in source.successor_addrs)
                    for block in artifact.blocks}
    # The complete coverage owner proves all blocks entry-reachable. Starting
    # from true gives a descending finite fixed point: each clobber propagates
    # through loops, while only an independently proved entry restore resets it.
    states = dict.fromkeys(predecessors, True)
    changed = True
    while changed:
        changed = False
        for block in artifact.blocks:
            incoming = all(states[address] for address in predecessors[block.addr])
            next_state = _block_preserves_8616(block, incoming, restores)
            if next_state != states[block.addr]:
                states[block.addr] = next_state
                changed = True
    returns = tuple(sorted(block.addr for block in exits))
    failure = None
    if not all(states[block.addr] for block in exits):
        failure = BPPreservationFailure8616.STORE_ALIAS_UNPROVEN if refused else BPPreservationFailure8616.BP_CLOBBERED
    return failure, returns


def prove_bp_preservation_8616(coverage: IRBoundaryCoverageResult8616) -> BPPreservationResult8616:
    """Return exact incoming-BP preservation or one atomic typed refusal."""
    failure, returns = _preservation_evidence_8616(coverage)
    accepted = int(failure is None)
    return BPPreservationResult8616(coverage, failure, returns, 1, 1, accepted, accepted, 1 - accepted)
