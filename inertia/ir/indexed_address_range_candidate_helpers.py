"""Exact CFG, write, and guard helpers for indexed range candidates.

Layer: IR.
Responsibility: normalize authoritative SSA evidence into reusable loop, write-
site, and condition witnesses without deciding whether a range materializes.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from .condition_ir import ConditionIR
from .core import IRValue
from .indexed_address_range_witnesses import (
    IndexedInductionSourceIdentity8616,
    IndexedLoopGuardPolarity8616,
    IndexedLoopGuardRelation8616,
    IndexedLoopProofSite8616,
    IndexedNaturalLoopWitness8616,
    canonical_induction_source_identity_8616,
)
from .logical_memory_write_value import LogicalWordWriteValueFact8616
from .ssa import SSABlock
from .ssa_cfg import (
    SSADominators8616,
    SSANaturalLoop8616,
    build_ssa_cfg_snapshot_8616,
    classify_ssa_natural_loop_8616,
    compute_ssa_dominators_8616,
)
from .ssa_function import SSAFunctionArtifact

__all__ = [
    "collect_ssa_natural_loops_8616",
    "indexed_guard_polarity_8616",
    "indexed_guard_proof_site_8616",
    "logical_write_matches_induction_8616",
    "logical_write_proof_site_8616",
    "normalize_indexed_guard_relation_8616",
    "project_ssa_loop_witness_8616",
]


def collect_ssa_natural_loops_8616(
    artifact: SSAFunctionArtifact,
) -> tuple[tuple[SSANaturalLoop8616, ...], SSADominators8616]:
    """Return every proven natural loop and the exact dominator relation."""
    snapshot = build_ssa_cfg_snapshot_8616(artifact)
    dominators = compute_ssa_dominators_8616(snapshot)
    if not snapshot.complete or not dominators.complete:
        return (), dominators
    loops = tuple(
        loop
        for source, target in snapshot.edges
        if dominators.dominates(target, source) is True
        for loop in (
            classify_ssa_natural_loop_8616(
                snapshot,
                dominators,
                target,
                source,
            ),
        )
        if loop.complete
    )
    return tuple(sorted(loops, key=lambda item: (item.header, item.latch))), dominators


def project_ssa_loop_witness_8616(
    loop: SSANaturalLoop8616,
) -> IndexedNaturalLoopWitness8616:
    """Project one exact SSA natural loop without dropping its edge proof."""
    return IndexedNaturalLoopWitness8616(
        loop.header,
        loop.latch,
        loop.blocks,
        loop.latch,
        loop.header,
        bool(loop.entry_edges),
        loop.backedges == ((loop.latch, loop.header),),
        loop.entry_edges,
        loop.exit_edges,
    )


def logical_write_matches_induction_8616(
    write: LogicalWordWriteValueFact8616,
    identity: IndexedInductionSourceIdentity8616,
) -> bool:
    """Return whether one proven write owns the exact induction storage."""
    return canonical_induction_source_identity_8616(write.access.address) == identity


def logical_write_proof_site_8616(
    write: LogicalWordWriteValueFact8616,
) -> IndexedLoopProofSite8616:
    """Return the first exact byte execution position for one logical write."""
    first = min(
        (lane.execution_slice for lane in write.lanes),
        key=lambda item: item.instr_index,
    )
    return IndexedLoopProofSite8616(
        first.block_addr,
        first.instr_index,
        write.access.key.insn_addr,
    )


def _condition_value_matches_8616(
    value: object,
    identity: IndexedInductionSourceIdentity8616,
) -> bool:
    """Match the relifted condition's canonical stack-value projection."""
    return bool(
        isinstance(value, IRValue)
        and value.space is identity.space
        and value.offset == identity.offset
        and value.size == identity.width
    )


def normalize_indexed_guard_relation_8616(
    condition: ConditionIR,
    identity: IndexedInductionSourceIdentity8616,
) -> tuple[IndexedLoopGuardRelation8616, object] | None:
    """Normalize strict bound forms while preserving comparison signedness."""
    if _condition_value_matches_8616(condition.lhs, identity):
        relation = {
            "ult": IndexedLoopGuardRelation8616.UNSIGNED_LT,
            "uge": IndexedLoopGuardRelation8616.UNSIGNED_GE,
            "slt": IndexedLoopGuardRelation8616.SIGNED_LT,
            "sge": IndexedLoopGuardRelation8616.SIGNED_GE,
        }.get(condition.op, IndexedLoopGuardRelation8616.OTHER)
        return relation, condition.rhs
    if _condition_value_matches_8616(condition.rhs, identity):
        relation = {
            "ugt": IndexedLoopGuardRelation8616.UNSIGNED_LT,
            "ule": IndexedLoopGuardRelation8616.UNSIGNED_GE,
            "sgt": IndexedLoopGuardRelation8616.SIGNED_LT,
            "sle": IndexedLoopGuardRelation8616.SIGNED_GE,
        }.get(condition.op, IndexedLoopGuardRelation8616.OTHER)
        return relation, condition.lhs
    return None


def indexed_guard_polarity_8616(
    condition: ConditionIR,
    loop: SSANaturalLoop8616,
) -> tuple[IndexedLoopGuardPolarity8616, int, int] | None:
    """Return the unique continued and exited branch edge of one loop guard."""
    taken = condition.taken_target
    fallthrough = condition.fallthrough_target
    if taken is None or fallthrough is None:
        return None
    taken_inside = taken in loop.blocks
    fallthrough_inside = fallthrough in loop.blocks
    if taken_inside == fallthrough_inside:
        return None
    if taken_inside:
        return IndexedLoopGuardPolarity8616.CONTINUE_WHEN_TRUE, taken, fallthrough
    return IndexedLoopGuardPolarity8616.CONTINUE_WHEN_FALSE, fallthrough, taken


def indexed_guard_proof_site_8616(
    condition: ConditionIR,
    block: SSABlock,
) -> IndexedLoopProofSite8616 | None:
    """Place the machine JCC at the exact SSA block terminator position."""
    if condition.src_insn is None:
        return None
    return IndexedLoopProofSite8616(
        block.addr,
        len(block.instrs),
        condition.src_insn,
    )
