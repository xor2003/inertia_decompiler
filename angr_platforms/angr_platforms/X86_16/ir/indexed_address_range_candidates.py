"""Build indexed loop-range candidates from authoritative function SSA.

Layer: IR.
Responsibility: join exact CFG, logical word-write, condition, and indexed-
address evidence into explicit range candidates without inventing bounds.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import replace

from .condition_ir import ConditionIR
from .core import IRValue, MemSpace
from .indexed_address_contracts import IndexedAddressEvidence8616, IndexedAddressFact8616
from .indexed_address_range_candidate_helpers import (
    collect_ssa_natural_loops_8616,
    indexed_guard_polarity_8616,
    indexed_guard_proof_site_8616,
    logical_write_matches_induction_8616,
    logical_write_proof_site_8616,
    normalize_indexed_guard_relation_8616,
    project_ssa_loop_witness_8616,
)
from .indexed_address_range_contracts import (
    IndexedLoopGuardWitness8616,
    IndexedLoopProofSite8616,
    IndexedLoopRangeCandidate8616,
    IndexedLoopRangeEvidence8616,
    IndexedLoopRangeFailureKind8616,
    canonical_induction_source_identity_8616,
)
from .indexed_address_range_evidence import collect_indexed_loop_range_evidence_8616
from .indexed_induction_write_census import (
    IndexedInductionWriteCensus8616,
    collect_indexed_induction_write_census_8616,
)
from .logical_memory_write_value import (
    LogicalWordWriteValueArtifact8616,
    LogicalWordWriteValueFact8616,
    LogicalWordWriteValueKind8616,
    trace_logical_word_write_values_8616,
)
from .ssa_cfg import (
    SSADominators8616,
    SSANaturalLoop8616,
)
from .ssa_function import SSAFunctionArtifact

__all__ = [
    "build_indexed_loop_range_candidates_8616",
    "collect_indexed_loop_ranges_from_ssa_8616",
]


def _generation_refusal_8616(
    source: IndexedAddressFact8616,
    failure: IndexedLoopRangeFailureKind8616,
    detail: str,
) -> IndexedLoopRangeCandidate8616:
    """Retain one indexed source with a typed candidate-generation refusal."""
    return IndexedLoopRangeCandidate8616(
        source=source,
        induction_source=canonical_induction_source_identity_8616(
            source.index_source
        ),
        generation_failure=failure,
        generation_detail=detail,
    )


def _induction_lifetime_failure_8616(
    source: IndexedAddressFact8616,
    loop: SSANaturalLoop8616, dominators: SSADominators8616,
    init_write: LogicalWordWriteValueFact8616,
    census: IndexedInductionWriteCensus8616,
) -> IndexedLoopRangeCandidate8616 | None:
    """Refuse initialization bypasses and every unaccounted raw mutation."""
    if dominators.dominates(init_write.access.key.block_addr, loop.header) is not True:
        return _generation_refusal_8616(
            source, IndexedLoopRangeFailureKind8616.INIT_UNPROVEN,
            "initializer does not dominate every entry into the loop header",
        )
    if not census.complete:
        return _generation_refusal_8616(
            source, IndexedLoopRangeFailureKind8616.INDUCTION_MUTATION_UNPROVEN,
            "raw induction lifetime contains an unaccounted memory or frame effect",
        )
    return None


def _constant_bound_8616(bound: object) -> tuple[bool, int | None]:
    """Retain only a condition operand's explicit IR constant value."""
    if isinstance(bound, IRValue) and bound.space is MemSpace.CONST and bound.const is not None:
        return True, bound.const
    return False, None


def _header_conditions_8616(
    artifact: SSAFunctionArtifact, header: int,
) -> tuple[ConditionIR, ...]:
    """Read header guards only from the closed condition evidence owner."""
    evidence = artifact.condition_evidence
    if evidence is None or not evidence.complete:
        return ()
    return evidence.conditions_for_block(header)


def _select_step_write_8616(
    source: IndexedAddressFact8616,
    writes: LogicalWordWriteValueArtifact8616, loop: SSANaturalLoop8616,
) -> LogicalWordWriteValueFact8616 | IndexedLoopRangeCandidate8616:
    """Select one exact increment without dropping independently proven guards."""
    identity = canonical_induction_source_identity_8616(source.index_source)
    steps = tuple(
        write for write in writes.facts
        if write.kind is LogicalWordWriteValueKind8616.OLD_LOGICAL_WORD_PLUS_ONE
        and write.access.key.block_addr == loop.latch
        and identity is not None and logical_write_matches_induction_8616(write, identity)
    )
    if len(steps) != 1:
        failure = (IndexedLoopRangeFailureKind8616.STEP_UNPROVEN if not steps
                   else IndexedLoopRangeFailureKind8616.STEP_CONFLICT)
        return _generation_refusal_8616(
            source, failure, f"expected one latch increment, found {len(steps)}",
        )
    return steps[0]


def _close_induction_candidate_8616(
    artifact: SSAFunctionArtifact, candidate: IndexedLoopRangeCandidate8616,
    loop: SSANaturalLoop8616, dominators: SSADominators8616,
    init_write: LogicalWordWriteValueFact8616, step_write: LogicalWordWriteValueFact8616,
) -> IndexedLoopRangeCandidate8616:
    """Retain guard/CFG evidence even when the complete mutation proof refuses."""
    # Dynamic candidates cannot materialize: the bound owner refuses first.
    # Preserve that prerequisite diagnostic; never invent a constant to reach
    # the mutation proof. Caller-bound ranges need their own retained context.
    if not candidate.upper_bound_is_constant:
        return candidate
    identity = canonical_induction_source_identity_8616(candidate.source.index_source)
    if identity is None:
        return replace(candidate, generation_failure=(
            IndexedLoopRangeFailureKind8616.INDUCTION_IDENTITY_UNPROVEN),
            generation_detail="induction lifetime has no canonical source identity")
    census = collect_indexed_induction_write_census_8616(
        artifact, identity, loop.blocks, loop.header, init_write, step_write,
        initializer_dominates_header=(
            dominators.dominates(init_write.access.key.block_addr, loop.header) is True
        ),
    )
    candidate = replace(candidate, induction_write_census=census)
    failure = _induction_lifetime_failure_8616(
        candidate.source, loop, dominators, init_write, census,
    )
    if failure is None:
        return candidate
    return replace(candidate, generation_failure=failure.generation_failure,
                   generation_detail=failure.generation_detail)


def _candidate_for_source_8616(
    artifact: SSAFunctionArtifact,
    source: IndexedAddressFact8616,
    writes: LogicalWordWriteValueArtifact8616,
    loops: tuple[SSANaturalLoop8616, ...],
    dominators: SSADominators8616,
) -> IndexedLoopRangeCandidate8616:
    """Join all exact witnesses for one indexed access or retain one refusal."""
    identity = canonical_induction_source_identity_8616(source.index_source)
    if identity is None:
        return _generation_refusal_8616(
            source,
            IndexedLoopRangeFailureKind8616.INDUCTION_IDENTITY_UNPROVEN,
            "indexed source has no canonical BP-relative identity",
        )
    matching_loops = tuple(loop for loop in loops if source.block_addr in loop.blocks)
    if not matching_loops:
        return _generation_refusal_8616(
            source,
            IndexedLoopRangeFailureKind8616.NATURAL_LOOP_UNPROVEN,
            "indexed access is not owned by a proven natural loop",
        )
    if len(matching_loops) != 1:
        return _generation_refusal_8616(
            source,
            IndexedLoopRangeFailureKind8616.LOOP_CONFLICT,
            "indexed access is owned by multiple proven natural loops",
        )
    loop = matching_loops[0]
    entry_sources = {edge_source for edge_source, _target in loop.entry_edges}
    init_writes = tuple(
        write
        for write in writes.facts
        if write.proves_constant_zero
        and write.access.key.block_addr in entry_sources
        and logical_write_matches_induction_8616(write, identity)
    )
    if len(init_writes) != 1:
        failure = (
            IndexedLoopRangeFailureKind8616.INIT_UNPROVEN
            if not init_writes
            else IndexedLoopRangeFailureKind8616.INIT_CONFLICT
        )
        return _generation_refusal_8616(
            source,
            failure,
            f"expected one entry zero-write, found {len(init_writes)}",
        )
    step_write = _select_step_write_8616(
        source, writes, loop,
    )
    if isinstance(step_write, IndexedLoopRangeCandidate8616):
        return step_write
    conditions = _header_conditions_8616(artifact, loop.header)
    if len(conditions) != 1:
        failure = (
            IndexedLoopRangeFailureKind8616.GUARD_UNPROVEN
            if not conditions
            else IndexedLoopRangeFailureKind8616.GUARD_CONFLICT
        )
        return _generation_refusal_8616(
            source,
            failure,
            f"expected one typed header guard, found {len(conditions)}",
        )
    condition = conditions[0]
    normalized = normalize_indexed_guard_relation_8616(condition, identity)
    if normalized is None:
        return _generation_refusal_8616(
            source,
            IndexedLoopRangeFailureKind8616.INDUCTION_IDENTITY_MISMATCH,
            "header guard does not reference the indexed induction storage",
        )
    relation, bound = normalized
    polarity = indexed_guard_polarity_8616(condition, loop)
    block = next((item for item in artifact.blocks if item.addr == loop.header), None)
    if polarity is None or block is None:
        return _generation_refusal_8616(
            source,
            IndexedLoopRangeFailureKind8616.GUARD_UNPROVEN,
            "header guard has no unique loop-continue and exit edge",
        )
    guard_site = indexed_guard_proof_site_8616(condition, block)
    if guard_site is None:
        return _generation_refusal_8616(
            source,
            IndexedLoopRangeFailureKind8616.GUARD_UNPROVEN,
            "header guard has no exact machine instruction address",
        )
    edge_polarity, continue_block, exit_block = polarity
    upper_bound_is_constant, upper_bound = _constant_bound_8616(bound)
    guard = IndexedLoopGuardWitness8616(
        relation,
        edge_polarity,
        loop.header,
        continue_block,
        exit_block,
        dominators.dominates(loop.header, source.block_addr) is True,
        dominators.dominates(loop.header, loop.latch) is True,
        condition,
    )
    init_write = init_writes[0]
    candidate = IndexedLoopRangeCandidate8616(
        source=source,
        induction_source=identity,
        init=init_write.constant,
        step=step_write.constant,
        upper_bound=upper_bound,
        upper_bound_is_constant=upper_bound_is_constant,
        init_site=logical_write_proof_site_8616(init_write),
        step_site=logical_write_proof_site_8616(step_write),
        guard_site=guard_site,
        access_site=IndexedLoopProofSite8616(
            source.block_addr,
            source.instr_index,
            source.instr_addr,
        ),
        natural_loop=project_ssa_loop_witness_8616(loop),
        guard=guard,
        init_write=init_write,
        step_write=step_write,
    )
    return _close_induction_candidate_8616(
        artifact, candidate, loop, dominators, init_write, step_write,
    )


def build_indexed_loop_range_candidates_8616(
    artifact: SSAFunctionArtifact,
    indexed: IndexedAddressEvidence8616,
    writes: LogicalWordWriteValueArtifact8616,
) -> tuple[IndexedLoopRangeCandidate8616, ...]:
    """Build one deterministic candidate for every accepted indexed fact."""
    if not indexed.closed or indexed.function_addr != artifact.function_addr:
        raise ValueError("indexed-address evidence is open or belongs to another function")
    if not writes.closed or writes.function_addr != artifact.function_addr:
        raise ValueError("logical write-value evidence is open or belongs to another function")
    loops, dominators = collect_ssa_natural_loops_8616(artifact)
    return tuple(
        _candidate_for_source_8616(artifact, source, writes, loops, dominators)
        for source in indexed.facts
    )


def collect_indexed_loop_ranges_from_ssa_8616(
    artifact: SSAFunctionArtifact,
    indexed: IndexedAddressEvidence8616,
) -> IndexedLoopRangeEvidence8616:
    """Collect closed ranges from exact function-owned IR evidence."""
    writes = trace_logical_word_write_values_8616(artifact)
    candidates = build_indexed_loop_range_candidates_8616(
        artifact,
        indexed,
        writes,
    )
    return collect_indexed_loop_range_evidence_8616(
        artifact.function_addr,
        candidates,
    )
