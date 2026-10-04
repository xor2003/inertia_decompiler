"""Typed IR contracts for bounded indexed-address loop ranges.

Layer: IR.
Responsibility: retain explicit SSA/CFG witnesses for zero-based, unit-step,
strict constant-bound natural loops that own indexed global accesses. Signed
bounds require exact positive constants below the sign bit; dynamic bounds
remain refused.
This module does not discover loops, infer Alias identity, choose object counts,
widen storage, inspect rendered text, or mutate generated code.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .indexed_address_contracts import IndexedAddressFact8616
from .indexed_address_range_witnesses import (
    IndexedInductionSourceIdentity8616,
    IndexedLoopGuardPolarity8616,
    IndexedLoopGuardRelation8616,
    IndexedLoopGuardWitness8616,
    IndexedLoopProofSite8616,
    IndexedNaturalLoopWitness8616,
    canonical_induction_source_identity_8616,
)
from .indexed_induction_write_census import IndexedInductionWriteCensus8616
from .logical_memory_write_value import (
    LogicalWordWriteValueFact8616,
    LogicalWordWriteValueKind8616,
)


class IndexedLoopRangeFailureKind8616(StrEnum):
    """Stable reason one typed loop-range candidate was refused."""

    FUNCTION_MISMATCH = "function_mismatch"
    SOURCE_FACT_INCOMPLETE = "source_fact_incomplete"
    DUPLICATE_ACCESS = "duplicate_access"
    INDUCTION_IDENTITY_UNPROVEN = "induction_identity_unproven"
    INDUCTION_IDENTITY_MISMATCH = "induction_identity_mismatch"
    INDUCTION_MUTATION_UNPROVEN = "induction_mutation_unproven"
    INIT_UNPROVEN = "init_unproven"
    INIT_NOT_ZERO = "init_not_zero"
    STEP_UNPROVEN = "step_unproven"
    STEP_NOT_UNIT = "step_not_unit"
    DYNAMIC_BOUND = "dynamic_bound"
    BOUND_UNPROVEN = "bound_unproven"
    BOUND_OUT_OF_RANGE = "bound_out_of_range"
    GUARD_UNPROVEN = "guard_unproven"
    GUARD_NOT_STRICT_UNSIGNED = "guard_not_strict_unsigned"
    GUARD_NOT_STRICT_BOUND = "guard_not_strict_bound"
    NATURAL_LOOP_UNPROVEN = "natural_loop_unproven"
    DOMINANCE_UNPROVEN = "dominance_unproven"
    BACKEDGE_UNPROVEN = "backedge_unproven"
    ACCESS_SITE_UNPROVEN = "access_site_unproven"
    ACCESS_SITE_MISMATCH = "access_site_mismatch"
    ACCESS_OUTSIDE_LOOP = "access_outside_loop"
    LOOP_CONFLICT = "loop_conflict"
    INIT_CONFLICT = "init_conflict"
    STEP_CONFLICT = "step_conflict"
    GUARD_CONFLICT = "guard_conflict"
    PROOF_SITE_CONFLICT = "proof_site_conflict"


@dataclass(frozen=True, slots=True)
class IndexedLoopRangeCandidate8616:
    """Explicit typed SSA/CFG adapter input; absent proof is never inferred."""

    source: IndexedAddressFact8616
    induction_source: IndexedInductionSourceIdentity8616 | None = None
    init: int | None = None
    step: int | None = None
    upper_bound: int | None = None
    upper_bound_is_constant: bool = False
    init_site: IndexedLoopProofSite8616 | None = None
    step_site: IndexedLoopProofSite8616 | None = None
    guard_site: IndexedLoopProofSite8616 | None = None
    access_site: IndexedLoopProofSite8616 | None = None
    natural_loop: IndexedNaturalLoopWitness8616 | None = None
    guard: IndexedLoopGuardWitness8616 | None = None
    init_write: LogicalWordWriteValueFact8616 | None = None
    step_write: LogicalWordWriteValueFact8616 | None = None
    induction_write_census: IndexedInductionWriteCensus8616 | None = None
    generation_failure: IndexedLoopRangeFailureKind8616 | None = None
    generation_detail: str = ""


@dataclass(frozen=True, slots=True)
class IndexedLoopRangeFact8616:
    """One indexed access proven to execute for the exact range ``[0, N)``."""

    source: IndexedAddressFact8616
    induction_source: IndexedInductionSourceIdentity8616
    init: int
    step: int
    upper_bound: int
    init_site: IndexedLoopProofSite8616
    step_site: IndexedLoopProofSite8616
    guard_site: IndexedLoopProofSite8616
    access_site: IndexedLoopProofSite8616
    natural_loop: IndexedNaturalLoopWitness8616
    guard: IndexedLoopGuardWitness8616
    init_write: LogicalWordWriteValueFact8616
    step_write: LogicalWordWriteValueFact8616
    induction_write_census: IndexedInductionWriteCensus8616 | None = None

    @property
    def proof_sites(self) -> tuple[IndexedLoopProofSite8616, ...]:
        """Return init, step, guard, and access sites in semantic-role order."""
        return self.init_site, self.step_site, self.guard_site, self.access_site

    @property
    def complete(self) -> bool:
        """Return whether every retained range and control-flow witness agrees."""
        canonical = canonical_induction_source_identity_8616(self.source.index_source)
        max_value = (1 << (self.source.index_value.size * 8)) - 1
        access_matches = (
            self.access_site.block_addr,
            self.access_site.instr_index,
            self.access_site.instr_addr,
        ) == (self.source.block_addr, self.source.instr_index, self.source.instr_addr)
        loop = self.natural_loop
        guard = self.guard
        init_identity = canonical_induction_source_identity_8616(
            self.init_write.access.address
        )
        step_identity = canonical_induction_source_identity_8616(
            self.step_write.access.address
        )
        init_slice_indexes = {
            lane.execution_slice.instr_index for lane in self.init_write.lanes
        }
        step_slice_indexes = {
            lane.execution_slice.instr_index for lane in self.step_write.lanes
        }
        census = self.induction_write_census
        if census is None or not census.matches_lifetime(
            self.source.function_addr, self.induction_source, self.init_write, self.step_write,
            loop.blocks, loop.header_block_addr,
        ):
            return False
        return bool(
            self.source.complete
            and canonical == self.induction_source
            and self.induction_source.complete
            and self.init == 0
            and self.step == 1
            and self.init_write.complete
            and self.init_write.proves_constant_zero
            and self.init_write.constant == self.init
            and init_identity == self.induction_source
            and self.step_write.complete
            and self.step_write.kind
            is LogicalWordWriteValueKind8616.OLD_LOGICAL_WORD_PLUS_ONE
            and self.step_write.constant == self.step
            and step_identity == self.induction_source
            and not isinstance(self.upper_bound, bool)
            and 0 < self.upper_bound <= max_value
            and all(site.complete for site in self.proof_sites)
            and access_matches
            and loop.complete
            and self.init_site.block_addr not in loop.blocks
            and self.init_site.block_addr == self.init_write.access.key.block_addr
            and self.init_site.instr_addr == self.init_write.access.key.insn_addr
            and self.init_site.instr_index in init_slice_indexes
            and any(
                source == self.init_site.block_addr
                for source, _target in loop.entry_edges
            )
            and self.step_site.block_addr == loop.latch_block_addr
            and self.step_site.block_addr == self.step_write.access.key.block_addr
            and self.step_site.instr_addr == self.step_write.access.key.insn_addr
            and self.step_site.instr_index in step_slice_indexes
            and self.guard_site.block_addr == loop.header_block_addr
            and self.access_site.block_addr in loop.blocks
            and self.access_site.block_addr != loop.header_block_addr
            and all(
                site.block_addr != self.step_site.block_addr
                or site.instr_index < min(step_slice_indexes)
                for site in self.source.definition_path if site.op == "LOAD"
            )
            and guard.guard_block_addr == loop.header_block_addr
            and guard.continue_block_addr in loop.blocks
            and guard.exit_block_addr not in loop.blocks
            and guard.complete
            and (guard.proves_strict_unsigned_continue or guard.proves_positive_signed_bound(
                self.upper_bound, self.source.index_value.size, self.induction_source,
            ))
            and guard.guard_dominates_access
            and guard.guard_dominates_latch
        )


@dataclass(frozen=True, slots=True)
class IndexedLoopRangeRefusal8616:
    """One candidate retained with its exact typed refusal reason."""

    candidate: IndexedLoopRangeCandidate8616
    failure: IndexedLoopRangeFailureKind8616
    detail: str

    @property
    def complete(self) -> bool:
        """Return whether the refusal retains a non-empty diagnostic."""
        return bool(self.detail)


@dataclass(frozen=True, slots=True)
class IndexedLoopRangeStats8616:
    """Closed accounting for explicit loop-range witness candidates."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether every candidate has exactly one final outcome."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        return bool(
            all(count >= 0 for count in counts)
            and self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count + self.failure_count
        )


@dataclass(frozen=True, slots=True)
class IndexedLoopRangeEvidence8616:
    """Function-local accepted ranges and all explicit refusals."""

    function_addr: int
    facts: tuple[IndexedLoopRangeFact8616, ...]
    refusals: tuple[IndexedLoopRangeRefusal8616, ...]
    stats: IndexedLoopRangeStats8616

    @property
    def closed(self) -> bool:
        """Return whether facts, refusals, and counters are coherent."""
        return bool(
            self.function_addr >= 0
            and self.stats.closed
            and len(self.facts) == self.stats.materialized_count
            and len(self.refusals) == self.stats.failure_count
            and all(fact.complete for fact in self.facts)
            and all(refusal.complete for refusal in self.refusals)
        )


__all__ = [
    "IndexedInductionSourceIdentity8616",
    "IndexedLoopGuardPolarity8616",
    "IndexedLoopGuardRelation8616",
    "IndexedLoopGuardWitness8616",
    "IndexedLoopProofSite8616",
    "IndexedLoopRangeCandidate8616",
    "IndexedLoopRangeEvidence8616",
    "IndexedLoopRangeFact8616",
    "IndexedLoopRangeFailureKind8616",
    "IndexedLoopRangeRefusal8616",
    "IndexedLoopRangeStats8616",
    "IndexedNaturalLoopWitness8616",
    "canonical_induction_source_identity_8616",
]
