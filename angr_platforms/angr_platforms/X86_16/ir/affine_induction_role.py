"""Select an affine address term using exact loop guard and write evidence.

Layer: IR.
Responsibility: bind one loaded address term to a zero initializer, latch
increment and strict continued guard in one supplied natural loop. This role
receipt proves neither memory stability nor a bound/range, Alias identity,
pointer type, physical disjointness or completeness of binary CFG coverage.
Residual terms remain unclassified values, never guessed pointer bases.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .affine_indexed_address import AffineIndexedAddressReceipt8616
from .core import IRAddress, IRValue
from .indexed_address_contracts import IndexedAddressStats8616
from .indexed_address_range_candidate_helpers import (
    collect_ssa_natural_loops_8616,
    indexed_guard_polarity_8616,
    indexed_guard_proof_site_8616,
    logical_write_matches_induction_8616,
    logical_write_proof_site_8616,
    normalize_indexed_guard_relation_8616,
    project_ssa_loop_witness_8616,
)
from .indexed_address_range_witnesses import (
    IndexedLoopGuardWitness8616,
    IndexedLoopProofSite8616,
    IndexedNaturalLoopWitness8616,
    canonical_induction_source_identity_8616,
)
from .logical_memory_write_value import LogicalWordWriteValueKind8616, trace_logical_word_write_values_8616
from .scalar_affine_contracts import ScalarAffineTerm8616


class AffineInductionRoleFailure8616(StrEnum):
    """Why exact loop evidence cannot select one affine term."""

    ADDRESS_UNPROVEN = "address_unproven"
    ROLE_UNPROVEN = "role_unproven"
    ROLE_CONFLICT = "role_conflict"


@dataclass(frozen=True, slots=True)
class AffineInductionRoleWitness8616:
    """Exact selected term and the supplied CFG/guard/write proof sites."""

    term_index: int
    loop: IndexedNaturalLoopWitness8616
    initializer: IndexedLoopProofSite8616
    increment: IndexedLoopProofSite8616
    guard_site: IndexedLoopProofSite8616
    guard: IndexedLoopGuardWitness8616


def _role_candidates_8616(
    address: AffineIndexedAddressReceipt8616,
) -> tuple[AffineInductionRoleWitness8616, ...]:
    """Match all terms against current owned evidence without term-order heuristics."""
    artifact = address.artifact
    loops, dominators = collect_ssa_natural_loops_8616(artifact)
    loops = tuple(loop for loop in loops if address.access.block_addr in loop.blocks)
    writes = trace_logical_word_write_values_8616(artifact)
    conditions = artifact.condition_evidence
    if len(loops) != 1 or not writes.closed or conditions is None or not conditions.complete:
        return ()
    loop = loops[0]
    guards = conditions.conditions_for_block(loop.header)
    block = next((item for item in artifact.blocks if item.addr == loop.header), None)
    if len(guards) != 1 or block is None:
        return ()
    condition = guards[0]
    polarity = indexed_guard_polarity_8616(condition, loop)
    guard_site = indexed_guard_proof_site_8616(condition, block)
    if polarity is None or guard_site is None:
        return ()
    candidates: list[AffineInductionRoleWitness8616] = []
    for index, term in enumerate(address.terms):
        if not isinstance(term.source, IRAddress):
            continue
        identity = canonical_induction_source_identity_8616(term.source)
        normalized = None if identity is None else normalize_indexed_guard_relation_8616(condition, identity)
        if identity is None or normalized is None:
            continue
        guard = IndexedLoopGuardWitness8616(
            normalized[0], polarity[0], loop.header, polarity[1], polarity[2],
            dominators.dominates(loop.header, address.access.block_addr) is True,
            dominators.dominates(loop.header, loop.latch) is True, condition,
        )
        if not ((guard.proves_strict_unsigned_continue or guard.proves_strict_signed_continue)
                and guard.guard_dominates_access and guard.guard_dominates_latch):
            continue
        matching = tuple(write for write in writes.facts
                         if write.complete and logical_write_matches_induction_8616(write, identity))
        entries = {source for source, _target in loop.entry_edges}
        initializers = tuple(write for write in matching if write.proves_constant_zero
                             and write.access.key.block_addr in entries
                             and dominators.dominates(write.access.key.block_addr, loop.header) is True)
        increments = tuple(write for write in matching
                           if write.kind is LogicalWordWriteValueKind8616.OLD_LOGICAL_WORD_PLUS_ONE
                           and write.access.key.block_addr == loop.latch)
        if len(initializers) == len(increments) == 1:
            candidates.append(AffineInductionRoleWitness8616(
                index, project_ssa_loop_witness_8616(loop),
                logical_write_proof_site_8616(initializers[0]),
                logical_write_proof_site_8616(increments[0]), guard_site, guard,
            ))
    return tuple(candidates)


@dataclass(frozen=True, slots=True)
class AffineInductionRoleReceipt8616:
    """Replayable role selection, deliberately not a materialized range."""

    address: AffineIndexedAddressReceipt8616
    witness: AffineInductionRoleWitness8616 | None
    failure: AffineInductionRoleFailure8616 | None
    stats: IndexedAddressStats8616

    @property
    def complete(self) -> bool:
        """Require exact current selection and closed one-role accounting."""
        expected = IndexedAddressStats8616(1, 1, 1, 1, 0)
        if self.failure is not None or self.witness is None or self.stats != expected or not self.address.complete:
            return False
        if type(self.witness.term_index) is not int:
            return False
        counts = (self.stats.raw_fact_count, self.stats.normalized_fact_count,
                  self.stats.classified_fact_count, self.stats.materialized_count,
                  self.stats.failure_count, self.stats.coalesced_fact_count)
        if not all(type(count) is int for count in counts):
            return False
        current = _role_candidates_8616(self.address)
        if current != (self.witness,):
            return False
        # Value equality deliberately omits capture identity; replay must not.
        original = current[0].guard.condition
        retained = self.witness.guard.condition
        for left, right in ((original.lhs, retained.lhs), (original.rhs, retained.rhs)):
            if isinstance(left, IRValue) and isinstance(right, IRValue) and left.to_dict() != right.to_dict():
                return False
        return True

    @property
    def induction(self) -> ScalarAffineTerm8616 | None:
        """Expose the selected loaded term only after source replay."""
        if not self.complete or self.witness is None:
            return None
        return self.address.terms[self.witness.term_index]

    @property
    def residual_terms(self) -> tuple[ScalarAffineTerm8616, ...]:
        """Keep every remaining value without inferring pointer or stability roles."""
        if not self.complete or self.witness is None:
            return ()
        return tuple(term for index, term in enumerate(self.address.terms) if index != self.witness.term_index)


def prove_affine_induction_role_8616(
    address: AffineIndexedAddressReceipt8616,
) -> AffineInductionRoleReceipt8616:
    """Publish one exact loop role or an atomic typed refusal."""
    failure: AffineInductionRoleFailure8616 | None = None
    candidates: tuple[AffineInductionRoleWitness8616, ...] = ()
    if not address.complete:
        failure = AffineInductionRoleFailure8616.ADDRESS_UNPROVEN
    else:
        candidates = _role_candidates_8616(address)
        if not candidates:
            failure = AffineInductionRoleFailure8616.ROLE_UNPROVEN
        elif len(candidates) != 1:
            failure = AffineInductionRoleFailure8616.ROLE_CONFLICT
    accepted = int(failure is None)
    return AffineInductionRoleReceipt8616(
        address, candidates[0] if candidates and failure is None else None, failure,
        IndexedAddressStats8616(1, 1, 1, accepted, 1 - accepted),
    )
