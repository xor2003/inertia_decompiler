"""Immutable IR witnesses used by indexed loop-range contracts.

Layer: IR.
Responsibility: retain canonical induction identity, exact proof sites, typed
guard polarity, and complete natural-loop edge evidence.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .condition_ir import ConditionIR
from .core import AddressStatus, IRAddress, IRValue, MemSpace, SegmentOrigin

__all__ = [
    "IndexedInductionSourceIdentity8616",
    "IndexedLoopGuardPolarity8616",
    "IndexedLoopGuardRelation8616",
    "IndexedLoopGuardWitness8616",
    "IndexedLoopProofSite8616",
    "IndexedNaturalLoopWitness8616",
    "canonical_induction_source_identity_8616",
]


class IndexedLoopGuardRelation8616(StrEnum):
    """Typed comparison relation present at the loop guard."""

    UNSIGNED_LT = "unsigned_lt"
    UNSIGNED_GE = "unsigned_ge"
    SIGNED_LT = "signed_lt"
    SIGNED_GE = "signed_ge"
    OTHER = "other"


class IndexedLoopGuardPolarity8616(StrEnum):
    """CFG edge polarity that continues execution inside the loop."""

    CONTINUE_WHEN_TRUE = "continue_when_true"
    CONTINUE_WHEN_FALSE = "continue_when_false"
    UNKNOWN = "unknown"


@dataclass(frozen=True, order=True, slots=True)
class IndexedLoopProofSite8616:
    """One exact machine instruction and block-local SSA position."""

    block_addr: int
    instr_index: int
    instr_addr: int

    @property
    def complete(self) -> bool:
        """Return whether all site coordinates are exact and non-negative."""
        return self.block_addr >= 0 and self.instr_index >= 0 and self.instr_addr >= 0


@dataclass(frozen=True, slots=True)
class IndexedInductionSourceIdentity8616:
    """Canonical IR storage identity for one BP-relative induction source."""

    space: MemSpace
    base: tuple[str, ...]
    offset: int
    width: int

    @property
    def complete(self) -> bool:
        """Return whether this is one exact supported stack identity."""
        return self.space is MemSpace.SS and self.base == ("bp",) and self.width > 0


def canonical_induction_source_identity_8616(
    address: IRAddress,
) -> IndexedInductionSourceIdentity8616 | None:
    """Return a canonical identity only for an exact proven BP stack address."""
    if (
        address.space is not MemSpace.SS
        or address.base != ("bp",)
        or address.size <= 0
        or address.status is not AddressStatus.STABLE
        or address.segment_origin is not SegmentOrigin.PROVEN
    ):
        return None
    if address.base_values:
        if len(address.base_values) != 1:
            return None
        base_value = address.base_values[0]
        if not (
            isinstance(base_value, IRValue)
            and base_value.space is MemSpace.REG
            and base_value.name == "bp"
            and base_value.offset == 0
            and base_value.const is None
            and base_value.index is None
        ):
            return None
    return IndexedInductionSourceIdentity8616(
        address.space,
        address.base,
        address.offset,
        address.size,
    )


@dataclass(frozen=True, slots=True)
class IndexedLoopGuardWitness8616:
    """Typed guard polarity and dominance facts supplied by SSA/CFG analysis."""

    relation: IndexedLoopGuardRelation8616
    polarity: IndexedLoopGuardPolarity8616
    guard_block_addr: int
    continue_block_addr: int
    exit_block_addr: int
    guard_dominates_access: bool
    guard_dominates_latch: bool
    condition: ConditionIR

    @property
    def complete(self) -> bool:
        """Return whether the normalized edge polarity retains exact IR."""
        if self.condition.block_addr != self.guard_block_addr:
            return False
        if self.polarity is IndexedLoopGuardPolarity8616.CONTINUE_WHEN_TRUE:
            edges_match = (
                self.condition.taken_target == self.continue_block_addr
                and self.condition.fallthrough_target == self.exit_block_addr
            )
        elif self.polarity is IndexedLoopGuardPolarity8616.CONTINUE_WHEN_FALSE:
            edges_match = (
                self.condition.fallthrough_target == self.continue_block_addr
                and self.condition.taken_target == self.exit_block_addr
            )
        else:
            edges_match = False
        return bool(self.condition.is_comparison and edges_match)

    @property
    def proves_strict_unsigned_continue(self) -> bool:
        """Return whether the continued edge is canonically ``index < bound``."""
        return (
            self.complete
            and self.relation is IndexedLoopGuardRelation8616.UNSIGNED_LT
            and self.condition.op in {"ult", "ugt"}
            and self.polarity is IndexedLoopGuardPolarity8616.CONTINUE_WHEN_TRUE
        ) or (
            self.complete
            and self.relation is IndexedLoopGuardRelation8616.UNSIGNED_GE
            and self.condition.op in {"uge", "ule"}
            and self.polarity is IndexedLoopGuardPolarity8616.CONTINUE_WHEN_FALSE
        )

    @property
    def proves_strict_signed_continue(self) -> bool:
        """Retain signedness and require a strict continued comparison edge."""
        if not self.complete:
            return False
        if self.relation is IndexedLoopGuardRelation8616.SIGNED_LT:
            return (self.condition.op in {"slt", "sgt"}
                    and self.polarity is IndexedLoopGuardPolarity8616.CONTINUE_WHEN_TRUE)
        if self.relation is IndexedLoopGuardRelation8616.SIGNED_GE:
            return (self.condition.op in {"sge", "sle"}
                    and self.polarity is IndexedLoopGuardPolarity8616.CONTINUE_WHEN_FALSE)
        return False

    def proves_positive_signed_bound(
        self, upper_bound: int, width: int,
        induction: IndexedInductionSourceIdentity8616 | None,
    ) -> bool:
        """Prove a constant signed bound reached before unit-step overflow.

        A zero-initialized induction stops at N <= signed_max; no live
        induction value crosses the sign bit. The exact condition constant
        and width must agree, rather than trusting normalized metadata alone.
        """
        if not self.proves_strict_signed_continue or self.condition.width_bits != width * 8:
            return False
        if type(upper_bound) is not int or type(width) is not int or width not in {1, 2, 4}:
            return False
        if not 0 < upper_bound <= (1 << (width * 8 - 1)) - 1:
            return False
        bound = self.condition.rhs if self.condition.op in {"slt", "sge"} else self.condition.lhs
        index = self.condition.lhs if self.condition.op in {"slt", "sge"} else self.condition.rhs
        if induction is None or not induction.complete or not isinstance(index, IRValue):
            return False
        index_matches = (
            index.space is induction.space and index.name == "bp"
            and index.offset == induction.offset and index.size == induction.width == width
        )
        return bool(isinstance(bound, IRValue) and bound.space is MemSpace.CONST
                    and type(bound.const) is int and bound.const == upper_bound and index_matches)


@dataclass(frozen=True, slots=True)
class IndexedNaturalLoopWitness8616:
    """Exact natural-loop block set, header, latch, and edge proof."""

    header_block_addr: int
    latch_block_addr: int
    blocks: tuple[int, ...]
    backedge_source_addr: int
    backedge_target_addr: int
    single_entry: bool
    backedge_proven: bool
    entry_edges: tuple[tuple[int, int], ...]
    exit_edges: tuple[tuple[int, int], ...]

    @property
    def complete(self) -> bool:
        """Return whether this is one deterministic single-entry natural loop."""
        return bool(
            self.blocks
            and self.blocks == tuple(sorted(set(self.blocks)))
            and self.header_block_addr in self.blocks
            and self.latch_block_addr in self.blocks
            and self.single_entry
            and self.backedge_proven
            and self.backedge_source_addr == self.latch_block_addr
            and self.backedge_target_addr == self.header_block_addr
            and self.entry_edges
            and self.entry_edges == tuple(sorted(set(self.entry_edges)))
            and all(
                target == self.header_block_addr
                for _source, target in self.entry_edges
            )
            and self.exit_edges
            and self.exit_edges == tuple(sorted(set(self.exit_edges)))
            and all(
                source in self.blocks and target not in self.blocks
                for source, target in self.exit_edges
            )
        )
