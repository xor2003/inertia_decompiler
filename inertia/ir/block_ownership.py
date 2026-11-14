# cython: language_level=3, infer_types=True
"""Canonicalize overlapping recovered blocks without losing IR instructions.

Layer: IR.
Responsibility: assign each machine-instruction address to the latest recovered
block start that contains an exact decode, removing only proven duplicate IR
facts and retaining typed refusals for ambiguous overlaps.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from .block_successor_chain import proven_suffix_owner_chain_8616
from .core import IRBlock
import dataclasses
import operator

__all__ = [
    "IRBlockOwnershipArtifact8616",
    "IRBlockOwnershipFailure8616",
    "IRBlockOwnershipRefusal8616",
    "IRBlockOwnershipRemoval8616",
    "IRBlockOwnershipStats8616",
    "IRBlockSuccessorRewrite8616",
    "IRBlockSuccessorRewriteFailure8616",
    "IRBlockSuccessorRewriteRefusal8616",
    "IRBlockSuccessorRewriteStats8616",
    "canonicalize_ir_block_ownership_8616",
]


class IRBlockOwnershipFailure8616(StrEnum):
    """Stable reason an overlapping instruction cannot change ownership."""

    CANONICAL_OWNER_MISSING_INSTRUCTION = "canonical_owner_missing_instruction"


class IRBlockSuccessorRewriteFailure8616(StrEnum):
    """Stable reason an overlap prefix kept its original successors."""

    SOURCE_PREFIX_EMPTY = "source_prefix_empty"
    MULTIPLE_SUFFIX_OWNERS = "multiple_suffix_owners"
    SUCCESSOR_CONFLICT = "successor_conflict"


@dataclasses.dataclass(frozen=True, )
class IRBlockOwnershipRemoval8616:
    """One duplicate IR instruction removed in favor of its canonical block."""

    source_block_addr: cython.longlong
    canonical_block_addr: cython.longlong
    instr_index: cython.longlong
    instr_addr: cython.longlong


@dataclasses.dataclass(frozen=True, )
class IRBlockOwnershipRefusal8616:
    """One ambiguous overlap retained without changing the input IR."""

    source_block_addr: cython.longlong
    proposed_owner_addr: cython.longlong
    instr_index: cython.longlong
    instr_addr: cython.longlong
    failure: IRBlockOwnershipFailure8616


@dataclasses.dataclass(frozen=True, )
class IRBlockOwnershipStats8616:
    """Closed evidence accounting for overlapping instruction ownership."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def complete(self) -> cython.bint:
        """Return whether every overlap candidate has one retained outcome."""
        return (
            operator.eq(self.raw_fact_count, self.normalized_fact_count)
            and operator.eq(self.classified_fact_count, self.materialized_count + self.failure_count)
        )

    def to_summary(self) -> dict[str, cython.longlong]:
        """Return stable flat counters for the function IR summary."""
        return {
            "block_ownership_raw_fact_count": self.raw_fact_count,
            "block_ownership_normalized_fact_count": self.normalized_fact_count,
            "block_ownership_classified_fact_count": self.classified_fact_count,
            "block_ownership_materialized_count": self.materialized_count,
            "block_ownership_failure_count": self.failure_count,
        }


@dataclasses.dataclass(frozen=True, )
class IRBlockSuccessorRewrite8616:
    """One overlap prefix rewired to its canonical suffix owner."""

    source_block_addr: cython.longlong
    canonical_block_addr: cython.longlong
    original_successors: object
    canonical_successors: object

    @property
    def complete(self) -> cython.bint:
        """Return whether one exact duplicated branch became a suffix edge."""
        return bool(
            operator.ne(self.source_block_addr, self.canonical_block_addr)
            and operator.eq(self.original_successors, self.canonical_successors)
        )


@dataclasses.dataclass(frozen=True, )
class IRBlockSuccessorRewriteRefusal8616:
    """One overlap prefix whose successor ownership remained ambiguous."""

    source_block_addr: cython.longlong
    proposed_owner_addrs: object
    source_successors: object
    failure: IRBlockSuccessorRewriteFailure8616

    @property
    def complete(self) -> cython.bint:
        """Return whether the refusal retains an exact source and owner set."""
        return self.source_block_addr >= 0 and bool(self.proposed_owner_addrs)


@dataclasses.dataclass(frozen=True, )
class IRBlockSuccessorRewriteStats8616:
    """Closed accounting for overlap-prefix CFG successor candidates."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def closed(self) -> cython.bint:
        """Return whether every candidate was rewritten or refused."""
        return bool(
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count + self.failure_count
        )

    def to_summary(self) -> dict[str, cython.longlong]:
        """Return stable flat CFG-rewrite counters for IR diagnostics."""
        return {
            "block_successor_rewrite_raw_fact_count": self.raw_fact_count,
            "block_successor_rewrite_normalized_fact_count": self.normalized_fact_count,
            "block_successor_rewrite_classified_fact_count": self.classified_fact_count,
            "block_successor_rewrite_materialized_count": self.materialized_count,
            "block_successor_rewrite_failure_count": self.failure_count,
        }


@dataclasses.dataclass(frozen=True, )
class IRBlockOwnershipArtifact8616:
    """Canonical blocks plus every duplicate removal and overlap refusal."""

    blocks: object
    removals: object
    refusals: object
    stats: IRBlockOwnershipStats8616
    successor_rewrites: tuple[IRBlockSuccessorRewrite8616, ...] = ()
    successor_refusals: tuple[IRBlockSuccessorRewriteRefusal8616, ...] = ()
    successor_stats: IRBlockSuccessorRewriteStats8616 = (
        IRBlockSuccessorRewriteStats8616()
    )

    @property
    def complete(self) -> cython.bint:
        """Return whether all input instructions remain owned or canonicalized."""
        retained_count = sum(len(block.instrs) for block in iter(self.blocks))
        return (
            self.stats.complete
            and self.successor_stats.closed
            and operator.eq(retained_count + self.stats.materialized_count, self.stats.raw_fact_count)
            and operator.eq(len(self.successor_rewrites), self.successor_stats.materialized_count)
            and operator.eq(len(self.successor_refusals), self.successor_stats.failure_count)
            and all(item.complete for item in iter(self.successor_rewrites))
            and all(item.complete for item in iter(self.successor_refusals))
        )


def canonicalize_ir_block_ownership_8616(
    blocks: object,
) -> IRBlockOwnershipArtifact8616:
    """Remove only overlap instructions exactly decoded by a later block."""
    instr_addr: object
    next_start: object
    block_index: object
    instr_index: object
    instruction: object
    ordered = tuple(sorted(blocks, key=lambda block: block.addr))
    starts = tuple(block.addr for block in iter(ordered))
    by_addr = {block.addr: block for block in iter(ordered)}
    removals: list[IRBlockOwnershipRemoval8616] = []
    refusals: list[IRBlockOwnershipRefusal8616] = []
    successor_rewrites: list[IRBlockSuccessorRewrite8616] = []
    successor_refusals: list[IRBlockSuccessorRewriteRefusal8616] = []
    canonical_blocks: list[IRBlock] = []
    canonical_by_addr: dict[cython.longlong, IRBlock] = {}

    # Canonicalize suffixes first so prefix CFG edges can consume their proof.
    for block_index in reversed(range(len(ordered))):
        block = ordered[block_index]
        removal_start = len(removals)
        later_starts = starts[block_index + 1 :]
        next_start = later_starts[0] if later_starts else None
        retained = []
        for instr_index, instruction in enumerate(block.instrs):
            instr_addr = instruction.addr
            if next_start is None or instr_addr is None or instr_addr < next_start:
                retained.append(instruction)
                continue
            owner_addr = max(start for start in iter(later_starts) if start <= instr_addr)
            owner = by_addr[owner_addr]
            if any(operator.eq(candidate.addr, instr_addr) for candidate in iter(owner.instrs)):
                removals.append(
                    IRBlockOwnershipRemoval8616(
                        block.addr,
                        owner_addr,
                        instr_index,
                        instr_addr,
                    )
                )
                continue
            refusals.append(
                IRBlockOwnershipRefusal8616(
                    block.addr,
                    owner_addr,
                    instr_index,
                    instr_addr,
                    IRBlockOwnershipFailure8616.CANONICAL_OWNER_MISSING_INSTRUCTION,
                )
            )
            retained.append(instruction)
        block_removals = tuple(removals[removal_start:])
        successors = block.successor_addrs
        if block_removals:
            owner_addrs = tuple(
                sorted({removal.canonical_block_addr for removal in iter(block_removals)})
            )
            if successors == owner_addrs:
                pass
            elif not retained:
                successor_refusals.append(
                    IRBlockSuccessorRewriteRefusal8616(
                        block.addr,
                        owner_addrs,
                        successors,
                        IRBlockSuccessorRewriteFailure8616.SOURCE_PREFIX_EMPTY,
                    )
                )
            elif len(owner_addrs) != 1 and not proven_suffix_owner_chain_8616(
                block, tuple(retained), owner_addrs, by_addr, canonical_by_addr,
            ):
                successor_refusals.append(
                    IRBlockSuccessorRewriteRefusal8616(
                        block.addr,
                        owner_addrs,
                        successors,
                        IRBlockSuccessorRewriteFailure8616.MULTIPLE_SUFFIX_OWNERS,
                    )
                )
            else:
                owner = by_addr[owner_addrs[0]]
                if operator.eq(successors, owner.successor_addrs):
                    successor_rewrites.append(
                        IRBlockSuccessorRewrite8616(
                            block.addr,
                            owner.addr,
                            successors,
                            owner.successor_addrs,
                        )
                    )
                    successors = (owner.addr,)
                else:
                    successor_refusals.append(
                        IRBlockSuccessorRewriteRefusal8616(
                            block.addr,
                            owner_addrs,
                            successors,
                            IRBlockSuccessorRewriteFailure8616.SUCCESSOR_CONFLICT,
                        )
                    )
        canonical_blocks.append(
            IRBlock(
                addr=block.addr,
                instrs=tuple(retained),
                refusals=block.refusals,
                successor_addrs=successors,
            )
        )
        canonical_by_addr[block.addr] = canonical_blocks[-1]

    raw_count = sum(len(block.instrs) for block in iter(ordered))
    stats = IRBlockOwnershipStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=raw_count,
        classified_fact_count=len(removals) + len(refusals),
        materialized_count=len(removals),
        failure_count=len(refusals),
    )
    successor_raw_count = len(successor_rewrites) + len(successor_refusals)
    return IRBlockOwnershipArtifact8616(
        blocks=tuple(reversed(canonical_blocks)),
        removals=tuple(sorted(removals, key=lambda item: (item.source_block_addr, item.instr_index))),
        refusals=tuple(sorted(refusals, key=lambda item: (item.source_block_addr, item.instr_index))),
        stats=stats,
        successor_rewrites=tuple(sorted(successor_rewrites, key=lambda item: item.source_block_addr)),
        successor_refusals=tuple(sorted(successor_refusals, key=lambda item: item.source_block_addr)),
        successor_stats=IRBlockSuccessorRewriteStats8616(
            raw_fact_count=successor_raw_count,
            normalized_fact_count=successor_raw_count,
            classified_fact_count=successor_raw_count,
            materialized_count=len(successor_rewrites),
            failure_count=len(successor_refusals),
        ),
    )
