# cython: language_level=3, infer_types=True
"""Typed contracts for deterministic SSA CFG proof artifacts.

Layer: IR.
Responsibility: retain immutable CFG, dominator, natural-loop, refusal, and
closed evidence-counter projections for IR-owned control-flow proof.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum
import dataclasses
import operator

SSACFGEdge8616 = typing.TypeAliasType("SSACFGEdge8616", tuple[int, int])
SSACFGAdjacency8616 = typing.TypeAliasType("SSACFGAdjacency8616", tuple[tuple[int, tuple[int, ...]], ...])


class SSACFGFailureKind8616(StrEnum):
    """Stable reason a CFG, dominator, or natural-loop proof was refused."""

    EMPTY_CFG = "empty_cfg"
    DUPLICATE_BLOCK = "duplicate_block"
    ENTRY_BLOCK_MISSING = "entry_block_missing"
    SUCCESSOR_EVIDENCE_INCOMPLETE = "successor_evidence_incomplete"
    UNKNOWN_SUCCESSOR = "unknown_successor"
    UNKNOWN_PREDECESSOR = "unknown_predecessor"
    ENTRY_HAS_PREDECESSOR = "entry_has_predecessor"
    UNREACHABLE_BLOCK = "unreachable_block"
    SNAPSHOT_UNPROVEN = "snapshot_unproven"
    CFG_MISMATCH = "cfg_mismatch"
    LOOP_NODE_MISSING = "loop_node_missing"
    LATCH_BACKEDGE_MISSING = "latch_backedge_missing"
    HEADER_DOMINANCE_UNPROVEN = "header_dominance_unproven"
    NON_UNIQUE_LATCH = "non_unique_latch"
    NON_UNIQUE_ENTRY = "non_unique_entry"
    NON_UNIQUE_EXIT_TARGET = "non_unique_exit_target"


@dataclasses.dataclass(frozen=True, )
class SSACFGEvidenceStats8616:
    """Closed five-counter accounting for one CFG proof candidate."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0

    @property
    def closed(self) -> cython.bint:
        """Return whether the candidate has exactly one final outcome."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        return bool(
            all(count >= 0 for count in iter(counts))
            and self.raw_fact_count >= self.normalized_fact_count
            and self.normalized_fact_count >= self.classified_fact_count
            and self.classified_fact_count >= self.materialized_count
            and operator.eq(self.raw_fact_count, self.materialized_count + self.failure_count)
            and not (
                self.classified_fact_count > 0
                and self.materialized_count == 0
            )
        )


def ssa_cfg_neighbors_8616(
    adjacency: SSACFGAdjacency8616,
    node: cython.longlong,
) -> object:
    """Look up one immutable adjacency entry without manufacturing emptiness."""
    return next(
        (neighbors for address, neighbors in iter(adjacency) if address == node),
        None,
    )


@dataclasses.dataclass(frozen=True, )
class SSACFGSnapshot8616:
    """Immutable closed SSA CFG, or an empty typed refusal."""

    function_addr: cython.longlong
    block_addrs: object
    predecessor_map: SSACFGAdjacency8616
    successor_map: SSACFGAdjacency8616
    edges: object
    stats: SSACFGEvidenceStats8616
    failure: SSACFGFailureKind8616 | None = None
    refusal_nodes: tuple[cython.longlong, ...] = ()

    @property
    def complete(self) -> cython.bint:
        """Return whether all nodes and both adjacency projections are exact."""
        return bool(
            self.failure is None
            and self.stats.closed
            and self.stats.materialized_count == 1
            and operator.eq(self.block_addrs, tuple(sorted(tuple(set(self.block_addrs)))))
            and self.function_addr in self.block_addrs
            and operator.eq(tuple(node for node, _items in iter(self.predecessor_map)), self.block_addrs)
            and operator.eq(tuple(node for node, _items in iter(self.successor_map)), self.block_addrs)
            and self.refusal_nodes == ()
        )

    def predecessors(self, node: cython.longlong) -> object:
        """Return exact predecessors, or ``None`` when no CFG was proven."""
        return ssa_cfg_neighbors_8616(self.predecessor_map, node) if self.complete else None

    def successors(self, node: cython.longlong) -> object:
        """Return exact successors, or ``None`` when no CFG was proven."""
        return ssa_cfg_neighbors_8616(self.successor_map, node) if self.complete else None


@dataclasses.dataclass(frozen=True, )
class SSADominators8616:
    """Exact dominator sets tied to one immutable CFG edge relation."""

    function_addr: cython.longlong
    block_addrs: object
    cfg_edges: object
    dominator_sets: SSACFGAdjacency8616
    stats: SSACFGEvidenceStats8616
    failure: SSACFGFailureKind8616 | None = None

    @property
    def complete(self) -> cython.bint:
        """Return whether every CFG node has one exact dominator set."""
        return bool(
            self.failure is None
            and self.stats.closed
            and self.stats.materialized_count == 1
            and operator.eq(tuple(node for node, _items in iter(self.dominator_sets)), self.block_addrs)
        )

    def dominators(self, node: cython.longlong) -> object:
        """Return the node's exact dominators, or ``None`` when unproven."""
        return ssa_cfg_neighbors_8616(self.dominator_sets, node) if self.complete else None

    def dominates(self, dominator: cython.longlong, node: cython.longlong) -> bool | None:
        """Return exact dominance, or ``None`` when the relation is unproven."""
        values: object
        values = self.dominators(node)
        return None if values is None else dominator in values


@dataclasses.dataclass(frozen=True, )
class SSANaturalLoop8616:
    """Exact single-latch natural loop, or an empty typed refusal."""

    header: cython.longlong
    latch: cython.longlong
    blocks: object
    entry_edges: object
    backedges: object
    exit_edges: object
    stats: SSACFGEvidenceStats8616
    failure: SSACFGFailureKind8616 | None = None

    @property
    def complete(self) -> cython.bint:
        """Return whether exact single-entry and single-exit topology is proven."""
        return bool(
            self.failure is None
            and self.stats.closed
            and self.stats.materialized_count == 1
            and operator.eq(self.blocks, tuple(sorted(tuple(set(self.blocks)))))
            and self.header in self.blocks
            and self.latch in self.blocks
            and operator.eq(self.backedges, ((self.latch, self.header),))
            and all(operator.eq(target, self.header) for _source, target in iter(self.entry_edges))
            and self.exit_edges
            and len({target for _source, target in iter(self.exit_edges)}) == 1
        )


__all__ = [
    "SSACFGAdjacency8616",
    "SSACFGEdge8616",
    "SSACFGEvidenceStats8616",
    "SSACFGFailureKind8616",
    "SSACFGSnapshot8616",
    "SSADominators8616",
    "SSANaturalLoop8616",
    "ssa_cfg_neighbors_8616",
]
