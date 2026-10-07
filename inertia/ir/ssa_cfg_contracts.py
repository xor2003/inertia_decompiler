"""Typed contracts for deterministic SSA CFG proof artifacts.

Layer: IR.
Responsibility: retain immutable CFG, dominator, natural-loop, refusal, and
closed evidence-counter projections for IR-owned control-flow proof.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

type SSACFGEdge8616 = tuple[int, int]
type SSACFGAdjacency8616 = tuple[tuple[int, tuple[int, ...]], ...]


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


@dataclass(frozen=True, slots=True)
class SSACFGEvidenceStats8616:
    """Closed five-counter accounting for one CFG proof candidate."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    @property
    def closed(self) -> bool:
        """Return whether the candidate has exactly one final outcome."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        return bool(
            all(count >= 0 for count in counts)
            and self.raw_fact_count >= self.normalized_fact_count
            and self.normalized_fact_count >= self.classified_fact_count
            and self.classified_fact_count >= self.materialized_count
            and self.raw_fact_count == self.materialized_count + self.failure_count
            and not (
                self.classified_fact_count > 0
                and self.materialized_count == 0
            )
        )


def ssa_cfg_neighbors_8616(
    adjacency: SSACFGAdjacency8616,
    node: int,
) -> tuple[int, ...] | None:
    """Look up one immutable adjacency entry without manufacturing emptiness."""
    return next(
        (neighbors for address, neighbors in adjacency if address == node),
        None,
    )


@dataclass(frozen=True, slots=True)
class SSACFGSnapshot8616:
    """Immutable closed SSA CFG, or an empty typed refusal."""

    function_addr: int
    block_addrs: tuple[int, ...]
    predecessor_map: SSACFGAdjacency8616
    successor_map: SSACFGAdjacency8616
    edges: tuple[SSACFGEdge8616, ...]
    stats: SSACFGEvidenceStats8616
    failure: SSACFGFailureKind8616 | None = None
    refusal_nodes: tuple[int, ...] = ()

    @property
    def complete(self) -> bool:
        """Return whether all nodes and both adjacency projections are exact."""
        return bool(
            self.failure is None
            and self.stats.closed
            and self.stats.materialized_count == 1
            and self.block_addrs == tuple(sorted(set(self.block_addrs)))
            and self.function_addr in self.block_addrs
            and tuple(node for node, _items in self.predecessor_map)
            == self.block_addrs
            and tuple(node for node, _items in self.successor_map)
            == self.block_addrs
            and self.refusal_nodes == ()
        )

    def predecessors(self, node: int) -> tuple[int, ...] | None:
        """Return exact predecessors, or ``None`` when no CFG was proven."""
        return ssa_cfg_neighbors_8616(self.predecessor_map, node) if self.complete else None

    def successors(self, node: int) -> tuple[int, ...] | None:
        """Return exact successors, or ``None`` when no CFG was proven."""
        return ssa_cfg_neighbors_8616(self.successor_map, node) if self.complete else None


@dataclass(frozen=True, slots=True)
class SSADominators8616:
    """Exact dominator sets tied to one immutable CFG edge relation."""

    function_addr: int
    block_addrs: tuple[int, ...]
    cfg_edges: tuple[SSACFGEdge8616, ...]
    dominator_sets: SSACFGAdjacency8616
    stats: SSACFGEvidenceStats8616
    failure: SSACFGFailureKind8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether every CFG node has one exact dominator set."""
        return bool(
            self.failure is None
            and self.stats.closed
            and self.stats.materialized_count == 1
            and tuple(node for node, _items in self.dominator_sets)
            == self.block_addrs
        )

    def dominators(self, node: int) -> tuple[int, ...] | None:
        """Return the node's exact dominators, or ``None`` when unproven."""
        return ssa_cfg_neighbors_8616(self.dominator_sets, node) if self.complete else None

    def dominates(self, dominator: int, node: int) -> bool | None:
        """Return exact dominance, or ``None`` when the relation is unproven."""
        values = self.dominators(node)
        return None if values is None else dominator in values


@dataclass(frozen=True, slots=True)
class SSANaturalLoop8616:
    """Exact single-latch natural loop, or an empty typed refusal."""

    header: int
    latch: int
    blocks: tuple[int, ...]
    entry_edges: tuple[SSACFGEdge8616, ...]
    backedges: tuple[SSACFGEdge8616, ...]
    exit_edges: tuple[SSACFGEdge8616, ...]
    stats: SSACFGEvidenceStats8616
    failure: SSACFGFailureKind8616 | None = None

    @property
    def complete(self) -> bool:
        """Return whether exact single-entry and single-exit topology is proven."""
        return bool(
            self.failure is None
            and self.stats.closed
            and self.stats.materialized_count == 1
            and self.blocks == tuple(sorted(set(self.blocks)))
            and self.header in self.blocks
            and self.latch in self.blocks
            and self.backedges == ((self.latch, self.header),)
            and all(target == self.header for _source, target in self.entry_edges)
            and self.exit_edges
            and len({target for _source, target in self.exit_edges}) == 1
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
