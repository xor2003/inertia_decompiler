"""Region-based control-flow graph representation for structuring.

Layer: Structuring.
Responsibility: Maintain region graph ownership, edge rewrites, and dominator facts for structuring.

This module provides a region graph abstraction that wraps angr's control-flow graph.
Regions represent groups of statements that are being progressively coalesced into
structured control-flow patterns (sequence, if-then-else, loops, etc).

Inspired by:
  - Reko's StructureAnalysis.cs
  - "Native x86 Decompilation using Semantics-Preserving Structural Analysis
     and Iterative Control-Flow Structuring"
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass, field

type CNode = object


def _dynamic_codegen_attr_8616(obj: object, name: str, default: object = None) -> object:
    """Read optional angr/codegen attributes at the dynamic compatibility boundary."""
    return getattr(obj, name, default)


def _metadata_tuple_8616(value: object) -> tuple[object, ...]:
    """Normalize optional region metadata sequences to an immutable tuple."""
    if isinstance(value, tuple):
        return value
    if isinstance(value, list | set | frozenset):
        return tuple(value)
    return ()


def _metadata_int_tuple_8616(value: object) -> tuple[int, ...]:
    """Normalize optional region metadata address sequences to integer tuples."""
    return tuple(item for item in _metadata_tuple_8616(value) if isinstance(item, int))


class RegionType(enum.Enum):
    """Classification of regions based on their control-flow structure."""

    # A linear sequence of statements (no branches)
    Linear = "linear"

    # A conditional region (if-then, if-then-else, or other split)
    Condition = "condition"

    # An incomplete switch statement (multiple targets from one guard)
    IncSwitch = "incswitch"

    # A tail region terminated by a return or tail statement
    Tail = "tail"

    # A loop region (cyclic with single entry/exit where possible)
    Loop = "loop"


@dataclass(frozen=False)
class Region:
    """A region represents a set of statements with unified control-flow semantics.

    Initially, one region exists for each basic block. Through iterative refinement,
    regions are merged into larger structures representing if-then-else, loops, etc.

    Attributes:
        block_addr: Address of the primary block this region represents
        region_id: Unique identifier for this region (usually block_addr)
        region_type: Classification of the region
        statements: List of C AST statements in this region
        condition_expr: Optional condition expression (for Condition regions)
        predecessors: Set of regions that can branch to this one
        successors: Set of regions that this one can branch to
        is_switch_pad: True if this region is a switch guard block
        metadata: Additional metadata for debugging/analysis
    """

    block_addr: int | None = None
    region_id: int | None = None
    region_type: RegionType = RegionType.Linear
    statements: list[CNode] = field(default_factory=list)
    condition_expr: CNode | None = None
    predecessors: set[Region] = field(default_factory=set)
    successors: set[Region] = field(default_factory=set)
    is_switch_pad: bool = False
    metadata: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Ensure region_id defaults to block_addr if not set."""
        if self.region_id is None and self.block_addr is not None:
            self.region_id = self.block_addr

    def __hash__(self) -> int:
        """Regions are hashable by their ID."""
        return hash(self.region_id)

    def __eq__(self, other: object) -> bool:
        """Regions are equal if they have the same ID."""
        if not isinstance(other, Region):
            return False
        return self.region_id == other.region_id

    def __repr__(self) -> str:
        """String representation of region."""
        type_str = self.region_type.value
        switch_marker = "_$sw" if self.is_switch_pad else ""
        addr_str = f"{self.region_id:#x}" if self.region_id is not None else "?"
        return f"Region({addr_str}:{type_str}{switch_marker})"

    @property
    def is_linear(self) -> bool:
        """True if this region is a simple linear sequence."""
        return self.region_type == RegionType.Linear

    @property
    def is_condition(self) -> bool:
        """True if this region represents a conditional split."""
        return self.region_type == RegionType.Condition

    @property
    def is_cyclic(self) -> bool:
        """True if this region is part of a cycle (loop)."""
        # A region is cyclic if any successor dominates it
        # This is determined by the dominator graph, not stored here
        return False

    @property
    def is_tail(self) -> bool:
        """True if this region ends in a return/exit."""
        return self.region_type == RegionType.Tail

    def add_statement(self, stmt: CNode) -> None:
        """Add a statement to this region."""
        self.statements.append(stmt)

    def add_successor(self, successor: Region) -> None:
        """Add a successor edge to another region."""
        if successor not in self.successors:
            self.successors.add(successor)
            successor.predecessors.add(self)

    def add_predecessor(self, predecessor: Region) -> None:
        """Add a predecessor edge from another region."""
        if predecessor not in self.predecessors:
            self.predecessors.add(predecessor)
            predecessor.successors.add(self)

    def remove_successor(self, successor: Region) -> None:
        """Remove a successor edge."""
        if successor in self.successors:
            self.successors.discard(successor)
            successor.predecessors.discard(self)

    def remove_predecessor(self, predecessor: Region) -> None:
        """Remove a predecessor edge."""
        if predecessor in self.predecessors:
            self.predecessors.discard(predecessor)
            predecessor.successors.discard(self)

    def redirect_edges_to(self, target: Region) -> None:
        """Redirect all successors and predecessors to point to target instead.

        Used when merging or replacing regions.
        """
        # Redirect predecessors
        for pred in list(self.predecessors):
            pred.remove_successor(self)
            pred.add_successor(target)

        # Redirect successors
        for succ in list(self.successors):
            succ.remove_predecessor(self)
            succ.add_predecessor(target)

        # Clear our edges
        self.predecessors.clear()
        self.successors.clear()


@dataclass(frozen=False)
class RegionGraph:
    """A directed graph of regions representing the control-flow structure.

    This graph is built from angr's CFG and progressively refined by merging
    regions into larger structured patterns.

    Attributes:
        nodes: Set of all regions in the graph
        entry: The entry region (usually corresponds to function entry)
        _adjacency: Internal representation of edges
    """

    nodes: set[Region] = field(default_factory=set)
    entry: Region | None = None
    _adjacency: dict[Region, set[Region]] = field(default_factory=dict)

    def add_node(self, region: Region) -> None:
        """Add a region to the graph."""
        if region not in self.nodes:
            self.nodes.add(region)
            if region not in self._adjacency:
                self._adjacency[region] = set()

    def remove_node(self, region: Region) -> None:
        """Remove a region from the graph."""
        if region in self.nodes:
            self.nodes.discard(region)
            for pred in list(region.predecessors):
                pred.remove_successor(region)
                if pred in self._adjacency:
                    self._adjacency[pred].discard(region)
            for succ in list(region.successors):
                succ.remove_predecessor(region)
            region.predecessors.clear()
            region.successors.clear()
            self._adjacency.pop(region, None)

    def add_edge(self, src: Region, dst: Region) -> None:
        """Add a directed edge from src to dst."""
        self.add_node(src)
        self.add_node(dst)
        src.add_successor(dst)
        if src not in self._adjacency:
            self._adjacency[src] = set()
        self._adjacency[src].add(dst)

    def remove_edge(self, src: Region, dst: Region) -> None:
        """Remove a directed edge from src to dst."""
        src.remove_successor(dst)
        if src in self._adjacency:
            self._adjacency[src].discard(dst)

    def predecessors(self, region: Region) -> list[Region]:
        """Return all predecessors of a region."""
        return list(region.predecessors)

    def successors(self, region: Region) -> list[Region]:
        """Return all successors of a region."""
        return list(region.successors)

    def _merge_region_metadata_8616(self, src: Region, dst: Region) -> None:
        """Merge statement provenance and free metadata from src into dst."""
        src_statement_addrs = _metadata_int_tuple_8616(src.metadata.get("region_statement_ins_addrs", ()))
        dst_statement_addrs = _metadata_int_tuple_8616(dst.metadata.get("region_statement_ins_addrs", ()))
        src_statement_keys = _metadata_tuple_8616(src.metadata.get("region_statement_provenance_keys", ()))
        dst_statement_keys = _metadata_tuple_8616(dst.metadata.get("region_statement_provenance_keys", ()))
        if src_statement_addrs or dst_statement_addrs:
            dst.metadata["region_statement_ins_addrs"] = tuple(
                dict.fromkeys(
                    [
                        *dst_statement_addrs,
                        *src_statement_addrs,
                    ]
                )
            )
            dst.metadata["region_statement_span_source"] = "merged_region_statement_ins_addrs"
        if src_statement_keys or dst_statement_keys:
            dst.metadata["region_statement_provenance_keys"] = tuple(
                dict.fromkeys([*dst_statement_keys, *src_statement_keys])
            )
            dst.metadata["region_statement_span_source"] = "merged_region_statement_provenance"
        for key, value in src.metadata.items():
            if key not in dst.metadata:
                dst.metadata[key] = value

    def _transfer_merge_edges_8616(self, src: Region, dst: Region, transfer_edges: str) -> None:
        """Transfer selected src edges onto dst during a region merge."""
        if transfer_edges in ("both", "pred"):
            for pred in list(src.predecessors):
                pred.remove_successor(src)
                if pred != dst:
                    pred.add_successor(dst)

        if transfer_edges in ("both", "succ"):
            for succ in list(src.successors):
                src.remove_successor(succ)
                if succ != dst:
                    dst.add_successor(succ)

    def _merge_regions_impl_8616(self, src: Region, dst: Region, transfer_edges: str) -> None:
        """Apply the merge after the public method records the contract.

        Args:
            src: Source region to merge (will be removed)
            dst: Destination region (will absorb src's statements)
            transfer_edges: How to handle edges:
                - "both": transfer all src's edges to dst
                - "pred": transfer only incoming edges
                - "succ": transfer only outgoing edges
                - "none": don't transfer edges
        """
        if src == dst:
            return

        # Merge statements
        dst.statements.extend(src.statements)

        # Preserve structured region types (Loop, IncSwitch, Condition) over Linear
        # If either region has a more specific type, use that
        if src.region_type != RegionType.Linear:
            dst.region_type = src.region_type
        # Also merge metadata from src to dst
        self._merge_region_metadata_8616(src, dst)

        # Transfer edges
        self._transfer_merge_edges_8616(src, dst, transfer_edges)

        # Remove self-referencing edges from dst (can happen when merging loop bodies)
        if dst in dst.predecessors:
            dst.predecessors.discard(dst)
        if dst in dst.successors:
            dst.successors.discard(dst)
        if dst in self._adjacency.get(dst, set()):
            self._adjacency[dst].discard(dst)

        # Remove src from graph
        if src in self.nodes:
            self.nodes.discard(src)
            del self._adjacency[src]

    def merge_regions(self, src: Region, dst: Region, transfer_edges: str = "both") -> None:
        """Merge src into dst, combining statements and selected graph edges."""
        return self._merge_regions_impl_8616(src, dst, transfer_edges)

    def iter_postorder(self) -> list[Region]:
        """Return regions in post-order (children before parents).

        Used by structuring algorithm to ensure children are processed
        before their parents.
        """
        visited = set()
        postorder = []

        def dfs(node: Region) -> None:
            if node in visited:
                return
            visited.add(node)
            for succ in node.successors:
                dfs(succ)
            postorder.append(node)

        if self.entry is not None:
            dfs(self.entry)

        return postorder

    def iter_nodes(self) -> list[Region]:
        """Return all regions."""
        return list(self.nodes)

    def copy(self) -> RegionGraph:
        """Create a shallow copy of this graph."""
        new_graph = RegionGraph()
        new_graph.entry = self.entry
        new_graph.nodes = set(self.nodes)
        new_graph._adjacency = {k: set(v) for k, v in self._adjacency.items()}
        return new_graph


@dataclass(frozen=True)
class DominatorInfo:
    """Cached dominator and post-dominator relationships.

    Attributes:
        dominators: Set of regions that dominate each region
        immediate_dominator: The unique immediate dominator for each region
        strictly_dominates_map: Set of regions strictly dominated by each region
        post_dominators: Set of regions that post-dominate each region
        immediate_post_dominator: The unique immediate post-dominator for each region
        strictly_post_dominates_map: Set of regions strictly post-dominated by each region
    """

    dominators: dict[Region, set[Region]] = field(default_factory=dict)
    immediate_dominator: dict[Region, Region | None] = field(default_factory=dict)
    strictly_dominates_map: dict[Region, set[Region]] = field(default_factory=dict)
    post_dominators: dict[Region, set[Region]] = field(default_factory=dict)
    immediate_post_dominator: dict[Region, Region | None] = field(default_factory=dict)
    strictly_post_dominates_map: dict[Region, set[Region]] = field(default_factory=dict)

    def dominates(self, dom: Region, node: Region) -> bool:
        """True if dom dominates node."""
        return dom in self.dominators.get(node, set())

    def strictly_dominates(self, dom: Region, node: Region) -> bool:
        """True if dom strictly dominates node (dominates and is not equal)."""
        return node in self.strictly_dominates_map.get(dom, set())

    def is_back_edge(self, src: Region, dst: Region) -> bool:
        """True if src -> dst is a back edge.

        A back edge is one where the target dominates the source.
        """
        return self.strictly_dominates(dst, src)

    def post_dominates(self, pdom: Region, node: Region) -> bool:
        """True if pdom post-dominates node."""
        return pdom in self.post_dominators.get(node, set())

    def strictly_post_dominates(self, pdom: Region, node: Region) -> bool:
        """True if pdom strictly post-dominates node (post-dominates and is not equal)."""
        return node in self.strictly_post_dominates_map.get(pdom, set())


class RegionGraphBuilder:
    """Builds a region graph from an angr CFG."""

    def __init__(self, cfunc: object, logger: logging.Logger | None = None) -> None:
        """Initialize the builder.

        Args:
            cfunc: angr CFunctionNode (codegen.cfunc)
            logger: Optional logger for diagnostics
        """
        self.cfunc = cfunc
        self.logger = logger or logging.getLogger(__name__)
        self.regions_by_addr: dict[int, Region] = {}

    def build(self) -> tuple[RegionGraph, Region | None]:
        """Build a region graph from the CFG.

        Returns:
            Tuple of (region_graph, entry_region)
        """
        graph = RegionGraph()

        # Extract blocks from CFG (angr stores these in the codegen)
        blocks = self._extract_blocks()
        if not blocks:
            self.logger.warning("No blocks found in CFG")
            return graph, None

        # Create one region per block
        for block_addr in blocks:
            region = Region(
                block_addr=block_addr,
                region_type=RegionType.Linear,
            )
            graph.add_node(region)
            self.regions_by_addr[block_addr] = region

        # Extract edges (successors) from CFG
        edges = self._extract_edges(blocks)
        for src_addr, dst_addr in edges:
            src_region = self.regions_by_addr.get(src_addr)
            dst_region = self.regions_by_addr.get(dst_addr)
            if src_region is not None and dst_region is not None:
                graph.add_edge(src_region, dst_region)

        # Determine entry region
        entry_addr = _dynamic_codegen_attr_8616(self.cfunc, "addr", None)
        if isinstance(entry_addr, int):
            graph.entry = self.regions_by_addr.get(entry_addr)

        if graph.entry is None and graph.nodes:
            # Fallback: use any region as entry
            graph.entry = next(iter(graph.nodes))

        return graph, graph.entry

    def _extract_blocks(self) -> list[int]:
        """Extract basic block addresses from the CFG.

        Returns:
            List of block addresses
        """
        # This is a simplified version - in real implementation,
        # we'd extract from angr's CFG structure in codegen
        blocks: list[int] = []

        # Try to get blocks from cfunc
        blocks_attr = _dynamic_codegen_attr_8616(self.cfunc, "blocks", ())
        if isinstance(blocks_attr, list | tuple | set | frozenset):
            for block in blocks_attr:
                block_addr = _dynamic_codegen_attr_8616(block, "addr", None)
                if isinstance(block_addr, int):
                    blocks.append(block_addr)

        return blocks

    def _extract_edges(self, blocks: list[int]) -> list[tuple[int, int]]:
        """Extract control-flow edges from the CFG.

        Args:
            blocks: List of block addresses

        Returns:
            List of (src_addr, dst_addr) tuples
        """
        # This is a simplified version - in real implementation,
        # we'd extract from angr's execution graph
        edges: list[tuple[int, int]] = []

        # Try to get successors from cfunc
        successors = _dynamic_codegen_attr_8616(self.cfunc, "successors", None)
        if isinstance(successors, dict):
            for block_addr in blocks:
                succs = successors.get(block_addr, [])
                if not isinstance(succs, list | tuple | set | frozenset):
                    continue
                for succ_addr in succs:
                    if isinstance(succ_addr, int) and succ_addr in blocks:
                        edges.append((block_addr, succ_addr))

        return edges


def _immediate_dominators_8616(
    dominators: dict[Region, set[Region]],
    all_regions: list[Region],
) -> tuple[dict[Region, Region | None], dict[Region, set[Region]]]:
    """Derive immediate dominators and strict-dominance from dominator sets."""
    immediate_dominator: dict[Region, Region | None] = {}
    strictly_dominates_map: dict[Region, set[Region]] = {r: set() for r in all_regions}

    for region in all_regions:
        doms = dominators[region] - {region}
        immediate_dominator[region] = None if not doms else max(doms, key=lambda d: len(dominators[d]))
    for region, doms in dominators.items():
        for dom in doms:
            if dom != region:
                strictly_dominates_map[dom].add(region)
    return immediate_dominator, strictly_dominates_map


def _immediate_post_dominators_8616(
    post_dominators: dict[Region, set[Region]],
    all_regions: list[Region],
) -> tuple[dict[Region, Region | None], dict[Region, set[Region]]]:
    """Derive immediate post-dominators and strict post-dominance."""
    immediate_post_dominator: dict[Region, Region | None] = {}
    strictly_post_dominates_map: dict[Region, set[Region]] = {r: set() for r in all_regions}

    for region in all_regions:
        pdoms = post_dominators[region] - {region}
        if not pdoms:
            immediate_post_dominator[region] = None
        else:
            # Immediate post-dominator is the one that post-dominates the fewest nodes
            # (closest in the post-dominator tree)
            ipdom = min(pdoms, key=lambda pd: len(post_dominators[pd]))
            immediate_post_dominator[region] = ipdom

    for region, pdoms in post_dominators.items():
        for pdom in pdoms:
            if pdom != region:
                strictly_post_dominates_map[pdom].add(region)
    return immediate_post_dominator, strictly_post_dominates_map


def _compute_dominators_impl_8616(graph: RegionGraph) -> DominatorInfo:
    """Run the iterative dominator and post-dominator fixpoint algorithms.

    Implements the iterative fixpoint algorithm:
    - dom(entry) = {entry}
    - dom(n) = {n} ∪ (∩ dom(predecessors of n))

    Args:
        graph: Region graph to analyze

    Returns:
        DominatorInfo object with cached relationships
    """  # noqa: RUF002
    if graph.entry is None:
        return DominatorInfo()

    all_regions = graph.iter_nodes()
    dominators = _compute_fixpoint_dominators(graph, all_regions)

    # Compute immediate dominators and strictly_dominates relationships
    immediate_dominator, strictly_dominates_map = _immediate_dominators_8616(
        dominators, all_regions
    )

    # Compute post-dominators (dominators in reverse graph)
    # Identify exit nodes (regions with no successors)
    exit_nodes = [r for r in all_regions if not graph.successors(r)]

    post_dominators = _compute_fixpoint_post_dominators(graph, all_regions, exit_nodes)

    # Compute immediate post-dominators
    immediate_post_dominator, strictly_post_dominates_map = (
        _immediate_post_dominators_8616(post_dominators, all_regions)
    )

    return DominatorInfo(
        dominators=dominators,
        immediate_dominator=immediate_dominator,
        strictly_dominates_map=strictly_dominates_map,
        post_dominators=post_dominators,
        immediate_post_dominator=immediate_post_dominator,
        strictly_post_dominates_map=strictly_post_dominates_map,
    )


def compute_dominators(graph: RegionGraph) -> DominatorInfo:
    """Compute dominator relationships for all regions."""
    return _compute_dominators_impl_8616(graph)


def _compute_fixpoint_dominators(graph: RegionGraph, all_regions: list[Region]) -> dict[Region, set[Region]]:
    entry = graph.entry
    if entry is None:
        return {}
    dominators: dict[Region, set[Region]] = {region: set(all_regions) for region in all_regions}
    dominators[entry] = {entry}
    changed = True
    while changed:
        changed = False
        for region in all_regions:
            if region == entry:
                continue
            preds = graph.predecessors(region)
            new_dom = (
                {region}
                if not preds
                else {region} | set.intersection(*(dominators.get(p, set(all_regions)) for p in preds))
            )
            if new_dom != dominators[region]:
                dominators[region] = new_dom
                changed = True
    return dominators


def _compute_fixpoint_post_dominators(
    graph: RegionGraph, all_regions: list[Region], exit_nodes: list[Region]
) -> dict[Region, set[Region]]:
    post_dominators: dict[Region, set[Region]] = {region: set(all_regions) for region in all_regions}
    for exit_node in exit_nodes:
        post_dominators[exit_node] = {exit_node}
    changed = True
    while changed:
        changed = False
        for region in all_regions:
            if region in exit_nodes:
                continue
            succs = graph.successors(region)
            new_pdom = (
                {region}
                if not succs
                else {region} | set.intersection(*(post_dominators.get(s, set(all_regions)) for s in succs))
            )
            if new_pdom != post_dominators[region]:
                post_dominators[region] = new_pdom
                changed = True
    return post_dominators
