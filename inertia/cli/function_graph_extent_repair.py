# cython: language_level=3, infer_types=True
"""Repair undercovered x86-16 function-graph nodes before decompilation.

Layer: CLI/fallback/reporting.
Responsibility: reconcile bounded angr function nodes when transition evidence lies outside their decoded extent.

This module does not recover semantics; it repairs the discovery artifact that owns which instructions reach Clinic.
Later IR, Structuring, and Rewrite layers must never synthesize instructions
that this boundary silently omitted.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import Enum

import angr
import networkx as nx
from angr.codenode import BlockNode
from angr.knowledge_plugins.functions.function import Function
import dataclasses
import operator
import builtins


class FunctionGraphExtentRepairVerdict8616(Enum):
    """Typed outcome of one function-graph extent reconciliation."""

    CLEAN = "clean"
    REPAIRED = "repaired"
    REFUSED = "refused"


class FunctionGraphExtentRefusalReason8616(Enum):
    """Evidence reason why an undercovered source node was not extended."""

    DECODE_FAILED = "decode_failed"
    DECODE_ADDR_MISMATCH = "decode_addr_mismatch"
    DECODE_NOT_WIDER = "decode_not_wider"
    MISSING_EXACT_REGION = "missing_exact_region"
    TERMINATOR_NOT_DECODED = "terminator_not_decoded"
    INTERIOR_LEADER = "interior_leader"
    NON_LOCAL_SOURCE = "non_local_source"
    OUTSIDE_EXACT_REGION = "outside_exact_region"
    REPLACEMENT_FAILED = "replacement_failed"


@dataclasses.dataclass(frozen=True, )
class FunctionGraphExtentRefusal8616:
    """One typed refusal to alter an incoherent transition source node."""

    source_addr: cython.longlong
    existing_size: cython.longlong
    edge_ins_addrs: object
    reason: FunctionGraphExtentRefusalReason8616
    detail: object = None


@dataclasses.dataclass(frozen=True, )
class FunctionGraphExtentRepairStats8616:
    """Closed evidence accounting for one graph-extent repair pass."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong
    refusals: object

    @property
    def verdict(self) -> FunctionGraphExtentRepairVerdict8616:
        """Return the typed aggregate verdict without parsing diagnostics."""
        if self.failure_count:
            return FunctionGraphExtentRepairVerdict8616.REFUSED
        if self.materialized_count:
            return FunctionGraphExtentRepairVerdict8616.REPAIRED
        return FunctionGraphExtentRepairVerdict8616.CLEAN


class FunctionGraphExtentRepairError(RuntimeError):
    """Raised when an undercovered transition source cannot be proven safe."""


@cython.ccall
def _third_party_node_addr(node: object) -> int | None:
    """Read an optional address from a dynamic angr/networkx graph node."""
    addr: object
    # Dynamic third-party graph boundary: nodes are not all BlockNode instances.
    addr = getattr(node, "addr", None)
    return int(addr) if isinstance(addr, int) else None


@cython.ccall
def _refusal(
    source: BlockNode,
    edge_ins_addrs: object,
    reason: FunctionGraphExtentRefusalReason8616,
    detail: object = None,
) -> FunctionGraphExtentRefusal8616:
    """Build a refusal from one normalized source-node fact."""
    return FunctionGraphExtentRefusal8616(
        source_addr=int(source.addr),
        existing_size=int(source.size),
        edge_ins_addrs=edge_ins_addrs,
        reason=reason,
        detail=detail,
    )


def _replace_function_block_node_8616(
    function: Function,
    source: BlockNode,
    decoded_block: angr.Block,
) -> None:
    """Replace one BlockNode while preserving graph and function ownership."""
    edge_data: object
    edge_source: object
    edge_target: object
    sites: object
    graph = function.transition_graph
    replacement = BlockNode(
        int(source.addr),
        int(decoded_block.size),
        bytestr=bytes(decoded_block.bytes),
        thumb=source.thumb,
    )
    node_attributes = dict(graph.nodes[source])
    incident_edges = tuple(
        (edge_source, edge_target, dict(edge_data))
        for edge_source, edge_target, edge_data in builtins.iter(graph.edges(data=True))
        if edge_source is source or edge_target is source
    )
    graph.remove_node(source)
    graph.add_node(replacement, **node_attributes)
    replacement.set_graph(graph)
    for edge_source, edge_target, edge_data in incident_edges:
        graph.add_edge(
            replacement if edge_source is source else edge_source,
            replacement if edge_target is source else edge_target,
            **edge_data,
        )

    function._addr_to_block_node[int(source.addr)] = replacement
    function._block_sizes[int(source.addr)] = int(decoded_block.size)
    function._local_blocks[int(source.addr)] = replacement
    function._local_block_addrs.add(int(source.addr))
    if function.startpoint is source:
        function.startpoint = replacement
    for sites in (function._ret_sites,
        function._jumpout_sites,
        function._callout_sites,
        function._retout_sites,
        ) + tuple(function._endpoints.values()):
        if source in sites:
            sites.remove(source)
            sites.add(replacement)
    function._local_transition_graph = None
    function._cyclomatic_complexity = None
    function.mark_dirty()


def _materialize_replacements_8616(
    function: Function,
    plans: object,
) -> None:
    """Apply all proven replacements atomically across angr graph caches."""
    _data: object
    decoded_block: object
    node: object
    source: object
    graph = function.transition_graph
    saved_nodes = tuple((node, dict(data)) for node, data in builtins.iter(graph.nodes(data=True)))
    saved_edges = tuple((source, target, dict(data)) for source, target, data in builtins.iter(graph.edges(data=True)))
    saved_addr_nodes = dict(function._addr_to_block_node)
    saved_block_sizes = dict(function._block_sizes)
    saved_local_blocks = dict(function._local_blocks)
    saved_local_addrs = set(function._local_block_addrs)
    saved_startpoint = function.startpoint
    endpoint_sets = (function._ret_sites, function._jumpout_sites, function._callout_sites, function._retout_sites)
    saved_endpoint_sets = tuple(set(sites) for sites in iter(endpoint_sets))
    saved_endpoints = {kind: set(sites) for kind, sites in builtins.iter(function._endpoints.items())}
    saved_local_graph = function._local_transition_graph
    saved_complexity = function._cyclomatic_complexity
    saved_dirty = function._dirty
    try:
        for source, decoded_block in plans:
            _replace_function_block_node_8616(function, source, decoded_block)
    except Exception:
        graph.clear()
        graph.add_nodes_from(saved_nodes)
        graph.add_edges_from(saved_edges)
        for node, _data in saved_nodes:
            node.set_graph(graph)
        function._addr_to_block_node = saved_addr_nodes
        function._block_sizes = saved_block_sizes
        function._local_blocks = saved_local_blocks
        function._local_block_addrs = saved_local_addrs
        function.startpoint = saved_startpoint
        function._ret_sites, function._jumpout_sites, function._callout_sites, function._retout_sites = (
            saved_endpoint_sets
        )
        function._endpoints = saved_endpoints
        function._local_transition_graph = saved_local_graph
        function._cyclomatic_complexity = saved_complexity
        function._dirty = saved_dirty
        raise


@cython.ccall
def _out_of_block_ins_addrs_8616(graph: nx.DiGraph) -> object:
    """Collect edge ins_addrs that fall outside their source block extent."""
    ins_addr: object
    _target: object
    edge_data: object
    source: object
    raw_facts: list[tuple[BlockNode, cython.longlong]] = []
    for source, _target, edge_data in tuple(graph.edges(data=True)):
        if not isinstance(source, BlockNode):
            continue
        ins_addr = edge_data.get("ins_addr")
        if not isinstance(ins_addr, int):
            continue
        if int(source.addr) <= ins_addr < int(source.addr) + int(source.size):
            continue
        raw_facts.append((source, ins_addr))
    normalized: dict[BlockNode, set[cython.longlong]] = {}
    for source, ins_addr in raw_facts:
        normalized.setdefault(source, set()).add(ins_addr)
    return normalized


def _extent_repair_plan_8616(
    project: angr.Project,
    function: Function,
    graph: nx.DiGraph,
    source: BlockNode,
    edge_ins_addrs: object,
    exact_region: object,
) -> object:
    """Validate one source and return its replacement plan or typed refusal."""
    final_instruction: object
    if exact_region is None:
        return _refusal(source, edge_ins_addrs, FunctionGraphExtentRefusalReason8616.MISSING_EXACT_REGION)
    if (
        function._local_blocks.get(int(source.addr)) is not source
        or int(source.addr) not in function._local_block_addrs
    ):
        return _refusal(source, edge_ins_addrs, FunctionGraphExtentRefusalReason8616.NON_LOCAL_SOURCE)
    try:
        decoded_block = project.factory.block(int(source.addr), opt_level=0)
    except Exception as exc:  # Third-party decoder boundary.
        return _refusal(
            source,
            edge_ins_addrs,
            FunctionGraphExtentRefusalReason8616.DECODE_FAILED,
            type(exc).__name__,
        )

    if operator.ne(int(decoded_block.addr), int(source.addr)):
        return _refusal(source, edge_ins_addrs, FunctionGraphExtentRefusalReason8616.DECODE_ADDR_MISMATCH)
    decoded_size = int(decoded_block.size)
    if decoded_size <= int(source.size):
        return _refusal(source, edge_ins_addrs, FunctionGraphExtentRefusalReason8616.DECODE_NOT_WIDER)
    decoded_end = int(source.addr) + decoded_size
    decoded_instructions = tuple(decoded_block.capstone.insns or ())
    final_instruction = decoded_instructions[-1] if decoded_instructions else None
    final_addr = final_instruction.address if final_instruction is not None else None
    final_size = final_instruction.size if final_instruction is not None else None
    if (
        not isinstance(final_addr, int)
        or not isinstance(final_size, int)
        or operator.ne(final_addr + final_size, decoded_end)
        or any(ins_addr != final_addr for ins_addr in iter(edge_ins_addrs))
    ):
        return _refusal(source, edge_ins_addrs, FunctionGraphExtentRefusalReason8616.TERMINATOR_NOT_DECODED)
    if not (exact_region[0] <= int(source.addr) and decoded_end <= exact_region[1]):
        return _refusal(source, edge_ins_addrs, FunctionGraphExtentRefusalReason8616.OUTSIDE_EXACT_REGION)
    interior_leaders = tuple(
        sorted(
            addr
            for node in iter(graph.nodes)
            if node is not source
            if (addr := _third_party_node_addr(node)) is not None
            if int(source.addr) < addr < decoded_end
        )
    )
    if interior_leaders:
        detail = ",".join(f"{addr:#x}" for addr in iter(interior_leaders))
        return _refusal(source, edge_ins_addrs, FunctionGraphExtentRefusalReason8616.INTERIOR_LEADER, detail)

    return source, decoded_block


def repair_undercovered_transition_sources_8616(
    project: angr.Project,
    function: Function,
    *,
    exact_region: object = None,
) -> FunctionGraphExtentRepairStats8616:
    """Extend transition sources only when decoded coverage proves the extent."""
    raw_edge_ins_addrs: object
    source: object
    graph = function.transition_graph
    normalized = _out_of_block_ins_addrs_8616(graph)

    plans: list[tuple[BlockNode, angr.Block]] = []
    refusals: list[FunctionGraphExtentRefusal8616] = []
    for source, raw_edge_ins_addrs in normalized.items():
        outcome = _extent_repair_plan_8616(
            project,
            function,
            graph,
            source,
            tuple(sorted(raw_edge_ins_addrs)),
            exact_region,
        )
        if isinstance(outcome, FunctionGraphExtentRefusal8616):
            refusals.append(outcome)
        else:
            plans.append(outcome)

    materialized_count = 0
    if plans and not refusals:
        try:
            _materialize_replacements_8616(function, tuple(plans))
        except Exception as exc:  # Third-party graph mutation boundary.
            source = plans[0][0]
            edge_ins_addrs = tuple(sorted(normalized[source]))
            refusals.append(
                _refusal(
                    source,
                    edge_ins_addrs,
                    FunctionGraphExtentRefusalReason8616.REPLACEMENT_FAILED,
                    type(exc).__name__,
                )
            )
        else:
            materialized_count = len(plans)

    return FunctionGraphExtentRepairStats8616(
        raw_fact_count=sum(len(addrs) for addrs in builtins.iter(normalized.values())),
        normalized_fact_count=len(normalized),
        classified_fact_count=len(plans),
        materialized_count=materialized_count,
        failure_count=len(refusals),
        refusals=tuple(refusals),
    )


def enforce_covered_transition_sources_8616(
    project: angr.Project,
    function: Function,
    *,
    exact_region: object = None,
) -> FunctionGraphExtentRepairStats8616:
    """Repair proven extents and stop recovery on every unresolved deficit."""
    stats = repair_undercovered_transition_sources_8616(
        project,
        function,
        exact_region=exact_region,
    )
    if stats.failure_count:
        details = "; ".join(
            f"source={refusal.source_addr:#x} edge={','.join(f'{addr:#x}' for addr in iter(refusal.edge_ins_addrs))} "
            f"reason={refusal.reason.value} detail={refusal.detail or '-'}"
            for refusal in iter(stats.refusals)
        )
        raise FunctionGraphExtentRepairError(
            "x86-16 function graph has unresolved undercovered transition sources: "
            f"raw={stats.raw_fact_count} normalized={stats.normalized_fact_count} "
            f"classified={stats.classified_fact_count} materialized={stats.materialized_count} "
            f"failures={stats.failure_count}; {details}"
        )
    return stats
