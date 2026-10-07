"""Layer: Structuring.

Responsibility: convert dynamic angr/codegen clinic graphs into typed region graphs.
Forbidden: alias ownership, type recovery, rewrite cleanup, or source/COD/text-backed repair.

Package ownership contract (canonical inertia/structuring package):
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import cast

from inertia.structuring.structuring_region import Region, RegionGraph, RegionType


@dataclass(frozen=True)
class RegionGraphBuildResult:
    """Typed result of building a region graph from codegen/clinic state."""

    graph: RegionGraph | None
    entry: Region | None


def resolve_clinic_from_codegen(codegen: object) -> object | None:
    """Resolve the clinic object across the dynamic third-party angr/codegen boundary."""
    clinic = getattr(codegen, "_clinic", None)
    if clinic is not None:
        return cast(object, clinic)

    project = getattr(codegen, "project", None)
    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if project is None or func_addr is None:
        return None

    func = project.kb.functions.function(addr=func_addr, create=False)
    if func is None:
        return None
    return cast(object | None, getattr(func, "_clinic", None))


def _statement_addr_8616(stmt: object) -> int | None:
    """Read statement addresses across the dynamic third-party angr/codegen boundary."""
    tags = getattr(stmt, "tags", None)
    if isinstance(tags, dict) and isinstance(tags.get("ins_addr"), int):
        return int(tags["ins_addr"])
    for attr in ("ins_addr", "addr"):
        value = getattr(stmt, attr, None)
        if isinstance(value, int):
            return int(value)
    return None


def _statement_provenance_key_8616(stmt: object) -> tuple[str, int, int] | None:
    """Read statement provenance across the dynamic third-party angr/codegen boundary."""
    tags = getattr(stmt, "tags", None)
    if not isinstance(tags, dict):
        return None
    vex_block_addr = tags.get("vex_block_addr")
    vex_stmt_idx = tags.get("vex_stmt_idx")
    if isinstance(vex_block_addr, int) and isinstance(vex_stmt_idx, int):
        return ("vex", int(vex_block_addr), int(vex_stmt_idx))
    block_idx = tags.get("block_idx")
    stmt_idx = tags.get("stmt_idx")
    if isinstance(block_idx, int) and isinstance(stmt_idx, int):
        return ("ail", int(block_idx), int(stmt_idx))
    ins_addr = tags.get("ins_addr")
    if isinstance(ins_addr, int) and isinstance(stmt_idx, int):
        return ("stmt", int(ins_addr), int(stmt_idx))
    return None


def _node_statement_addrs_8616(node: object) -> tuple[int, ...]:
    """Collect statement addresses across the dynamic third-party angr/codegen boundary."""
    statements = tuple(getattr(node, "statements", ()) or ())
    addrs = sorted(
        {
            addr
            for stmt in statements
            if (addr := _statement_addr_8616(stmt)) is not None
        }
    )
    return tuple(addrs)


def _node_statement_provenance_keys_8616(node: object) -> tuple[tuple[str, int, int], ...]:
    """Collect provenance keys across the dynamic third-party angr/codegen boundary."""
    statements = tuple(getattr(node, "statements", ()) or ())
    keys = tuple(
        key
        for stmt in statements
        if (key := _statement_provenance_key_8616(stmt)) is not None
    )
    return tuple(dict.fromkeys(keys))


def _attach_region_statement_span_metadata_8616(region: Region, node: object) -> None:
    statement_addrs = _node_statement_addrs_8616(node)
    if not statement_addrs:
        statement_addrs = ()
    statement_keys = _node_statement_provenance_keys_8616(node)
    if statement_addrs:
        region.metadata["region_statement_ins_addrs"] = statement_addrs
    if statement_keys:
        region.metadata["region_statement_provenance_keys"] = statement_keys
    if statement_addrs or statement_keys:
        region.metadata["region_statement_span_source"] = "clinic_node_statements"


def build_region_graph(codegen: object) -> RegionGraphBuildResult:
    """Build a deterministic RegionGraph across the dynamic third-party angr/codegen boundary."""
    graph = RegionGraph()
    regions_by_addr: dict[int, Region] = {}
    clinic = resolve_clinic_from_codegen(codegen)

    ail_graph = getattr(clinic, "graph", None) if clinic is not None else None
    nodes_method = getattr(ail_graph, "nodes", None)
    edges_method = getattr(ail_graph, "edges", None)
    if callable(nodes_method) and callable(edges_method):
        node_iter = cast(Callable[[], Iterable[object]], nodes_method)
        edge_iter = cast(Callable[[], Iterable[tuple[object, object]]], edges_method)
        for node in node_iter():
            node_addr = getattr(node, "addr", None)
            if node_addr is None:
                continue
            region = Region(
                block_addr=node_addr,
                region_type=RegionType.Linear,
            )
            _attach_region_statement_span_metadata_8616(region, node)
            graph.add_node(region)
            regions_by_addr[node_addr] = region

        for src, dst in edge_iter():
            src_addr = getattr(src, "addr", None)
            dst_addr = getattr(dst, "addr", None)
            if src_addr in regions_by_addr and dst_addr in regions_by_addr:
                graph.add_edge(regions_by_addr[src_addr], regions_by_addr[dst_addr])

    cfunc = getattr(codegen, "cfunc", None)
    func_addr = getattr(cfunc, "addr", None)
    if func_addr is not None and func_addr in regions_by_addr:
        graph.entry = regions_by_addr[func_addr]
    elif regions_by_addr:
        graph.entry = next(iter(regions_by_addr.values()))

    if not graph.nodes:
        return RegionGraphBuildResult(graph=None, entry=None)
    return RegionGraphBuildResult(graph=graph, entry=graph.entry)
