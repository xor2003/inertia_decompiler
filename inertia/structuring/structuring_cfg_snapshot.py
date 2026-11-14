# cython: language_level=3, infer_types=True
"""Layer: Structuring.

Responsibility: publish deterministic CFG snapshots from typed region graphs.
Forbidden: alias ownership, type recovery, rewrite cleanup, or source/COD/text-backed repair.

Package ownership contract (canonical inertia/structuring package):
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass

from inertia.structuring.structuring_graph_builder import build_region_graph
import dataclasses
import builtins

CFGStatementProvenanceKey8616 = typing.TypeAliasType("CFGStatementProvenanceKey8616", tuple[str, int, int])


@dataclasses.dataclass(frozen=True, )
class CFGSnapshotNode:
    """One region node in the structuring CFG snapshot."""

    region_id: cython.longlong
    block_addr: int | None
    predecessor_ids: object
    successor_ids: object
    ownership: object
    reachable_from_entry: cython.bint
    statement_ins_addrs: tuple[cython.longlong, ...] = ()
    statement_provenance_keys: tuple[CFGStatementProvenanceKey8616, ...] = ()


@dataclasses.dataclass(frozen=True, )
class CFGSnapshot:
    """Deterministic snapshot of the region graph seen by structuring."""

    entry_region_id: int | None
    node_count: cython.longlong
    edge_count: cython.longlong
    nodes: object
    shared_region_ids: tuple[cython.longlong, ...] = ()
    external_entry_region_ids: tuple[cython.longlong, ...] = ()
    indirect_site_ids: tuple[cython.longlong, ...] = ()

    def summary_line(self) -> str:
        """Compact deterministic summary for diagnostics."""
        entry = hex(self.entry_region_id) if self.entry_region_id is not None else "none"
        return (
            f"cfg_snapshot nodes={self.node_count} edges={self.edge_count} "
            f"entry={entry} shared={len(self.shared_region_ids)} indirect={len(self.indirect_site_ids)}"
        )

    def to_dict(self) -> dict[str, object]:
        """Stable serialization for reports and artifacts."""
        return {
            "entry_region_id": hex(self.entry_region_id) if self.entry_region_id is not None else None,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "shared_region_ids": [hex(region_id) for region_id in iter(self.shared_region_ids)],
            "external_entry_region_ids": [hex(region_id) for region_id in iter(self.external_entry_region_ids)],
            "indirect_site_ids": [hex(region_id) for region_id in iter(self.indirect_site_ids)],
            "nodes": [
                {
                    "region_id": hex(node.region_id),
                    "block_addr": hex(node.block_addr) if node.block_addr is not None else None,
                    "predecessor_ids": [hex(region_id) for region_id in iter(node.predecessor_ids)],
                    "successor_ids": [hex(region_id) for region_id in iter(node.successor_ids)],
                    "ownership": node.ownership,
                    "reachable_from_entry": node.reachable_from_entry,
                    "statement_ins_addrs": [hex(ins_addr) for ins_addr in iter(node.statement_ins_addrs)],
                    "statement_provenance_keys": [
                        [kind, hex(block_addr), statement_index]
                        for kind, block_addr, statement_index in iter(node.statement_provenance_keys)
                    ],
                }
                for node in iter(self.nodes)
            ],
        }


def _statement_ins_addrs_8616(metadata: object) -> tuple[cython.longlong, ...]:
    """Copy a complete typed instruction-address tuple or refuse malformed metadata."""
    raw_addrs: object
    raw_addrs = metadata.get("region_statement_ins_addrs", ())
    if not isinstance(raw_addrs, tuple) or any(not isinstance(addr, int) for addr in iter(raw_addrs)):
        return ()
    return tuple(raw_addrs)


@cython.ccall
def _statement_provenance_keys_8616(
    metadata: object,
) -> tuple[CFGStatementProvenanceKey8616, ...]:
    """Copy complete typed statement provenance or refuse malformed metadata."""
    raw_keys: object
    key: object
    raw_keys = metadata.get("region_statement_provenance_keys", ())
    if not isinstance(raw_keys, tuple):
        return ()
    keys: list[CFGStatementProvenanceKey8616] = []
    for key in raw_keys:
        if not (
            isinstance(key, tuple)
            and len(key) == 3
            and isinstance(key[0], str)
            and isinstance(key[1], int)
            and isinstance(key[2], int)
        ):
            return ()
        keys.append((key[0], key[1], key[2]))
    return tuple(keys)


def build_cfg_snapshot(codegen: object) -> CFGSnapshot | None:
    """Build a deterministic CFG snapshot from codegen."""
    graph: object
    region: object
    succ: object
    result = build_region_graph(codegen)
    graph = result.graph
    if graph is None:
        return None

    reachable_from_entry: set[cython.longlong] = set()
    if result.entry is not None:
        worklist = [result.entry]
        seen = set()
        while worklist:
            region = worklist.pop()
            if region in seen:
                continue
            seen.add(region)
            if region.region_id is not None:
                reachable_from_entry.add(region.region_id)
            for succ in graph.successors(region):
                if succ not in seen:
                    worklist.append(succ)

    snapshot_nodes: list[CFGSnapshotNode] = []
    edge_count = 0
    ordered_regions = sorted(
        graph.nodes,
        key=lambda item: ((item.region_id is None), item.region_id if item.region_id is not None else -1),
    )
    for region in ordered_regions:
        predecessor_ids = tuple(
            sorted(pred.region_id for pred in builtins.iter(graph.predecessors(region)) if pred.region_id is not None)
        )
        successor_ids = tuple(
            sorted(succ.region_id for succ in builtins.iter(graph.successors(region)) if succ.region_id is not None)
        )
        edge_count += len(successor_ids)
        ownership = "shared" if len(predecessor_ids) > 1 else "single"
        snapshot_nodes.append(
            CFGSnapshotNode(
                region_id=region.region_id if region.region_id is not None else -1,
                block_addr=region.block_addr,
                predecessor_ids=predecessor_ids,
                successor_ids=successor_ids,
                ownership=ownership,
                reachable_from_entry=(region.region_id in reachable_from_entry),
                statement_ins_addrs=_statement_ins_addrs_8616(region.metadata),
                statement_provenance_keys=_statement_provenance_keys_8616(region.metadata),
            )
        )

    shared_region_ids = tuple(node.region_id for node in iter(snapshot_nodes) if node.ownership == "shared")
    entry_region_id = result.entry.region_id if result.entry is not None else None
    return CFGSnapshot(
        entry_region_id=entry_region_id,
        node_count=len(snapshot_nodes),
        edge_count=edge_count,
        nodes=tuple(snapshot_nodes),
        shared_region_ids=shared_region_ids,
    )
