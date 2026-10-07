"""Typed pre-join CFG ownership fixtures for carry/borrow Lowering tests."""

from __future__ import annotations

from types import SimpleNamespace

import networkx as nx
from inertia.structuring.structuring_cfg_ownership import CFGOwnershipArtifact, build_cfg_ownership_artifact


class _ClinicStatement:
    """Minimal AIL statement boundary carrying exact instruction provenance."""

    def __init__(self, block_addr: int, ins_addr: int) -> None:
        self.ins_addr = ins_addr
        self.addr = ins_addr
        self.tags = {"ins_addr": ins_addr, "vex_block_addr": block_addr, "vex_stmt_idx": ins_addr}


class _ClinicNode:
    """Minimal Clinic CFG node with exact statement ownership."""

    def __init__(self, block_addr: int, statement_addrs: tuple[int, ...]) -> None:
        self.addr = block_addr
        self.statements = tuple(_ClinicStatement(block_addr, ins_addr) for ins_addr in statement_addrs)


def build_test_cfg_ownership_8616(
    block_statements: dict[int, tuple[int, ...]],
    edges: tuple[tuple[int, int], ...] = (),
) -> CFGOwnershipArtifact:
    """Build the production ownership contract for a deterministic synthetic CFG."""
    nodes = {
        block_addr: _ClinicNode(block_addr, statement_addrs)
        for block_addr, statement_addrs in block_statements.items()
    }
    graph = nx.DiGraph()
    graph.add_nodes_from(nodes.values())
    graph.add_edges_from((nodes[source], nodes[target]) for source, target in edges)
    function_addr = min(nodes)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=function_addr, name="fixture"),
        _clinic=SimpleNamespace(graph=graph),
        project=None,
    )
    artifact = build_cfg_ownership_artifact(codegen)
    assert artifact is not None
    return artifact


__all__ = ["build_test_cfg_ownership_8616"]
