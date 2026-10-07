from dataclasses import replace

import networkx as nx

from inertia.structuring.structuring_cfg_ownership import (
    CFGInstructionReachability8616,
    CFGInstructionSite8616,
    build_cfg_ownership_artifact,
)


class _Stmt:
    def __init__(self, ins_addr, block_addr, statement_index):
        self.tags = {
            "ins_addr": ins_addr,
            "vex_block_addr": block_addr,
            "vex_stmt_idx": statement_index,
        }


class _Node:
    def __init__(self, addr, statements=()):
        self.addr = addr
        self.statements = statements


class _Clinic:
    def __init__(self, graph):
        self.graph = graph


class _CFunc:
    def __init__(self, addr):
        self.addr = addr
        self.name = "func"


class _Codegen:
    def __init__(self, addr, clinic):
        self.cfunc = _CFunc(addr)
        self._clinic = clinic
        self.project = None


def test_cfg_ownership_marks_shared_owner_and_entry():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, c)
    graph.add_edge(b, c)
    clinic = _Clinic(graph)

    artifact = build_cfg_ownership_artifact(_Codegen(0x1000, clinic))

    assert artifact is not None
    assert artifact.shared_region_ids == (0x1002,)
    assert artifact.entry_fragment_region_ids == (0x1001,)
    ownership = {record.region_id: record for record in artifact.records}
    assert ownership[0x1000].ownership_kind == "entry"
    assert ownership[0x1002].refusal_reason == "mixed_reachability_predecessors"
    assert ownership[0x1002].reachable_from_entry is True


def test_cfg_ownership_returns_none_without_snapshot():
    class _EmptyCodegen:
        def __init__(self):
            self.cfunc = _CFunc(0x1000)
            self._clinic = None
            self.project = None

    assert build_cfg_ownership_artifact(_EmptyCodegen()) is None


def test_cfg_ownership_marks_mixed_reachability_shared_owner():
    graph = nx.DiGraph()
    a = _Node(0x1000)
    b = _Node(0x1001)
    c = _Node(0x1002)
    d = _Node(0x1003)
    graph.add_nodes_from([a, b, c, d])
    graph.add_edge(a, c)
    graph.add_edge(b, c)
    graph.add_edge(c, d)
    clinic = _Clinic(graph)

    artifact = build_cfg_ownership_artifact(_Codegen(0x1000, clinic))

    assert artifact is not None
    ownership = {record.region_id: record for record in artifact.records}
    assert ownership[0x1002].ownership_kind == "shared_owner"
    assert ownership[0x1002].refusal_reason == "mixed_reachability_predecessors"


def test_cfg_instruction_reachability_uses_exact_owners_and_cfg_paths():
    graph = nx.DiGraph()
    a = _Node(0x1000, (_Stmt(0x1000, 0x1000, 1), _Stmt(0x1002, 0x1000, 2)))
    b = _Node(0x1010, (_Stmt(0x1010, 0x1010, 1),))
    c = _Node(0x1020, (_Stmt(0x1020, 0x1020, 1),))
    graph.add_nodes_from([a, b, c])
    graph.add_edge(a, b)
    graph.add_edge(b, c)

    artifact = build_cfg_ownership_artifact(_Codegen(0x1000, _Clinic(graph)))

    assert artifact is not None
    first = CFGInstructionSite8616(0x1000, 0x1000)
    later_same_region = CFGInstructionSite8616(0x1000, 0x1002)
    later_region = CFGInstructionSite8616(0x1020, 0x1020)
    assert artifact.instruction_sites(0x1002) == (later_same_region,)
    assert artifact.instruction_owner_region_id(first) == 0x1000
    assert artifact.instruction_reachability(first, later_same_region) is CFGInstructionReachability8616.REACHES
    assert artifact.instruction_reachability(first, later_region) is CFGInstructionReachability8616.REACHES
    assert (
        artifact.instruction_reachability(later_region, first)
        is CFGInstructionReachability8616.DOES_NOT_REACH
    )
    assert (
        artifact.instruction_reachability(later_same_region, first)
        is CFGInstructionReachability8616.ORDER_CONFLICT
    )


def test_cfg_instruction_sites_are_deterministic_for_overlapping_addresses():
    graph = nx.DiGraph()
    high = _Node(0x1010, (_Stmt(0x1004, 0x1010, 1),))
    low = _Node(0x1000, (_Stmt(0x1004, 0x1000, 1),))
    graph.add_nodes_from([high, low])

    artifact = build_cfg_ownership_artifact(_Codegen(0x1000, _Clinic(graph)))

    assert artifact is not None
    assert artifact.instruction_sites(0x1004) == (
        CFGInstructionSite8616(0x1000, 0x1004),
        CFGInstructionSite8616(0x1010, 0x1004),
    )


def test_cfg_instruction_reachability_refuses_missing_and_ambiguous_owners():
    graph = nx.DiGraph()
    graph.add_node(_Node(0x1000, (_Stmt(0x1000, 0x1000, 1),)))
    artifact = build_cfg_ownership_artifact(_Codegen(0x1000, _Clinic(graph)))

    assert artifact is not None
    known = CFGInstructionSite8616(0x1000, 0x1000)
    missing = CFGInstructionSite8616(0x2000, 0x2000)
    assert artifact.instruction_owner_region_id(missing) is CFGInstructionReachability8616.OWNER_MISSING
    assert (
        artifact.instruction_reachability(missing, known)
        is CFGInstructionReachability8616.OWNER_MISSING
    )

    [owner] = artifact.snapshot.nodes
    ambiguous_snapshot = replace(
        artifact.snapshot,
        node_count=2,
        nodes=(owner, owner),
    )
    ambiguous_artifact = replace(artifact, snapshot=ambiguous_snapshot)
    assert (
        ambiguous_artifact.instruction_owner_region_id(known)
        is CFGInstructionReachability8616.OWNER_AMBIGUOUS
    )
    assert (
        ambiguous_artifact.instruction_reachability(known, known)
        is CFGInstructionReachability8616.OWNER_AMBIGUOUS
    )
