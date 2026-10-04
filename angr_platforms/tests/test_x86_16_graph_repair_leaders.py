"""Regression: repair-edge install must not cross an existing graph leader.

Mirrors the SORTD failure ``source=0x10f46 edge=0x10f52 reason=interior_leader``:
a maximal decode spans a call that the graph already split into its own node
(a real jump target via a backedge), and the wide block's fallthrough edge is
then installed onto the narrower existing node with an ``ins_addr`` outside
that node's extent.

Production regressions for decoded leader clipping and successor retention.
"""

from __future__ import annotations

import io
from types import ModuleType, SimpleNamespace

import angr
import networkx
import pytest
from angr.codenode import BlockNode
from angr.knowledge_plugins.functions.function import Function
from angr_platforms.X86_16.arch_86_16 import Arch86_16

from inertia_decompiler import cli_function_discovery as discovery_owner
from inertia_decompiler.function_graph_extent_repair import (
    FunctionGraphExtentRefusalReason8616,
    _out_of_block_ins_addrs_8616,
    repair_undercovered_transition_sources_8616,
)


def _load_module_under_test() -> ModuleType:
    """Use the production owner; frozen overlays remain review artifacts."""
    return discovery_owner


CODE = bytearray(0x101)
CODE[0x00:0x03] = bytes.fromhex("B84300")  # 0x1000 mov ax, 0x43
CODE[0x03:0x06] = bytes.fromhex("8956FE")  # 0x1003 mov [bp-2], dx
CODE[0x06:0x09] = bytes.fromhex("E8F700")  # 0x1006 call 0x1100
CODE[0x09:0x0C] = bytes.fromhex("3B56FE")  # 0x1009 cmp dx, [bp-2]
CODE[0x0C] = 0xC3                          # 0x100C ret
CODE[0x10:0x12] = bytes.fromhex("EBF4")    # 0x1010 jmp 0x1006 (backedge)
CODE[0x100] = 0xC3                         # 0x1100 ret (call target body)


class _FakeRepairFunction:
    """Minimal angr-Function surface used by the graph-repair helpers."""

    def __init__(self) -> None:
        self.transition_graph = networkx.DiGraph()
        self._local_blocks: dict[int, object] = {}
        self._local_block_addrs: set[int] = set()
        self._addr_to_block_node: dict[int, object] = {}
        self.return_sites: list[object] = []

    def get_node(self, addr: int) -> object | None:
        """Return the cached node at ``addr`` like angr.Function.get_node."""
        return self._addr_to_block_node.get(addr)

    def _update_addr_to_block_cache(self, node: BlockNode) -> None:
        self._addr_to_block_node[int(node.addr)] = node

    def _register_node(
        self, is_local: bool, node: BlockNode, update_func_block_count: bool = True
    ) -> BlockNode:
        self._local_blocks[int(node.addr)] = node
        self._local_block_addrs.add(int(node.addr))
        self._update_addr_to_block_cache(node)
        self.transition_graph.add_node(node)
        return node

    def _transit_to(
        self,
        from_node: BlockNode,
        to_node: BlockNode | None,
        outside: bool = False,
        ins_addr: int | None = None,
        stmt_idx: int | None = None,
        **_ignored: object,
    ) -> None:
        self._register_node(True, from_node)
        if to_node is not None:
            self._register_node(True, to_node)
            self.transition_graph.add_edge(
                from_node,
                to_node,
                type="transition",
                outside=outside,
                ins_addr=ins_addr,
                stmt_idx=stmt_idx,
            )

    def _add_return_site(self, node: BlockNode) -> None:
        self.return_sites.append(node)


def _project() -> angr.Project:
    """Build the blob project holding the synthetic instruction stream."""
    return angr.Project(
        io.BytesIO(bytes(CODE)),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
    )


def _leader_graph() -> tuple[_FakeRepairFunction, BlockNode, BlockNode, BlockNode, BlockNode]:
    """Graph where the call at 0x1006 is a leader via a real jump backedge."""
    function = _FakeRepairFunction()
    node_a = BlockNode(0x1000, 6, bytestr=bytes(CODE[0:6]))
    node_c = BlockNode(0x1006, 3, bytestr=bytes(CODE[6:9]))
    node_d = BlockNode(0x1009, 4, bytestr=bytes(CODE[9:13]))
    node_e = BlockNode(0x1010, 2, bytestr=bytes(CODE[0x10:0x12]))
    for node in (node_a, node_c, node_d, node_e):
        function._register_node(True, node)
    function._transit_to(node_a, node_c, ins_addr=0x1003)
    function._transit_to(node_c, node_d, ins_addr=0x1006)
    function._transit_to(node_e, node_c, ins_addr=0x1010)
    return function, node_a, node_c, node_d, node_e


def _discovery(module: ModuleType, project: angr.Project, edges: set[tuple[int, int]]) -> object:
    """Build the discovery contract the BFS scan would produce."""
    return module._GraphRepairDiscovery8616(
        {0x1000: project.factory.block(0x1000, opt_level=0)},
        set(edges),
        None,
    )


def _run_repair(module: ModuleType, function: _FakeRepairFunction, discovery: object) -> None:
    """Clip (when the staged module provides it) then install edges."""
    clip = getattr(module, "_clip_repair_blocks_at_leaders_8616", None)
    if clip is not None:
        clip(function, discovery)
    module._install_repair_edges_8616(function, BlockNode, discovery, False)


def test_edge_install_never_crosses_existing_leader() -> None:
    """Wide decode + narrow node + interior leader must stay coherent."""
    module = _load_module_under_test()
    project = _project()
    function, node_a, node_c, node_d, node_e = _leader_graph()
    discovery = _discovery(module, project, {(0x1000, 0x1009)})

    _run_repair(module, function, discovery)

    assert _out_of_block_ins_addrs_8616(function.transition_graph) == {}
    if getattr(module, "_clip_repair_blocks_at_leaders_8616", None) is not None:
        assert discovery.clip_ends == {0x1000: 0x1006}
        assert discovery.edges == {(0x1000, 0x1006)}
        graph = function.transition_graph
        assert graph[node_a][node_c]["ins_addr"] == 0x1003
        assert not graph.has_edge(node_a, node_d)
        # The real backedge leader edge must be preserved.
        assert graph.has_edge(node_e, node_c)


def test_created_node_extent_stops_at_leader() -> None:
    """A node created for a clipped block must not swallow the leader."""
    module = _load_module_under_test()
    project = _project()
    function = _FakeRepairFunction()
    node_c = BlockNode(0x1006, 3, bytestr=bytes(CODE[6:9]))
    function._register_node(True, node_c)
    discovery = _discovery(module, project, {(0x1000, 0x1006)})

    _run_repair(module, function, discovery)

    created = function.get_node(0x1000)
    assert created is not None
    assert int(created.size) == 6
    assert _out_of_block_ins_addrs_8616(function.transition_graph) == {}
    if getattr(module, "_clip_repair_blocks_at_leaders_8616", None) is not None:
        graph = function.transition_graph
        assert graph[created][node_c]["ins_addr"] == 0x1003


def test_no_leader_keeps_full_width_decode() -> None:
    """Without interior leaders the original wide-extent behavior is kept."""
    module = _load_module_under_test()
    project = _project()
    function = _FakeRepairFunction()
    discovery = module._GraphRepairDiscovery8616(
        {
            0x1000: project.factory.block(0x1000, opt_level=0),
            0x1009: project.factory.block(0x1009, opt_level=0),
        },
        {(0x1000, 0x1009)},
        None,
    )

    _run_repair(module, function, discovery)

    node_a = function.get_node(0x1000)
    node_d = function.get_node(0x1009)
    assert node_a is not None and node_d is not None
    assert int(node_a.size) == 9
    assert _out_of_block_ins_addrs_8616(function.transition_graph) == {}
    assert function.transition_graph[node_a][node_d]["ins_addr"] == 0x1006

    if getattr(module, "_clip_repair_blocks_at_leaders_8616", None) is not None:
        assert module._install_repair_return_sites_8616(function, discovery) == 1
    else:
        assert module._install_repair_return_sites_8616(function, discovery.blocks) == 1
    assert node_d in function.return_sites


def test_mid_instruction_leader_is_not_clipped() -> None:
    """A leader inside a decoded instruction is never a guessed cut point."""
    module = _load_module_under_test()
    project = _project()
    function = _FakeRepairFunction()
    node_a = BlockNode(0x1000, 6, bytestr=bytes(CODE[0:6]))
    node_mid = BlockNode(0x1007, 1, bytestr=bytes(CODE[7:8]))
    node_d = BlockNode(0x1009, 4, bytestr=bytes(CODE[9:13]))
    for node in (node_a, node_mid, node_d):
        function._register_node(True, node)
    function._transit_to(node_a, node_mid, ins_addr=0x1003)
    discovery = _discovery(module, project, {(0x1000, 0x1009)})

    _run_repair(module, function, discovery)

    assert discovery.clip_ends == {}
    # Keep the edge visible so the authoritative coverage gate rejects the
    # unproved overlap; an empty graph is not a successfully repaired graph.
    stats = repair_undercovered_transition_sources_8616(
        project, function, exact_region=(0x1000, 0x1101)
    )
    assert stats.failure_count == 1
    assert stats.materialized_count == 0
    assert stats.refusals[0].reason is FunctionGraphExtentRefusalReason8616.INTERIOR_LEADER


def test_undercovered_source_keeps_edge_for_evidence_repair() -> None:
    """An exact decoded successor cannot disappear because a cached node is short."""
    owner = discovery_owner
    function = Function(None, 0x1000, name="boundary", binary_name="boundary", syscall=False,
                        is_simprocedure=False, is_plt=False, returning=False)
    source = BlockNode(0x1000, 2, bytestr=b"\x90\x90")
    target = BlockNode(0x1006, 1, bytestr=b"\xc3")
    function._register_node(True, source)
    function._register_node(True, target)
    instructions = tuple(SimpleNamespace(address=addr, size=size, mnemonic=name)
                         for addr, size, name in [(0x1000, 1, "nop"), (0x1001, 1, "nop"),
                            (0x1002, 1, "nop"), (0x1003, 1, "nop"), (0x1004, 2, "jmp")])
    block = SimpleNamespace(addr=0x1000, size=6, bytes=b"\x90" * 4 + b"\xeb\x00",
                            capstone=SimpleNamespace(insns=instructions))
    discovery = owner._GraphRepairDiscovery8616({0x1000: block}, {(0x1000, 0x1006)}, None)
    owner._install_repair_edges_8616(function, BlockNode, discovery, False)
    # The existing coverage owner can repair this source once it sees ins_addr.
    # Silently dropping the edge removes both behavior and the repair evidence.
    assert function.transition_graph.has_edge(source, target)
    assert function.transition_graph[source][target]["ins_addr"] == 0x1004


def test_edge_install_propagates_graph_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unexpected graph defects cannot silently discard semantic edges."""
    function, *_ = _leader_graph()
    discovered = _discovery(discovery_owner, _project(), {(0x1000, 0x1009)})

    def broken(*args: object, **kwargs: object) -> None:
        raise RuntimeError("graph defect")

    monkeypatch.setattr(function, "_transit_to", broken)
    with pytest.raises(RuntimeError, match="graph defect"):
        _run_repair(discovery_owner, function, discovered)


def test_aligned_leader_cannot_hide_earlier_mid_instruction_leader() -> None:
    """An invalid earlier boundary cannot be bypassed by a later valid cut."""
    function, *_ = _leader_graph()
    function._register_node(True, BlockNode(0x1001, 1, bytestr=bytes(CODE[1:2])))
    discovered = _discovery(discovery_owner, _project(), {(0x1000, 0x1009)})
    discovery_owner._clip_repair_blocks_at_leaders_8616(function, discovered)
    assert discovered.clip_ends == {}
    assert discovered.edges == {(0x1000, 0x1009)}
