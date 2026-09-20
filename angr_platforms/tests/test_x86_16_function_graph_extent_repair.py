"""Tests for evidence-bound x86-16 function graph extent repair."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import angr
import pytest
from angr.codenode import BlockNode
from angr.knowledge_plugins.functions.function import Function
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact

import inertia_decompiler.function_graph_extent_repair as extent_repair
from inertia_decompiler import cli_function_discovery as discovery
from inertia_decompiler.function_graph_extent_repair import (
    FunctionGraphExtentRefusalReason8616,
    FunctionGraphExtentRepairError,
    FunctionGraphExtentRepairVerdict8616,
    enforce_covered_transition_sources_8616,
    repair_undercovered_transition_sources_8616,
)


def _function_with_transition(
    *,
    source_size: int = 2,
    target_addr: int = 0x1006,
    edge_ins_addr: int = 0x1004,
    interior_leader: int | None = None,
) -> Function:
    function = Function(
        None,
        0x1000,
        name="extent_test",
        binary_name="extent_test.bin",
        syscall=False,
        is_simprocedure=False,
        is_plt=False,
        returning=False,
    )
    source = BlockNode(0x1000, source_size, bytestr=b"\x90" * source_size)
    target = BlockNode(target_addr, 1, bytestr=b"\xc3")
    function._register_node(True, source)
    function._register_node(True, target)
    if interior_leader is not None:
        function._register_node(True, BlockNode(interior_leader, 1, bytestr=b"\x90"))
    function.transition_graph.add_edge(source, target, type="transition", ins_addr=edge_ins_addr, evidence="kept")
    return function


def _project_with_decoded_block(
    *,
    block_addr: int = 0x1000,
    block_size: int = 6,
    instruction_addrs: tuple[int, ...] = (0x1000, 0x1004),
) -> angr.Project:
    instructions = tuple(
        SimpleNamespace(address=addr, size=2, mnemonic="call" if addr == 0x1004 else "push")
        for addr in instruction_addrs
    )
    block = SimpleNamespace(
        addr=block_addr,
        size=block_size,
        bytes=b"\x90" * block_size,
        capstone=SimpleNamespace(insns=instructions),
    )
    project = SimpleNamespace(factory=SimpleNamespace(block=lambda _addr, opt_level=0: block))
    return cast(angr.Project, project)


def test_repairs_undercovered_transition_source_and_preserves_graph_evidence() -> None:
    function = _function_with_transition()
    original_source = function.get_node(0x1000)
    assert original_source is not None
    predecessor = BlockNode(0x0FFE, 2, bytestr=b"\x90\x90")
    function._register_node(True, predecessor)
    function.transition_graph.nodes[original_source]["owner"] = "kept"
    function.transition_graph.add_edge(predecessor, original_source, type="incoming")
    function.transition_graph.add_edge(original_source, original_source, type="self")
    function._ret_sites.add(original_source)
    function._endpoints.setdefault("return", set()).add(original_source)
    function._local_transition_graph = function.transition_graph.copy()
    function._cyclomatic_complexity = 7

    stats = enforce_covered_transition_sources_8616(
        _project_with_decoded_block(),
        function,
        exact_region=(0x1000, 0x1007),
    )

    repaired_source = function.get_node(0x1000)
    assert repaired_source is not None
    assert repaired_source is not original_source
    assert repaired_source.size == 6
    assert function.transition_graph.nodes[repaired_source]["owner"] == "kept"
    assert function.transition_graph[predecessor][repaired_source] == {"type": "incoming"}
    assert function.transition_graph[repaired_source][repaired_source] == {"type": "self"}
    assert function.startpoint is repaired_source
    assert repaired_source in function._ret_sites
    assert repaired_source in function._endpoints["return"]
    assert function._local_blocks[0x1000] is repaired_source
    assert function._block_sizes[0x1000] == 6
    assert function._local_transition_graph is None
    assert function._cyclomatic_complexity is None
    target = function.get_node(0x1006)
    assert target is not None
    assert function.transition_graph[repaired_source][target] == {
        "type": "transition",
        "ins_addr": 0x1004,
        "evidence": "kept",
    }
    assert stats.verdict is FunctionGraphExtentRepairVerdict8616.REPAIRED
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_covered_transition_source_is_clean() -> None:
    function = _function_with_transition(source_size=6)

    stats = repair_undercovered_transition_sources_8616(_project_with_decoded_block(), function)

    assert stats.verdict is FunctionGraphExtentRepairVerdict8616.CLEAN
    assert stats.raw_fact_count == 0
    assert stats.failure_count == 0


def test_refuses_extension_across_an_interior_cfg_leader() -> None:
    function = _function_with_transition(interior_leader=0x1003)

    stats = repair_undercovered_transition_sources_8616(
        _project_with_decoded_block(),
        function,
        exact_region=(0x1000, 0x1007),
    )

    assert stats.verdict is FunctionGraphExtentRepairVerdict8616.REFUSED
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
    assert stats.refusals[0].reason is FunctionGraphExtentRefusalReason8616.INTERIOR_LEADER
    assert function.get_node(0x1000).size == 2


def test_refuses_when_edge_terminator_is_not_in_decoded_block() -> None:
    function = _function_with_transition()

    stats = repair_undercovered_transition_sources_8616(
        _project_with_decoded_block(instruction_addrs=(0x1000, 0x1002)),
        function,
        exact_region=(0x1000, 0x1007),
    )

    assert stats.refusals[0].reason is FunctionGraphExtentRefusalReason8616.TERMINATOR_NOT_DECODED
    assert stats.classified_fact_count == 0
    assert stats.failure_count == 1


def test_refuses_interior_instruction_even_when_it_is_decoded() -> None:
    function = _function_with_transition(edge_ins_addr=0x1002)

    stats = repair_undercovered_transition_sources_8616(
        _project_with_decoded_block(instruction_addrs=(0x1000, 0x1002, 0x1004)),
        function,
        exact_region=(0x1000, 0x1007),
    )

    assert stats.refusals[0].reason is FunctionGraphExtentRefusalReason8616.TERMINATOR_NOT_DECODED
    assert function.get_node(0x1000).size == 2


def test_refuses_undercovered_source_without_authoritative_region() -> None:
    function = _function_with_transition()

    stats = repair_undercovered_transition_sources_8616(_project_with_decoded_block(), function)

    assert stats.refusals[0].reason is FunctionGraphExtentRefusalReason8616.MISSING_EXACT_REGION
    assert function.get_node(0x1000).size == 2


def test_refuses_source_not_owned_by_function_local_blocks() -> None:
    function = _function_with_transition()
    function._local_blocks.clear()
    function._local_block_addrs.clear()

    stats = repair_undercovered_transition_sources_8616(
        _project_with_decoded_block(),
        function,
        exact_region=(0x1000, 0x1007),
    )

    assert stats.refusals[0].reason is FunctionGraphExtentRefusalReason8616.NON_LOCAL_SOURCE
    assert function.get_node(0x1000).size == 2


def test_replacement_failure_rolls_back_graph_and_all_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    function = _function_with_transition()
    original_source = function.get_node(0x1000)
    original_edge = dict(function.transition_graph[original_source][function.get_node(0x1006)])
    original_set_graph = BlockNode.set_graph

    def _fail_replacement_set_graph(node: BlockNode, graph: object) -> None:
        if node.addr == 0x1000 and node.size == 6:
            raise RuntimeError("replacement rejected")
        original_set_graph(node, graph)

    monkeypatch.setattr(BlockNode, "set_graph", _fail_replacement_set_graph)
    stats = extent_repair.repair_undercovered_transition_sources_8616(
        _project_with_decoded_block(),
        function,
        exact_region=(0x1000, 0x1007),
    )

    restored_source = function.get_node(0x1000)
    restored_target = function.get_node(0x1006)
    assert stats.refusals[0].reason is FunctionGraphExtentRefusalReason8616.REPLACEMENT_FAILED
    assert stats.materialized_count == 0
    assert restored_source is original_source
    assert restored_target is not None
    assert function.transition_graph[restored_source][restored_target] == original_edge
    assert function._local_blocks[0x1000] is original_source
    assert function._block_sizes[0x1000] == 2


def test_fallback_entry_forwards_recovery_region_to_graph_repair(monkeypatch: pytest.MonkeyPatch) -> None:
    project = SimpleNamespace(entry=0x1000, arch=SimpleNamespace(name="86_16"))
    function = SimpleNamespace(addr=project.entry)
    captured: list[tuple[int, int] | None] = []
    monkeypatch.setattr(discovery, "_infer_x86_16_linear_region", lambda *_args, window: (0x1000, 0x1000 + window))
    monkeypatch.setattr(discovery, "_pick_function", lambda *_args, **_kwargs: (SimpleNamespace(), function))
    monkeypatch.setattr(
        discovery,
        "_stitch_x86_16_exact_function_8616",
        lambda _project, candidate, _region: (candidate, False),
    )
    monkeypatch.setattr(
        discovery,
        "_repair_x86_16_function_graph_8616",
        lambda _project, _function, *, exact_region=None: captured.append(exact_region),
    )

    discovery._fallback_entry_function(project, timeout=10, window=0x200)

    assert captured == [(0x1000, 0x1200)]


@pytest.mark.parametrize("label", [None, "entry"])
@pytest.mark.parametrize("exact_region", [None, (0x1000, 0x1100)])
def test_direct_addr_forwards_inferred_region_to_graph_repair(monkeypatch, label, exact_region) -> None:
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=None, max_addr=None)),
    )
    function = SimpleNamespace(addr=project.entry)
    captured: list[tuple[int, int] | None] = []
    monkeypatch.setattr(discovery, "_infer_x86_16_linear_region", lambda *_args, window: (0x1000, 0x1000 + window))
    monkeypatch.setattr(discovery, "_pick_function", lambda *_args, **_kwargs: (SimpleNamespace(), function))
    monkeypatch.setattr(
        discovery,
        "_repair_x86_16_function_graph_8616",
        lambda _project, _function, *, exact_region=None: captured.append(exact_region),
    )

    discovery._recover_direct_addr_function(
        project,
        0x1000,
        timeout=10,
        window=0x200,
        function_label=label,
        lst_metadata=None,
        low_memory_path=False,
        prefer_fast_recovery=False,
        exact_region=exact_region,
    )

    assert captured == [exact_region or (0x1000, 0x1200)]


def test_refuses_extension_outside_exact_region() -> None:
    function = _function_with_transition()

    with pytest.raises(FunctionGraphExtentRepairError, match="outside_exact_region"):
        enforce_covered_transition_sources_8616(
            _project_with_decoded_block(),
            function,
            exact_region=(0x1000, 0x1005),
        )

    assert function.get_node(0x1000).size == 2


@pytest.mark.parametrize("rebuild", [False, True])
@pytest.mark.parametrize("warm_graph", [False, True])
def test_recovered_transitions_reach_cached_graph_and_ssa(rebuild: bool, warm_graph: bool) -> None:
    """Graph repair must retain a jump-only connector in every CFG projection."""
    project = angr.load_shellcode(bytes.fromhex("eb029090b80100c3"), arch=Arch86_16(), load_address=0x1000)
    function = project.kb.functions.function(addr=0x1000, create=True)
    function._register_node(True, BlockNode(0x1000, 2, bytestr=bytes.fromhex("eb02")))
    if warm_graph:
        assert not tuple(function.graph.edges)
    if rebuild:
        blocks = {addr: project.factory.block(addr, opt_level=0) for addr in (0x1000, 0x1004)}
        discovery._rebuild_function_transition_graph_8616(function, blocks, {(0x1000, 0x1004)})
    else:
        discovery._repair_x86_16_function_graph_8616(project, function, exact_region=(0x1000, 0x1008))

    expected = {(0x1000, 0x1004)}
    assert {(a.addr, b.addr) for a, b in function.transition_graph.edges} == expected
    assert {(a.addr, b.addr) for a, b in function.graph.edges} == expected
    artifact = build_x86_16_ir_function_artifact(project, function)
    assert artifact.blocks[0].successor_addrs == (0x1004,)
    assert build_x86_16_function_ssa(artifact).predecessor_map[0x1004] == (0x1000,)


def test_reset_function_graph_clears_cached_edges_and_nodes() -> None:
    """Resetting a graph must not leave the old cached local projection readable."""
    function = _function_with_transition()
    assert tuple(function.graph.edges)

    discovery._reset_function_graph_state_8616(function)

    assert not tuple(function.transition_graph.nodes)
    assert not tuple(function.graph.nodes)
