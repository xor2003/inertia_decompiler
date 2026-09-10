"""Stack producer links require exact source keys and distinct CFG occurrences."""

from types import SimpleNamespace
from typing import cast

import networkx as nx
import pytest
from angr import ailment
from angr_platforms.X86_16.ir import stack_pointer_provenance as provenance


def _graph(operation="Sub", width=16):
    source_tags = {"ins_addr": 0x1010, "vex_block_addr": 0x1000, "vex_stmt_idx": 8}
    value = ailment.Expr.BinaryOp(
        1, operation, [ailment.Expr.Tmp(0, 7, width), ailment.Expr.Const(1, 2, width)],
        False, bits=width, **source_tags,
    )
    write = ailment.Stmt.Assignment(
        4, ailment.Expr.Register(2, 16, width), value,
        **{**source_tags, "vex_stmt_idx": 15},
    )
    block = ailment.Block(0x1000, 20, statements=[write])
    graph = nx.DiGraph()
    graph.add_node(block)
    return graph, block, write


@pytest.mark.parametrize("operation", ["Add", "Sub"])
@pytest.mark.parametrize("width", [16, 32])
def test_nonadjacent_producer_and_write_keep_exact_identity(operation, width):
    graph, _block, _write = _graph(operation, width)
    result = provenance.collect_stack_pointer_provenance_8616(graph, sp_offset=16)
    assert result.raw_fact_count == result.normalized_fact_count == 1
    assert result.classified_fact_count == result.materialized_count == 1
    assert result.failure_count == 0
    [fact] = result.projections
    assert fact.producer_index == 8 and fact.write_index == 15
    assert fact.instruction_addr == 0x1010 and fact.vex_block_addr == 0x1000
    assert fact.register_offset == 16 and fact.width_bits == width
    assert fact.operation is provenance.StackPointerArithmetic8616(operation)
    assert fact.amount == 2


def test_duplicate_source_keys_keep_separate_cfg_occurrences():
    graph, block, write = _graph()
    graph.add_node(ailment.Block(0x2000, 20, statements=[write.copy()], idx=1))
    result = provenance.collect_stack_pointer_provenance_8616(graph, sp_offset=16)
    assert len(result.projections) == 2
    assert {(fact.block_addr, fact.block_index) for fact in result.projections} == {(block.addr, None), (0x2000, 1)}
    assert {fact.write_index for fact in result.projections} == {15}


@pytest.mark.parametrize("corruption", ["missing", "instruction", "block", "width", "nonconstant"])
def test_unknown_producer_link_refuses_without_mutating_graph(corruption):
    graph, block, write = _graph()
    source = write.src
    tags = dict(source.tags)
    operands = list(source.operands)
    if corruption == "missing":
        tags.pop("vex_stmt_idx")
    elif corruption == "instruction":
        tags["ins_addr"] = 0x100F
    elif corruption == "block":
        tags["vex_block_addr"] = 0x2000
    elif corruption == "width":
        write.dst = ailment.Expr.Register(2, 16, 32)
    else:
        operands[1] = ailment.Expr.Tmp(3, 9, 16)
    write.src = ailment.Expr.BinaryOp(1, "Sub", operands, False, bits=16, **tags)
    original = tuple(block.statements)
    result = provenance.collect_stack_pointer_provenance_8616(graph, sp_offset=16)
    assert result.raw_fact_count == result.failure_count == 1
    assert result.classified_fact_count == result.materialized_count == 0
    assert not result.projections
    assert tuple(block.statements) == original


@pytest.mark.parametrize("value", [True, False, -1, None, "8"])
def test_source_key_refuses_non_integer_or_negative_metadata(value):
    assert provenance._source_key_8616({
        "ins_addr": 0x1010, "vex_block_addr": 0x1000, "vex_stmt_idx": value,
    }) is None


def test_unrelated_register_write_is_not_a_stack_candidate():
    graph, _block, write = _graph()
    write.dst = ailment.Expr.Register(2, 8, 16)
    result = provenance.collect_stack_pointer_provenance_8616(graph, sp_offset=16)
    assert result.raw_fact_count == result.failure_count == 0
    assert not result.projections


def test_native_stage_publishes_provenance_after_call_frame_consumption(monkeypatch):
    from angr.analyses.decompiler.clinic import Clinic
    from angr_platforms.X86_16 import call_frame_compat as adapter

    graph, block, write = _graph()
    monkeypatch.setattr(Clinic, "_stage_pre_ssa_level0_fixups", lambda _: None)
    monkeypatch.setattr(adapter, "_apply_return_cleanup_compatibility_8616", lambda: None)

    def consume(*args, **kwargs):
        block.statements.append(write.copy())
        return adapter.CallFrameBoundaryStats8616()

    monkeypatch.setattr(adapter, "consume_returning_call_frames_8616", consume)
    adapter.apply_call_frame_compatibility_8616()
    clinic = SimpleNamespace(
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16", sp_offset=16)),
        function=None, _ail_graph=graph, _ail_manager=ailment.Manager(),
    )
    Clinic._stage_pre_ssa_level0_fixups(cast(Clinic, clinic))
    assert clinic._inertia_stack_pointer_provenance_8616.materialized_count == 2
    assert {fact.statement_index for fact in clinic._inertia_stack_pointer_provenance_8616.projections} == {0, 1}
