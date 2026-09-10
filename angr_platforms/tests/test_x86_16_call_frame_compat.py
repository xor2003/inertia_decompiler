"""Early source-call frame consumption must be complete and provenance-bound."""

import networkx as nx
import pytest
from angr import ailment
from angr_platforms.X86_16 import call_frame_compat as adapter
from angr_platforms.X86_16.semantics.call_return_frame_effects import (
    CallReturnFrameEffectCollection8616,
    CallReturnFrameEffectFact8616,
    CallReturnFrameEffectKey8616,
    CallReturnFrameEffectRole8616,
)
from angr_platforms.X86_16.semantics.call_return_frame_projections import CallReturnFrameProjectionCollection8616
from angr_platforms.X86_16.semantics.call_return_segment import ReturnSegmentEffect8616, ReturnSegmentFrame8616


def _fixture(monkeypatch):
    def tags(index):
        return {"ins_addr": 0x1000, "vex_block_addr": 0x1000, "vex_stmt_idx": index}

    constant = ailment.Expr.Const(0, 0, 16)
    argument = ailment.Stmt.Store(0, constant, constant, 2, "Iend_LE", ins_addr=0xFFF)
    update = ailment.Stmt.Assignment(1, ailment.Expr.Register(1, 16, 16), constant, **tags(1))
    store = ailment.Stmt.Store(2, constant, constant, 2, "Iend_LE", **tags(2))
    call = ailment.Stmt.SideEffectStatement(3, ailment.Expr.Call(3, constant, args=(), bits=16), **tags(-2))
    block = ailment.Block(0x1000, 3, statements=[argument, update, store, call])
    successor = ailment.Block(0x1003, 1, statements=[])
    graph = nx.DiGraph([(block, successor)])
    facts = tuple(CallReturnFrameEffectFact8616(CallReturnFrameEffectKey8616(0x1000, 0x1000, index), role)
                  for index, role in [(1, CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE),
                                      (2, CallReturnFrameEffectRole8616.STACK_STORE)])
    collection = CallReturnFrameEffectCollection8616(
        1, 1, 2, 2, 0, facts, CallReturnFrameProjectionCollection8616(0, 0, 0, 0, 0, (), ()),
    )
    monkeypatch.setattr(adapter, "collect_call_return_frame_effects_8616", lambda *args: collection)
    return graph, block, successor, argument, update, store, call


def test_complete_frame_consumes_only_exact_effects(monkeypatch):
    graph, block, successor, argument, _update, _store, call = _fixture(monkeypatch)
    result = adapter.consume_returning_call_frames_8616(None, None, graph, sp_offset=16)
    assert block.statements == [argument, call]
    assert successor.statements == []
    assert result.raw_fact_count == result.normalized_fact_count == 1
    assert result.classified_fact_count == result.materialized_count == 2
    assert result.failure_count == 0
    assert result.accepted_calls == (0x1000,)


@pytest.mark.parametrize("mismatch", ["missing_store", "duplicate", "register", "provenance", "return_edge", "call_tag"])
def test_incomplete_frame_refuses_atomically(monkeypatch, mismatch):
    graph, block, successor, _argument, update, store, call = _fixture(monkeypatch)
    if mismatch == "missing_store":
        block.statements.remove(store)
    elif mismatch == "duplicate":
        block.statements.insert(1, update)
    elif mismatch == "register":
        update.dst = ailment.Expr.Register(5, 12, 16)
    elif mismatch == "provenance":
        store.tags["vex_block_addr"] = 0x2000
    elif mismatch == "return_edge":
        graph.remove_edge(block, successor)
    else:
        call.tags.pop("ins_addr")
    original = tuple(block.statements)
    result = adapter.consume_returning_call_frames_8616(None, None, graph, sp_offset=16)
    assert tuple(block.statements) == original
    assert result.classified_fact_count == result.materialized_count == 0
    assert result.failure_count == 1
    assert result.accepted_calls == ()


def test_shared_successor_is_not_rewritten(monkeypatch):
    graph, block, successor, argument, _update, _store, call = _fixture(monkeypatch)
    other = ailment.Block(0x900, 1, statements=[])
    graph.add_edge(other, successor)
    result = adapter.consume_returning_call_frames_8616(None, None, graph, sp_offset=16)
    assert result.materialized_count == 2
    assert block.statements == [argument, call]
    assert successor.statements == []
    assert graph.has_edge(other, successor)


@pytest.mark.parametrize("mismatch", [None, "missing", "duplicate", "wrong_role"])
def test_separate_return_segment_consumption_is_atomic(monkeypatch, mismatch):
    graph, block, _successor, argument, _update, _store, call = _fixture(monkeypatch)
    tags = {"ins_addr": 0xFFF, "vex_block_addr": 0x1000, "vex_stmt_idx": 10}
    prefix = ailment.Stmt.Assignment(10, ailment.Expr.Register(10, 16, 16), argument.data, **tags)
    block.statements.insert(0, prefix)
    frame = ReturnSegmentFrame8616(0x1000, (
        ReturnSegmentEffect8616(0xFFF, 0x1000, 10, CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE),
    ))
    monkeypatch.setattr(adapter, "collect_return_segment_frames_8616", lambda *args: (frame,))
    if mismatch == "missing":
        block.statements.remove(prefix)
    elif mismatch == "duplicate":
        block.statements.insert(0, prefix)
    elif mismatch == "wrong_role":
        prefix.dst = ailment.Expr.Register(10, 12, 16)
    original = tuple(block.statements)
    result = adapter.consume_returning_call_frames_8616(None, None, graph, sp_offset=16)
    assert result.return_segment_frames == (frame,)
    if mismatch is None:
        assert block.statements == [argument, call]
        assert result.materialized_count == 3
    else:
        assert tuple(block.statements) == original
        assert result.materialized_count == 0
        assert result.failure_count == 1
