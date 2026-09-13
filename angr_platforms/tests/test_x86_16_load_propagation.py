"""Native propagation must preserve pre-store byte captures."""

import angr
import networkx
import pytest
from angr import ailment
from angr.analyses.s_propagator import SPropagator
from angr.code_location import AILCodeLocation
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.load_propagation import refuse_reordered_loads_8616


@pytest.mark.parametrize("graph_mode", [False, True])
@pytest.mark.parametrize("same_instruction", [False, True])
@pytest.mark.parametrize("intervening_store", [False, True])
def test_native_load_propagation_keeps_pre_store_value(graph_mode, same_instruction, intervening_store):
    project = angr.load_shellcode(b"\xc3", arch=Arch86_16(), load_address=0x1000)
    address = ailment.Expr.Const(0, 0x200, 32)
    saved = ailment.Expr.Tmp(1, 1, 8)
    loaded = ailment.Expr.Load(2, address, 1, "Iend_LE")
    statements = [ailment.Stmt.Assignment(0, saved, loaded, ins_addr=0x1000)]
    if intervening_store:
        statements.append(ailment.Stmt.Store(1, address, saved, 1, "Iend_LE", ins_addr=0x1000))
    use_index = len(statements)
    statements.append(ailment.Stmt.Store(
        2, address, saved, 1, "Iend_LE", ins_addr=0x1000 if same_instruction else 0x1001,
    ))
    block = ailment.Block(0x1000, 2, statements=statements)
    function = project.kb.functions.function(addr=0x1000, create=True)
    model = SPropagator(
        project, function if graph_mode else block, ail_manager=ailment.Manager(),
        func_graph=networkx.DiGraph([(block, block)]) if graph_mode else None,
        only_consts=False,
    ).model
    entries = model.replacements.get(AILCodeLocation(0x1000, None, use_index), {})
    assert (saved in entries) is (not intervening_store)


@pytest.mark.parametrize("kind", ["missing_block", "missing_use", "missing_definition", "call", "constant"])
def test_load_order_guard_refuses_unknown_evidence_and_preserves_constants(kind):
    address = ailment.Expr.Const(0, 0x200, 32)
    saved = ailment.Expr.Tmp(1, 1, 8)
    loaded = ailment.Expr.Load(2, address, 1, "Iend_LE")
    statements = [] if kind == "missing_definition" else [ailment.Stmt.Assignment(0, saved, loaded)]
    if kind == "call":
        statements.append(ailment.Stmt.SideEffectStatement(1, ailment.Expr.Call(3, address, bits=16)))
    use_index = len(statements)
    statements.append(ailment.Stmt.Return(2, [saved]))
    block = ailment.Block(0x1000, 1, statements=statements)
    location = AILCodeLocation(0x1000, None, None if kind == "missing_use" else use_index)
    entries = {saved: ailment.Expr.Const(4, 7, 8) if kind == "constant" else loaded}
    report = refuse_reordered_loads_8616(
        {} if kind == "missing_block" else {(block.addr, block.idx): block}, {location: entries},
    )
    expected_refusal = kind != "constant"
    assert (not entries) is expected_refusal
    assert report.raw_fact_count == int(expected_refusal)
    assert report.refused_count == int(expected_refusal)
    assert report.normalized_fact_count == report.raw_fact_count
    assert report.classified_fact_count == report.materialized_count
    assert report.failure_count == int(kind in {"missing_block", "missing_use"})
