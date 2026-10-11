"""Native propagation must preserve pre-store byte captures."""

import angr
import networkx
import pytest
from angr import ailment
from angr.analyses.s_propagator import SPropagator
from angr.code_location import AILCodeLocation
from angr.utils.ssa import AILBlacklistExprTypeWalker

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.load_propagation import refuse_reordered_loads_8616
from inertia.frontend.x86_16.stack_compat import apply_x86_16_stack_compatibility


@pytest.mark.parametrize("graph_mode", [False, True])
@pytest.mark.parametrize("same_instruction", [False, True])
@pytest.mark.parametrize("intervening_store", [False, True])
def test_native_load_propagation_keeps_pre_store_value(graph_mode, same_instruction, intervening_store):
    apply_x86_16_stack_compatibility()
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


def _guard_scenario(kind):
    """Build (block, location, old, new) plus expected kept/failure flags."""
    address = ailment.Expr.Const(0, 0x200, 32)
    saved = ailment.Expr.Tmp(1, 1, 8)
    other = ailment.Expr.Tmp(2, 2, 8)
    loaded = ailment.Expr.Load(3, address, 1, "Iend_LE")
    store = ailment.Stmt.Store(4, address, saved, 1, "Iend_LE", ins_addr=0x4001)
    same_ins_store = ailment.Stmt.Store(11, address, saved, 1, "Iend_LE", ins_addr=0x4000)
    call = ailment.Stmt.SideEffectStatement(5, ailment.Expr.Call(6, address, bits=16))
    define_saved = ailment.Stmt.Assignment(7, saved, loaded, ins_addr=0x4000)
    statements = {
        "keep": [define_saved],
        "store_between": [define_saved, store],
        "same_instruction_store": [define_saved, same_ins_store],
        "side_effect_between": [define_saved, call],
        "def_after_store": [store, define_saved],
        "redefined_after_store": [ailment.Stmt.Assignment(8, saved, address), store, define_saved],
        "stale_then_other_def": [define_saved, store, ailment.Stmt.Assignment(9, other, loaded)],
        "missing_definition": [ailment.Stmt.Assignment(9, other, loaded)],
        "out_of_range_use": [define_saved],
        "negative_use": [define_saved],
    }[kind]
    use_index = {
        "out_of_range_use": len(statements) + 4,
        "negative_use": -1,
    }.get(kind, len(statements))
    statements.append(ailment.Stmt.Return(10, [saved]))
    block = ailment.Block(0x4000, 0, statements=statements)
    location = AILCodeLocation(0x4000, None, use_index)
    expected_keep = kind in {"keep", "def_after_store", "redefined_after_store"}
    return block, location, saved, loaded, expected_keep


@pytest.mark.parametrize(
    "kind",
    [
        "keep",
        "store_between",
        "same_instruction_store",
        "side_effect_between",
        "def_after_store",
        "redefined_after_store",
        "stale_then_other_def",
        "missing_definition",
        "out_of_range_use",
        "negative_use",
    ],
)
def test_load_ordering_semantics_differential(kind):
    """Each barrier/def ordering variant must keep or refuse identically."""
    block, location, saved, loaded, expected_keep = _guard_scenario(kind)
    invalid_use = kind in {"out_of_range_use", "negative_use"}
    entries = {saved: loaded}
    report = refuse_reordered_loads_8616({(block.addr, block.idx): block}, {location: entries})
    assert (saved in entries) is expected_keep
    assert report.raw_fact_count == 1
    assert report.refused_count == int(not expected_keep)
    assert report.failure_count == int(invalid_use)
    assert report.classified_fact_count == report.materialized_count == 1 - report.failure_count


def test_load_classification_walks_each_object_once_and_never_builds_statements(monkeypatch):
    """Identical replacement objects share one verdict; no statement is built."""
    expression_walks = []
    statement_walks = []
    original_expression = AILBlacklistExprTypeWalker.walk_expression
    original_statement = AILBlacklistExprTypeWalker.walk_statement

    def counting_expression(self, expr, *args, **kwargs):
        expression_walks.append(expr)
        return original_expression(self, expr, *args, **kwargs)

    def counting_statement(self, stmt, *args, **kwargs):
        statement_walks.append(stmt)
        return original_statement(self, stmt, *args, **kwargs)

    monkeypatch.setattr(AILBlacklistExprTypeWalker, "walk_expression", counting_expression)
    monkeypatch.setattr(AILBlacklistExprTypeWalker, "walk_statement", counting_statement)

    address = ailment.Expr.Const(0, 0x200, 32)
    shared = ailment.Expr.Load(1, address, 1, "Iend_LE")
    distinct_a = ailment.Expr.Load(2, address, 1, "Iend_LE")
    distinct_b = ailment.Expr.Load(3, address, 1, "Iend_LE")
    saved = [ailment.Expr.Tmp(10 + i, i, 8) for i in range(4)]
    statements = [ailment.Stmt.Assignment(20 + i, tmp, address) for i, tmp in enumerate(saved)]
    use_index = len(statements)
    statements.append(ailment.Stmt.Return(30, list(saved)))
    block = ailment.Block(0x5000, 0, statements=statements)
    # Equal-but-distinct objects are separate identities and each walked once.
    news = [shared, shared, distinct_a, distinct_b]
    replacements = {}
    for block_addr in (0x5000, 0x5001):
        replacements[AILCodeLocation(block_addr, None, use_index)] = dict(zip(saved, news, strict=True))
    report = refuse_reordered_loads_8616(
        {(0x5000, None): block, (0x5001, None): block}, replacements
    )
    assert report.raw_fact_count == 8
    assert report.refused_count == 0
    assert len(expression_walks) == 3
    assert statement_walks == []


def test_identity_cache_observes_mutation_between_invocations():
    """Per-call caches must not hide edits to blocks or replacement objects."""
    address = ailment.Expr.Const(0, 0x200, 32)
    saved = ailment.Expr.Tmp(1, 1, 8)
    loaded = ailment.Expr.Load(2, address, 1, "Iend_LE")
    define_saved = ailment.Stmt.Assignment(3, saved, loaded)
    statements = [define_saved, ailment.Stmt.Return(4, [saved])]
    block = ailment.Block(0x6000, 0, statements=statements)
    location = AILCodeLocation(0x6000, None, 1)
    blocks = {(block.addr, block.idx): block}

    entries = {saved: loaded}
    first = refuse_reordered_loads_8616(blocks, {location: entries})
    assert first.raw_fact_count == 1 and saved in entries

    # A store inserted inside the scanned prefix must be observed on the next
    # call at the same location; a stale scan would wrongly keep the entry.
    statements.insert(0, ailment.Stmt.Store(5, address, saved, 1, "Iend_LE"))
    second = refuse_reordered_loads_8616(blocks, {location: {saved: loaded}})
    assert second.refused_count == 1

    # The same expression object edited to drop its load is re-observed.
    wrapper = ailment.Expr.BinaryOp(6, "Add", [loaded, address], False, bits=32)
    third = refuse_reordered_loads_8616(blocks, {location: {saved: wrapper}})
    assert third.raw_fact_count == 1
    wrapper.operands = (address, address)
    fourth_entries = {saved: wrapper}
    fourth = refuse_reordered_loads_8616(blocks, {location: fourth_entries})
    assert fourth.raw_fact_count == 0
    assert saved in fourth_entries


def test_many_adjacent_uses_do_not_rescan_or_copy_block_prefixes():
    """Ordering lookup stays linear for a sequence of adjacent definition/use pairs."""
    class ObservedStatements(list):
        visits = 0

        def __getitem__(self, index):
            self.visits += len(range(*index.indices(len(self)))) if isinstance(index, slice) else 1
            return super().__getitem__(index)

        def __iter__(self):
            for item in super().__iter__():
                self.visits += 1
                yield item

    address = ailment.Expr.Const(0, 0x200, 32)
    loaded = ailment.Expr.Load(1, address, 1, "Iend_LE")
    statements = ObservedStatements()
    replacements = {}
    for index in range(300):
        saved = ailment.Expr.Tmp(index + 2, index, 8)
        statements.append(ailment.Stmt.Assignment(index * 2, saved, loaded))
        replacements[AILCodeLocation(0x7000, None, len(statements))] = {saved: loaded}
        statements.append(ailment.Stmt.Return(index * 2 + 1, [saved]))
    block = ailment.Block(0x7000, 1, statements=statements)
    report = refuse_reordered_loads_8616({(block.addr, block.idx): block}, replacements)
    assert report.refused_count == 0
    assert report.raw_fact_count == 300
    assert 0 < statements.visits <= len(statements)


def test_load_verdict_does_not_leak_into_pure_replacements():
    """A reusable walker resets its verdict even after rejecting a loaded expression."""
    pure = ailment.Expr.Const(0, 7, 8)
    loaded = ailment.Expr.Load(1, ailment.Expr.Const(2, 0x200, 32), 1, "Iend_LE")
    saved = [ailment.Expr.Tmp(3 + index, index, 8) for index in range(4)]
    entries = dict(zip(saved, [loaded, pure, loaded, pure], strict=True))
    report = refuse_reordered_loads_8616({}, {AILCodeLocation(0x8000, None, 0): entries})
    assert report.raw_fact_count == report.failure_count == report.refused_count == 2
    assert set(entries) == {saved[1], saved[3]}


@pytest.mark.parametrize("kind", ["call", "ite_true", "ite_false", "mse_assignment", "mse_store_guard"])
def test_nested_loads_keep_ordering_obligations(kind):
    """Expression-only walking must also inspect calls and embedded statements."""
    address = ailment.Expr.Const(0, 0x200, 32)
    pure = ailment.Expr.Const(1, 0, 8)
    loaded = ailment.Expr.Load(2, address, 1, "Iend_LE")
    saved = ailment.Expr.Tmp(3, 1, 8)
    if kind == "call":
        replacement = ailment.Expr.Call(4, address, args=(loaded,), bits=8)
    elif kind in {"ite_true", "ite_false"}:
        replacement = ailment.Expr.ITE(
            4, ailment.Expr.Const(5, 1, 1),
            loaded if kind == "ite_false" else pure,
            loaded if kind == "ite_true" else pure,
        )
    else:
        statement = (
            ailment.Stmt.Assignment(4, saved, loaded) if kind == "mse_assignment" else
            ailment.Stmt.Store(4, address, pure, 1, "Iend_LE", guard=loaded)
        )
        replacement = ailment.Expr.MultiStatementExpression(5, [statement], pure)
    entries = {saved: replacement}
    report = refuse_reordered_loads_8616({}, {AILCodeLocation(0x9000, None, 0): entries})
    assert report.raw_fact_count == report.refused_count == 1
    assert entries == {}
