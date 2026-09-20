"""Wide-store projection must not create calls from physical carrier reads."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CIfElse,
    CStatements,
)
from angr.sim_type import SimTypeShort
from angr_platforms.X86_16.lowering import segmented_global_loads as owner
from angr_platforms.X86_16.lowering.straight_line_placement import adjacent_straight_line_statements_8616
from test_x86_16_segmented_global_loads import _DummyCodegen, _mem_word, _reg


@pytest.mark.parametrize("placement", [
    "absent", "conditional", "wrong_address", "wrong_target", "exact", "near_exact", "near_wrong",
])
def test_wide_store_preserves_call_placement_and_arguments(placement):
    """Only an exact adjacent original call can become the store RHS."""
    codegen = _DummyCodegen()
    evidence = owner.DirectGlobalCallReturnStoreEvidence8616(
        offset=0x200, width=4, source_call_name="sub_100f",
        source_call_target=0x100f, source_call_ins_addr=0x1004,
        low_store_ins_addr=0x1007, high_store_ins_addr=0x100a,
    )
    argument = _reg(codegen.project, codegen, "bx")
    call = CFunctionCall(
        "sub_2000" if placement == "wrong_target" else "sub_100f", None,
        [argument], codegen=codegen,
        tags={"ins_addr": 0x1001 if placement == "wrong_address" else 0x1004},
    )
    statement = CExpressionStatement(call, codegen=codegen, tags=call.tags)
    if placement in {"near_exact", "near_wrong"}:
        codegen.project.loader = SimpleNamespace(main_object=SimpleNamespace(min_addr=0x1000))
        call.callee_target = CConstant(
            0xf if placement == "near_exact" else 0xe, SimTypeShort(False), codegen=codegen,
        )
    prefix = [] if placement == "absent" else [statement]
    branch_body = CStatements([statement], codegen=codegen)
    if placement == "conditional":
        prefix = [CIfElse([(argument, branch_body)], else_node=None, cstyle_ifs=True, codegen=codegen)]
    low = _reg(codegen.project, codegen, "ax")
    high = _reg(codegen.project, codegen, "dx")
    stores = [
        CAssignment(_mem_word(0x200, codegen, name="g_0200"), low,
                    codegen=codegen, tags={"ins_addr": 0x1007}),
        CAssignment(_mem_word(0x202, codegen, name="g_0202"), high,
                    codegen=codegen, tags={"ins_addr": 0x100a}),
    ]
    root = CStatements([*prefix, *stores], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)
    refs = owner._merge_direct_global_symbol_refs_8616((
        owner.DirectGlobalSymbolRef8616(0x200, "wide_value", 0, 2, 2),
        owner.DirectGlobalSymbolRef8616(0x202, "wide_value", 2, 2, 2),
    ))
    stats = owner.SegmentedGlobalLoadStats8616()
    assert owner.materialize_direct_global_symbol_stores_from_evidence_8616(
        codegen, refs, direct_call_return_stores=(evidence,), stats=stats,
    )
    assignment = root.statements[-1]
    assert isinstance(assignment, CAssignment)
    if placement in {"exact", "near_exact"}:
        assert len(root.statements) == 1
        assert assignment.rhs is call
        assert call.args == [argument]
        assert stats.direct_symbol_call_return_materialized_count == 1
    else:
        assert isinstance(assignment.rhs, CBinaryOp)
        assert assignment.rhs.op == "Or"
        assert assignment.rhs.lhs is low
        assert assignment.rhs.rhs.lhs is high
        assert stats.direct_symbol_call_return_materialized_count == 0
        assert root.statements[:-1] == prefix
        if placement == "conditional":
            assert branch_body.statements == [statement]
    assert call.args == [argument]


@pytest.mark.parametrize("layout, expected", [
    ("nested", True), ("empty_group", True), ("reverse", False),
    ("barrier", False), ("duplicate", False), ("shared_group", False),
    ("cycle", False),
])
def test_straight_line_placement_requires_unique_uninterrupted_order(layout, expected):
    codegen = _DummyCodegen()
    first, second, barrier = object(), object(), object()
    first_group = CStatements([first], codegen=codegen)
    second_group = CStatements([second], codegen=codegen)
    layouts = {
        "nested": [first_group, second_group],
        "empty_group": [first_group, CStatements([], codegen=codegen), second_group],
        "reverse": [second_group, first_group],
        "barrier": [first_group, barrier, second_group],
        "duplicate": [first, first, second],
        "shared_group": [first_group, second_group, first_group],
        "cycle": [first_group, second_group],
    }
    root = CStatements(layouts[layout], codegen=codegen)
    if layout == "cycle":
        first_group.statements.append(root)
    assert adjacent_straight_line_statements_8616(root, first, second) is expected
