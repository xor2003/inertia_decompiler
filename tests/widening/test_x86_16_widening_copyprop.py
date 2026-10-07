from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CDirtyExpression,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CIndexedVariable,
    CMultiStatementExpression,
    CStatements,
    CSwitchCase,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimTemporaryVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.lowering.c_ast_utils import _c_ast_cycle_path_8616
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.widening.widening_copyprop_8616 import _widening_copy_propagation_8616


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _global_indexed(name: str, base_addr: int, index, codegen):
    base = CVariable(
        SimMemoryVariable(base_addr, 2, name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    return CIndexedVariable(base, index, variable_type=SimTypeShort(False), codegen=codegen)


def test_widening_copyprop_rewrites_nested_index_rhs_before_memory_store_kill():
    codegen = _DummyCodegen()
    i_var = CVariable(
        SimStackVariable(-4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    bx_carrier = CVariable(
        SimRegisterVariable(6, 2, name="v15"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    copy = CAssignment(bx_carrier, i_var, codegen=codegen)
    store = CAssignment(
        _global_indexed("g_work", 0x44, i_var, codegen),
        _global_indexed("g_work", 0x44, bx_carrier, codegen),
        codegen=codegen,
    )
    root = CStatements([copy, store], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is True
    assert store.rhs.index.variable is i_var.variable
    assert store.rhs.index is not i_var
    assert codegen.widening_copyprop_nested_replacements_8616 == 1


def test_widening_copyprop_consumes_structured_virtual_value_identity() -> None:
    codegen = _DummyCodegen()
    global_limit = CVariable(
        SimMemoryVariable(0x160, 2, name="cszMenu"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    induction = CVariable(
        SimStackVariable(-2, 2, base="bp", name="i"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_definition = CDirtyExpression(SimpleNamespace(varid=356, bits=16), codegen=codegen)
    carrier_read = CDirtyExpression(SimpleNamespace(varid=356, bits=16), codegen=codegen)
    copy = CAssignment(carrier_definition, global_limit, codegen=codegen)
    guard = CIfBreak(CBinaryOp("CmpGE", induction, carrier_read, codegen=codegen), codegen=codegen)
    root = CStatements([copy, guard], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is True
    assert isinstance(guard.condition.rhs, CVariable)
    assert guard.condition.rhs.variable.addr == 0x160


def test_widening_copyprop_consumes_typed_temporary_in_nested_value_expression() -> None:
    codegen = _DummyCodegen()
    source = CVariable(
        SimStackVariable(4, 2, base="bp", name="x"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    definition = CVariable(SimTemporaryVariable(7, 16), codegen=codegen)
    read = CVariable(SimTemporaryVariable(7, 16), codegen=codegen)
    copy = CAssignment(definition, source, codegen=codegen)
    shifted = CBinaryOp(
        "Shl",
        read,
        CConstant(1, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
    )
    store = CAssignment(
        CVariable(SimMemoryVariable(0x44, 2, name="g_word"), codegen=codegen),
        shifted,
        codegen=codegen,
    )
    root = CStatements([copy, store], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is True
    assert isinstance(store.rhs, CBinaryOp)
    assert isinstance(store.rhs.lhs, CVariable)
    assert store.rhs.lhs.variable.offset == 4


def test_widening_copyprop_refuses_virtual_name_without_structured_identity() -> None:
    codegen = _DummyCodegen()
    source = CVariable(SimRegisterVariable(0, 2, name="ax"), codegen=codegen)
    dirty_definition = CDirtyExpression(SimpleNamespace(name="vvar_356"), codegen=codegen)
    dirty_definition.idx = None
    dirty_read = CDirtyExpression(SimpleNamespace(name="vvar_356"), codegen=codegen)
    dirty_read.idx = None
    copy = CAssignment(dirty_definition, source, codegen=codegen)
    guard = CIfBreak(CBinaryOp("CmpGE", source, dirty_read, codegen=codegen), codegen=codegen)
    root = CStatements([copy, guard], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is False
    assert guard.condition.rhs is dirty_read


def test_widening_copyprop_refuses_distinct_register_views_without_alias_identity() -> None:
    codegen = _DummyCodegen()
    source = CVariable(
        SimStackVariable(5, 1, base="bp", name="arg_high_byte", region=0x4010),
        codegen=codegen,
    )
    definition = CVariable(
        SimRegisterVariable(20, 1, name="v6"),
        codegen=codegen,
    )
    unrelated_read = CVariable(
        SimRegisterVariable(22, 1, name="v7"),
        codegen=codegen,
    )
    limit = CVariable(
        SimStackVariable(-2, 2, base="bp", name="goal_high", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    copy = CAssignment(definition, source, codegen=codegen)
    condition = CBinaryOp("CmpLE", unrelated_read, limit, codegen=codegen)
    guard = CIfBreak(condition, codegen=codegen)
    root = CStatements([copy, guard], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is False
    assert condition.lhs is unrelated_read
    assert codegen.widening_copyprop_unknown_identity_refused_8616 > 0


def test_widening_copyprop_refuses_virtual_carrier_inside_compound_condition() -> None:
    codegen = _DummyCodegen()
    global_limit = CVariable(
        SimMemoryVariable(0x160, 2, name="cszMenu"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    induction = CVariable(
        SimStackVariable(-2, 2, base="bp", name="i"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_definition = CDirtyExpression(SimpleNamespace(varid=356, bits=16), codegen=codegen)
    carrier_read = CDirtyExpression(SimpleNamespace(varid=356, bits=16), codegen=codegen)
    copy = CAssignment(carrier_definition, global_limit, codegen=codegen)
    comparison = CBinaryOp("CmpGE", induction, carrier_read, codegen=codegen)
    compound = CBinaryOp(
        "LogicalAnd",
        CConstant(1, SimTypeShort(False), codegen=codegen),
        comparison,
        codegen=codegen,
    )
    guard = CIfBreak(compound, codegen=codegen)
    root = CStatements([copy, guard], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is False
    assert comparison.rhs is carrier_read


def test_widening_copyprop_refuses_preloop_virtual_definition_in_loop_header() -> None:
    codegen = _DummyCodegen()
    initial = CVariable(
        SimStackVariable(4, 2, base="bp", name="initial"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    limit = CVariable(
        SimStackVariable(6, 2, base="bp", name="limit"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier_definition = CDirtyExpression(SimpleNamespace(varid=412, bits=16), codegen=codegen)
    carrier_read = CDirtyExpression(SimpleNamespace(varid=412, bits=16), codegen=codegen)
    copy = CAssignment(carrier_definition, initial, codegen=codegen)
    condition = CBinaryOp("CmpLE", carrier_read, limit, codegen=codegen)
    loop = CWhileLoop(condition, CStatements([], codegen=codegen), codegen=codegen)
    root = CStatements([copy, loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is False
    assert condition.lhs is carrier_read


def test_widening_copyprop_refuses_nested_replacement_under_address_context():
    codegen = _DummyCodegen()
    source = CVariable(
        SimStackVariable(-4, 2, base="bp", name="source", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    temp = CVariable(
        SimRegisterVariable(6, 2, name="v52"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    out = CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    source_expr = CBinaryOp("Add", source, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen)
    address_expr = CUnaryOp("Reference", temp, codegen=codegen)
    deref_expr = CUnaryOp(
        "Dereference",
        CBinaryOp("Add", address_expr, CConstant(2, SimTypeShort(False), codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    copy = CAssignment(temp, source_expr, codegen=codegen)
    use = CAssignment(out, deref_expr, codegen=codegen)
    root = CStatements([copy, use], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is False
    assert address_expr.operand is temp
    assert codegen.widening_copyprop_address_context_refused_8616 == 1


def test_widening_copyprop_walks_list_backed_switch_case_bodies():
    codegen = _DummyCodegen()
    source = CVariable(
        SimStackVariable(-4, 2, base="bp", name="source", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    temp = CVariable(
        SimRegisterVariable(6, 2, name="v72"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    out = CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    copy = CAssignment(temp, source, codegen=codegen)
    use = CAssignment(out, temp, codegen=codegen)
    case_body = CStatements([copy, use], addr=0x4020, codegen=codegen)
    switch = CSwitchCase(
        temp,
        [(69, case_body)],
        None,
        codegen=codegen,
    )
    root = CStatements([switch], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen)

    assert changed is True
    assert use.rhs.variable is source.variable
    assert use.rhs is not source


def test_widening_copyprop_refuses_self_referential_update_definition():
    codegen = _DummyCodegen()
    accumulator = CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    output = CVariable(
        SimStackVariable(-2, 2, base="bp", name="output", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    update_rhs = CBinaryOp(
        "Or",
        accumulator,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    update = CAssignment(accumulator, update_rhs, codegen=codegen)
    use_rhs = CBinaryOp(
        "Or",
        accumulator,
        CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    use = CAssignment(output, use_rhs, codegen=codegen)
    root = CStatements([update, use], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is False
    assert use_rhs.lhs is accumulator
    assert _c_ast_cycle_path_8616(root) == ()
    assert codegen.widening_copyprop_recursive_definitions_refused_8616 == 1


def test_widening_copyprop_does_not_duplicate_nontrivial_definition() -> None:
    codegen = _DummyCodegen()
    index = CVariable(
        SimStackVariable(-4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    parent = CVariable(
        SimStackVariable(-2, 2, base="bp", name="iParent", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    quotient = CBinaryOp(
        "Div",
        index,
        CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    definition = CAssignment(parent, quotient, codegen=codegen)
    condition = CBinaryOp(
        "CmpLE",
        index,
        parent,
        codegen=codegen,
    )
    guard = CIfBreak(condition, codegen=codegen)
    root = CStatements([definition, guard], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is False
    assert condition.rhs is parent
    assert codegen.widening_copyprop_nontrivial_stack_definitions_refused_8616 == 1


def test_widening_copyprop_materializes_nontrivial_transient_carrier() -> None:
    codegen = _DummyCodegen()
    source = CVariable(
        SimStackVariable(-4, 2, base="bp", name="source", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = CVariable(
        SimRegisterVariable(6, 2, name="v72"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    expression = CBinaryOp(
        "Add",
        source,
        CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    definition = CAssignment(carrier, expression, codegen=codegen)
    ordinary_use = CBinaryOp(
        "Sub",
        carrier,
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    sink = CVariable(SimRegisterVariable(8, 2, name="v73"), variable_type=SimTypeShort(False), codegen=codegen)
    use = CAssignment(sink, ordinary_use, codegen=codegen)
    condition = CBinaryOp(
        "CmpLE",
        source,
        carrier,
        codegen=codegen,
    )
    guard = CIfBreak(condition, codegen=codegen)
    root = CStatements([definition, use, guard], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is True
    assert ordinary_use.lhs is carrier
    assert isinstance(condition.rhs, CBinaryOp)
    assert condition.rhs is not expression
    assert codegen.widening_copyprop_nontrivial_stack_definitions_refused_8616 == 0
    assert codegen.widening_copyprop_nontrivial_assignment_uses_refused_8616 == 1
    assert codegen._inertia_widening_nontrivial_definition_guard_8616.is_closed


def test_widening_copyprop_rewrites_direct_break_condition_from_preceding_copy():
    codegen = _DummyCodegen()
    limit = CVariable(
        SimMemoryVariable(0x44, 2, name="limit"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = CVariable(
        SimRegisterVariable(6, 2, name="v72"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    copy = CAssignment(carrier, limit, codegen=codegen)
    condition = CBinaryOp("CmpGE", index, carrier, codegen=codegen)
    wrapped_condition = CBinaryOp(
        "LogicalAnd",
        CConstant(1, SimTypeShort(False), codegen=codegen),
        condition,
        codegen=codegen,
    )
    guard = CIfBreak(wrapped_condition, codegen=codegen, cstyle_ifs=True)
    root = CStatements([copy, guard], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is True
    assert condition.rhs.variable is limit.variable
    assert condition.rhs is not limit
    assert codegen.widening_copyprop_nested_replacements_8616 == 1


def test_widening_copyprop_refuses_signed_byte_cast_definition_in_break_condition() -> None:
    codegen = _DummyCodegen()
    source_word = CVariable(
        SimStackVariable(-8, 2, base="bp", name="barTemp", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    signed_length = CVariable(
        SimStackVariable(-6, 2, base="bp", name="iLength", region=0x4010),
        variable_type=SimTypeShort(True),
        codegen=codegen,
    )
    indexed_length = CVariable(
        SimStackVariable(-4, 2, base="bp", name="indexedLength", region=0x4010),
        variable_type=SimTypeShort(True),
        codegen=codegen,
    )
    signed_byte = CTypeCast(
        SimTypeShort(False),
        SimTypeChar(True),
        source_word,
        codegen=codegen,
    )
    definition = CAssignment(signed_length, signed_byte, codegen=codegen)
    condition = CBinaryOp("CmpLE", indexed_length, signed_length, codegen=codegen)
    guard = CIfBreak(condition, codegen=codegen, cstyle_ifs=True)
    root = CStatements([definition, guard], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is False
    assert condition.rhs is signed_length
    assert definition.rhs is signed_byte
    assert codegen.widening_copyprop_typed_cast_definitions_refused_8616 == 1


def test_widening_copyprop_walks_distinct_render_body_root():
    codegen = _DummyCodegen()
    source = CVariable(
        SimStackVariable(-4, 2, base="bp", name="source", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = CVariable(
        SimRegisterVariable(6, 2, name="v82"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    output = CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stale_root = CStatements([], addr=0x4010, codegen=codegen)
    copy = CAssignment(carrier, source, codegen=codegen)
    use = CAssignment(output, carrier, codegen=codegen)
    render_root = CStatements([copy, use], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=stale_root, body=render_root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is True
    assert use.rhs.variable is source.variable
    assert use.rhs is not source


def test_widening_copyprop_rewrites_ifelse_break_condition_from_preceding_copy():
    codegen = _DummyCodegen()
    limit = CVariable(
        SimMemoryVariable(0x48, 2, name="limit"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = CVariable(
        SimRegisterVariable(6, 2, name="v92"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    copy = CAssignment(carrier, limit, codegen=codegen)
    condition = CBinaryOp("CmpGE", index, carrier, codegen=codegen)
    break_body = CStatements([CBreak(codegen=codegen)], codegen=codegen)
    guard = CIfElse([(condition, break_body)], else_node=None, cstyle_ifs=True, codegen=codegen)
    root = CStatements([copy, guard], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is True
    rewritten_condition = guard.condition_and_nodes[0][0]
    assert rewritten_condition.rhs.variable is limit.variable
    assert rewritten_condition.rhs is not limit


def test_widening_copyprop_preserves_definitions_across_transparent_statement_wrappers():
    codegen = _DummyCodegen()
    limit = CVariable(
        SimMemoryVariable(0x4A, 2, name="limit"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = CVariable(
        SimRegisterVariable(6, 2, name="v102"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    copy_wrapper = CStatements([CAssignment(carrier, limit, codegen=codegen)], codegen=codegen)
    condition = CBinaryOp("CmpGE", index, carrier, codegen=codegen)
    break_body = CStatements([CBreak(codegen=codegen)], codegen=codegen)
    guard = CIfElse([(condition, break_body)], else_node=None, cstyle_ifs=True, codegen=codegen)
    guard_wrapper = CStatements([guard], codegen=codegen)
    root = CStatements([copy_wrapper, guard_wrapper], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is True
    rewritten_condition = guard.condition_and_nodes[0][0]
    assert rewritten_condition.rhs.variable is limit.variable


def test_widening_copyprop_refuses_untagged_call_definition():
    codegen = _DummyCodegen()
    carrier = CVariable(
        SimRegisterVariable(6, 2, name="v122"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    output = CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall("unknown_call", None, [], codegen=codegen)
    copy = CAssignment(carrier, call, codegen=codegen)
    use = CAssignment(output, carrier, codegen=codegen)
    root = CStatements([copy, use], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is False
    assert use.rhs is carrier


def test_widening_copyprop_consumes_multistatement_expression_definitions_in_order():
    codegen = _DummyCodegen()
    limit = CVariable(
        SimMemoryVariable(0x4C, 2, name="limit"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = CVariable(
        SimRegisterVariable(6, 2, name="v132"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    copy = CAssignment(carrier, limit, codegen=codegen)
    comparison = CBinaryOp("CmpGE", index, carrier, codegen=codegen)
    condition = CMultiStatementExpression(
        CStatements([copy], codegen=codegen),
        comparison,
        codegen=codegen,
    )
    guard = CIfBreak(condition, codegen=codegen, cstyle_ifs=True)
    root = CStatements([guard], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is True
    assert condition.expr.rhs.variable is limit.variable
    assert condition.expr.rhs is not limit


def test_widening_copyprop_refuses_exact_call_push_definition_in_condition_mse():
    codegen = _DummyCodegen()
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    push_definition = CAssignment(
        index,
        CConstant(104, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    comparison = CBinaryOp(
        "CmpEQ",
        index,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    condition = CMultiStatementExpression(
        CStatements([push_definition], codegen=codegen),
        comparison,
        codegen=codegen,
    )
    guard = CIfBreak(condition, codegen=codegen, cstyle_ifs=True)
    root = CStatements([guard], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    summary = CallsiteSummary8616(
        callsite_addr=0x4020,
        target_addr=0x5000,
        return_addr=0x4023,
        kind="near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=True,
        push_arg_instruction_addrs=(0x4016,),
    )
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is False
    assert condition.expr.lhs is index
    guard_stats = codegen._inertia_widening_call_push_definition_guard_8616
    assert (
        guard_stats.raw_fact_count,
        guard_stats.normalized_fact_count,
        guard_stats.classified_fact_count,
        guard_stats.materialized_count,
        guard_stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_widening_copyprop_keeps_near_match_definition_behavior():
    codegen = _DummyCodegen()
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="index", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ordinary_definition = CAssignment(
        index,
        CConstant(104, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    comparison = CBinaryOp(
        "CmpEQ",
        index,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements(
        [ordinary_definition, CIfBreak(comparison, codegen=codegen, cstyle_ifs=True)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    summary = CallsiteSummary8616(
        callsite_addr=0x4020,
        target_addr=0x5000,
        return_addr=0x4023,
        kind="near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=True,
        push_arg_instruction_addrs=(0x4016,),
    )
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}

    changed = _widening_copy_propagation_8616(codegen, enable_nested=True)

    assert changed is True
    assert isinstance(comparison.lhs, CConstant)
    assert comparison.lhs.value == 104
    guard_stats = codegen._inertia_widening_call_push_definition_guard_8616
    assert guard_stats.classified_fact_count == 0
    assert guard_stats.materialized_count == 0
