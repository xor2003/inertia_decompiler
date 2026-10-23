"""Red/green tests for the combined widening-pass applicability probe.

The probe must return ``False`` only when BOTH transforms of the combined
structuring pass (contained stack subviews, then widening copy propagation)
are proven unable to change the current C AST. Unknown input stays
applicable. These tests cross-check the probe against the real production
transforms on identical fixtures, so a probe that wrongly reports a no-op
fails against the real pass's ``changed`` result.
"""


from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CDirtyExpression,
    CIfBreak,
    CIfElse,
    CMultiStatementExpression,
    CStatements,
    CSwitchCase,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import (
    SimMemoryVariable,
    SimRegisterVariable,
    SimStackVariable,
    SimTemporaryVariable,
)

from inertia.alias.stack_memory_ssa import (
    build_x86_16_stack_memory_ssa_alias_artifact,
)
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa
from inertia.lowering.c_ast_utils import _structured_codegen_node_8616, _structured_slot_names_8616
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.structuring.decompiler_structuring_stage import (
    _build_decompiler_structuring_passes,
    _run_structuring_widening_copy_propagation_8616,
)
from inertia.widening.stack_memory_objects import (
    build_x86_16_stack_memory_object_widening_artifact,
)
from inertia.widening.stack_subview_projection import (
    materialize_contained_stack_subviews_8616 as overlay_materialize_subviews,
)
from inertia.widening.stack_subview_projection import stack_subview_projection_probe_8616
from inertia.widening.widening_copyprop_8616 import (
    _widening_copy_propagation_8616 as overlay_copyprop,
)
from inertia.widening.widening_copyprop_8616 import widening_copy_propagation_probe_8616
from inertia.widening.widening_subview_copyprop_applicability_8616 import (
    widening_subview_copyprop_applicable_8616,
)

FUNCTION_ADDR = 0x4010

_COUNTER_PREFIXES = ("_inertia_", "widening_copyprop_")


class _DummyCodegen:
    def __init__(self) -> None:
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


def _codegen_metadata(codegen: object) -> dict[str, object]:
    """Snapshot owned Inertia counters/artifacts on a dynamic codegen."""
    return {
        name: value
        for name, value in vars(codegen).items()
        if isinstance(name, str) and name.startswith(_COUNTER_PREFIXES)
    }


def _ast_fingerprint(node: object, _active: frozenset[int] = frozenset()) -> object:
    """Serialize a structured C AST subtree by shape, attrs and identity."""
    if not _structured_codegen_node_8616(node):
        if isinstance(node, dict):
            return (
                "dict",
                *(
                    (repr(key), _ast_fingerprint(value, _active))
                    for key, value in sorted(node.items(), key=lambda item: repr(item[0]))
                ),
            )
        if isinstance(node, (list, tuple)):
            return (type(node).__name__, *(_ast_fingerprint(item, _active) for item in node))
        return ("leaf", type(node).__name__, repr(node))
    marker = id(node)
    if marker in _active:
        return ("cycle", type(node).__name__)
    active = _active | {marker}
    children: list[object] = []
    for attr in _structured_slot_names_8616(node):
        try:
            value = getattr(node, attr)
        except Exception:
            value = "<unreadable>"
        children.append((attr, _ast_fingerprint(value, active)))
    return (type(node).__name__, marker, tuple(children))


def _stack_var(offset: int, size: int, name: str, codegen: _DummyCodegen, *, signed: bool = False) -> CVariable:
    return CVariable(
        SimStackVariable(offset, size, base="bp", name=name, region=FUNCTION_ADDR),
        variable_type=SimTypeShort(signed),
        codegen=codegen,
    )


def _reg_var(reg_offset: int, name: str, codegen: _DummyCodegen) -> CVariable:
    return CVariable(
        SimRegisterVariable(reg_offset, 2, name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _constant(value: int, codegen: _DummyCodegen) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _bp_slot(offset: int, size: int) -> IRAddress:
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.DEFAULTED,
    )


def _store(address: IRAddress) -> IRInstr:
    return IRInstr(
        "STORE",
        None,
        (address, IRValue(MemSpace.CONST, const=1, size=address.size)),
        size=address.size,
    )


def _load(address: IRAddress) -> IRInstr:
    return IRInstr(
        "LOAD",
        IRValue(MemSpace.REG, name="ax", size=address.size),
        (address,),
        size=address.size,
    )


def _attach_word_proof(
    codegen: _DummyCodegen,
    offset: int,
    *,
    view_offsets: tuple[int, ...] = (1,),
) -> None:
    function_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            function_addr=FUNCTION_ADDR,
            blocks=(
                IRBlock(
                    addr=FUNCTION_ADDR,
                    instrs=(
                        _store(_bp_slot(offset, 2)),
                        *tuple(_load(_bp_slot(offset + delta, 1)) for delta in view_offsets),
                    ),
                ),
            ),
        )
    )
    source = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)
    codegen._inertia_stack_memory_ssa_alias_artifact = source
    codegen._inertia_stack_memory_object_widening_artifact = (
        build_x86_16_stack_memory_object_widening_artifact(source)
    )


def _callsite_summary(push_addrs: tuple[int, ...]) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x4020,
        target_addr=0x5000,
        return_addr=0x4023,
        kind="near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=True,
        push_arg_instruction_addrs=push_addrs,
    )


# ---------------------------------------------------------------------------
# Positive cases: the probe must stay applicable whenever a transform can
# change the AST. Each case cross-checks the real production combined pass.
# ---------------------------------------------------------------------------


def test_applicable_stays_true_for_simple_copyprop_replacement() -> None:
    codegen = _DummyCodegen()
    source = _stack_var(-4, 2, "source", codegen)
    carrier = _reg_var(6, "v72", codegen)
    output = _reg_var(0, "ax", codegen)
    copy_stmt = CAssignment(carrier, source, codegen=codegen)
    use = CAssignment(output, carrier, codegen=codegen)
    root = CStatements([copy_stmt, use], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)

    assert widening_subview_copyprop_applicable_8616(codegen) is True
    # Read-only proof: the AST still holds the unpropagated carrier.
    assert use.rhs is carrier
    assert _run_structuring_widening_copy_propagation_8616(codegen) is True
    assert use.rhs.variable is source.variable


def test_applicable_stays_true_for_condition_copyprop() -> None:
    codegen = _DummyCodegen()
    limit = CVariable(
        SimMemoryVariable(0x44, 2, name="limit"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = _reg_var(6, "v72", codegen)
    index = _stack_var(-2, 2, "index", codegen)
    copy_stmt = CAssignment(carrier, limit, codegen=codegen)
    condition = CBinaryOp("CmpGE", index, carrier, codegen=codegen)
    wrapped = CBinaryOp("LogicalAnd", _constant(1, codegen), condition, codegen=codegen)
    guard = CIfBreak(wrapped, codegen=codegen, cstyle_ifs=True)
    root = CStatements([copy_stmt, guard], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)

    assert widening_subview_copyprop_applicable_8616(codegen) is True
    assert condition.rhs is carrier
    assert _run_structuring_widening_copy_propagation_8616(codegen) is True
    assert condition.rhs.variable is limit.variable


def test_applicable_stays_true_for_virtual_copy_in_condition() -> None:
    codegen = _DummyCodegen()
    global_limit = CVariable(
        SimMemoryVariable(0x160, 2, name="cszMenu"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    induction = _stack_var(-2, 2, "i", codegen)
    carrier_definition = CDirtyExpression(SimpleNamespace(varid=356, bits=16), codegen=codegen)
    carrier_read = CDirtyExpression(SimpleNamespace(varid=356, bits=16), codegen=codegen)
    copy_stmt = CAssignment(carrier_definition, global_limit, codegen=codegen)
    guard = CIfBreak(CBinaryOp("CmpGE", induction, carrier_read, codegen=codegen), codegen=codegen)
    root = CStatements([copy_stmt, guard], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)

    assert widening_subview_copyprop_applicable_8616(codegen) is True
    assert _run_structuring_widening_copy_propagation_8616(codegen) is True
    assert isinstance(guard.condition.rhs, CVariable)


def test_applicable_stays_true_for_nested_multistatement_copyprop() -> None:
    codegen = _DummyCodegen()
    limit = CVariable(
        SimMemoryVariable(0x4C, 2, name="limit"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = _reg_var(6, "v132", codegen)
    index = _stack_var(-2, 2, "index", codegen)
    copy_stmt = CAssignment(carrier, limit, codegen=codegen)
    comparison = CBinaryOp("CmpGE", index, carrier, codegen=codegen)
    condition = CMultiStatementExpression(
        CStatements([copy_stmt], codegen=codegen), comparison, codegen=codegen
    )
    guard = CIfBreak(condition, codegen=codegen, cstyle_ifs=True)
    root = CStatements([guard], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)

    assert widening_subview_copyprop_applicable_8616(codegen) is True
    assert _run_structuring_widening_copy_propagation_8616(codegen) is True
    assert condition.expr.rhs.variable is limit.variable


def test_applicable_stays_true_for_ifelse_condition_pair() -> None:
    codegen = _DummyCodegen()
    limit = CVariable(
        SimMemoryVariable(0x48, 2, name="limit"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    carrier = _reg_var(6, "v92", codegen)
    index = _stack_var(-2, 2, "index", codegen)
    copy_stmt = CAssignment(carrier, limit, codegen=codegen)
    condition = CBinaryOp("CmpGE", index, carrier, codegen=codegen)
    break_body = CStatements([CBreak(codegen=codegen)], codegen=codegen)
    guard = CIfElse([(condition, break_body)], else_node=None, cstyle_ifs=True, codegen=codegen)
    root = CStatements([copy_stmt, guard], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)

    assert widening_subview_copyprop_applicable_8616(codegen) is True
    assert _run_structuring_widening_copy_propagation_8616(codegen) is True
    assert guard.condition_and_nodes[0][0].rhs.variable is limit.variable


def test_applicable_stays_true_for_switch_case_body_copyprop() -> None:
    codegen = _DummyCodegen()
    source = _stack_var(-4, 2, "source", codegen)
    carrier = _reg_var(6, "v72", codegen)
    output = _reg_var(0, "ax", codegen)
    copy_stmt = CAssignment(carrier, source, codegen=codegen)
    use = CAssignment(output, carrier, codegen=codegen)
    case_body = CStatements([copy_stmt, use], addr=0x4020, codegen=codegen)
    switch = CSwitchCase(carrier, [(69, case_body)], None, codegen=codegen)
    root = CStatements([switch], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)

    # Combined pass runs with enable_nested=True.
    assert widening_subview_copyprop_applicable_8616(codegen) is True
    assert _run_structuring_widening_copy_propagation_8616(codegen) is True
    assert use.rhs.variable is source.variable


def test_applicable_stays_true_for_temporary_carrier_copyprop() -> None:
    codegen = _DummyCodegen()
    source = _stack_var(4, 2, "x", codegen)
    definition = CVariable(SimTemporaryVariable(7, 16), codegen=codegen)
    read = CVariable(SimTemporaryVariable(7, 16), codegen=codegen)
    copy_stmt = CAssignment(definition, source, codegen=codegen)
    shifted = CBinaryOp("Shl", read, CConstant(1, SimTypeChar(False), codegen=codegen), codegen=codegen)
    store = CAssignment(
        CVariable(SimMemoryVariable(0x44, 2, name="g_word"), codegen=codegen),
        shifted,
        codegen=codegen,
    )
    root = CStatements([copy_stmt, store], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)

    assert widening_subview_copyprop_applicable_8616(codegen) is True
    assert _run_structuring_widening_copy_propagation_8616(codegen) is True
    assert isinstance(store.rhs.lhs, CVariable)


def _subview_read_fixture() -> tuple[_DummyCodegen, CAssignment]:
    codegen = _DummyCodegen()
    word = _stack_var(-4, 2, "local_4", codegen)
    byte = _stack_var(-3, 1, "byte_view", codegen)
    destination = CVariable(SimpleNamespace(name="inertia_ax"), codegen=codegen)
    assignment = CAssignment(destination, byte, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={word.variable: word, byte.variable: byte},
    )
    _attach_word_proof(codegen, -4, view_offsets=(1,))
    return codegen, assignment


def test_applicable_stays_true_for_subview_direct_read() -> None:
    codegen, assignment = _subview_read_fixture()

    assert widening_subview_copyprop_applicable_8616(codegen) is True
    assert _run_structuring_widening_copy_propagation_8616(codegen) is True
    assert isinstance(assignment.rhs, CBinaryOp)


def test_applicable_stays_true_for_subview_recomposition() -> None:
    codegen = _DummyCodegen()
    word = _stack_var(-4, 2, "local_4", codegen)
    high_byte = _stack_var(-3, 1, "local_3", codegen)
    recomposed = CBinaryOp(
        "Or",
        word,
        CBinaryOp("Shl", high_byte, _constant(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    assignment = CAssignment(
        word,
        CBinaryOp("Add", recomposed, _constant(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={word.variable: word, high_byte.variable: high_byte},
    )
    _attach_word_proof(codegen, -4)

    assert widening_subview_copyprop_applicable_8616(codegen) is True
    assert _run_structuring_widening_copy_propagation_8616(codegen) is True
    assert isinstance(assignment.rhs.lhs, CVariable)


def test_applicable_stays_true_for_subview_direct_write() -> None:
    codegen = _DummyCodegen()
    word = _stack_var(-4, 2, "local_4", codegen)
    byte = _stack_var(-3, 1, "byte_view", codegen)
    assignment = CAssignment(byte, _constant(7, codegen), codegen=codegen, tags={"ins_addr": 0x4020})
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={word.variable: word, byte.variable: byte},
    )
    _attach_word_proof(codegen, -4, view_offsets=(1,))

    assert widening_subview_copyprop_applicable_8616(codegen) is True
    assert _run_structuring_widening_copy_propagation_8616(codegen) is True
    projected = codegen.cfunc.statements.statements[0]
    assert isinstance(projected, CAssignment) and projected.lhs.variable is word.variable


# ---------------------------------------------------------------------------
# Proven no-op cases: applicable must be False, the AST must be untouched,
# diagnostics must match an executed no-op run, and the real combined pass
# must agree (changed == False) on an identical fresh fixture.
# ---------------------------------------------------------------------------


def _normalized_flat_fixture() -> tuple[_DummyCodegen, CStatements]:
    codegen = _DummyCodegen()
    first = _stack_var(-4, 2, "first", codegen)
    second = _stack_var(-6, 2, "second", codegen)
    assign_a = CAssignment(first, _constant(3, codegen), codegen=codegen)
    assign_b = CAssignment(second, _constant(9, codegen), codegen=codegen)
    # The condition reads carriers with no recorded definitions, so no copy
    # can propagate and no subview candidate exists.
    left = _reg_var(0, "ax", codegen)
    right = _reg_var(6, "v_cx", codegen)
    condition = CBinaryOp("CmpLE", left, right, codegen=codegen)
    guard = CIfBreak(condition, codegen=codegen, cstyle_ifs=True)
    root = CStatements([assign_a, assign_b, guard], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)
    return codegen, root


def test_applicable_false_for_already_normalized_ast() -> None:
    codegen, root = _normalized_flat_fixture()
    before_ast = _ast_fingerprint(root)
    before_meta = _codegen_metadata(codegen)

    assert widening_subview_copyprop_applicable_8616(codegen) is False
    assert _ast_fingerprint(root) == before_ast

    # Documented zero-work diagnostics only.
    after_meta = _codegen_metadata(codegen)
    published = set(after_meta) - set(before_meta)
    expected = {
        "_inertia_stack_subview_raw_fact_count",
        "_inertia_stack_subview_normalized_fact_count",
        "_inertia_stack_subview_classified_fact_count",
        "_inertia_stack_subview_materialized_count",
        "_inertia_stack_subview_failure_count",
        "_inertia_stack_subview_last_stats_8616",
        "_inertia_widening_call_push_definition_guard_8616",
        "_inertia_widening_nontrivial_definition_guard_8616",
        "_inertia_widening_copy_width_guard_8616",
        "widening_copyprop_nested_replacements_8616",
        "widening_copyprop_address_context_refused_8616",
        "widening_copyprop_memory_kills_8616",
        "widening_copyprop_nontrivial_stack_definitions_refused_8616",
        "widening_copyprop_nontrivial_assignment_uses_refused_8616",
        "widening_copyprop_recursive_definitions_refused_8616",
        "widening_copyprop_typed_cast_definitions_refused_8616",
        "widening_copyprop_unknown_identity_refused_8616",
        "widening_copyprop_width_mismatch_refused_8616",
    }
    assert published == expected
    stats = codegen._inertia_stack_subview_last_stats_8616
    assert stats.materialized_count == 0
    assert stats.classified_fact_count == 0

    # The real combined pass agrees: no change on the same AST.
    fresh, _ = _normalized_flat_fixture()
    assert _run_structuring_widening_copy_propagation_8616(fresh) is False


def test_applicable_false_for_refusal_only_copyprop_fixtures() -> None:
    # Signed-cast definition refusal (typed-cast barrier).
    codegen = _DummyCodegen()
    source_word = _stack_var(-8, 2, "barTemp", codegen)
    signed_length = _stack_var(-6, 2, "iLength", codegen, signed=True)
    indexed_length = _stack_var(-4, 2, "indexedLength", codegen, signed=True)
    signed_byte = CTypeCast(
        SimTypeShort(False), SimTypeChar(True), source_word, codegen=codegen
    )
    definition = CAssignment(signed_length, signed_byte, codegen=codegen)
    condition = CBinaryOp("CmpLE", indexed_length, signed_length, codegen=codegen)
    guard = CIfBreak(condition, codegen=codegen, cstyle_ifs=True)
    root = CStatements([definition, guard], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)

    assert widening_subview_copyprop_applicable_8616(codegen) is False
    assert condition.rhs is signed_length
    # Refusal evidence was replayed like an executed no-op run.
    assert codegen.widening_copyprop_typed_cast_definitions_refused_8616 == 1


def test_applicable_false_for_recursive_and_width_refusals() -> None:
    # Self-referential definition refusal.
    codegen = _DummyCodegen()
    accumulator = _reg_var(0, "ax", codegen)
    output = _stack_var(-2, 2, "output", codegen)
    update_rhs = CBinaryOp("Or", accumulator, _constant(1, codegen), codegen=codegen)
    update = CAssignment(accumulator, update_rhs, codegen=codegen)
    use_rhs = CBinaryOp("Or", accumulator, _constant(2, codegen), codegen=codegen)
    use = CAssignment(output, use_rhs, codegen=codegen)
    root = CStatements([update, use], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)

    assert widening_subview_copyprop_applicable_8616(codegen) is False
    assert use_rhs.lhs is accumulator
    assert codegen.widening_copyprop_recursive_definitions_refused_8616 == 1


def test_applicable_false_for_call_push_guarded_definition() -> None:
    codegen = _DummyCodegen()
    index = _stack_var(-2, 2, "index", codegen)
    push_definition = CAssignment(
        index,
        _constant(104, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4016},
    )
    comparison = CBinaryOp("CmpEQ", index, _constant(0, codegen), codegen=codegen)
    condition = CMultiStatementExpression(
        CStatements([push_definition], codegen=codegen), comparison, codegen=codegen
    )
    guard = CIfBreak(condition, codegen=codegen, cstyle_ifs=True)
    root = CStatements([guard], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)
    summary = _callsite_summary((0x4016,))
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}

    assert widening_subview_copyprop_applicable_8616(codegen) is False
    assert condition.expr.lhs is index
    guard_stats = codegen._inertia_widening_call_push_definition_guard_8616
    assert (
        guard_stats.raw_fact_count,
        guard_stats.normalized_fact_count,
        guard_stats.classified_fact_count,
        guard_stats.materialized_count,
        guard_stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_applicable_false_for_address_context_refusal() -> None:
    codegen = _DummyCodegen()
    source = _stack_var(-4, 2, "source", codegen)
    temp = _reg_var(6, "v52", codegen)
    out = _reg_var(0, "ax", codegen)
    source_expr = CBinaryOp("Add", source, _constant(1, codegen), codegen=codegen)
    address_expr = CUnaryOp("Reference", temp, codegen=codegen)
    deref_expr = CUnaryOp(
        "Dereference",
        CBinaryOp("Add", address_expr, _constant(2, codegen), codegen=codegen),
        codegen=codegen,
    )
    copy_stmt = CAssignment(temp, source_expr, codegen=codegen)
    use = CAssignment(out, deref_expr, codegen=codegen)
    root = CStatements([copy_stmt, use], addr=FUNCTION_ADDR, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)

    assert widening_subview_copyprop_applicable_8616(codegen) is False
    assert address_expr.operand is temp
    assert codegen.widening_copyprop_address_context_refused_8616 == 1


def test_applicable_false_for_preloop_virtual_definition() -> None:
    codegen = _DummyCodegen()
    initial = _stack_var(4, 2, "initial", codegen)
    limit = _stack_var(6, 2, "limit", codegen)
    carrier_definition = CDirtyExpression(SimpleNamespace(varid=412, bits=16), codegen=codegen)
    carrier_read = CDirtyExpression(SimpleNamespace(varid=412, bits=16), codegen=codegen)
    copy_stmt = CAssignment(carrier_definition, initial, codegen=codegen)
    condition = CBinaryOp("CmpLE", carrier_read, limit, codegen=codegen)
    loop = CWhileLoop(condition, CStatements([], codegen=codegen), codegen=codegen)
    root = CStatements([copy_stmt, loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root, body=root)

    assert widening_subview_copyprop_applicable_8616(codegen) is False
    assert condition.lhs is carrier_read


def test_applicable_false_for_unproven_subview_syntax() -> None:
    codegen = _DummyCodegen()
    word = _stack_var(-4, 2, "local_4", codegen)
    high_byte = _stack_var(-3, 1, "local_3", codegen)
    recomposed = CBinaryOp(
        "Or",
        word,
        CBinaryOp("Shl", high_byte, _constant(8, codegen), codegen=codegen),
        codegen=codegen,
    )
    assignment = CAssignment(word, recomposed, codegen=codegen)
    root = CStatements([assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)
    before_ast = _ast_fingerprint(root)

    # No widening artifact: both halves of the pass are proven no-ops.
    assert widening_subview_copyprop_applicable_8616(codegen) is False
    assert _ast_fingerprint(root) == before_ast
    assert codegen._inertia_stack_subview_last_stats_8616.failure_count == 1


def test_applicable_false_for_missing_cfunc() -> None:
    codegen = _DummyCodegen()
    assert widening_subview_copyprop_applicable_8616(codegen) is False
    # No diagnostics are published when both passes exit before any evidence.
    assert _codegen_metadata(codegen) == {}


# ---------------------------------------------------------------------------
# Unknown surface stays applicable.
# ---------------------------------------------------------------------------


def test_applicable_true_for_unknown_callsite_inventory_surface() -> None:
    codegen, root = _normalized_flat_fixture()
    codegen._inertia_callsite_summary_inventory_8616 = ["not-a-dict"]
    before_ast = _ast_fingerprint(root)

    assert widening_subview_copyprop_applicable_8616(codegen) is True
    assert _ast_fingerprint(root) == before_ast


# ---------------------------------------------------------------------------
# Per-probe isolation and diagnostics fidelity.
# ---------------------------------------------------------------------------


def test_copyprop_probe_publish_matches_executed_noop_diagnostics() -> None:
    probed, _ = _normalized_flat_fixture()
    assert widening_copy_propagation_probe_8616(probed) is not None
    probe_result = widening_subview_copyprop_applicable_8616(probed)
    assert probe_result is False

    executed, _ = _normalized_flat_fixture()
    assert overlay_copyprop(executed, enable_nested=True) is False

    for name in (
        "widening_copyprop_nested_replacements_8616",
        "widening_copyprop_address_context_refused_8616",
        "widening_copyprop_memory_kills_8616",
        "widening_copyprop_nontrivial_stack_definitions_refused_8616",
        "widening_copyprop_nontrivial_assignment_uses_refused_8616",
        "widening_copyprop_recursive_definitions_refused_8616",
        "widening_copyprop_typed_cast_definitions_refused_8616",
        "widening_copyprop_unknown_identity_refused_8616",
        "widening_copyprop_width_mismatch_refused_8616",
    ):
        assert getattr(probed, name) == getattr(executed, name), name
    for guard_name in (
        "_inertia_widening_call_push_definition_guard_8616",
        "_inertia_widening_nontrivial_definition_guard_8616",
        "_inertia_widening_copy_width_guard_8616",
    ):
        assert getattr(probed, guard_name).to_dict() == getattr(executed, guard_name).to_dict()


def test_subview_probe_and_transform_share_decision() -> None:
    # Proven work: probe returns None, transform changes the AST.
    codegen, assignment = _subview_read_fixture()
    assert stack_subview_projection_probe_8616(codegen) is None
    assert overlay_materialize_subviews(codegen) is True
    assert isinstance(assignment.rhs, CBinaryOp)

    # Refused-only work: probe proves a no-op, transform leaves the AST alone.
    refused, refused_assignment = _subview_read_fixture()
    del refused._inertia_stack_memory_ssa_alias_artifact
    del refused._inertia_stack_memory_object_widening_artifact
    assert stack_subview_projection_probe_8616(refused) is not None
    assert overlay_materialize_subviews(refused) is False
    assert refused_assignment.rhs.variable.name == "byte_view"


def test_probe_does_not_modify_codegen_metadata_when_applicable() -> None:
    codegen, _ = _normalized_flat_fixture()
    before_meta = dict(_codegen_metadata(codegen))
    # Force a changeable AST through a copy that still leaves no metadata.
    source = _stack_var(-8, 2, "extra_source", codegen)
    carrier = _reg_var(6, "v_extra", codegen)
    output = _reg_var(0, "ax", codegen)
    codegen.cfunc.statements.statements.append(
        CAssignment(carrier, source, codegen=codegen)
    )
    codegen.cfunc.statements.statements.append(CAssignment(output, carrier, codegen=codegen))

    assert widening_subview_copyprop_applicable_8616(codegen) is True
    assert _codegen_metadata(codegen) == before_meta


def test_wired_spec_invokes_probe_callback() -> None:
    spec = next(
        item for item in _build_decompiler_structuring_passes()
        if item.name == "_widening_copy_propagation_8616"
    )
    assert spec.name == "_widening_copy_propagation_8616"
    assert spec.func is _run_structuring_widening_copy_propagation_8616
    assert spec.needs_project is False
    assert spec.applicable is not None

    applicable_codegen, _ = _normalized_flat_fixture()
    # Validation preparation may introduce new propagation opportunities.
    assert spec.applicable(applicable_codegen) is True
    applicable_codegen._inertia_structuring_validation_semantics_primed = True
    assert spec.applicable(applicable_codegen) is False

    codegen = _DummyCodegen()
    source = _stack_var(-4, 2, "source", codegen)
    carrier = _reg_var(6, "v72", codegen)
    output = _reg_var(0, "ax", codegen)
    root = CStatements(
        [CAssignment(carrier, source, codegen=codegen), CAssignment(output, carrier, codegen=codegen)],
        addr=FUNCTION_ADDR,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=FUNCTION_ADDR, statements=root, body=root)
    assert spec.applicable(codegen) is True


def _width_counter_fixture(counter):
    cg = _DummyCodegen()
    lhs = _reg_var(0, "ax", cg)
    rhs = _stack_var(-1, 1, "byte", cg)
    root = CStatements([CAssignment(lhs, rhs, codegen=cg)], codegen=cg)
    cg.cfunc = SimpleNamespace(statements=root, body=root)
    cg.widening_copyprop_width_mismatch_refused_8616 = counter
    return cg


@pytest.mark.parametrize("counter", [None, "4"])
def test_probe_preserves_width_counter_error(counter):
    real = _width_counter_fixture(counter)
    with pytest.raises(TypeError):
        _run_structuring_widening_copy_propagation_8616(real)
    probed = _width_counter_fixture(counter)
    with pytest.raises(TypeError):
        assert widening_subview_copyprop_applicable_8616(probed) is True
        _run_structuring_widening_copy_propagation_8616(probed)


def test_probe_preserves_width_counter_number():
    real = _width_counter_fixture(2.5)
    assert _run_structuring_widening_copy_propagation_8616(real) is False
    probed = _width_counter_fixture(2.5)
    assert widening_subview_copyprop_applicable_8616(probed) is True
    assert _run_structuring_widening_copy_propagation_8616(probed) is False
    assert probed.widening_copyprop_width_mismatch_refused_8616 == real.widening_copyprop_width_mismatch_refused_8616
