"""GP capture value proof controls independent of display names and cached writers."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimTemporaryVariable

from inertia.lowering.gp_register_state import lower_architectural_gp_register_state_8616
from inertia.validation.gp_capture_values import resolve_gp_capture_constant_8616
from inertia.validation.tail_validation import X86_16TailValidationSummary, compare_x86_16_tail_validation_summaries
from inertia.validation.tail_validation_fingerprint import _expr_fingerprint, _location_fingerprint
from tests.lowering.test_x86_16_gp_register_versions import _fixture


def _captured(value=5):
    codegen, returned, _types = _fixture("ax")
    codegen.cfunc.statements.statements[0].rhs.value = value
    assert lower_architectural_gp_register_state_8616(codegen)
    return codegen, returned.retval, codegen.cfunc.statements.statements[0]


@pytest.mark.parametrize("value,op,mask", [(5, "And", 7), (9, "Shl", 3)])
def test_real_capture_preserves_exposed_bitfield_value(value, op, mask):
    codegen, temporary, definition = _captured(value)
    raw = CBinaryOp(op, CConstant(value, temporary.type, codegen=codegen),
                    CConstant(mask, temporary.type, codegen=codegen), codegen=codegen)
    captured = CBinaryOp(op, temporary, CConstant(mask, temporary.type, codegen=codegen), codegen=codegen)
    codegen.cfunc.statements.statements[-1] = CReturn(captured, codegen=codegen)
    before = X86_16TailValidationSummary((), (), (), (), (), (), (), (),
        exposed_stack_values=("stack_slot:SS:BP-0xe:size1=" + _expr_fingerprint(raw, codegen.project),))
    after = X86_16TailValidationSummary((), (), (), (), (), (), (), (),
        exposed_stack_values=("stack_slot:SS:BP-0xe:size1=" + _expr_fingerprint(captured, codegen.project),))
    assert compare_x86_16_tail_validation_summaries(before, after)["changed"] is False
    assert _location_fingerprint(temporary, codegen.project) == "virtual:tmp_0"
    assert definition.lhs is temporary


def test_changed_capture_constant_remains_mismatch():
    codegen, temporary, _definition = _captured(6)
    assert _expr_fingerprint(temporary, codegen.project) == "const:6"
    baseline = X86_16TailValidationSummary((), (), (), (), (), (), (), (),
        exposed_stack_values=("stack_slot:SS:BP-0xe:size1=const:5",))
    candidate = X86_16TailValidationSummary((), (), (), (), (), (), (), (),
        exposed_stack_values=("stack_slot:SS:BP-0xe:size1=" + _expr_fingerprint(temporary, codegen.project),))
    assert compare_x86_16_tail_validation_summaries(baseline, candidate)["changed"] is True


@pytest.mark.parametrize("damage", ["missing", "duplicate", "before", "conditional", "mutable", "effectful", "untagged", "collision", "escape", "cycle", "overflow"])
def test_current_capture_corruption_refuses(damage):
    codegen, temporary, definition = _captured()
    root = codegen.cfunc.statements
    assert resolve_gp_capture_constant_8616(temporary) is definition.rhs
    if damage == "missing":
        root.statements.remove(definition)
    elif damage == "duplicate":
        root.statements.insert(1, CAssignment(temporary, definition.rhs, codegen=codegen))
    elif damage == "before":
        root.statements.insert(0, CReturn(temporary, codegen=codegen))
    elif damage == "conditional":
        root.statements[0] = CIfElse([(CConstant(1, temporary.type, codegen=codegen),
            CStatements([definition], codegen=codegen))], None, codegen=codegen)
    elif damage == "collision":
        other = CVariable(SimTemporaryVariable(temporary.variable.tmp_id, temporary.variable.size),
                          variable_type=temporary.type, codegen=codegen)
        root.statements.append(CReturn(other, codegen=codegen))
    elif damage == "escape":
        root.statements.append(CReturn(CUnaryOp("Reference", temporary, codegen=codegen), codegen=codegen))
    elif damage == "cycle":
        root.statements.append(root)
    else:
        _damage_definition(damage, codegen, temporary, definition)
    codegen._inertia_assignment_maps = ({id(temporary.variable): CConstant(5, temporary.type, codegen=codegen)}, {}, {}, {}, {}, {}, {}, {})
    assert resolve_gp_capture_constant_8616(temporary) is None


def test_unowned_named_temporary_never_borrows_writer():
    codegen, temporary, definition = _captured()
    definition.tags.clear()
    temporary.variable.name = "v42"
    codegen._inertia_assignment_maps = ({}, {"v42": definition.rhs}, {}, {}, {}, {}, {"v42": definition.rhs}, {})
    assert resolve_gp_capture_constant_8616(temporary) is None
    assert _expr_fingerprint(temporary, codegen.project) == "virtual:tmp_0"


def test_capture_definition_can_dominate_nested_reads():
    codegen, temporary, definition = _captured()
    root = codegen.cfunc.statements
    root.statements[-1] = CIfElse([(CConstant(1, temporary.type, codegen=codegen),
        CStatements([root.statements[-1]], codegen=codegen))], None, codegen=codegen)
    assert resolve_gp_capture_constant_8616(temporary) is definition.rhs


def _damage_definition(damage, codegen, temporary, definition):
    if damage == "mutable":
        definition.rhs = codegen.cfunc.statements.statements[2].lhs
    elif damage == "effectful":
        definition.rhs = CFunctionCall("opaque", None, [], codegen=codegen)
    elif damage == "untagged":
        definition.tags.clear()
    elif damage == "overflow":
        definition.rhs.value = 1 << (temporary.variable.size * 8)


@pytest.mark.parametrize("kind", ["untagged", "nonliteral", "missing"])
def test_irrelevant_temporary_does_not_census_expression_tree(monkeypatch, kind):
    import inertia.validation.gp_capture_values as owner

    codegen, temporary, definition = _captured()
    if kind == "untagged":
        definition.tags.clear()
    elif kind == "nonliteral":
        definition.rhs = temporary
    else:
        codegen.cfunc.statements.statements.remove(definition)

    def unexpected_census(_root):
        pytest.fail("noncandidate temporary entered full expression census")

    monkeypatch.setattr(owner, "_occurrences", unexpected_census)
    assert owner.resolve_gp_capture_constant_8616(temporary) is None


@pytest.mark.parametrize("masked,value", [(False, 5), (True, 9), (False, 6)])
def test_capture_exact_unsigned_byte_conversion(masked, value):
    from angr.sim_type import SimTypeChar, SimTypeShort

    codegen, temporary, definition = _captured()
    byte = SimTypeChar(signed=False).with_arch(codegen.project.arch)
    word = SimTypeShort(signed=False).with_arch(codegen.project.arch)
    temporary.variable_type = byte
    definition.rhs = CConstant(value, word, codegen=codegen)
    if masked:
        definition.rhs = CBinaryOp("And", definition.rhs, CConstant(31, word, codegen=codegen), codegen=codegen)
    result = resolve_gp_capture_constant_8616(temporary)
    assert result is not None
    assert result.value == value
    assert result.type == byte
    assert _expr_fingerprint(temporary, codegen.project) == f"const:{value}"
    assert (_expr_fingerprint(temporary, codegen.project) == "const:5") is (value == 5)


@pytest.mark.parametrize("damage", ["unsigned_truncation", "signed_overflow", "invalid_literal", "shift", "arithmetic", "negative_bitwise", "expression_budget"])
def test_constant_conversion_refuses_undefined_or_unproved_operations(damage):
    from angr.sim_type import SimTypeChar, SimTypeShort

    codegen, temporary, definition = _captured()
    byte = SimTypeChar(signed=damage == "signed_overflow").with_arch(codegen.project.arch)
    word = SimTypeShort(signed=damage == "negative_bitwise").with_arch(codegen.project.arch)
    temporary.variable_type = byte
    values = {"unsigned_truncation": 256, "signed_overflow": 128, "invalid_literal": 65536}
    definition.rhs = CConstant(values.get(damage, 5), word, codegen=codegen)
    if damage in {"shift", "arithmetic", "negative_bitwise"}:
        op = {"shift": "Shl", "arithmetic": "Add", "negative_bitwise": "And"}[damage]
        definition.rhs = CBinaryOp(op, CConstant(-1 if damage == "negative_bitwise" else 5, word, codegen=codegen),
                                    CConstant(31, word, codegen=codegen), codegen=codegen)
    elif damage == "expression_budget":
        for _ in range(40):
            definition.rhs = CBinaryOp("And", definition.rhs, CConstant(31, word, codegen=codegen), codegen=codegen)
    assert resolve_gp_capture_constant_8616(temporary) is None


def test_bitwise_negation_read_does_not_invalidate_capture():
    codegen, temporary, definition = _captured(9)
    codegen.cfunc.statements.statements.append(
        CReturn(CUnaryOp("BitwiseNeg", temporary, codegen=codegen), codegen=codegen))
    assert resolve_gp_capture_constant_8616(temporary) is definition.rhs


@pytest.mark.parametrize("value,op,mask,expected", [(5, "And", 7, 5), (9, "Shl", 3, 72), (6, "And", 7, 5)])
def test_captured_bitfield_matches_actual_folded_baseline(value, op, mask, expected):
    from angr.sim_type import SimTypeChar, SimTypeShort

    codegen, temporary, definition = _captured(value)
    temporary.variable_type = SimTypeChar(signed=False).with_arch(codegen.project.arch)
    word = SimTypeShort(signed=False).with_arch(codegen.project.arch)
    definition.rhs = CConstant(value, word, codegen=codegen)
    expression = CBinaryOp(op, temporary, CConstant(mask, word, codegen=codegen), codegen=codegen)
    codegen.cfunc.statements.statements[-1] = CReturn(expression, codegen=codegen)
    baseline = X86_16TailValidationSummary((), (), (), (), (), (), (), (),
        exposed_stack_values=(f"stack_slot:SS:BP-0xe:size1=const:{expected}",))
    after = X86_16TailValidationSummary((), (), (), (), (), (), (), (),
        exposed_stack_values=("stack_slot:SS:BP-0xe:size1=" + _expr_fingerprint(expression, codegen.project),))
    assert compare_x86_16_tail_validation_summaries(baseline, after)["changed"] is (value == 6)


@pytest.mark.parametrize("left,count,signed", [(9, -1, False), (9, 16, False), (255, 8, False), (-1, 1, True), (9, 3, True)])
def test_shift_proof_refuses_promotion_and_domain_hazards(left, count, signed):
    from angr.sim_type import SimTypeShort

    from inertia.validation.typed_constant_values import constant_integer_value_8616

    codegen, _temporary, _definition = _captured()
    word = SimTypeShort(signed=signed).with_arch(codegen.project.arch)
    expr = CBinaryOp("Shl", CConstant(left, word, codegen=codegen),
                     CConstant(count, word, codegen=codegen), codegen=codegen)
    assert constant_integer_value_8616(expr) is None
