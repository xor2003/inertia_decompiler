from __future__ import annotations

from types import SimpleNamespace

import archinfo
import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimStruct, SimTypeArray, SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimTemporaryVariable
from angr_platforms.X86_16.lowering.gp_register_state import runtime_gp_state_expr_8616
from angr_platforms.X86_16.postprocess.optimization.dce import _dead_code_elimination_8616
from angr_platforms.X86_16.postprocess.optimization.dce_local_array_reads import is_pure_local_array_read_8616
from angr_platforms.X86_16.postprocess.optimization.dce_value_identity import assignment_reads_destination_8616


class _Codegen(SimpleNamespace):
    """Minimal dynamic angr codegen boundary for focused DCE tests."""

    def __init__(self) -> None:
        super().__init__()
        self._next = 0
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        """Return one stable synthetic node index."""
        self._next += 1
        return self._next

    def next_node_idx(self) -> int:
        """Return one stable synthetic AST node index."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Keep requested identifiers stable in the synthetic AST."""
        return name


def _variable(codegen: _Codegen, name: str, reg: int) -> structured_c.CVariable:
    """Build one local register carrier at the dynamic angr boundary."""
    return structured_c.CVariable(
        SimRegisterVariable(reg, 2, name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


@pytest.mark.parametrize("unary_op", ("LogicalNot", "BitwiseNegate"))
def test_dce_deletes_unread_pure_angr_unary_carrier(unary_op: str) -> None:
    codegen = _Codegen()
    source = _variable(codegen, "flags_in", 36)
    result = _variable(codegen, "ir_flags_out", 38)
    rhs = structured_c.CUnaryOp(unary_op, source, codegen=codegen)
    assignment = structured_c.CAssignment(result, rhs, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([assignment], codegen=codegen),
    )

    assert _dead_code_elimination_8616(codegen) is True
    assert codegen.cfunc.statements.statements == []
    assert codegen.dce_deleted == 1


@pytest.mark.parametrize("indirect", (False, True))
@pytest.mark.parametrize("aggregate", (False, True))
@pytest.mark.parametrize("live", (False, True))
def test_dce_local_aggregate_field_requires_value_not_pointer(
    indirect: bool, aggregate: bool, live: bool,
) -> None:
    codegen = _Codegen()
    layout = SimStruct({"byte": SimTypeChar(False)}, name="entry")
    local = structured_c.CVariable(
        SimStackVariable(-4, 1, base="bp", name="local_entry"),
        variable_type=layout if aggregate else SimTypeShort(False), codegen=codegen,
    )
    field = structured_c.CStructField(layout, 0, "byte", codegen=codegen)
    rhs = structured_c.CVariableField(local, field, var_is_ptr=indirect, codegen=codegen)
    result = _variable(codegen, "tmp_field", 38)
    assignment = structured_c.CAssignment(result, rhs, codegen=codegen)
    statements = [assignment]
    if live:
        statements.append(structured_c.CReturn(result, codegen=codegen))
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(statements, codegen=codegen),
    )

    removable = aggregate and not indirect and not live
    assert _dead_code_elimination_8616(codegen) is removable
    assert codegen.cfunc.statements.statements == ([] if removable else statements)


def test_dce_deletes_unread_flag_equation_over_angr_temporaries() -> None:
    codegen = _Codegen()
    low = structured_c.CVariable(
        SimTemporaryVariable(49, 16),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    high = structured_c.CVariable(
        SimTemporaryVariable(60, 16),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    one = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
    two = structured_c.CConstant(2, SimTypeShort(False), codegen=codegen)
    shifted = structured_c.CBinaryOp("Shl", low, one, codegen=codegen)
    mixed = structured_c.CBinaryOp("Xor", shifted, high, codegen=codegen)
    negated = structured_c.CUnaryOp("BitwiseNeg", mixed, codegen=codegen)
    parity_bit = structured_c.CBinaryOp("And", negated, one, codegen=codegen)
    rhs = structured_c.CBinaryOp("Shl", parity_bit, two, codegen=codegen)
    result = _variable(codegen, "tmp_78", 38)
    assignment = structured_c.CAssignment(result, rhs, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements([assignment], codegen=codegen),
    )

    assert _dead_code_elimination_8616(codegen) is True
    assert codegen.cfunc.statements.statements == []
    assert codegen.dce_deleted == 1


@pytest.mark.parametrize("offset_kind", ("constant", "register", "runtime", "call", "global"))
@pytest.mark.parametrize("array", (False, True))
@pytest.mark.parametrize("live", (False, True))
def test_dce_local_array_read_requires_array_and_effect_free_offset(offset_kind, array, live):
    codegen = _Codegen()
    word = SimTypeShort(False)
    pointer = SimTypePointer(SimTypeChar(False))
    storage_type = SimTypeArray(word, 8) if array else pointer
    base = structured_c.CVariable(
        SimStackVariable(-16, 16, base="bp", name="local_array"),
        variable_type=storage_type, codegen=codegen,
    )
    offset = structured_c.CConstant(1, word, codegen=codegen)
    if offset_kind == "register":
        offset = _variable(codegen, "index", 36)
    elif offset_kind == "runtime":
        offset = runtime_gp_state_expr_8616("si", codegen=codegen, function_addr=0x1000)
    elif offset_kind == "call":
        offset = structured_c.CFunctionCall("next_index", None, [], codegen=codegen)
    elif offset_kind == "global":
        offset = structured_c.CVariable(
            SimMemoryVariable(0x100, 2, name="global_index"), variable_type=word, codegen=codegen,
        )
    address = structured_c.CBinaryOp(
        "Add", structured_c.CTypeCast(storage_type, pointer, base, codegen=codegen),
        offset, codegen=codegen,
    )
    rhs = structured_c.CUnaryOp("Dereference", address, codegen=codegen)
    result = _variable(codegen, "tmp_array_read", 38)
    assignment = structured_c.CAssignment(result, rhs, codegen=codegen)
    statements = [assignment]
    if live:
        statements.append(structured_c.CReturn(result, codegen=codegen))
    codegen.cfunc = SimpleNamespace(statements=structured_c.CStatements(statements, codegen=codegen))

    removable = array and offset_kind in {"constant", "register", "runtime"} and not live
    assert _dead_code_elimination_8616(codegen) is removable
    assert codegen.cfunc.statements.statements == ([] if removable else statements)


def test_local_array_read_classifier_refuses_cyclic_address():
    codegen = _Codegen()
    one = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
    address = structured_c.CBinaryOp("Add", one, one, codegen=codegen)
    address.lhs = address
    read = structured_c.CUnaryOp("Dereference", address, codegen=codegen)

    assert is_pure_local_array_read_8616(read) is False


@pytest.mark.parametrize("same_version", (False, True))
def test_dce_preserves_consecutive_live_register_decrements(same_version):
    codegen = _Codegen()
    source = _variable(codegen, "input_value", 0)
    first = _variable(codegen, "first_value", 0)
    second = first if same_version else _variable(codegen, "second_value", 0)
    one = structured_c.CConstant(1, SimTypeShort(False), codegen=codegen)
    first_rhs = structured_c.CBinaryOp("Sub", source if not same_version else first, one, codegen=codegen)
    second_rhs = structured_c.CBinaryOp("Sub", first, one, codegen=codegen)
    assignments = [
        structured_c.CAssignment(first, first_rhs, codegen=codegen),
        structured_c.CAssignment(second, second_rhs, codegen=codegen),
    ]
    ret = structured_c.CReturn(second, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=structured_c.CStatements([*assignments, ret], codegen=codegen))

    assert _dead_code_elimination_8616(codegen) is False
    assert codegen.cfunc.statements.statements == [*assignments, ret]


def test_dce_preserves_live_copy_between_versions_of_one_register():
    codegen = _Codegen()
    source = _variable(codegen, "input_value", 0)
    result = _variable(codegen, "copied_value", 0)
    assignment = structured_c.CAssignment(result, source, codegen=codegen)
    ret = structured_c.CReturn(result, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=structured_c.CStatements([assignment, ret], codegen=codegen))

    assert _dead_code_elimination_8616(codegen) is False
    assert codegen.cfunc.statements.statements == [assignment, ret]


@pytest.mark.parametrize(("offset", "overlap"), ((-8, True), (-6, True), (-4, False)))
def test_duplicate_assignment_dependency_preserves_stack_overlap(offset, overlap):
    codegen = _Codegen()
    destination = structured_c.CVariable(SimStackVariable(-8, 4, base="bp"), codegen=codegen)
    source = structured_c.CVariable(SimStackVariable(offset, 2, base="bp"), codegen=codegen)

    assert assignment_reads_destination_8616(destination, source) is overlap


def test_dce_does_not_deduplicate_different_rhs_register_versions():
    codegen = _Codegen()
    destination = structured_c.CVariable(SimStackVariable(-2, 2, base="bp", name="local"), codegen=codegen)
    first = structured_c.CAssignment(destination, _variable(codegen, "first_value", 0), codegen=codegen)
    second = structured_c.CAssignment(destination, _variable(codegen, "second_value", 0), codegen=codegen)
    ret = structured_c.CReturn(destination, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=structured_c.CStatements([first, second, ret], codegen=codegen))

    _dead_code_elimination_8616(codegen)

    assert second in codegen.cfunc.statements.statements
    assert codegen.dce_duplicate_assignment_deleted == 0
