from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimStruct, SimTypeChar, SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from inertia.postprocess.decompiler_postprocess_stage import (
    _dead_code_elimination_after_flag_prune_8616,
    _dead_code_elimination_final_cleanup_8616,
    _postprocess_runtime_config_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)

from inertia.postprocess.optimization.dce import (
    _dead_code_elimination_8616,
)


class _FakeCodegen(SimpleNamespace):
    def __init__(self):
        super().__init__()
        self._next = 0
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        self._next += 1
        return self._next
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _mk_codegen_with_statements(statements):
    codegen = _FakeCodegen()
    codegen.cfunc = SimpleNamespace()
    codegen.cfunc.statements = structured_c.CStatements(list(statements), codegen=codegen)
    return codegen


def _mk_cvar(codegen, name: str, reg: int = 0):
    return structured_c.CVariable(
        SimRegisterVariable(reg, 2, name=name),
        codegen=codegen,
    )


def _const(codegen, value: int = 1):
    return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)


def test_dce_deletes_unread_plain_temp_assignment():
    codegen = _mk_codegen_with_statements([])
    tmp = _mk_cvar(codegen, "tmp_1", 0)
    stmt = structured_c.CAssignment(tmp, _const(codegen, 7), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_deleted", 0) == 1


def test_dce_deletes_unread_wide_multiply_temp_assignment():
    codegen = _mk_codegen_with_statements([])
    tmp = _mk_cvar(codegen, "tmp_wide", 0)
    rhs = structured_c.CBinaryOp("Mull", _const(codegen, 60), _const(codegen, 3), codegen=codegen)
    stmt = structured_c.CAssignment(tmp, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert codegen.dce_deleted == 1


def test_dce_refuses_unread_temp_assignment_from_dereference():
    codegen = _mk_codegen_with_statements([])
    tmp = _mk_cvar(codegen, "tmp_1", 0)
    ptr = _mk_cvar(codegen, "tmp_ptr", 2)
    deref = structured_c.CUnaryOp("Dereference", ptr, codegen=codegen)
    stmt = structured_c.CAssignment(tmp, deref, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_deleted", 0) == 0
    assert getattr(codegen, "dce_keep_unknown", 0) == 1


def test_dce_refuses_cyclic_unread_expression_without_recursing():
    codegen = _mk_codegen_with_statements([])
    tmp = _mk_cvar(codegen, "tmp_1", 0)
    rhs = structured_c.CBinaryOp("Add", _const(codegen, 1), _const(codegen, 2), codegen=codegen)
    rhs.lhs = rhs
    stmt = structured_c.CAssignment(tmp, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_deleted", 0) == 0
    assert getattr(codegen, "dce_keep_unknown", 0) == 1


def test_dce_deletes_unread_temp_assignment_from_indexed_global_read():
    codegen = _mk_codegen_with_statements([])
    tmp = _mk_cvar(codegen, "tmp_1", 0)
    index = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    base = structured_c.CVariable(
        SimMemoryVariable(0x44, 2, name="g_work"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    rhs = structured_c.CIndexedVariable(base, index, variable_type=SimTypeShort(False), codegen=codegen)
    stmt = structured_c.CAssignment(tmp, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_dead_memory_read_candidates", 0) == 1
    assert getattr(codegen, "dce_dead_memory_read_deleted", 0) == 1


def test_terminal_dce_deletes_consumed_wide_call_setup_chain() -> None:
    codegen = _mk_codegen_with_statements([])
    low_byte = structured_c.CVariable(
        SimMemoryVariable(0x0BA8, 1, name="mem_0BA8"),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    high_byte = structured_c.CVariable(
        SimMemoryVariable(0x0BA9, 1, name="mem_0BA9"),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    low_carrier = _mk_cvar(codegen, "ir_12", 0)
    high_carrier = _mk_cvar(codegen, "ir_13", 2)
    result = _mk_cvar(codegen, "ir_14", 4)
    flags = structured_c.CDirtyExpression(
        SimpleNamespace(varid=20, idx=20, name="flags_20", bits=16),
        codegen=codegen,
    )
    wide_word = structured_c.CBinaryOp(
        "Or",
        low_carrier,
        structured_c.CBinaryOp("Shl", high_carrier, _const(codegen, 8), codegen=codegen),
        codegen=codegen,
    )
    rhs = structured_c.CBinaryOp(
        "Sub",
        wide_word,
        structured_c.CBinaryOp("And", flags, _const(codegen, 1), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [
            structured_c.CAssignment(low_carrier, low_byte, codegen=codegen),
            structured_c.CAssignment(high_carrier, high_byte, codegen=codegen),
            structured_c.CAssignment(result, rhs, tags={"ins_addr": 0x104D4}, codegen=codegen),
        ],
        codegen=codegen,
    )

    changed = _dead_code_elimination_final_cleanup_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_dead_memory_read_deleted", 0) == 2
    assert not hasattr(codegen, "_inertia_dce_allow_storage_free_dirty_8616")
    assert not hasattr(codegen, "_inertia_dce_allow_dirty_value_reads_8616")


def test_dce_deletes_unread_temp_assignment_from_indexed_global_field_read():
    codegen = _mk_codegen_with_statements([])
    tmp = _mk_cvar(codegen, "tmp_1", 0)
    index = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    struct_type = SimStruct({"field_0": SimTypeChar(False)}, name="work_entry")
    base = structured_c.CVariable(
        SimMemoryVariable(0x44, 2, name="g_work"),
        variable_type=struct_type,
        codegen=codegen,
    )
    indexed = structured_c.CIndexedVariable(base, index, variable_type=struct_type, codegen=codegen)
    field = structured_c.CStructField(struct_type, 0, "field_0", codegen=codegen)
    rhs = structured_c.CVariableField(indexed, field, var_is_ptr=False, codegen=codegen)
    stmt = structured_c.CAssignment(tmp, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_dead_memory_read_candidates", 0) == 1
    assert getattr(codegen, "dce_dead_memory_read_deleted", 0) == 1


def test_dce_deletes_unread_temp_assignment_from_direct_global_address_read():
    codegen = _mk_codegen_with_statements([])
    tmp = _mk_cvar(codegen, "tmp_1", 0)
    index = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    base = structured_c.CVariable(
        SimMemoryVariable(0x42, 1, name="mem_0042"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    address = structured_c.CBinaryOp(
        "Add",
        structured_c.CUnaryOp("Reference", base, codegen=codegen),
        structured_c.CBinaryOp("Mul", index, _const(codegen, 2), codegen=codegen),
        codegen=codegen,
    )
    rhs = structured_c.CUnaryOp("Dereference", address, codegen=codegen)
    stmt = structured_c.CAssignment(tmp, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_dead_memory_read_candidates", 0) == 1
    assert getattr(codegen, "dce_dead_memory_read_deleted", 0) == 1


def test_dce_keeps_direct_global_memory_assignment_with_call_rhs():
    codegen = _mk_codegen_with_statements([])
    lhs = structured_c.CVariable(
        SimMemoryVariable(0xB48, 4, name="clFinish", region=0x4010),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    rhs = structured_c.CFunctionCall("clock", None, [], codegen=codegen)
    stmt = structured_c.CAssignment(lhs, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_deleted", 0) == 0


def test_dce_preserves_effectful_call_when_dropping_unused_temp_result_declaration():
    codegen = _mk_codegen_with_statements([])
    tmp_var = SimRegisterVariable(0, 2, name="vvar_21")
    tmp = structured_c.CVariable(tmp_var, variable_type=SimTypeShort(False), codegen=codegen)
    arg = _mk_cvar(codegen, "arg_1", 2)
    call = structured_c.CFunctionCall("outtext", None, [arg], codegen=codegen)
    stmt = structured_c.CAssignment(tmp, call, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)
    codegen.cfunc.variables_in_use = {tmp_var: tmp}
    codegen.cfunc.unified_local_vars = {tmp_var: {(tmp, SimTypeShort(False))}}

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    statements = list(codegen.cfunc.statements.statements)
    assert len(statements) == 1
    assert isinstance(statements[0], structured_c.CExpressionStatement)
    assert statements[0].expr is call
    assert getattr(codegen, "dce_deleted", 0) == 1
    assert codegen.cfunc.variables_in_use == {}
    assert codegen.cfunc.unified_local_vars == {}


def test_dce_deletes_unread_local_assignment_from_pure_global_address():
    codegen = _mk_codegen_with_statements([])
    local = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_0", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    global_var = structured_c.CVariable(
        SimMemoryVariable(0x42, 2, name="v0"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    rhs = structured_c.CUnaryOp("Reference", global_var, codegen=codegen)
    stmt = structured_c.CAssignment(local, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_deleted", 0) == 1


def test_dce_keeps_evidenced_direct_stack_update_but_deletes_later_dead_overwrite():
    codegen = _mk_codegen_with_statements([])
    local = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    update = structured_c.CAssignment(
        local,
        structured_c.CBinaryOp("Add", local, _const(codegen, 1), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4018},
    )
    dead_overwrite = structured_c.CAssignment(
        local,
        _const(codegen, 7),
        codegen=codegen,
        tags={"ins_addr": 0x4020},
    )
    codegen._inertia_direct_stack_update_evidence_8616 = (
        (
            ("offset", -2),
            ("width", 2),
            ("delta", 1),
            ("ins_addr", 0x4018),
        ),
    )
    codegen.cfunc.statements = structured_c.CStatements([update, dead_overwrite], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [update]
    assert getattr(codegen, "dce_deleted", 0) == 1
    assert getattr(codegen, "dce_keep_protected", 0) >= 1


def test_dce_keeps_stack_local_read_only_by_nested_loop_body():
    codegen = _mk_codegen_with_statements([])
    local = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="iLength", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    global_value = structured_c.CVariable(
        SimMemoryVariable(0xB4C, 2, name="abarWork"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    loop_guard = structured_c.CBinaryOp("CmpNE", _mk_cvar(codegen, "tmp_guard", 4), _const(codegen, 0), codegen=codegen)
    nested_read = structured_c.CIfBreak(
        structured_c.CBinaryOp("CmpLE", global_value, local, codegen=codegen),
        codegen=codegen,
    )
    loop = structured_c.CForLoop(
        None,
        loop_guard,
        None,
        structured_c.CStatements([nested_read], codegen=codegen),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(local, _const(codegen, 7), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt, loop], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt, loop]
    assert getattr(codegen, "dce_deleted", 0) == 0


def test_dce_deletes_standalone_pure_mkfp_dereference_expression():
    codegen = _mk_codegen_with_statements([])
    seg = _mk_cvar(codegen, "tmp_seg", 0)
    off = _mk_cvar(codegen, "tmp_off", 2)
    addr = structured_c.CFunctionCall("MK_FP", None, [seg, _const(codegen, 0)], codegen=codegen)
    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp("Add", addr, off, codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([deref], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_pure_expression_candidates", 0) == 1
    assert getattr(codegen, "dce_pure_expression_deleted", 0) == 1


def test_dce_deletes_wrapped_standalone_pure_mkfp_dereference_expression():
    codegen = _mk_codegen_with_statements([])
    seg = _mk_cvar(codegen, "tmp_seg", 0)
    off = _mk_cvar(codegen, "tmp_off", 2)
    addr = structured_c.CFunctionCall("MK_FP", None, [seg, _const(codegen, 0)], codegen=codegen)
    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp("Add", addr, off, codegen=codegen),
        codegen=codegen,
    )
    stmt = structured_c.CExpressionStatement(deref, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_pure_expression_candidates", 0) == 1
    assert getattr(codegen, "dce_pure_expression_deleted", 0) == 1


def test_dce_deletes_pure_mkfp_carrier_chain_to_fixed_point():
    codegen = _mk_codegen_with_statements([])
    seg_source = _mk_cvar(codegen, "vvar_55", 55)
    off_left = _mk_cvar(codegen, "vvar_706", 706)
    off_right = _mk_cvar(codegen, "vvar_707", 707)
    seg_carrier = _mk_cvar(codegen, "vvar_714", 714)
    off_carrier = _mk_cvar(codegen, "vvar_715", 715)
    assign_seg = structured_c.CAssignment(seg_carrier, seg_source, codegen=codegen)
    assign_off = structured_c.CAssignment(
        off_carrier,
        structured_c.CBinaryOp("Add", off_left, off_right, codegen=codegen),
        codegen=codegen,
    )
    addr = structured_c.CFunctionCall("MK_FP", None, [seg_carrier, _const(codegen, 0)], codegen=codegen)
    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp("Add", addr, off_carrier, codegen=codegen),
        codegen=codegen,
    )
    stmt = structured_c.CExpressionStatement(deref, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([assign_seg, assign_off, stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_pure_expression_candidates", 0) == 1
    assert getattr(codegen, "dce_pure_expression_deleted", 0) == 1
    assert getattr(codegen, "dce_deleted", 0) == 3


def test_dce_deletes_standalone_pure_mkfp_call_expression():
    codegen = _mk_codegen_with_statements([])
    seg = _mk_cvar(codegen, "tmp_seg", 0)
    off = _mk_cvar(codegen, "tmp_off", 2)
    call = structured_c.CFunctionCall("MK_FP", None, [seg, off], codegen=codegen)
    stmt = structured_c.CExpressionStatement(call, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_pure_expression_candidates", 0) == 1
    assert getattr(codegen, "dce_pure_expression_deleted", 0) == 1


def test_dce_deletes_pure_mkfp_call_carrier_chain_to_fixed_point():
    codegen = _mk_codegen_with_statements([])
    seg_source = _mk_cvar(codegen, "vvar_55", 55)
    off_left = _mk_cvar(codegen, "vvar_706", 706)
    off_right = _mk_cvar(codegen, "vvar_707", 707)
    seg_carrier = _mk_cvar(codegen, "vvar_711", 711)
    off_carrier = _mk_cvar(codegen, "vvar_708", 708)
    assign_seg = structured_c.CAssignment(seg_carrier, seg_source, codegen=codegen)
    assign_off = structured_c.CAssignment(
        off_carrier,
        structured_c.CBinaryOp("Add", off_left, off_right, codegen=codegen),
        codegen=codegen,
    )
    call = structured_c.CFunctionCall("MK_FP", None, [seg_carrier, off_carrier], codegen=codegen)
    stmt = structured_c.CExpressionStatement(call, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([assign_seg, assign_off, stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_pure_expression_candidates", 0) == 1
    assert getattr(codegen, "dce_pure_expression_deleted", 0) == 1
    assert getattr(codegen, "dce_deleted", 0) == 3


def test_dce_deletes_unused_dirty_address_helper_sink_to_fixed_point():
    codegen = _mk_codegen_with_statements([])
    codegen._inertia_dce_allow_storage_free_dirty_8616 = True
    codegen._inertia_dce_allow_dirty_value_reads_8616 = True
    seg_source = _mk_cvar(codegen, "vvar_55", 55)
    off_left = _mk_cvar(codegen, "vvar_706", 706)
    off_right = _mk_cvar(codegen, "vvar_707", 707)
    seg_carrier = _mk_cvar(codegen, "vvar_714", 714)
    off_carrier = _mk_cvar(codegen, "vvar_715", 715)
    addr_carrier = structured_c.CDirtyExpression(
        SimpleNamespace(varid=716, idx=716, name="vvar_716", reg_offset=0, bits=16),
        codegen=codegen,
    )
    value_carrier = structured_c.CDirtyExpression(
        SimpleNamespace(varid=717, idx=717, name="vvar_717", reg_offset=2, bits=16),
        codegen=codegen,
    )
    assign_seg = structured_c.CAssignment(seg_carrier, seg_source, codegen=codegen)
    assign_off = structured_c.CAssignment(
        off_carrier,
        structured_c.CBinaryOp("Add", off_left, off_right, codegen=codegen),
        codegen=codegen,
    )
    assign_addr = structured_c.CAssignment(
        addr_carrier,
        structured_c.CFunctionCall("MK_FP", None, [seg_carrier, _const(codegen, 0)], codegen=codegen),
        codegen=codegen,
    )
    assign_value = structured_c.CAssignment(
        value_carrier,
        structured_c.CUnaryOp(
            "Dereference",
            structured_c.CBinaryOp("Add", addr_carrier, off_carrier, codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [assign_seg, assign_off, assign_addr, assign_value],
        codegen=codegen,
    )

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_dirty_value_deleted", 0) >= 2
    assert getattr(codegen, "dce_deleted", 0) == 4


def test_dce_refuses_standalone_unknown_call_dereference_expression():
    codegen = _mk_codegen_with_statements([])
    seg = _mk_cvar(codegen, "tmp_seg", 0)
    off = _mk_cvar(codegen, "tmp_off", 2)
    addr = structured_c.CFunctionCall("unknown_addr", None, [seg, _const(codegen, 0)], codegen=codegen)
    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp("Add", addr, off, codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([deref], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [deref]
    assert getattr(codegen, "dce_pure_expression_candidates", 0) == 1
    assert getattr(codegen, "dce_pure_expression_refused", 0) == 1


def test_dce_refuses_wrapped_standalone_unknown_call_dereference_expression():
    codegen = _mk_codegen_with_statements([])
    seg = _mk_cvar(codegen, "tmp_seg", 0)
    off = _mk_cvar(codegen, "tmp_off", 2)
    addr = structured_c.CFunctionCall("unknown_addr", None, [seg, _const(codegen, 0)], codegen=codegen)
    deref = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp("Add", addr, off, codegen=codegen),
        codegen=codegen,
    )
    stmt = structured_c.CExpressionStatement(deref, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_pure_expression_candidates", 0) == 1
    assert getattr(codegen, "dce_pure_expression_refused", 0) == 1


def test_dce_deletes_pure_named_local_self_assignment():
    codegen = _mk_codegen_with_statements([])
    local = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(local, local, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_deleted", 0) == 1


def test_dce_deletes_overwritten_local_dirty_setup_before_read():
    codegen = _mk_codegen_with_statements([])
    local = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=27, idx=27, name="vvar_27", reg_offset=0, bits=16),
        codegen=codegen,
    )
    overwritten = structured_c.CAssignment(local, dirty, codegen=codegen)
    initializer = structured_c.CAssignment(local, _const(codegen, 0), codegen=codegen)
    ret = structured_c.CReturn(local, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([overwritten, initializer, ret], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [initializer, ret]
    assert getattr(codegen, "dce_overwritten_local_candidates", 0) == 1
    assert getattr(codegen, "dce_overwritten_local_deleted", 0) == 1


def test_dce_uses_projected_machine_bp_identity_for_stack_store_and_return():
    codegen = _mk_codegen_with_statements([])
    frame_carrier = structured_c.CVariable(
        SimStackVariable(-2, 1, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    projected_local = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected_local.variable,
        cvar=projected_local,
        bp_offset=-2,
        entry_sp_offset=-6,
        size=2,
    )
    stale_frame_setup = structured_c.CAssignment(
        frame_carrier,
        _const(codegen, 9),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    initializer = structured_c.CAssignment(
        projected_local,
        _const(codegen, 1),
        codegen=codegen,
        tags={"ins_addr": 0x4014},
    )
    ret = structured_c.CReturn(frame_carrier, codegen=codegen)
    codegen._inertia_direct_stack_move_evidence_8616 = (
        (("dst_offset", -2), ("width", 2), ("ins_addr", 0x4014)),
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [stale_frame_setup, initializer, ret],
        codegen=codegen,
    )

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [initializer, ret]
    assert codegen.dce_overwritten_local_deleted == 1
    assert codegen.dce_keep_protected >= 1


def test_dce_refuses_overwritten_local_side_effecting_rhs():
    codegen = _mk_codegen_with_statements([])
    local = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    side_effect = structured_c.CFunctionCall("helper", SimTypeShort(False), args=(), codegen=codegen)
    overwritten = structured_c.CAssignment(local, side_effect, codegen=codegen)
    initializer = structured_c.CAssignment(local, _const(codegen, 0), codegen=codegen)
    ret = structured_c.CReturn(local, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([overwritten, initializer, ret], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [overwritten, initializer, ret]
    assert getattr(codegen, "dce_overwritten_local_candidates", 0) == 1
    assert getattr(codegen, "dce_overwritten_local_refused", 0) == 1


def test_dce_refuses_overwritten_function_argument_setup():
    codegen = _mk_codegen_with_statements([])
    arg = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="arg", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [arg]
    overwritten = structured_c.CAssignment(arg, _const(codegen, 1), codegen=codegen)
    initializer = structured_c.CAssignment(arg, _const(codegen, 0), codegen=codegen)
    ret = structured_c.CReturn(arg, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([overwritten, initializer, ret], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [overwritten, initializer, ret]
    assert getattr(codegen, "dce_overwritten_local_deleted", 0) == 0


def test_dce_deletes_frame_anchor_assignment_even_when_dirty_carriers_read_it():
    codegen = _mk_codegen_with_statements([])
    frame_anchor = structured_c.CVariable(
        SimStackVariable(0, 2, base="bp", name="local_0", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    source = structured_c.CDirtyExpression(
        SimpleNamespace(varid=17, idx=17, name="vvar_17", reg_offset=14, bits=16),
        codegen=codegen,
    )
    dirty_sink = structured_c.CDirtyExpression(
        SimpleNamespace(varid=878, idx=878, name="vvar_878", reg_offset=18, bits=16),
        codegen=codegen,
    )
    frame_setup = structured_c.CAssignment(frame_anchor, source, codegen=codegen, tags={"ins_addr": 0x1003})
    carrier = structured_c.CAssignment(dirty_sink, frame_anchor, codegen=codegen, tags={"ins_addr": 0x1005})
    codegen.cfunc.statements = structured_c.CStatements([frame_setup, carrier], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [carrier]
    assert getattr(codegen, "dce_frame_anchor_candidates", 0) == 1
    assert getattr(codegen, "dce_frame_anchor_deleted", 0) == 1


def test_dce_deletes_frame_anchor_assignment_read_by_dirty_carrier_in_other_block():
    codegen = _mk_codegen_with_statements([])
    frame_anchor = structured_c.CVariable(
        SimStackVariable(0, 2, base="bp", name="local_0", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    source = structured_c.CDirtyExpression(
        SimpleNamespace(varid=17, idx=17, name="vvar_17", reg_offset=14, bits=16),
        codegen=codegen,
    )
    dirty_sink = structured_c.CDirtyExpression(
        SimpleNamespace(varid=878, idx=878, name="vvar_878", reg_offset=18, bits=16),
        codegen=codegen,
    )
    frame_setup = structured_c.CAssignment(frame_anchor, source, codegen=codegen, tags={"ins_addr": 0x1003})
    carrier = structured_c.CAssignment(dirty_sink, frame_anchor, codegen=codegen, tags={"ins_addr": 0x1005})
    first_block = structured_c.CStatements([frame_setup], codegen=codegen)
    second_block = structured_c.CStatements([carrier], codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first_block, second_block], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(first_block.statements) == []
    assert list(second_block.statements) == [carrier]
    assert getattr(codegen, "dce_frame_anchor_deleted", 0) == 1


def test_dce_refuses_frame_anchor_assignment_with_side_effecting_rhs():
    codegen = _mk_codegen_with_statements([])
    frame_anchor = structured_c.CVariable(
        SimStackVariable(0, 2, base="bp", name="local_0", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    side_effect = structured_c.CFunctionCall("helper", SimTypeShort(False), args=(), codegen=codegen)
    frame_setup = structured_c.CAssignment(frame_anchor, side_effect, codegen=codegen, tags={"ins_addr": 0x1003})
    codegen.cfunc.statements = structured_c.CStatements([frame_setup], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [frame_setup]
    assert getattr(codegen, "dce_frame_anchor_candidates", 0) == 1
    assert getattr(codegen, "dce_frame_anchor_refused", 0) == 1


def test_dce_refuses_frame_anchor_assignment_read_by_return():
    codegen = _mk_codegen_with_statements([])
    frame_anchor = structured_c.CVariable(
        SimStackVariable(0, 2, base="bp", name="local_0", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    source = structured_c.CDirtyExpression(
        SimpleNamespace(varid=17, idx=17, name="vvar_17", reg_offset=14, bits=16),
        codegen=codegen,
    )
    frame_setup = structured_c.CAssignment(frame_anchor, source, codegen=codegen, tags={"ins_addr": 0x1003})
    ret = structured_c.CReturn(frame_anchor, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([frame_setup, ret], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [frame_setup, ret]
    assert getattr(codegen, "dce_frame_anchor_candidates", 0) == 1
    assert getattr(codegen, "dce_frame_anchor_refused", 0) == 1
    assert getattr(codegen, "dce_frame_anchor_deleted", 0) == 0


def test_dce_deletes_untagged_unused_local_artifact_with_incomplete_calls():
    codegen = _mk_codegen_with_statements([])
    local = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_0", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    temp = _mk_cvar(codegen, "vvar_17", 0)
    artifact = structured_c.CAssignment(local, temp, codegen=codegen)
    call = structured_c.CExpressionStatement(
        structured_c.CFunctionCall("helper", SimTypeShort(False), args=(), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([artifact, call], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [call]
    assert getattr(codegen, "dce_deleted", 0) == 1


def test_dce_deletes_local_kept_alive_only_by_dirty_carrier_chain():
    codegen = _mk_codegen_with_statements([])
    codegen._inertia_dce_allow_storage_free_dirty_8616 = True
    codegen._inertia_dce_allow_dirty_value_reads_8616 = True
    local = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_0", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    temp = _mk_cvar(codegen, "vvar_17", 0)
    dirty_a = structured_c.CDirtyExpression(
        SimpleNamespace(varid=27, idx=27, name="vvar_27", bits=16),
        codegen=codegen,
    )
    dirty_b = structured_c.CDirtyExpression(
        SimpleNamespace(varid=28, idx=28, name="vvar_28", bits=16),
        codegen=codegen,
    )
    artifact = structured_c.CAssignment(local, temp, codegen=codegen)
    carrier_a = structured_c.CAssignment(dirty_a, local, codegen=codegen)
    carrier_b = structured_c.CAssignment(dirty_b, dirty_a, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([artifact, carrier_a, carrier_b], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []


def test_dce_preserves_dirty_carrier_with_observable_read():
    codegen = _mk_codegen_with_statements([])
    codegen._inertia_dce_allow_storage_free_dirty_8616 = True
    codegen._inertia_dce_allow_dirty_value_reads_8616 = True
    local = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_0", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=27, idx=27, name="vvar_27", bits=16),
        codegen=codegen,
    )
    carrier = structured_c.CAssignment(dirty, local, codegen=codegen)
    ret = structured_c.CReturn(dirty, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([carrier, ret], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [carrier, ret]


def test_dce_deletes_unread_binary_consumed_boolean_carrier():
    codegen = _mk_codegen_with_statements([])
    codegen._inertia_consumed_direct_global_boolean_carrier_ins_addrs_8616 = (
        frozenset({0x10418})
    )
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=521, idx=521, name="vvar_521", bits=16),
        codegen=codegen,
    )
    carrier = structured_c.CAssignment(
        dirty,
        _const(codegen, 1),
        codegen=codegen,
        tags={"ins_addr": 0x10418},
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [carrier],
        codegen=codegen,
    )

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert codegen.dce_boolean_carrier_candidates == 1
    assert codegen.dce_boolean_carrier_deleted == 1
    assert codegen.dce_boolean_carrier_refused == 0


def test_dce_preserves_live_binary_consumed_boolean_carrier():
    codegen = _mk_codegen_with_statements([])
    codegen._inertia_consumed_direct_global_boolean_carrier_ins_addrs_8616 = (
        frozenset({0x10418})
    )
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=521, idx=521, name="vvar_521", bits=16),
        codegen=codegen,
    )
    carrier = structured_c.CAssignment(
        dirty,
        _const(codegen, 1),
        codegen=codegen,
        tags={"ins_addr": 0x10418},
    )
    ret = structured_c.CReturn(dirty, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements(
        [carrier, ret],
        codegen=codegen,
    )

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [carrier, ret]
    assert codegen.dce_boolean_carrier_candidates == 1
    assert codegen.dce_boolean_carrier_deleted == 0
    assert codegen.dce_boolean_carrier_refused == 1


def test_dce_deletes_unread_binary_consumed_call_cleanup_carrier():
    codegen = _mk_codegen_with_statements([])
    codegen._inertia_consumed_call_cleanup_carrier_ins_addrs_8616 = (
        frozenset({0x103C2})
    )
    carrier = structured_c.CAssignment(
        _mk_cvar(codegen, "vvar_101", 101),
        structured_c.CUnaryOp(
            "BitwiseNeg",
            structured_c.CBinaryOp(
                "CmpEQ",
                _const(codegen, 1),
                _const(codegen, 0),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x103C2},
    )
    codegen.cfunc.statements = structured_c.CStatements(
        [carrier],
        codegen=codegen,
    )

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert codegen.dce_call_cleanup_carrier_candidates == 1
    assert codegen.dce_call_cleanup_carrier_deleted == 1
    assert codegen.dce_call_cleanup_carrier_refused == 0


def test_dce_preserves_live_binary_consumed_call_cleanup_carrier():
    codegen = _mk_codegen_with_statements([])
    codegen._inertia_consumed_call_cleanup_carrier_ins_addrs_8616 = (
        frozenset({0x103C2})
    )
    carrier_var = _mk_cvar(codegen, "vvar_101", 101)
    carrier = structured_c.CAssignment(
        carrier_var,
        _const(codegen, 1),
        codegen=codegen,
        tags={"ins_addr": 0x103C2},
    )
    ret = structured_c.CReturn(carrier_var, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements(
        [carrier, ret],
        codegen=codegen,
    )

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [carrier, ret]
    assert codegen.dce_call_cleanup_carrier_candidates == 1
    assert codegen.dce_call_cleanup_carrier_deleted == 0
    assert codegen.dce_call_cleanup_carrier_refused == 1


def test_dce_preserves_tagged_unused_local_assignment_with_incomplete_calls():
    codegen = _mk_codegen_with_statements([])
    local = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_0", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    temp = _mk_cvar(codegen, "vvar_17", 0)
    tagged = structured_c.CAssignment(local, temp, tags={"ins_addr": 0x1000}, codegen=codegen)
    call = structured_c.CExpressionStatement(
        structured_c.CFunctionCall("helper", SimTypeShort(False), args=(), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([tagged, call], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [tagged, call]
    assert getattr(codegen, "dce_deleted", 0) == 0


def test_dce_deletes_unread_pure_named_local_copy_after_callsite_materialization():
    codegen = _mk_codegen_with_statements([])
    codegen._inertia_callsite_materialization_stats = SimpleNamespace(
        call_arg_fact_count=0,
        call_arg_materialized_count=0,
        call_target_fact_count=0,
        call_target_materialized_count=0,
        failure_count=0,
    )
    dst = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_0", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    src = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="fn", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dst, src, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_deleted", 0) == 1


def test_dce_keeps_unread_stack_assignment_with_direct_stack_move_evidence():
    codegen = _mk_codegen_with_statements([])
    codegen._inertia_callsite_materialization_stats = SimpleNamespace(
        call_arg_fact_count=0,
        call_arg_materialized_count=0,
        call_target_fact_count=0,
        call_target_materialized_count=0,
        failure_count=0,
    )
    total = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="total", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(total, _const(codegen, 0), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)
    codegen._inertia_direct_stack_move_evidence_8616 = ((("dst_offset", -2), ("ins_addr", 0x400B)),)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_deleted", 0) == 0
    assert getattr(codegen, "dce_keep_unknown", 0) == 1


def test_dce_deletes_unproven_dirty_register_overwrite_of_live_argument():
    codegen = _mk_codegen_with_statements([])
    arg = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="a", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=4, idx=4, name="vvar_4", reg_offset=12, bits=16),
        codegen=codegen,
    )
    overwrite = structured_c.CAssignment(arg, dirty, codegen=codegen)
    ret = structured_c.CReturn(arg, codegen=codegen)
    codegen.cfunc.arg_list = [arg]
    codegen.cfunc.statements = structured_c.CStatements([overwrite, ret], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [ret]
    assert getattr(codegen, "dce_arg_overwrite_artifact_candidates", 0) == 1
    assert getattr(codegen, "dce_arg_overwrite_artifact_deleted", 0) == 1


def test_dce_refuses_unproven_dirty_register_overwrite_using_only_cod_stack_alias():
    codegen = _mk_codegen_with_statements([])
    codegen.cfunc.addr = 0x4010
    codegen.project._inertia_cod_metadata_by_func_addr_8616 = {
        0x4010: SimpleNamespace(stack_aliases={4: "a"}),
    }
    arg = structured_c.CVariable(
        SimRegisterVariable(12, 2, name="a"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=4, idx=4, name="vvar_4", reg_offset=12, bits=16),
        codegen=codegen,
    )
    overwrite = structured_c.CAssignment(arg, dirty, codegen=codegen)
    ret = structured_c.CReturn(arg, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([overwrite, ret], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [overwrite, ret]
    assert getattr(codegen, "dce_arg_overwrite_artifact_deleted", 0) == 0


def test_dce_deletes_tag_only_argument_overwrite_without_stack_store_evidence():
    codegen = _mk_codegen_with_statements([])
    arg = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="a", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=4, idx=4, name="vvar_4", reg_offset=12, bits=16),
        codegen=codegen,
    )
    overwrite = structured_c.CAssignment(arg, dirty, codegen=codegen, tags={"ins_addr": 0x4010})
    ret = structured_c.CReturn(arg, codegen=codegen)
    codegen.cfunc.arg_list = [arg]
    codegen.cfunc.statements = structured_c.CStatements([overwrite, ret], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [ret]
    assert getattr(codegen, "dce_arg_overwrite_artifact_deleted", 0) == 1


def test_dce_keeps_direct_stack_evidenced_argument_write():
    codegen = _mk_codegen_with_statements([])
    arg = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="a", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=4, idx=4, name="vvar_4", reg_offset=12, bits=16),
        codegen=codegen,
    )
    overwrite = structured_c.CAssignment(arg, dirty, codegen=codegen)
    ret = structured_c.CReturn(arg, codegen=codegen)
    codegen.cfunc.arg_list = [arg]
    codegen.cfunc.statements = structured_c.CStatements([overwrite, ret], codegen=codegen)
    codegen._inertia_direct_stack_move_evidence_8616 = ((("dst_offset", 4), ("ins_addr", 0x4010)),)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [overwrite, ret]
    assert getattr(codegen, "dce_arg_overwrite_artifact_refused", 0) == 1


def test_dce_keeps_pre_loop_initializer_read_from_nested_control_body():
    codegen = _mk_codegen_with_statements([])
    codegen._inertia_callsite_materialization_stats = SimpleNamespace(
        call_arg_fact_count=0,
        call_arg_materialized_count=0,
        call_target_fact_count=0,
        call_target_materialized_count=0,
        failure_count=0,
    )
    changed_var = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="changed", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    init_changed = structured_c.CAssignment(changed_var, _const(codegen, 0), codegen=codegen)
    set_changed = structured_c.CAssignment(changed_var, _const(codegen, 1), codegen=codegen)
    guard = _mk_cvar(codegen, "tmp_guard", 8)
    if_node = structured_c.CIfElse(
        [(guard, structured_c.CStatements([set_changed], codegen=codegen))],
        codegen=codegen,
    )
    loop = structured_c.CForLoop(
        None,
        _const(codegen, 1),
        None,
        structured_c.CStatements([if_node, structured_c.CReturn(changed_var, codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([init_changed, loop], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [init_changed, loop]
    assert list(if_node.condition_and_nodes[0][1].statements) == [set_changed]
    assert getattr(codegen, "dce_deleted", 0) == 0


def test_dce_keeps_indexed_global_store_as_observable_memory_write():
    codegen = _mk_codegen_with_statements([])
    index = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    base = structured_c.CVariable(
        SimMemoryVariable(0x44, 2, name="g_work"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    lhs = structured_c.CIndexedVariable(base, index, variable_type=SimTypeShort(False), codegen=codegen)
    rhs = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="tmp", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(lhs, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_deleted", 0) == 0


def test_dce_refuses_dirty_lhs_provenance_carrier_without_typed_proof():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=13, idx=13, name="vvar_13", reg_offset=0, bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, _const(codegen, 7), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_deleted", 0) == 0
    assert getattr(codegen, "dce_keep_unknown", 0) == 1


def test_dce_refuses_dirty_self_assignment_without_storage_free_mode():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=300, idx=300, name="vvar_300", bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, dirty, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_deleted", 0) == 0
    assert getattr(codegen, "dce_keep_unknown", 0) == 1


def test_dce_refuses_storage_free_dirty_condition_carrier_in_normal_mode():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=301, idx=301, name="vvar_301", bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, _const(codegen, 7), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_deleted", 0) == 0
    assert getattr(codegen, "dce_keep_unknown", 0) == 1


def test_dce_deletes_unread_dirty_segmented_read_artifact_with_storage_provenance():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=14, idx=14, name="vvar_14", reg_offset=0, bits=16),
        codegen=codegen,
    )
    seg = _mk_cvar(codegen, "tmp_seg", 0)
    off = _mk_cvar(codegen, "tmp_off", 2)
    addr = structured_c.CFunctionCall("MK_FP", None, [seg, _const(codegen, 0)], codegen=codegen)
    rhs = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp("Add", addr, off, codegen=codegen),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_dirty_value_candidates", 0) == 1
    assert getattr(codegen, "dce_dirty_value_deleted", 0) == 1


def test_dce_keeps_live_dirty_segmented_read_artifact_with_storage_provenance():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=14, idx=14, name="vvar_14", reg_offset=0, bits=16),
        codegen=codegen,
    )
    seg = _mk_cvar(codegen, "tmp_seg", 0)
    off = _mk_cvar(codegen, "tmp_off", 2)
    addr = structured_c.CFunctionCall("MK_FP", None, [seg, _const(codegen, 0)], codegen=codegen)
    rhs = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CBinaryOp("Add", addr, off, codegen=codegen),
        codegen=codegen,
    )
    define_dirty = structured_c.CAssignment(dirty, rhs, codegen=codegen)
    use_dirty = structured_c.CAssignment(_mk_cvar(codegen, "tmp_dst", 4), dirty, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([define_dirty, use_dirty], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [define_dirty, use_dirty]
    assert getattr(codegen, "dce_dirty_value_candidates", 0) == 1
    assert getattr(codegen, "dce_dirty_value_refused", 0) == 1


def test_dce_refuses_unread_dirty_unknown_call_artifact():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=14, idx=14, name="vvar_14", reg_offset=0, bits=16),
        codegen=codegen,
    )
    rhs = structured_c.CFunctionCall("unknown_addr", None, [_const(codegen, 0)], codegen=codegen)
    stmt = structured_c.CAssignment(dirty, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_dirty_value_candidates", 0) == 1
    assert getattr(codegen, "dce_dirty_value_refused", 0) == 1


def test_dce_deletes_unread_storage_free_dirty_only_in_post_flag_mode():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=225, idx=225, name="tmp_225", bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, _const(codegen, 7), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]

    codegen._inertia_dce_allow_storage_free_dirty_8616 = True
    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []


def test_post_flag_dirty_dce_deletes_unread_structured_body_carrier():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=225, idx=225, name="tmp_225", bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, _const(codegen, 7), codegen=codegen)
    condition = _mk_cvar(codegen, "tmp_cond", 9)
    if_node = structured_c.CIfElse(
        [(condition, structured_c.CStatements([stmt], codegen=codegen))],
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([if_node], codegen=codegen)

    changed = _dead_code_elimination_after_flag_prune_8616(codegen)

    assert changed is True
    assert list(if_node.condition_and_nodes[0][1].statements) == []


def test_post_flag_dirty_dce_deletes_unread_switch_case_carrier():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=225, idx=225, name="tmp_225", bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, _const(codegen, 7), codegen=codegen)
    case_body = structured_c.CStatements([stmt], codegen=codegen)
    switch = structured_c.CSwitchCase(
        _mk_cvar(codegen, "tmp_switch", 9),
        [(69, case_body)],
        None,
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([switch], codegen=codegen)

    changed = _dead_code_elimination_after_flag_prune_8616(codegen)

    assert changed is True
    assert list(case_body.statements) == []


def test_post_flag_dirty_dce_refuses_very_large_function_without_local_proof():
    codegen = _mk_codegen_with_statements([])
    codegen._inertia_postprocess_function_complexity_8616 = {"blocks": 76, "bytes": 0x1AE}
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=225, idx=225, name="tmp_225", bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, _const(codegen, 7), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_after_flag_prune_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]
    assert getattr(codegen, "dce_deleted", 0) == 0
    assert getattr(codegen, "_inertia_postprocess_refused_passes_8616", ()) == (
        {
            "pass": "_dead_code_elimination_after_flag_prune_8616",
            "reason": "very_large_function_local_validation_unavailable",
        },
    )


def test_post_flag_dirty_dce_allows_very_large_function_after_seqnode_replacement_proof():
    codegen = _mk_codegen_with_statements([])
    codegen._inertia_postprocess_function_complexity_8616 = {"blocks": 76, "bytes": 0x1AE}
    codegen._inertia_allow_large_function_flag_dce_after_seqnode_replacement_8616 = True
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=225, idx=225, name="tmp_225", bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, _const(codegen, 7), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_after_flag_prune_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_deleted", 0) == 1
    assert getattr(codegen, "_inertia_large_function_flag_dce_after_seqnode_replacement_8616", 0) == 1
    assert getattr(codegen, "_inertia_postprocess_refused_passes_8616", ()) == ()


def test_postprocess_runtime_config_enables_large_flag_dce_after_seqnode_replacement():
    project = SimpleNamespace(
        _inertia_tail_validation_enabled=False,
        _inertia_typed_switch_seqnode_replacement_8616=[
            {
                "function_addr": 0x1000,
                "changed": True,
                "replaced_count": 1,
            }
        ],
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    config = _postprocess_runtime_config_8616(project, codegen, ())

    assert codegen._inertia_allow_large_function_flag_dce_after_seqnode_replacement_8616 is True
    assert config[2] is True


def test_postprocess_runtime_config_matches_rebased_seqnode_replacement_addr():
    project = SimpleNamespace(
        _inertia_tail_validation_enabled=False,
        _inertia_original_linear_delta=0xF2E0,
        _inertia_typed_switch_seqnode_replacement_8616=[
            {
                "function_addr": 0x1000,
                "changed": True,
                "replaced_count": 1,
            }
        ],
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x102E0))

    _postprocess_runtime_config_8616(project, codegen, ())

    assert codegen._inertia_allow_large_function_flag_dce_after_seqnode_replacement_8616 is True


def test_postprocess_runtime_config_does_not_enable_large_flag_dce_without_replacement():
    project = SimpleNamespace(
        _inertia_tail_validation_enabled=False,
        _inertia_typed_switch_seqnode_replacement_8616=[
            {
                "function_addr": 0x1000,
                "changed": False,
                "replaced_count": 0,
            }
        ],
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    _postprocess_runtime_config_8616(project, codegen, ())

    assert codegen._inertia_allow_large_function_flag_dce_after_seqnode_replacement_8616 is False


def test_post_flag_dirty_dce_keeps_condition_source():
    codegen = _mk_codegen_with_statements([])
    dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=225, idx=225, name="tmp_225", bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(dirty, _const(codegen, 7), codegen=codegen)
    if_node = structured_c.CIfElse(
        [(dirty, structured_c.CStatements([], codegen=codegen))],
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([stmt, if_node], codegen=codegen)

    changed = _dead_code_elimination_after_flag_prune_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt, if_node]
    assert getattr(codegen, "dce_keep_live_use", 0) == 1


def test_post_flag_dirty_dce_deletes_pure_dirty_rhs_chain():
    codegen = _mk_codegen_with_statements([])
    dirty_a = structured_c.CDirtyExpression(
        SimpleNamespace(varid=225, idx=225, name="tmp_225", bits=16),
        codegen=codegen,
    )
    dirty_b = structured_c.CDirtyExpression(
        SimpleNamespace(varid=226, idx=226, name="tmp_226", bits=16),
        codegen=codegen,
    )
    assign_a = structured_c.CAssignment(dirty_a, _const(codegen, 7), codegen=codegen)
    rhs_b = structured_c.CBinaryOp("Add", dirty_a, _const(codegen, 1), codegen=codegen)
    assign_b = structured_c.CAssignment(dirty_b, rhs_b, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([assign_a, assign_b], codegen=codegen)

    changed = _dead_code_elimination_after_flag_prune_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []
    assert getattr(codegen, "dce_deleted", 0) == 2


def test_post_flag_dirty_dce_deletes_dead_dirty_copy_from_storage_value_read():
    codegen = _mk_codegen_with_statements([])
    storage_dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=224, idx=224, name="vvar_224", reg_offset=0, bits=16),
        codegen=codegen,
    )
    temp_dirty = structured_c.CDirtyExpression(
        SimpleNamespace(varid=225, idx=225, name="tmp_225", bits=16),
        codegen=codegen,
    )
    stmt = structured_c.CAssignment(temp_dirty, storage_dirty, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([stmt], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [stmt]

    changed = _dead_code_elimination_after_flag_prune_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == []


def test_dce_does_not_count_parent_structured_body_as_outside_read():
    codegen = _mk_codegen_with_statements([])
    tmp = _mk_cvar(codegen, "tmp_225", 225)
    body = structured_c.CStatements(
        [structured_c.CAssignment(tmp, _const(codegen, 7), codegen=codegen)], codegen=codegen
    )
    loop = structured_c.CWhileLoop(_const(codegen, 1), body, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([loop], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(body.statements) == []


def test_dce_keeps_loop_carried_write_when_read_precedes_write_in_body():
    codegen = _mk_codegen_with_statements([])
    carried = structured_c.CVariable(
        SimStackVariable(-1, 1, base="bp", name="high", region=0x4010),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    sink = structured_c.CVariable(
        SimMemoryVariable(0x44, 1, name="g_sink"),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    consume_previous_iteration = structured_c.CAssignment(sink, carried, codegen=codegen)
    produce_next_iteration = structured_c.CAssignment(carried, _const(codegen, 7), codegen=codegen)
    body = structured_c.CStatements(
        [consume_previous_iteration, produce_next_iteration],
        codegen=codegen,
    )
    loop = structured_c.CWhileLoop(_const(codegen, 1), body, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([loop], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(body.statements) == [consume_previous_iteration, produce_next_iteration]
    assert getattr(codegen, "dce_deleted", 0) == 0


def test_dce_keeps_address_carrier_read_by_variable_field_lvalue():
    codegen = _mk_codegen_with_statements([])
    address = _mk_cvar(codegen, "tmp_address", 8)
    define_address = structured_c.CAssignment(address, _const(codegen, 0x44), codegen=codegen)
    struct_type = SimStruct({"byte": SimTypeChar(False)}, name="ByteView")
    field = structured_c.CStructField(struct_type, 0, "byte", codegen=codegen)
    field_lvalue = structured_c.CVariableField(address, field, var_is_ptr=True, codegen=codegen)
    field_store = structured_c.CAssignment(field_lvalue, _const(codegen, 7), codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([define_address, field_store], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [define_address, field_store]
    assert getattr(codegen, "dce_deleted", 0) == 0


def test_dce_preserves_call_but_drops_unused_result_inside_loop():
    codegen = _mk_codegen_with_statements([])
    result = _mk_cvar(codegen, "ir_7", 8)
    call = structured_c.CFunctionCall("GetRandom", None, [], codegen=codegen)
    assignment = structured_c.CAssignment(result, call, codegen=codegen)
    body = structured_c.CStatements([assignment], codegen=codegen)
    loop = structured_c.CWhileLoop(_const(codegen, 1), body, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([loop], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert len(body.statements) == 1
    assert isinstance(body.statements[0], structured_c.CExpressionStatement)
    assert body.statements[0].expr is call
    assert getattr(codegen, "dce_deleted", 0) == 1


def test_dce_preserves_call_but_drops_unused_register_backed_result():
    codegen = _mk_codegen_with_statements([])
    result = structured_c.CDirtyExpression(
        SimpleNamespace(varid=53, idx=53, name="vvar_53", reg_offset=0, bits=16),
        codegen=codegen,
    )
    call = structured_c.CFunctionCall("DrawText", None, [], codegen=codegen)
    assignment = structured_c.CAssignment(result, call, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([assignment], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    statements = list(codegen.cfunc.statements.statements)
    assert len(statements) == 1
    assert isinstance(statements[0], structured_c.CExpressionStatement)
    assert statements[0].expr is call
    assert getattr(codegen, "dce_deleted", 0) == 1


def test_dce_keeps_register_backed_call_result_when_read():
    codegen = _mk_codegen_with_statements([])
    result = structured_c.CDirtyExpression(
        SimpleNamespace(varid=53, idx=53, name="vvar_53", reg_offset=0, bits=16),
        codegen=codegen,
    )
    call = structured_c.CFunctionCall("ReadValue", None, [], codegen=codegen)
    assignment = structured_c.CAssignment(result, call, codegen=codegen)
    ret = structured_c.CReturn(result, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([assignment, ret], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [assignment, ret]
    assert getattr(codegen, "dce_deleted", 0) == 0


def test_dce_removes_instruction_tagged_unread_temp_inside_loop():
    codegen = _mk_codegen_with_statements([])
    temp = _mk_cvar(codegen, "ir_8", 8)
    assignment = structured_c.CAssignment(
        temp,
        structured_c.CBinaryOp(
            "Shl",
            _mk_cvar(codegen, "arg_74", 10),
            _const(codegen, 1),
            codegen=codegen,
        ),
        tags={"ins_addr": 0x4050},
        codegen=codegen,
    )
    body = structured_c.CStatements([assignment], codegen=codegen)
    loop = structured_c.CWhileLoop(_const(codegen, 1), body, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([loop], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(body.statements) == []
    assert getattr(codegen, "dce_deleted", 0) == 1


def test_dce_keeps_instruction_tagged_temp_read_across_loop_backedge():
    codegen = _mk_codegen_with_statements([])
    temp = _mk_cvar(codegen, "ir_8", 8)
    temp_read = _mk_cvar(codegen, "ir_8", 80)
    sink = structured_c.CVariable(
        SimMemoryVariable(0x44, 2, name="g_sink"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    consume_previous_iteration = structured_c.CAssignment(
        sink,
        temp_read,
        codegen=codegen,
    )
    produce_next_iteration = structured_c.CAssignment(
        temp,
        _const(codegen, 7),
        tags={"ins_addr": 0x4050},
        codegen=codegen,
    )
    body = structured_c.CStatements(
        [consume_previous_iteration, produce_next_iteration],
        codegen=codegen,
    )
    loop = structured_c.CWhileLoop(_const(codegen, 1), body, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([loop], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(body.statements) == [
        consume_previous_iteration,
        produce_next_iteration,
    ]
    assert getattr(codegen, "dce_deleted", 0) == 0


def test_dce_matches_c_variable_liveness_by_emitted_name():
    codegen = _mk_codegen_with_statements([])
    tmp_def = _mk_cvar(codegen, "tmp_23", 23)
    tmp_use = _mk_cvar(codegen, "tmp_23", 2300)
    local = _mk_cvar(codegen, "local_2", 2)
    define_tmp = structured_c.CAssignment(tmp_def, _const(codegen, 7), codegen=codegen)
    use_tmp = structured_c.CAssignment(local, tmp_use, codegen=codegen)
    ret = structured_c.CReturn(local, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([define_tmp, use_tmp, ret], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [define_tmp, use_tmp, ret]


def test_dce_deletes_adjacent_duplicate_pure_stack_assignment():
    codegen = _mk_codegen_with_statements([])
    dst = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    src = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    first = structured_c.CAssignment(dst, src, codegen=codegen)
    second = structured_c.CAssignment(dst, src, codegen=codegen)
    ret = structured_c.CReturn(dst, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second, ret], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [first, ret]
    assert getattr(codegen, "dce_duplicate_assignment_candidates", 0) == 1
    assert getattr(codegen, "dce_duplicate_assignment_deleted", 0) == 1


def test_dce_refuses_adjacent_duplicate_dereference_assignment():
    codegen = _mk_codegen_with_statements([])
    dst = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    ptr = structured_c.CVariable(
        SimRegisterVariable(0, 2, name="ptr"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    rhs = structured_c.CUnaryOp("Dereference", ptr, codegen=codegen)
    first = structured_c.CAssignment(dst, rhs, codegen=codegen)
    second = structured_c.CAssignment(dst, rhs, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first, second], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(codegen.cfunc.statements.statements) == [first, second]
    assert getattr(codegen, "dce_duplicate_assignment_candidates", 0) == 1
    assert getattr(codegen, "dce_duplicate_assignment_refused", 0) == 1
    assert getattr(codegen, "dce_duplicate_assignment_deleted", 0) == 0


def test_dce_deletes_adjacent_duplicate_assignments_inside_single_statement_wrappers():
    codegen = _mk_codegen_with_statements([])
    dst = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    src = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    first = structured_c.CAssignment(dst, src, codegen=codegen)
    second = structured_c.CAssignment(dst, src, codegen=codegen)
    first_wrapper = structured_c.CStatements([first], codegen=codegen)
    second_wrapper = structured_c.CStatements([second], codegen=codegen)
    ret = structured_c.CReturn(dst, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first_wrapper, second_wrapper, ret], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [first_wrapper, ret]
    assert list(first_wrapper.statements) == [first]
    assert getattr(codegen, "dce_duplicate_assignment_candidates", 0) == 1
    assert getattr(codegen, "dce_duplicate_assignment_deleted", 0) == 1


def test_dce_deletes_duplicate_assignment_across_wrapper_boundary_after_call():
    codegen = _mk_codegen_with_statements([])
    dst = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    src = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = structured_c.CFunctionCall("SwapBars", None, [dst, src], codegen=codegen)
    first = structured_c.CAssignment(dst, src, codegen=codegen)
    second = structured_c.CAssignment(dst, src, codegen=codegen)
    first_wrapper = structured_c.CStatements([call, first], codegen=codegen)
    second_wrapper = structured_c.CStatements([second], codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([first_wrapper, second_wrapper], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [first_wrapper]
    assert list(first_wrapper.statements) == [call, first]
    assert getattr(codegen, "dce_duplicate_assignment_candidates", 0) == 1
    assert getattr(codegen, "dce_duplicate_assignment_deleted", 0) == 1


def test_dce_keeps_remaining_wrapper_statements_after_boundary_duplicate_delete():
    codegen = _mk_codegen_with_statements([])
    dst = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="i", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    src = structured_c.CVariable(
        SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    other_dst = structured_c.CVariable(
        SimStackVariable(-6, 2, base="bp", name="other", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    first = structured_c.CAssignment(dst, src, codegen=codegen)
    second = structured_c.CAssignment(dst, src, codegen=codegen)
    other = structured_c.CAssignment(other_dst, _const(codegen, 3), codegen=codegen)
    first_wrapper = structured_c.CStatements([first], codegen=codegen)
    second_wrapper = structured_c.CStatements([second, other], codegen=codegen)
    ret_dst = structured_c.CReturn(dst, codegen=codegen)
    ret_other = structured_c.CReturn(other_dst, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements(
        [first_wrapper, second_wrapper, ret_dst, ret_other], codegen=codegen
    )

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert list(codegen.cfunc.statements.statements) == [first_wrapper, second_wrapper, ret_dst, ret_other]
    assert list(first_wrapper.statements) == [first]
    assert list(second_wrapper.statements) == [other]
    assert getattr(codegen, "dce_duplicate_assignment_candidates", 0) == 1
    assert getattr(codegen, "dce_duplicate_assignment_deleted", 0) == 1
