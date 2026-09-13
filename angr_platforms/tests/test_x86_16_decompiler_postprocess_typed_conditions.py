from __future__ import annotations

from types import SimpleNamespace

import angr_platforms.X86_16.decompiler_postprocess_typed_conditions as typed_condition_postprocess
import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
    CSwitchCase,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_typed_conditions import (
    _apply_typed_condition_stack_arg_signedness_8616,
    _apply_typed_conditions_to_codegen_8616,
    _build_c_condition_expr,
    _build_c_expr_for_operand,
)
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRBinaryValue, IRValue, MemSpace
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from angr_platforms.X86_16.widening.segmented_load_identity import segmented_load_identity_8616
from x86_16_condition_definition_fixtures import install_condition_definition_block


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _codegen(statements):
    codegen = _DummyCodegen()
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    return codegen


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen, *, var_name: str | None = None):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=var_name or name), codegen=codegen)


def test_build_c_expr_for_indexed_ds_condition_operand_uses_stack_index():
    project = _project()
    codegen = _codegen([])
    operand = IRValue(
        MemSpace.DS,
        offset=0xB4C,
        size=2,
        index=IRValue(MemSpace.SS, name="bp", offset=-2, size=2),
        index_shift=1,
        memory_access_size=1,
    )
    condition = ConditionIR(
        "ugt",
        operand,
        IRValue(MemSpace.CONST, const=0, size=1),
        width_bits=8,
        producer_insn=0x4010,
    )

    expr = _build_c_expr_for_operand(project, operand, codegen, condition)

    assert isinstance(expr, CFunctionCall)
    assert expr.callee_target == "SEG_U8"
    assert expr.args[0].variable.name == "ds"
    offset = expr.args[1]
    assert isinstance(offset, CBinaryOp)
    assert offset.op == "Add"
    assert offset.lhs.value == 0xB4C
    scaled_index = offset.rhs
    assert isinstance(scaled_index, CBinaryOp)
    assert scaled_index.op == "Shl"
    assert scaled_index.lhs.variable.name == "local_2"
    assert scaled_index.lhs.variable.size == 2
    assert scaled_index.rhs.value == 1


def test_indexed_condition_resolves_register_index_at_producer(
    monkeypatch,
) -> None:
    """Nested register indices retain the condition's producer binding address."""
    project = _project()
    codegen = _codegen([])
    install_condition_definition_block(monkeypatch, project, address=0x4000, data=b"\xbe\x07\x00\x3a\x04")
    index_value = _const(7, codegen)
    monkeypatch.setattr(
        typed_condition_postprocess,
        "_register_exprs_by_ins_addr_8616",
        lambda _codegen, _project: {(0x4000, "si", 2): index_value},
    )
    operand = IRValue(
        MemSpace.DS,
        offset=0x2594,
        size=1,
        index=IRValue(MemSpace.REG, name="si", offset=24, size=2),
        memory_access_size=1,
    )
    condition = ConditionIR(
        "uge",
        IRValue(MemSpace.REG, name="al", offset=0, size=1),
        operand,
        width_bits=8,
        producer_insn=0x4003,
    )

    expr = _build_c_expr_for_operand(project, operand, codegen, condition)

    assert isinstance(expr, CFunctionCall)
    assert expr.callee_target == "SEG_U8"
    offset = expr.args[1]
    assert isinstance(offset, CBinaryOp)
    assert offset.op == "Add"
    assert offset.lhs.value == 0x2594
    assert offset.rhs is index_value


def test_build_c_condition_expr_preserves_signed_stack_operand_types():
    project = _project()
    codegen = _codegen([])
    cond = ConditionIR(
        "sgt",
        IRValue(MemSpace.SS, name="bp", offset=6, size=2),
        IRValue(MemSpace.SS, name="bp", offset=4, size=2),
        src_insn=0x4020,
        block_addr=0x4000,
    )

    expr = _build_c_condition_expr(project, cond, codegen)

    assert isinstance(expr, CBinaryOp)
    assert expr.op == "CmpGT"
    assert isinstance(expr.lhs, CVariable)
    assert isinstance(expr.rhs, CVariable)
    assert expr.lhs.variable_type.signed is True
    assert expr.rhs.variable_type.signed is True


def test_build_c_zero_condition_expr_materializes_typed_logical_value():
    project = _project()
    codegen = _codegen([])
    cond = ConditionIR(
        "zero",
        IRBinaryValue(
            op="or",
            lhs=IRValue(MemSpace.DS, offset=0x134, size=2),
            rhs=IRValue(MemSpace.DS, offset=0x132, size=2),
            size=2,
        ),
        src_insn=0x1007,
        block_addr=0x1000,
        producer_insn=0x1003,
    )

    expr = _build_c_condition_expr(project, cond, codegen)

    assert isinstance(expr, CBinaryOp)
    assert expr.op == "CmpEQ"
    assert isinstance(expr.lhs, CBinaryOp)
    assert expr.lhs.op == "Or"
    assert isinstance(expr.lhs.lhs, CFunctionCall)
    assert expr.lhs.lhs.callee_target == "SEG_U16"
    assert expr.lhs.lhs.args[1].value == 0x134
    assert isinstance(expr.lhs.rhs, CFunctionCall)
    assert expr.lhs.rhs.callee_target == "SEG_U16"
    assert expr.lhs.rhs.args[1].value == 0x132
    assert isinstance(expr.rhs, CConstant)
    assert expr.rhs.value == 0


def test_build_c_condition_expr_materializes_typed_stack_subtractions():
    project = _project()
    codegen = _codegen([])
    cond = ConditionIR(
        "slt",
        IRBinaryValue(
            op="sub",
            lhs=IRValue(MemSpace.SS, name="bp", offset=-6, size=2),
            rhs=IRValue(MemSpace.SS, name="bp", offset=4, size=2),
            size=2,
        ),
        IRBinaryValue(
            op="sub",
            lhs=IRValue(MemSpace.SS, name="bp", offset=6, size=2),
            rhs=IRValue(MemSpace.SS, name="bp", offset=-6, size=2),
            size=2,
        ),
        src_insn=0x4020,
        block_addr=0x4000,
    )

    expr = _build_c_condition_expr(project, cond, codegen)

    assert isinstance(expr, CBinaryOp)
    assert expr.op == "CmpLT"
    assert isinstance(expr.lhs, CBinaryOp)
    assert expr.lhs.op == "Sub"
    assert expr.lhs.lhs.variable.name == "local_6"
    assert expr.lhs.rhs.variable.name == "arg_4"
    assert isinstance(expr.rhs, CBinaryOp)
    assert expr.rhs.op == "Sub"
    assert expr.rhs.lhs.variable.name == "arg_6"
    assert expr.rhs.rhs.variable.name == "local_6"


def test_build_c_condition_expr_preserves_signed_register_resolved_stack_operand_type(monkeypatch):
    project = _project()
    codegen = _codegen([])
    install_condition_definition_block(monkeypatch, project, address=0x4010, data=b"\x8b\x46\x04\x3d\x00\x00")
    stack_arg = CVariable(
        SimStackVariable(4, 2, base="bp", name="a"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen._inertia_typed_condition_register_exprs_by_ins_addr_8616 = {
        (0x4010, "ax", 2): stack_arg,
    }
    cond = ConditionIR(
        "slt",
        IRValue(MemSpace.REG, name="ax", size=2),
        IRValue(MemSpace.CONST, const=0, size=2),
        producer_insn=0x4013,
        src_insn=0x4018,
        block_addr=0x4000,
    )

    expr = _build_c_condition_expr(project, cond, codegen)

    assert isinstance(expr, CBinaryOp)
    assert isinstance(expr.lhs, CTypeCast)
    assert isinstance(expr.lhs.expr, CVariable)
    assert expr.lhs.expr.variable is stack_arg.variable
    assert expr.lhs.dst_type.signed is True
    assert stack_arg.variable_type.signed is False


def test_signed_register_stack_view_keeps_projected_argument_identity(monkeypatch) -> None:
    """Keep adjacent BP arguments distinct across entry-SP projection."""
    project = _project()
    codegen = _codegen([])
    install_condition_definition_block(monkeypatch, project, address=0x4010, data=b"\x8b\x46\x04\x3b\x46\x06")
    word_type = SimTypeShort(False)
    left = CVariable(
        SimStackVariable(2, 2, base="bp", name="a"),
        variable_type=word_type,
        codegen=codegen,
    )
    right = CVariable(
        SimStackVariable(4, 2, base="bp", name="b"),
        variable_type=word_type,
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [left, right]
    codegen.cfunc.variables_in_use = {
        left.variable: left,
        right.variable: right,
    }
    codegen.cfunc.unified_local_vars = {}
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=left.variable,
        cvar=left,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=right.variable,
        cvar=right,
        bp_offset=6,
        entry_sp_offset=4,
        size=2,
    )
    codegen._inertia_typed_condition_register_exprs_by_ins_addr_8616 = {
        (0x4010, "ax", 2): left,
    }
    condition = ConditionIR(
        "sgt",
        IRValue(MemSpace.SS, name="bp", offset=6, size=2),
        IRValue(MemSpace.REG, name="ax", size=2),
        producer_insn=0x4013,
        src_insn=0x4018,
        block_addr=0x4000,
    )

    expression = _build_c_condition_expr(project, condition, codegen)

    assert isinstance(expression, CBinaryOp)
    assert isinstance(expression.lhs, CTypeCast)
    assert isinstance(expression.lhs.expr, CVariable)
    assert expression.lhs.expr.variable is right.variable
    assert isinstance(expression.rhs, CTypeCast)
    assert isinstance(expression.rhs.expr, CVariable)
    assert expression.rhs.expr.variable is left.variable


def test_apply_typed_condition_stack_arg_signedness_updates_only_signed_bp_args():
    project = _project()
    codegen = _codegen([])
    signed_arg = CVariable(
        SimStackVariable(4, 2, base="bp", name="a"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    unsigned_arg = CVariable(
        SimStackVariable(6, 2, base="bp", name="b"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [signed_arg, unsigned_arg]
    codegen.cfunc.functy = SimTypeFunction(
        [SimTypeShort(False), SimTypeShort(False)],
        SimTypeShort(False),
        arg_names=("a", "b"),
    )
    codegen._inertia_typed_conditions = [
        ConditionIR(
            "slt",
            IRValue(MemSpace.REG, name="ax", size=2),
            IRValue(MemSpace.CONST, const=0, size=2),
            producer_insn=0x4012,
            src_insn=0x4010,
            block_addr=0x4000,
        ),
        ConditionIR(
            "sgt",
            IRValue(MemSpace.SS, name="bp", offset=4, size=2),
            IRValue(MemSpace.SS, name="bp", offset=6, size=2),
            src_insn=0x4018,
            block_addr=0x4000,
        ),
        ConditionIR(
            "ult",
            IRValue(MemSpace.SS, name="bp", offset=6, size=2),
            IRValue(MemSpace.CONST, const=10, size=2),
            src_insn=0x4020,
            block_addr=0x4000,
        ),
    ]
    codegen._inertia_typed_condition_register_exprs_by_ins_addr_8616 = {
        (0x4010, "ax", 2): signed_arg,
    }

    changed = _apply_typed_condition_stack_arg_signedness_8616(project, codegen)

    assert changed is True
    assert signed_arg.variable_type.signed is True
    assert unsigned_arg.variable_type.signed is False
    assert codegen.cfunc.functy.args[0].signed is True
    assert codegen.cfunc.functy.args[1].signed is False


def test_apply_typed_condition_stack_arg_signedness_refuses_unowned_condition_drift(monkeypatch):
    project = _project()
    codegen = _codegen([])
    signed_arg = CVariable(
        SimStackVariable(4, 2, base="bp", name="a"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [signed_arg]
    codegen.cfunc.functy = SimTypeFunction(
        [SimTypeShort(False)],
        SimTypeShort(False),
        arg_names=("a",),
    )
    codegen._inertia_typed_conditions = [
        ConditionIR(
            "slt",
            IRValue(MemSpace.SS, name="bp", offset=4, size=2),
            IRValue(MemSpace.CONST, const=0, size=2),
            src_insn=0x4018,
            block_addr=0x4000,
        )
    ]
    fingerprints = iter(
        (
            {1: ("CmpLT(stack_slot:SS:BP-0x2:size2,const:1)", frozenset())},
            {1: ("CmpGE(stack_slot:SS:BP-0x2:size2,const:1)", frozenset())},
        )
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions."
        "_comparison_fingerprints_by_node_8616",
        lambda *_args: next(fingerprints),
    )

    changed = _apply_typed_condition_stack_arg_signedness_8616(project, codegen)

    assert changed is False
    assert signed_arg.variable_type.signed is False
    assert codegen.cfunc.functy.args[0].signed is False
    assert codegen._inertia_typed_condition_signed_stack_arg_refused_reason_8616 == "condition_fingerprint_drift"


def test_apply_typed_condition_stack_arg_signedness_promotes_return_type_from_return_expr(monkeypatch):
    project = _project()
    codegen = _codegen([])
    stack_var = SimStackVariable(4, 2, base="bp", name="x")
    stack_arg = CVariable(stack_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.arg_list = [stack_arg]
    codegen.cfunc.functy = SimTypeFunction(
        [SimTypeShort(False)],
        SimTypeShort(False),
        arg_names=("x",),
    )
    codegen.cfunc.statements = CStatements(
        [
            CReturn(
                CBinaryOp(
                    "Sub",
                    stack_arg,
                    CConstant(5, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        ConditionIR(
            "slt",
            IRValue(MemSpace.SS, name="bp", offset=4, size=2),
            IRValue(MemSpace.CONST, const=1, size=2),
            src_insn=0x4018,
            block_addr=0x4000,
        )
    ]
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions."
        "_condition_fingerprint_changes_are_owned_by_stack_args_8616",
        lambda *_args: True,
    )

    changed = _apply_typed_condition_stack_arg_signedness_8616(project, codegen)

    assert changed is True
    assert codegen.cfunc.functy.args[0].signed is True
    assert codegen.cfunc.functy.returnty.signed is True
    assert "prototype_return" in codegen._inertia_typed_condition_signed_stack_arg_changed_fields_8616


def test_apply_typed_conditions_refuses_self_compare_replacement(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        SimpleNamespace(src_insn=0x4020, block_addr=0x4000, op="sgt", lhs="ax", rhs="bx")
    ]

    same_expr = CBinaryOp("Add", _reg(project, "ax", codegen), _const(1, codegen), codegen=codegen)
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._build_c_condition_expr",
        lambda _project, _cond, _codegen: CBinaryOp("CmpGT", same_expr, same_expr, codegen=_codegen),
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond
    assert getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) == 0


def test_apply_typed_conditions_accepts_direct_cifelse_statement_root():
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = if_stmt
    codegen.cfunc.body = if_stmt
    codegen._inertia_typed_conditions = ()

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond
    assert getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) == 0


def test_apply_typed_conditions_rewrites_cifelse_condition_and_nodes(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        SimpleNamespace(src_insn=0x4020, block_addr=0x4000, op="sgt", lhs="ax", rhs="bx")
    ]

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._build_c_condition_expr",
        lambda _project, _cond, _codegen: CBinaryOp(
            "CmpGT",
            _reg(project, "ax", _codegen),
            _reg(project, "bx", _codegen),
            codegen=_codegen,
        ),
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is True
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"
    assert getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) == 1


def test_apply_typed_conditions_rewrites_tuple_switch_case_body(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    switch = CSwitchCase(
        _reg(project, "ax", codegen),
        [(33, CStatements([if_stmt], codegen=codegen))],
        None,
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([switch], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        SimpleNamespace(src_insn=0x4020, block_addr=0x4000, op="sgt", lhs="ax", rhs="bx")
    ]

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._build_c_condition_expr",
        lambda _project, _cond, _codegen: CBinaryOp(
            "CmpGT",
            _reg(project, "ax", _codegen),
            _reg(project, "bx", _codegen),
            codegen=_codegen,
        ),
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is True
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"
    assert getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) == 1


def test_apply_typed_conditions_rewrites_wrapped_flag_condition(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    inner = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    cond = CUnaryOp("Not", inner, codegen=codegen)
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        SimpleNamespace(src_insn=0x4020, block_addr=0x4000, op="sgt", lhs="ax", rhs="bx")
    ]

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._build_c_condition_expr",
        lambda _project, _cond, _codegen: CBinaryOp(
            "CmpGT",
            _reg(project, "ax", _codegen),
            _reg(project, "bx", _codegen),
            codegen=_codegen,
        ),
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is True
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"
    assert getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) == 1


def test_apply_typed_conditions_rewrites_cmp_wrapped_virtual_flag_carrier(monkeypatch):
    project = _project()
    codegen = _codegen([])
    carrier = _reg(project, "flags", codegen, var_name="vvar_1357")
    cond = CBinaryOp(
        "CmpEQ",
        CITE(carrier, _const(0, codegen), _const(1, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1118, "vex_block_addr": 0x1118},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        SimpleNamespace(src_insn=0x1118, block_addr=0x1118, op="slt", lhs="dx", rhs=0)
    ]

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._build_c_condition_expr",
        lambda _project, _cond, _codegen: CBinaryOp(
            "CmpLT",
            _reg(project, "dx", _codegen),
            _const(0, _codegen),
            codegen=_codegen,
        ),
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is True
    assert if_stmt.condition_and_nodes[0][0].op == "CmpLT"
    assert getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) == 1


def test_apply_typed_conditions_rewrites_unary_wrapped_virtual_flag_carrier(monkeypatch):
    project = _project()
    codegen = _codegen([])
    carrier = _reg(project, "flags", codegen, var_name="vvar_1357")
    cond = CUnaryOp(
        "Not",
        CITE(carrier, _const(0, codegen), _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1118, "vex_block_addr": 0x1118},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        SimpleNamespace(src_insn=0x1118, block_addr=0x1118, op="slt", lhs="dx", rhs=0)
    ]

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._build_c_condition_expr",
        lambda _project, _cond, _codegen: CBinaryOp(
            "CmpLT",
            _reg(project, "dx", _codegen),
            _const(0, _codegen),
            codegen=_codegen,
        ),
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is True
    assert if_stmt.condition_and_nodes[0][0].op == "CmpLT"
    assert getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) == 1


def test_apply_typed_conditions_rewrites_tagged_cite_carrier_without_name_heuristic(monkeypatch):
    project = _project()
    codegen = _codegen([])
    carrier = _reg(project, "ax", codegen, var_name="carrier")
    cond = CUnaryOp(
        "Not",
        CITE(carrier, _const(0, codegen), _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1118, "vex_block_addr": 0x1118},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        SimpleNamespace(src_insn=0x1118, block_addr=0x1118, op="slt", lhs="dx", rhs=0)
    ]

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._build_c_condition_expr",
        lambda _project, _cond, _codegen: CBinaryOp(
            "CmpLT",
            _reg(project, "dx", _codegen),
            _const(0, _codegen),
            codegen=_codegen,
        ),
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is True
    assert if_stmt.condition_and_nodes[0][0].op == "CmpLT"


def test_apply_typed_conditions_preserves_inverted_cite_truth_table(monkeypatch) -> None:
    project = _project()
    codegen = _codegen([])
    carrier = _reg(project, "ax", codegen, var_name="carrier")
    cond = CITE(
        carrier,
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1118, "vex_block_addr": 0x1118},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        SimpleNamespace(src_insn=0x1118, block_addr=0x1118, op="slt", lhs="dx", rhs=0)
    ]

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._build_c_condition_expr",
        lambda _project, _cond, _codegen: CBinaryOp(
            "CmpLT",
            _reg(project, "dx", _codegen),
            _const(0, _codegen),
            codegen=_codegen,
        ),
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    replacement = if_stmt.condition_and_nodes[0][0]
    assert changed is True
    assert isinstance(replacement, CUnaryOp)
    assert replacement.op == "Not"
    assert isinstance(replacement.operand, CBinaryOp)
    assert replacement.operand.op == "CmpLT"


def test_apply_typed_conditions_refuses_fingerprint_equal_replacement(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        SimpleNamespace(src_insn=0x4020, block_addr=0x4000, op="sgt", lhs="ax", rhs="bx")
    ]

    lhs = CBinaryOp("Add", _reg(project, "ax", codegen), _const(1, codegen), codegen=codegen)
    rhs = CBinaryOp("Add", _reg(project, "bx", codegen), _const(2, codegen), codegen=codegen)
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._build_c_condition_expr",
        lambda _project, _cond, _codegen: CBinaryOp("CmpGT", lhs, rhs, codegen=_codegen),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_typed_conditions._expr_fingerprint",
        lambda _expr, _project: "same",
    )

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond


def test_apply_typed_conditions_skips_already_explicit_equivalent_condition():
    project = _project()
    codegen = _codegen([])
    cond = CBinaryOp(
        "CmpLE",
        _reg(project, "dx", codegen),
        _reg(project, "bx", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        ConditionIR(
            op="ule",
            lhs=IRValue(MemSpace.REG, name="dx", size=2),
            rhs=IRValue(MemSpace.REG, name="bx", size=2),
            src_insn=0x4020,
            block_addr=0x4000,
        )
    ]

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond
    assert getattr(codegen, "_inertia_semantic_condition_materialized_count", 0) == 0


@pytest.mark.parametrize("proven_definition", [False, True])
def test_apply_typed_conditions_materializes_only_bound_irvalue_operands(monkeypatch, proven_definition):
    project = _project()
    codegen = _codegen([])
    install_condition_definition_block(
        monkeypatch, project, address=0x4010, data=b"\xb8\x01\x00" + b"\x90" * 10 + b"\x83\xf8\x07\x76\x00",
    )
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    assignment = CAssignment(_reg(project, "ax", codegen), _const(1, codegen), codegen=codegen, tags={"ins_addr": 0x4010})
    codegen.cfunc.statements = CStatements([assignment, if_stmt] if proven_definition else [if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        ConditionIR(
            op="ule",
            lhs=IRValue(MemSpace.REG, name="ax", size=2),
            rhs=IRValue(MemSpace.CONST, const=7, size=2),
            src_insn=0x4020,
            block_addr=0x4000,
        )
    ]

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    if not proven_definition:
        assert changed is False
        assert if_stmt.condition_and_nodes[0][0] is cond
        return
    assert changed is True
    updated = if_stmt.condition_and_nodes[0][0]
    assert isinstance(updated, CBinaryOp)
    assert updated.op == "CmpLE"
    assert updated.tags == {
        "typed_condition": True,
        "ins_addr": 0x4020,
        "vex_block_addr": 0x4000,
    }


def test_apply_typed_conditions_binds_register_operand_before_flag_producer(monkeypatch):
    project = _project()
    codegen = _codegen([])
    install_condition_definition_block(monkeypatch, project, address=0x401E, data=b"\x89\xd8\x90\x90\x83\xe8\x1b")
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    local_ax = _reg(project, "ax", codegen, var_name="local_2")
    pre_sub = CAssignment(
        _reg(project, "ax", codegen),
        local_ax,
        codegen=codegen,
        tags={"ins_addr": 0x401E},
    )
    post_sub = CAssignment(
        _reg(project, "ax", codegen),
        CBinaryOp("Sub", local_ax, _const(27, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4022},
    )
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4024, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([pre_sub, post_sub, if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        ConditionIR(
            op="ne",
            lhs=IRValue(MemSpace.REG, name="ax", size=2),
            rhs=IRValue(MemSpace.CONST, const=27, size=2),
            src_insn=0x4024,
            block_addr=0x4000,
            producer_insn=0x4022,
        )
    ]

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is True
    updated = if_stmt.condition_and_nodes[0][0]
    assert isinstance(updated, CBinaryOp)
    assert updated.op == "CmpNE"
    assert updated.lhs is local_ax
    assert isinstance(updated.rhs, CConstant)
    assert updated.rhs.value == 27


def test_apply_typed_conditions_materializes_segmented_irvalue_operand():
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        ConditionIR(
            op="ule",
            lhs=IRValue(MemSpace.DS, offset=0x132, size=2),
            rhs=IRValue(MemSpace.CONST, const=900, size=2),
            src_insn=0x4020,
            block_addr=0x4000,
        )
    ]

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is True
    updated = if_stmt.condition_and_nodes[0][0]
    assert isinstance(updated, CBinaryOp)
    assert updated.op == "CmpLE"
    assert updated.lhs.callee_target == "SEG_U16"
    assert getattr(updated.lhs.args[1], "value", None) == 0x132
    identity = segmented_load_identity_8616(updated.lhs)
    assert identity is not None
    assert identity.space is MemSpace.DS
    assert identity.offset == 0x132
    assert identity.width == 2


def test_apply_typed_conditions_materializes_stack_irvalue_operand():
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    cond = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements
    codegen._inertia_typed_conditions = [
        ConditionIR(
            op="ne",
            lhs=IRValue(MemSpace.SS, name="bp", offset=-2, size=2),
            rhs=IRValue(MemSpace.CONST, const=0, size=2),
            src_insn=0x4020,
            block_addr=0x4000,
        )
    ]

    changed = _apply_typed_conditions_to_codegen_8616(project, codegen)

    assert changed is True
    updated = if_stmt.condition_and_nodes[0][0]
    assert isinstance(updated, CBinaryOp)
    assert updated.op == "CmpNE"
    assert getattr(getattr(updated.lhs, "variable", None), "offset", None) == -2
