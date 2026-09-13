from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CITE,
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CDoWhileLoop,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CReturn,
    CStatements,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.annotations import ANNOTATION_KEY
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_postprocess_jcc import (
    _COND_TO_CMP_OP_8616,
    _JCC_COMPARE_OPS_8616,
    _bp_operand_stack_expr_8616,
    _build_arch_safe_binary_op_8616,
    _decode_inc_dec_jcc_guard_8616,
    _decode_test_jcc_guard_8616,
    _DecodedCmpGuard8616,
    _ensure_c_expr_type_has_arch_8616,
    _rewrite_decoded_jcc_conditions_8616,
    _stack_slot_expr_8616,
    _translate_cmp_jcc_guard_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_stage import (
    _apply_typed_conditions_to_codegen_pass_8616,
    _fix_interval_guard_conditions_pass_8616,
    _is_combined_jcc_callsite_stack_validation_delta_8616,
    _is_jcc_condition_materialization_validation_delta_8616,
    _materialize_unconsumed_loop_break_jcc_8616,
    _repair_loop_exit_return_guards_8616,
    _rewrite_decoded_jcc_conditions_pass_8616,
    _rewrite_flag_bit_value_uses_pass_8616,
    _rewrite_flag_condition_pairs_pass_8616,
)
from angr_platforms.X86_16.decompiler_structuring_stage import (
    _try_accept_structuring_validation_delta_from_evidence_8616,
)
from angr_platforms.X86_16.ir.condition_ir import JCC_TO_COND_8616
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)
from angr_platforms.X86_16.tail_validation_condition_context import build_x86_16_contextual_condition_fingerprints
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint


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


def test_stack_condition_lookup_uses_machine_bp_coordinate_without_renaming_shared_arg():
    codegen = _DummyCodegen()
    word = SimTypeShort(False).with_arch(codegen.project.arch)
    prototype = SimTypeFunction((word, word), word, arg_names=("a", "b")).with_arch(codegen.project.arch)
    a_var = SimStackVariable(2, 2, base="bp", name="a")
    b_var = SimStackVariable(4, 2, base="bp", name="b")
    a_arg = CVariable(a_var, variable_type=word, codegen=codegen)
    b_arg = CVariable(b_var, variable_type=word, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        arg_list=[a_arg, b_arg],
        functy=prototype,
        prototype=prototype,
        variables_in_use={a_var: a_arg, b_var: b_arg},
        unified_local_vars={},
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=a_var,
        cvar=a_arg,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=b_var,
        cvar=b_arg,
        bp_offset=6,
        entry_sp_offset=4,
        size=2,
    )

    result = _stack_slot_expr_8616(codegen, 4, 2, project=codegen.project)

    assert result is a_arg
    assert a_var.name == "a"
    assert b_var.name == "b"


def test_condition_materialization_postprocess_fallbacks_refuse_after_structuring(monkeypatch):
    calls: list[str] = []

    def _typed(_project, _codegen):
        calls.append("typed")
        return True

    def _jcc(_project, _codegen):
        calls.append("jcc")
        return True

    import angr_platforms.X86_16.decompiler_postprocess_stage as post_stage

    monkeypatch.setattr(post_stage, "_apply_typed_conditions_to_codegen_8616", _typed)
    monkeypatch.setattr(post_stage._jcc, "_rewrite_decoded_jcc_conditions_8616", _jcc)
    codegen = SimpleNamespace(_inertia_condition_materialization_structuring_pass_ran_8616=True)

    assert _apply_typed_conditions_to_codegen_pass_8616(object(), codegen) is False
    assert _rewrite_decoded_jcc_conditions_pass_8616(object(), codegen) is False
    assert calls == []


def test_flag_cleanup_postprocess_fallbacks_refuse_after_structuring(monkeypatch):
    calls: list[str] = []

    def _flag_pairs(_codegen):
        calls.append("pairs")
        return True

    def _flag_bits(_codegen):
        calls.append("bits")
        return True

    def _interval(_codegen):
        calls.append("interval")
        return True

    import angr_platforms.X86_16.decompiler_postprocess_stage as post_stage

    monkeypatch.setattr(post_stage._flags, "_rewrite_flag_condition_pairs_8616", _flag_pairs)
    monkeypatch.setattr(post_stage._flags, "_rewrite_flag_bit_value_uses_8616", _flag_bits)
    monkeypatch.setattr(post_stage._flags, "_fix_interval_guard_conditions_8616", _interval)
    codegen = SimpleNamespace(_inertia_condition_cleanup_structuring_pass_ran_8616=True)

    assert _rewrite_flag_condition_pairs_pass_8616(codegen) is False
    assert _rewrite_flag_bit_value_uses_pass_8616(codegen) is False
    assert _fix_interval_guard_conditions_pass_8616(codegen) is False
    assert calls == []


class _FakeMem:
    def __init__(self, *, base: int = 0, index: int = 0, disp: int = 0):
        self.base = base
        self.index = index
        self.disp = disp


class _FakeOperand:
    def __init__(
        self,
        operand_type: int,
        *,
        reg: int = 0,
        imm: int = 0,
        mem: _FakeMem | None = None,
        size: int = 2,
    ):
        self.type = operand_type
        self.reg = reg
        self.imm = imm
        self.mem = mem
        self.size = size


class _FakeInsn:
    def __init__(self, mnemonic: str, operands: tuple[_FakeOperand, ...], project, *, address: int = 0x4020):
        self.mnemonic = mnemonic
        self.operands = operands
        self.address = address
        self._project = project

    def reg_name(self, reg: int) -> str:
        for name, (offset, _size) in self._project.arch.registers.items():
            if int(offset) == int(reg):
                return name
        return f"reg_{reg:x}"


def _expr_contains_register(project, expr, name: str) -> bool:
    target = project.arch.registers[name][0]
    seen: set[int] = set()

    def _walk(node) -> bool:
        if node is None:
            return False
        marker = id(node)
        if marker in seen:
            return False
        seen.add(marker)
        if isinstance(node, CVariable):
            variable = getattr(node, "variable", None)
            if isinstance(variable, SimRegisterVariable):
                return int(getattr(variable, "reg", -1)) == int(target)
        for attr in ("lhs", "rhs", "expr", "operand", "condition", "cond", "iftrue", "iffalse"):
            if _walk(getattr(node, attr, None)):
                return True
        args = getattr(node, "args", None)
        if isinstance(args, (list, tuple)):
            return any(_walk(arg) for arg in args)
        return False

    return _walk(expr)


def _stack(offset: int, codegen, name: str):
    return CVariable(SimStackVariable(offset, 2, base="bp", name=name, region=0x4010), codegen=codegen)


def test_build_arch_safe_binary_op_normalizes_archless_pointer_operand():
    project = _project()
    codegen = _codegen([])
    pointer_type = SimTypePointer(SimTypeShort(False))
    lhs = CVariable(
        SimStackVariable(-2, 2, base="bp", name="ptr", region=0x4010),
        variable_type=pointer_type,
        codegen=codegen,
    )
    rhs = _const(0, codegen)

    expr = _build_arch_safe_binary_op_8616(project, codegen, "CmpNE", lhs, rhs)

    assert expr.op == "CmpNE"
    assert lhs.variable_type.size == project.arch.bits


def test_rewrite_decoded_jcc_conditions_refuses_self_compare(monkeypatch):
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

    same_expr = CBinaryOp("Add", _reg(project, "ax", codegen), _const(1, codegen), codegen=codegen)

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=same_expr,
            rhs=same_expr,
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond


def test_rewrite_decoded_jcc_conditions_accepts_direct_cifelse_statement_root(monkeypatch):
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

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda *_args, **_kwargs: None,
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond


def test_rewrite_decoded_jcc_conditions_refuses_explicit_nonflag_tagged_condition(monkeypatch):
    project = _project()
    codegen = _codegen([])
    ax = _reg(project, "ax", codegen)
    cond = CBinaryOp(
        "CmpNE",
        CBinaryOp("And", ax, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = cond
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "bx", codegen),
            rhs=_reg(project, "cx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond
    assert if_stmt.condition is cond


def test_rewrite_decoded_jcc_conditions_records_evidence_for_kept_explicit_cmp(monkeypatch):
    project = _project()
    codegen = _codegen([])
    lhs = _stack(-4, codegen, name="iChild")
    rhs = _stack(4, codegen, name="iMaxLevel")
    codegen.cfunc.arg_list = (rhs,)
    cond = CBinaryOp(
        "CmpGT",
        lhs,
        rhs,
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = cond
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=lhs,
            rhs=rhs,
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition is cond
    assert tuple(getattr(codegen, "_inertia_jcc_decoded_condition_fingerprints_8616", ())) == (
        _expr_fingerprint(cond, project),
    )
    assert getattr(codegen, "_inertia_jcc_decoded_condition_fingerprint_evidence_count_8616", 0) == 1
    assert getattr(codegen, "_inertia_jcc_rewrite_kept_explicit_cmp_with_decoded_evidence_8616", 0) >= 1


def test_decode_dec_signed_jcc_uses_predecessor_value_baseline():
    project = _project()
    codegen = _codegen([])
    ax_offset = project.arch.registers["ax"][0]
    insn = _FakeInsn("dec", (_FakeOperand(1, reg=ax_offset, size=2),), project)

    jge = _decode_inc_dec_jcc_guard_8616(project, codegen, insn, "jge", {})
    jg = _decode_inc_dec_jcc_guard_8616(project, codegen, insn, "jg", {})

    assert jge is not None
    assert jge.op == "CmpGE"
    assert isinstance(jge.rhs, CConstant)
    assert jge.rhs.value == 1
    assert jg is not None
    assert jg.op == "CmpGT"
    assert isinstance(jg.rhs, CConstant)
    assert jg.rhs.value == 1


def test_decode_or_same_register_jcc_as_zero_test():
    project = _project()
    codegen = _codegen([])
    ax_offset = project.arch.registers["ax"][0]
    insn = _FakeInsn(
        "or",
        (
            _FakeOperand(1, reg=ax_offset, size=2),
            _FakeOperand(1, reg=ax_offset, size=2),
        ),
        project,
    )

    decoded = _decode_test_jcc_guard_8616(project, codegen, insn, "jne", {}, None)

    assert decoded is not None
    assert decoded.op == "CmpNE"
    assert isinstance(decoded.rhs, CConstant)
    assert decoded.rhs.value == 0


def test_decode_or_distinct_registers_jcc_as_bitwise_or_zero_test():
    project = _project()
    codegen = _codegen([])
    ax_offset = project.arch.registers["ax"][0]
    dx_offset = project.arch.registers["dx"][0]
    insn = _FakeInsn(
        "or",
        (
            _FakeOperand(1, reg=ax_offset, size=2),
            _FakeOperand(1, reg=dx_offset, size=2),
        ),
        project,
    )

    decoded = _decode_test_jcc_guard_8616(project, codegen, insn, "je", {}, None)

    assert decoded is not None
    assert decoded.op == "CmpEQ"
    assert isinstance(decoded.lhs, CBinaryOp)
    assert decoded.lhs.op == "Or"
    assert _expr_contains_register(project, decoded.lhs.lhs, "ax")
    assert _expr_contains_register(project, decoded.lhs.rhs, "dx")
    assert isinstance(decoded.rhs, CConstant)
    assert decoded.rhs.value == 0


def test_decode_or_register_direct_memory_jcc_as_bitwise_or_zero_test():
    project = _project()
    codegen = _codegen([])
    ax_offset = project.arch.registers["ax"][0]
    insn = _FakeInsn(
        "or",
        (
            _FakeOperand(1, reg=ax_offset, size=2),
            _FakeOperand(3, mem=_FakeMem(disp=0xF0), size=2),
        ),
        project,
        address=0x1149,
    )

    decoded = _decode_test_jcc_guard_8616(project, codegen, insn, "je", {}, _reg(project, "ds", codegen))

    assert decoded is not None
    assert decoded.op == "CmpEQ"
    assert isinstance(decoded.lhs, CBinaryOp)
    assert decoded.lhs.op == "Or"
    assert _expr_contains_register(project, decoded.lhs.lhs, "ax")
    assert decoded.lhs.rhs is not None
    assert isinstance(decoded.rhs, CConstant)
    assert decoded.rhs.value == 0


def test_decode_and_distinct_registers_jcc_as_bitwise_and_zero_test():
    project = _project()
    codegen = _codegen([])
    ax_offset = project.arch.registers["ax"][0]
    dx_offset = project.arch.registers["dx"][0]
    insn = _FakeInsn(
        "and",
        (
            _FakeOperand(1, reg=ax_offset, size=2),
            _FakeOperand(1, reg=dx_offset, size=2),
        ),
        project,
    )

    decoded = _decode_test_jcc_guard_8616(project, codegen, insn, "jne", {}, None)

    assert decoded is not None
    assert decoded.op == "CmpNE"
    assert isinstance(decoded.lhs, CBinaryOp)
    assert decoded.lhs.op == "And"
    assert _expr_contains_register(project, decoded.lhs.lhs, "ax")
    assert _expr_contains_register(project, decoded.lhs.rhs, "dx")
    assert isinstance(decoded.rhs, CConstant)
    assert decoded.rhs.value == 0


def test_bp_operand_stack_expr_uses_offset_name_without_exact_prototype_slot():
    arch = Arch86_16()
    codegen = _DummyCodegen()
    codegen.project = SimpleNamespace(arch=arch)
    wrong_offset_arg = CVariable(
        SimStackVariable(8, 2, base="bp", name="x", region=0x4010),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x4010, arg_list=[wrong_offset_arg], variables_in_use={})

    expr = _bp_operand_stack_expr_8616(codegen, 4, 2)

    assert isinstance(expr, CVariable)
    assert expr is not wrong_offset_arg
    assert expr.name == "stack_bp_p4_b2"
    assert isinstance(expr.variable, SimStackVariable)
    assert expr.variable.offset == 4


def test_jcc_cmp_operand_type_arch_is_bound_before_binary_op():
    project = _project()
    codegen = _codegen([])
    lhs = CVariable(
        SimStackVariable(4, 2, base="bp", name="lhs", region=0x4010),
        variable_type=SimTypeShort(True),
        codegen=codegen,
    )
    rhs = CConstant(0, SimTypeShort(False), codegen=codegen)
    lhs.variable_type = SimTypeShort(True)
    rhs._type = SimTypeShort(False)

    with pytest.raises(ValueError, match="without an arch"):
        CBinaryOp("CmpGT", lhs, rhs, codegen=codegen)

    _ensure_c_expr_type_has_arch_8616(project, lhs)
    _ensure_c_expr_type_has_arch_8616(project, rhs)
    expr = CBinaryOp("CmpGT", lhs, rhs, codegen=codegen)

    assert expr.op == "CmpGT"
    assert lhs.variable_type.signed is True
    assert rhs.type.signed is False


def test_jcc_materialization_validation_accepts_callsite_helper_and_ax_setup_delta():
    project = _project()
    function = SimpleNamespace(
        get_call_sites=lambda: (0x10522,),
        get_call_target=lambda _addr: 0x12756,
    )
    codegen = SimpleNamespace(_inertia_semantic_condition_materialized_count=1)
    validation = {
        "delta": {
            "helper_calls": {"added": ("addr:0x12756",), "removed": ()},
            "register_writes": {"added": (), "removed": ("reg:ax",)},
            "stack_writes": {"added": (), "removed": ()},
            "global_writes": {"added": (), "removed": ()},
            "segmented_writes": {"added": (), "removed": ()},
            "returns": {"added": (), "removed": ()},
            "conditions": {"added": (), "removed": ()},
            "control_flow_effects": {"added": (), "removed": ()},
        }
    }

    assert (
        _is_jcc_condition_materialization_validation_delta_8616(
            project,
            codegen,
            validation,
            function=function,
        )
        is True
    )


def test_jcc_materialization_validation_refuses_non_ax_register_removal():
    project = _project()
    function = SimpleNamespace(
        get_call_sites=lambda: (0x10522,),
        get_call_target=lambda _addr: 0x12756,
    )
    codegen = SimpleNamespace(_inertia_semantic_condition_materialized_count=1)
    validation = {
        "delta": {
            "helper_calls": {"added": ("addr:0x12756",), "removed": ()},
            "register_writes": {"added": (), "removed": ("reg:bx",)},
        }
    }

    assert (
        _is_jcc_condition_materialization_validation_delta_8616(
            project,
            codegen,
            validation,
            function=function,
        )
        is False
    )


def test_jcc_materialization_validation_accepts_evidenced_condition_delta():
    project = _project()
    codegen = SimpleNamespace(
        _inertia_semantic_condition_materialized_count=1,
        _inertia_jcc_condition_validation_evidence_8616=(
            {
                "removed": "And(CmpEQ(And(reg:eflags,const:64),const:0),CmpEQ(reg:ax,reg:bx))",
                "added": "CmpGT(reg:ax,reg:bx)",
            },
        ),
    )
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpGT(reg:ax,reg:bx)",),
                "removed": ("And(CmpEQ(And(reg:eflags,const:64),const:0),CmpEQ(reg:ax,reg:bx))",),
            },
            "control_flow_effects": {
                "added": ("if:CmpGT(reg:ax,reg:bx)",),
                "removed": ("if:And(CmpEQ(And(reg:eflags,const:64),const:0),CmpEQ(reg:ax,reg:bx))",),
            },
        }
    }

    assert _is_jcc_condition_materialization_validation_delta_8616(project, codegen, validation) is True


def test_jcc_materialization_validation_accepts_empty_void_return_removal_with_evidence():
    project = _project()
    codegen = SimpleNamespace(
        _inertia_semantic_condition_materialized_count=1,
        _inertia_structuring_pretest_loop_guard_stats_8616=SimpleNamespace(
            call_return_carriers_removed_count=1,
        ),
        _inertia_jcc_condition_validation_evidence_8616=(
            {
                "removed": "CmpLE(call:addr:0x1446(),stack_slot:SS:BP-0x4:size4)",
                "added": "CmpGT(call:addr:0x1446(),stack_slot:SS:BP-0x4:size4)",
            },
        ),
    )
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpGT(call:addr:0x1446(),stack_slot:SS:BP-0x4:size4)",),
                "removed": ("CmpLE(call:addr:0x1446(),stack_slot:SS:BP-0x4:size4)", "const:True"),
            },
            "control_flow_effects": {
                "added": (
                    "while:CmpGT(call:addr:0x1446(),stack_slot:SS:BP-0x4:size4)",
                    "while-body-calls:CmpGT(call:addr:0x1446(),stack_slot:SS:BP-0x4:size4):addr:0x1137e",
                ),
                "removed": (
                    "if:CmpLE(call:addr:0x1446(),stack_slot:SS:BP-0x4:size4)",
                    "return",
                    "while:const:True",
                    "while-body-calls:const:True:addr:0x1137e",
                ),
            },
            "helper_calls": {
                "added": (),
                "removed": ("addr:0x1137e",),
            },
            "returns": {"added": (), "removed": ("none",)},
        }
    }

    assert _is_jcc_condition_materialization_validation_delta_8616(project, codegen, validation) is True


def test_jcc_materialization_validation_refuses_unevidenced_condition_delta():
    project = _project()
    codegen = SimpleNamespace(
        _inertia_semantic_condition_materialized_count=1,
        _inertia_jcc_condition_validation_evidence_8616=(
            {
                "removed": "CmpEQ(reg:ax,reg:bx)",
                "added": "CmpGT(reg:ax,reg:bx)",
            },
        ),
    )
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpLT(reg:ax,reg:bx)",),
                "removed": ("CmpEQ(reg:ax,reg:bx)",),
            },
            "control_flow_effects": {
                "added": ("if:CmpLT(reg:ax,reg:bx)",),
                "removed": ("if:CmpEQ(reg:ax,reg:bx)",),
            },
        }
    }

    assert _is_jcc_condition_materialization_validation_delta_8616(project, codegen, validation) is False


def test_structuring_validation_accepts_evidenced_jcc_condition_delta():
    project = _project()
    project.kb = SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: None))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_semantic_condition_materialized_count=1,
        _inertia_jcc_condition_validation_evidence_8616=(
            {
                "removed": "CmpLE(reg:ax,reg:bx)",
                "added": "CmpGT(reg:ax,reg:bx)",
            },
        ),
    )
    validation = {
        "changed": True,
        "status": "changed",
        "delta": {
            "conditions": {
                "added": ("CmpGT(reg:ax,reg:bx)",),
                "removed": ("CmpLE(reg:ax,reg:bx)",),
            },
            "control_flow_effects": {
                "added": ("if:CmpGT(reg:ax,reg:bx)",),
                "removed": ("if:CmpLE(reg:ax,reg:bx)",),
            },
        },
    }

    accepted = _try_accept_structuring_validation_delta_from_evidence_8616(
        project,
        codegen,
        validation,
        spec_name="_structuring_codegen_8616",
    )

    assert accepted is True
    assert validation["status"] == "stable"
    assert validation["changed"] is False
    assert "delta" not in validation
    assert codegen._inertia_structuring_jcc_condition_validation_accepts_8616 == 1


def test_structuring_validation_refuses_unevidenced_jcc_condition_delta():
    project = _project()
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4010),
        _inertia_semantic_condition_materialized_count=1,
        _inertia_jcc_condition_validation_evidence_8616=(
            {
                "removed": "CmpLE(reg:ax,reg:bx)",
                "added": "CmpGT(reg:ax,reg:bx)",
            },
        ),
    )
    validation = {
        "changed": True,
        "status": "changed",
        "delta": {
            "conditions": {
                "added": ("CmpLT(reg:ax,reg:bx)",),
                "removed": ("CmpLE(reg:ax,reg:bx)",),
            },
            "control_flow_effects": {
                "added": ("if:CmpLT(reg:ax,reg:bx)",),
                "removed": ("if:CmpLE(reg:ax,reg:bx)",),
            },
        },
    }

    assert (
        _try_accept_structuring_validation_delta_from_evidence_8616(
            project,
            codegen,
            validation,
            spec_name="_structuring_codegen_8616",
        )
        is False
    )
    assert validation["status"] == "changed"
    assert "delta" in validation


def test_jcc_materialization_validation_accepts_prior_structuring_evidence_delta():
    project = _project()
    recorded_delta = {
        "conditions": {
            "added": ("CmpGT(reg:ax,reg:bx)",),
            "removed": ("CmpLE(reg:ax,reg:bx)",),
        },
        "control_flow_effects": {
            "added": ("if:CmpGT(reg:ax,reg:bx)",),
            "removed": ("if:CmpLE(reg:ax,reg:bx)",),
        },
    }
    codegen = SimpleNamespace(
        _inertia_semantic_condition_materialized_count=0,
        _inertia_structuring_jcc_condition_validation_accepts_8616=1,
        _inertia_structuring_jcc_condition_validation_deltas_8616=(recorded_delta,),
    )
    validation = {"delta": dict(recorded_delta)}

    assert _is_jcc_condition_materialization_validation_delta_8616(project, codegen, validation) is True


def test_jcc_materialization_validation_refuses_mismatched_structuring_evidence_delta():
    project = _project()
    codegen = SimpleNamespace(
        _inertia_semantic_condition_materialized_count=0,
        _inertia_structuring_jcc_condition_validation_accepts_8616=1,
        _inertia_structuring_jcc_condition_validation_deltas_8616=(
            {
                "conditions": {
                    "added": ("CmpGT(reg:ax,reg:bx)",),
                    "removed": ("CmpLE(reg:ax,reg:bx)",),
                },
                "control_flow_effects": {
                    "added": ("if:CmpGT(reg:ax,reg:bx)",),
                    "removed": ("if:CmpLE(reg:ax,reg:bx)",),
                },
            },
        ),
    )
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpLT(reg:ax,reg:bx)",),
                "removed": ("CmpLE(reg:ax,reg:bx)",),
            },
            "control_flow_effects": {
                "added": ("if:CmpLT(reg:ax,reg:bx)",),
                "removed": ("if:CmpLE(reg:ax,reg:bx)",),
            },
        }
    }

    assert _is_jcc_condition_materialization_validation_delta_8616(project, codegen, validation) is False


def test_jcc_materialization_validation_accepts_decoded_condition_fingerprint_delta():
    project = _project()
    decoded = "CmpGE(Dereference(Add(Mul(reg:ds,const:16),Shl(stack_slot:SS:BP-0x2:size2,const:1),const:2892)),stack_slot:SS:BP-0x4:size2)"
    stale = "CmpGE(Dereference(Add(Mul(reg:ds,const:16),Shl(stack_slot:SS:BP-0x6:size2,const:1),const:2892)),stack_slot:SS:BP-0x4:size2)"
    codegen = SimpleNamespace(
        _inertia_semantic_condition_materialized_count=0,
        _inertia_jcc_decoded_condition_fingerprints_8616=(decoded,),
    )
    validation = {
        "delta": {
            "conditions": {
                "added": (decoded,),
                "removed": (stale,),
            },
            "control_flow_effects": {
                "added": (f"if:{decoded}",),
                "removed": (f"if:{stale}",),
            },
        }
    }

    assert _is_jcc_condition_materialization_validation_delta_8616(project, codegen, validation) is True


def test_jcc_materialization_validation_refuses_decoded_fingerprint_without_matching_control_delta():
    project = _project()
    decoded = "CmpGT(reg:ax,reg:bx)"
    stale = "CmpLE(reg:ax,reg:bx)"
    codegen = SimpleNamespace(
        _inertia_semantic_condition_materialized_count=0,
        _inertia_jcc_decoded_condition_fingerprints_8616=(decoded,),
    )
    validation = {
        "delta": {
            "conditions": {
                "added": (decoded,),
                "removed": (stale,),
            },
            "control_flow_effects": {
                "added": (),
                "removed": (),
            },
        }
    }

    assert _is_jcc_condition_materialization_validation_delta_8616(project, codegen, validation) is False


def test_combined_jcc_callsite_validation_requires_both_evidence_sources():
    project = _project()
    codegen = SimpleNamespace(
        _inertia_semantic_condition_materialized_count=1,
        _inertia_jcc_condition_validation_evidence_8616=(
            {
                "removed": "CmpLE(reg:ax,reg:bx)",
                "added": "CmpGT(reg:ax,reg:bx)",
            },
        ),
        _inertia_callsite_materialization_stats=SimpleNamespace(call_arg_materialized_count=1),
    )
    validation = {
        "delta": {
            "conditions": {
                "added": ("CmpGT(reg:ax,reg:bx)",),
                "removed": ("CmpLE(reg:ax,reg:bx)",),
            },
            "control_flow_effects": {
                "added": ("if:CmpGT(reg:ax,reg:bx)",),
                "removed": ("if:CmpLE(reg:ax,reg:bx)",),
            },
            "segmented_writes": {
                "added": (),
                "removed": ("deref:Add(Add(Mul(reg:ss,const:16),Add(reg:sp,const:-2)),const:-2)",),
            },
        }
    }

    assert _is_combined_jcc_callsite_stack_validation_delta_8616(project, None, codegen, validation) is True

    codegen._inertia_callsite_materialization_stats = SimpleNamespace(call_arg_materialized_count=0)

    assert _is_combined_jcc_callsite_stack_validation_delta_8616(project, None, codegen, validation) is False


def test_rewrite_decoded_jcc_conditions_refuses_fingerprint_equal_compare(monkeypatch):
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

    lhs = CBinaryOp("Add", _reg(project, "ax", codegen), _const(1, codegen), codegen=codegen)
    rhs = CBinaryOp("Add", _reg(project, "bx", codegen), _const(2, codegen), codegen=codegen)

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=lhs,
            rhs=rhs,
            op="CmpGT",
        ),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._expr_fingerprint",
        lambda _expr, _project: "same",
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond


def test_rewrite_decoded_jcc_conditions_rewrites_direct_condition_attr(monkeypatch):
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
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = cond
    if_stmt.iftrue = CStatements([], codegen=codegen)
    if_stmt.iffalse = None
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_rewrites_loop_body_condition(monkeypatch):
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
    loop = CWhileLoop(_const(1, codegen), CStatements([if_stmt], codegen=codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_loop_exit_return_repair_preserves_decoded_exit_condition_polarity():
    project = _project()
    codegen = _codegen([])
    exit_cond = CBinaryOp(
        "CmpGT",
        CFunctionCall("clock", SimpleNamespace(name="clock", prototype=None), [], codegen=codegen),
        CVariable(SimStackVariable(-4, 4, base="bp", name="goal", region=0x4010), codegen=codegen),
        codegen=codegen,
    )
    if_stmt = CIfElse(
        [(exit_cond, CStatements([CReturn(None, codegen=codegen)], codegen=codegen))],
        codegen=codegen,
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([if_stmt, CFunctionCall("tick", None, [], codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop, CReturn(None, codegen=codegen)], codegen=codegen)
    codegen.project = project
    codegen.cfunc.statements = root
    codegen.cfunc.body = root

    changed = _repair_loop_exit_return_guards_8616(codegen)

    assert changed is True
    rewritten = loop.body.statements[0]
    assert isinstance(rewritten, CIfBreak)
    assert rewritten.condition is exit_cond
    assert isinstance(rewritten.condition, CBinaryOp)
    assert rewritten.condition.op == "CmpGT"
    assert codegen._inertia_loop_exit_guard_stats_8616["preserved_exit_polarity"] == 1


def test_loop_exit_return_repair_postprocess_refuses_after_structuring_pass():
    project = _project()
    codegen = _codegen([])
    exit_cond = CBinaryOp(
        "CmpGT",
        CFunctionCall("clock", SimpleNamespace(name="clock", prototype=None), [], codegen=codegen),
        CVariable(SimStackVariable(-4, 4, base="bp", name="goal", region=0x4010), codegen=codegen),
        codegen=codegen,
    )
    if_stmt = CIfElse(
        [(exit_cond, CStatements([CReturn(None, codegen=codegen)], codegen=codegen))],
        codegen=codegen,
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([if_stmt, CFunctionCall("tick", None, [], codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop, CReturn(None, codegen=codegen)], codegen=codegen)
    codegen.project = project
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    codegen._inertia_loop_exit_guard_structuring_pass_ran_8616 = True

    changed = _repair_loop_exit_return_guards_8616(codegen)

    assert changed is False
    assert loop.body.statements[0] is if_stmt


def test_materialize_unconsumed_loop_break_jcc_inserts_guard_before_taken_body(monkeypatch):
    from test_x86_16_loop_break_topology import topology

    monkeypatch.setattr(
        "angr_platforms.X86_16.structuring.loop_break_jcc.collect_loop_break_topology_8616",
        lambda *_: topology(),
    )
    project = _project()
    codegen = _codegen([])
    pre_stmt = CAssignment(
        _reg(project, "ax", codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4002},
    )
    taken_stmt = CAssignment(
        _reg(project, "bx", codegen),
        _const(2, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([pre_stmt, taken_stmt], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root

    class _Operand:
        def __init__(self, type_, *, imm=0):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self, address, mnemonic, operands=()):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands
            self.size = 2

    jcc = _Insn(0x4005, "jg", (_Operand(2, imm=0x4010),))
    jmp = _Insn(0x4007, "jmp", (_Operand(2, imm=0x4020),))
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0, **_kwargs: SimpleNamespace(
            capstone=SimpleNamespace(insns=(_Insn(0x4000, "cmp"), jcc, jmp))
        )
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_stage._linear_jcc_block_starts_8616",
        lambda _project, _codegen: ((0x4000, jcc),),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_stage._linear_function_insns_for_codegen_8616",
        lambda _project, _codegen: (_Insn(0x4000, "cmp"), jcc, jmp),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _materialize_unconsumed_loop_break_jcc_8616(project, codegen)

    assert changed is True
    statements = loop.body.statements
    assert statements[0] is pre_stmt
    assert isinstance(statements[1], CIfBreak)
    assert statements[2] is taken_stmt
    assert isinstance(statements[1].condition, CBinaryOp)
    assert statements[1].condition.op == "CmpLE"
    stats = codegen._inertia_unconsumed_loop_break_jcc_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.materialized_count == 1
    assert codegen._inertia_semantic_condition_materialized_count == 1


def test_materialize_unconsumed_loop_break_jcc_refuses_postprocess_replay(
    monkeypatch,
):
    project = _project()
    codegen = _codegen([])
    codegen._inertia_unconsumed_loop_break_jcc_structuring_pass_ran_8616 = True
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_stage."
        "_structuring_materialize_unconsumed_loop_break_jcc_8616",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("Structuring-owned loop-JCC recovery was replayed")
        ),
    )

    changed = _materialize_unconsumed_loop_break_jcc_8616(project, codegen)

    assert changed is False


def test_materialize_unconsumed_loop_break_jcc_inverts_existing_continuation_ifbreak(monkeypatch):
    project = _project()
    codegen = _codegen([])

    class _Operand:
        def __init__(self, type_, *, imm=0):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self, address, mnemonic, operands=()):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands
            self.size = 2

    jcc = _Insn(0x4005, "jne", (_Operand(2, imm=0x4010),))
    jmp = _Insn(0x4007, "jmp", (_Operand(2, imm=0x4020),))
    decoded_lhs = _stack(-4, codegen, name="i")
    decoded_rhs = _const(0, codegen)
    continuation_cond = CBinaryOp(
        "CmpNE",
        decoded_lhs,
        decoded_rhs,
        codegen=codegen,
        tags={"ins_addr": 0x4005, "vex_block_addr": 0x4000},
    )
    existing_break = CIfBreak(continuation_cond, codegen=codegen)
    taken_stmt = CAssignment(
        _reg(project, "bx", codegen),
        _const(2, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([existing_break, taken_stmt], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0, **_kwargs: SimpleNamespace(
            capstone=SimpleNamespace(insns=(_Insn(0x4000, "cmp"), jcc, jmp))
        )
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_stage._linear_jcc_block_starts_8616",
        lambda _project, _codegen: ((0x4000, jcc),),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_stage._linear_function_insns_for_codegen_8616",
        lambda _project, _codegen: (_Insn(0x4000, "cmp"), jcc, jmp),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=decoded_lhs,
            rhs=decoded_rhs,
            op="CmpNE",
        ),
    )

    changed = _materialize_unconsumed_loop_break_jcc_8616(project, codegen)

    assert changed is True
    assert existing_break.condition is not continuation_cond
    assert isinstance(existing_break.condition, CBinaryOp)
    assert existing_break.condition.op == "CmpEQ"
    evidence = tuple(codegen._inertia_jcc_condition_validation_evidence_8616)
    assert evidence == (
        {
            "removed": _expr_fingerprint(continuation_cond, project),
            "added": _expr_fingerprint(existing_break.condition, project),
        },
    )
    assert _is_jcc_condition_materialization_validation_delta_8616(
        project,
        codegen,
        {
            "delta": {
                "conditions": {"added": (_expr_fingerprint(existing_break.condition, project),), "removed": ()},
                "control_flow_effects": {
                    "added": (f"ifbreak:{_expr_fingerprint(existing_break.condition, project)}",),
                    "removed": (f"ifbreak:{_expr_fingerprint(continuation_cond, project)}",),
                },
            }
        },
    )


def test_materialize_unconsumed_loop_break_jcc_inverts_existing_single_break_ifelse(monkeypatch):
    project = _project()
    codegen = _codegen([])

    class _Operand:
        def __init__(self, type_, *, imm=0):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self, address, mnemonic, operands=()):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands
            self.size = 2

    jcc = _Insn(0x4005, "jg", (_Operand(2, imm=0x4010),))
    jmp = _Insn(0x4007, "jmp", (_Operand(2, imm=0x4020),))
    decoded_lhs = _stack(-2, codegen, name="iDown")
    decoded_rhs = _stack(-6, codegen, name="iUp")
    body_edge_cond = CBinaryOp(
        "CmpGT",
        decoded_lhs,
        decoded_rhs,
        codegen=codegen,
        tags={"ins_addr": 0x4005, "vex_block_addr": 0x4000},
    )
    existing_break_if = CIfElse(
        [(body_edge_cond, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    taken_stmt = CAssignment(
        _reg(project, "bx", codegen),
        _const(2, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([existing_break_if, taken_stmt], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc.statements = root
    codegen.cfunc.body = root
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0, **_kwargs: SimpleNamespace(
            capstone=SimpleNamespace(insns=(_Insn(0x4000, "cmp"), jcc, jmp))
        )
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_stage._linear_jcc_block_starts_8616",
        lambda _project, _codegen: ((0x4000, jcc),),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_stage._linear_function_insns_for_codegen_8616",
        lambda _project, _codegen: (_Insn(0x4000, "cmp"), jcc, jmp),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=decoded_lhs,
            rhs=decoded_rhs,
            op="CmpGT",
        ),
    )

    changed = _materialize_unconsumed_loop_break_jcc_8616(project, codegen)

    assert changed is True
    rewritten_cond = existing_break_if.condition_and_nodes[0][0]
    assert rewritten_cond is not body_edge_cond
    assert isinstance(rewritten_cond, CBinaryOp)
    assert rewritten_cond.op == "CmpLE"
    evidence = tuple(codegen._inertia_jcc_condition_validation_evidence_8616)
    assert evidence == (
        {
            "removed": _expr_fingerprint(body_edge_cond, project),
            "added": _expr_fingerprint(rewritten_cond, project),
        },
    )


def test_rewrite_decoded_jcc_conditions_refuses_conflicting_repeated_key(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    key = {"ins_addr": 0x4020, "vex_block_addr": 0x4000}
    cond1 = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags=key,
    )
    cond2 = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x80, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags=key,
    )
    if_stmt = CIfElse(
        [
            (cond1, CStatements([], codegen=codegen)),
            (cond2, CStatements([], codegen=codegen)),
        ],
        codegen=codegen,
    )
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    decode_calls = []

    def _decode(_project, _codegen, _block_addr, _jcc_addr):
        decode_calls.append(1)
        if len(decode_calls) == 1:
            return _DecodedCmpGuard8616(lhs=_reg(project, "ax", codegen), rhs=_reg(project, "bx", codegen), op="CmpGT")
        return _DecodedCmpGuard8616(lhs=_reg(project, "ax", codegen), rhs=_reg(project, "bx", codegen), op="CmpLT")

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        _decode,
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond1
    assert if_stmt.condition_and_nodes[1][0] is cond2


def test_rewrite_decoded_jcc_conditions_allows_matching_repeated_key(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    key = {"ins_addr": 0x4020, "vex_block_addr": 0x4000}
    cond1 = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags=key,
    )
    cond2 = CBinaryOp(
        "CmpEQ",
        CBinaryOp("And", flags, _const(0x80, codegen), codegen=codegen),
        _const(0, codegen),
        codegen=codegen,
        tags=key,
    )
    if_stmt = CIfElse(
        [
            (cond1, CStatements([], codegen=codegen)),
            (cond2, CStatements([], codegen=codegen)),
        ],
        codegen=codegen,
    )
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert isinstance(if_stmt.condition_and_nodes[1][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"
    assert if_stmt.condition_and_nodes[1][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_finds_nested_tags_on_direct_condition(monkeypatch):
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
    cond = CBinaryOp("LogicalAnd", CConstant(1, SimTypeShort(False), codegen=codegen), inner, codegen=codegen)
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = cond
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_rewrites_not_cite_condition(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    inner = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
    )
    cond = CUnaryOp("Not", inner, codegen=codegen, tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000})
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = cond
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_uses_branch_target_body_polarity(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(1, codegen),
        _const(0, codegen),
        codegen=codegen,
    )
    cond = CUnaryOp("Not", carrier, codegen=codegen, tags={"ins_addr": 0x4005, "vex_block_addr": 0x4000})
    body_stmt = CAssignment(
        _reg(project, "ax", codegen, var_name="body_ax"),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    body = CStatements([body_stmt], codegen=codegen)
    if_stmt = CIfElse([(cond, body)], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4000, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    class _Operand:
        def __init__(self, type_, *, imm=0):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(
            capstone=SimpleNamespace(
                insns=(
                    _Insn(0x4000, "cmp", ()),
                    _Insn(0x4005, "jle", (_Operand(2, imm=0x4010),)),
                )
            )
        )
    )

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpLE",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert isinstance(rewritten, CBinaryOp)
    assert rewritten.op == "CmpLE"


def test_rewrite_decoded_jcc_conditions_uses_direct_negated_cite_as_polarity_evidence(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(carrier, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = carrier
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpNE",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert isinstance(rewritten, CBinaryOp)
    assert rewritten.op == "CmpEQ"
    assert getattr(codegen, "_inertia_jcc_decoded_condition_fingerprints_8616", ())


def test_rewrite_decoded_jcc_conditions_rewrites_direct_cite_with_tagged_literal_children(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    tags = {"ins_addr": 0x4020, "vex_block_addr": 0x4000}
    iftrue = _const(0, codegen)
    iffalse = _const(1, codegen)
    iftrue.tags = dict(tags)
    iffalse.tags = dict(tags)
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        iftrue,
        iffalse,
        codegen=codegen,
        tags=dict(tags),
    )
    if_stmt = CIfElse([(carrier, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = carrier
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpNE",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert isinstance(rewritten, CBinaryOp)
    assert rewritten.op == "CmpEQ"
    assert getattr(codegen, "_inertia_jcc_decoded_condition_fingerprints_8616", ())


def test_rewrite_decoded_jcc_conditions_refuses_raw_state_decoded_guard(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CBinaryOp(
        "And",
        flags,
        _const(0x40, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(carrier, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = carrier
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            rhs=_const(0, codegen),
            op="CmpNE",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is carrier
    assert codegen._inertia_jcc_rewrite_refused_raw_state_guard_8616 == 1
    assert not getattr(codegen, "_inertia_jcc_decoded_condition_fingerprints_8616", ())


def test_rewrite_decoded_jcc_conditions_decodes_raw_register_carrier(monkeypatch):
    project = _project()
    codegen = _codegen([])
    i_row_next = _stack(-2, codegen, name="iRowNext")
    c_row = _stack(-4, codegen, name="cRow")
    raw_guard = CBinaryOp(
        "CmpGE",
        i_row_next,
        _reg(project, "ax", codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_break = CIfBreak(raw_guard, codegen=codegen)
    codegen.cfunc.statements = CStatements([if_break], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=i_row_next,
            rhs=c_row,
            op="CmpGE",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_break.condition
    assert isinstance(rewritten, CBinaryOp)
    assert rewritten.op == "CmpGE"
    assert rewritten.lhs is i_row_next
    assert rewritten.rhs is c_row
    assert getattr(codegen, "_inertia_jcc_raw_register_condition_carrier_decoded_8616", 0) >= 1


def test_rewrite_decoded_jcc_conditions_prunes_adjacent_raw_duplicate_ifbreak():
    project = _project()
    codegen = _codegen([])
    tags = {"ins_addr": 0x4020, "vex_block_addr": 0x4000}
    i_row_next = _stack(-2, codegen, name="iRowNext")
    c_row = _stack(-4, codegen, name="cRow")
    ax = _reg(project, "ax", codegen)
    stable_guard = CBinaryOp(
        "CmpGE",
        i_row_next,
        c_row,
        codegen=codegen,
        tags={**tags, "inertia_jcc_materialized_8616": True},
    )
    raw_guard = CBinaryOp("CmpGE", i_row_next, ax, codegen=codegen, tags=dict(tags))
    stable_break = CIfBreak(stable_guard, codegen=codegen)
    raw_break = CIfBreak(raw_guard, codegen=codegen)
    codegen.cfunc.statements = CStatements([stable_break, raw_break], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    statements = tuple(codegen.cfunc.statements.statements)
    assert changed is True
    assert statements == (stable_break,)
    assert stable_break.condition is stable_guard
    assert getattr(codegen, "_inertia_jcc_duplicate_raw_guard_pruned_8616", 0) == 1


def test_rewrite_decoded_jcc_conditions_keeps_raw_ifbreak_with_different_jcc_key():
    project = _project()
    codegen = _codegen([])
    i_row_next = _stack(-2, codegen, name="iRowNext")
    c_row = _stack(-4, codegen, name="cRow")
    ax = _reg(project, "ax", codegen)
    stable_guard = CBinaryOp(
        "CmpGE",
        i_row_next,
        c_row,
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000, "inertia_jcc_materialized_8616": True},
    )
    raw_guard = CBinaryOp(
        "CmpGE",
        i_row_next,
        ax,
        codegen=codegen,
        tags={"ins_addr": 0x4022, "vex_block_addr": 0x4000},
    )
    stable_break = CIfBreak(stable_guard, codegen=codegen)
    raw_break = CIfBreak(raw_guard, codegen=codegen)
    codegen.cfunc.statements = CStatements([stable_break, raw_break], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    statements = tuple(codegen.cfunc.statements.statements)
    assert changed is False
    assert statements == (stable_break, raw_break)
    assert getattr(codegen, "_inertia_jcc_duplicate_raw_guard_pruned_8616", 0) == 0


def test_rewrite_decoded_jcc_conditions_uses_target_body_polarity_for_inverted_cite(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    target_stmt = CAssignment(
        _reg(project, "ax", codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4050},
    )
    body = CStatements([target_stmt], codegen=codegen)
    if_stmt = CIfElse([(carrier, body)], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = carrier
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpNE",
        ),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._decode_block_and_jcc_index_8616",
        lambda *_args, **_kwargs: ((object(),), 0),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._branch_target_imm_8616",
        lambda _insn: 0x4050,
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert isinstance(rewritten, CBinaryOp)
    assert rewritten.op == "CmpNE"
    assert getattr(codegen, "_inertia_jcc_decoded_condition_fingerprints_8616", ())


def test_rewrite_decoded_jcc_conditions_uses_following_target_as_early_guard_polarity(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    early_return = CReturn(_const(0, codegen), codegen=codegen, tags={"ins_addr": 0x4030})
    target_stmt = CAssignment(
        _reg(project, "ax", codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4050},
    )
    if_stmt = CIfElse([(carrier, CStatements([early_return], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = carrier
    codegen.cfunc.statements = CStatements([if_stmt, target_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpNE",
        ),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._decode_block_and_jcc_index_8616",
        lambda *_args, **_kwargs: ((object(),), 0),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._branch_target_imm_8616",
        lambda _insn: 0x4050,
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert isinstance(rewritten, CBinaryOp)
    assert rewritten.op == "CmpEQ"
    assert if_stmt.condition is rewritten
    assert getattr(codegen, "_inertia_jcc_decoded_condition_fingerprints_8616", ())


def test_rewrite_decoded_jcc_conditions_inverts_ifbreak_cite(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_break = CIfBreak(carrier, codegen=codegen)
    codegen.cfunc.statements = CStatements([if_break], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_break.condition, CBinaryOp)
    assert if_break.condition.op == "CmpLE"
    assert getattr(codegen, "_inertia_jcc_rewrite_refused_unknown_polarity_8616", 0) == 0


def test_rewrite_decoded_jcc_conditions_inverts_do_while_continuation_cite(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    loop = CDoWhileLoop(carrier, CStatements([], codegen=codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpLE",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(loop.condition, CBinaryOp)
    assert loop.condition.op == "CmpGT"
    assert getattr(codegen, "_inertia_jcc_rewrite_refused_unknown_polarity_8616", 0) == 0


def test_rewrite_decoded_jcc_conditions_inverts_break_only_condition_pair(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(carrier, CStatements([CBreak(codegen=codegen)], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert isinstance(rewritten, CBinaryOp)
    assert rewritten.op == "CmpLE"
    assert getattr(codegen, "_inertia_jcc_rewrite_refused_unknown_polarity_8616", 0) == 0


def test_rewrite_decoded_jcc_keeps_following_sibling_break_polarity(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(carrier, CStatements([CBreak(codegen=codegen)], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    following_target = CAssignment(
        _reg(project, "ax", codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4050},
    )
    codegen.cfunc.statements = CStatements([if_stmt, following_target], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    class _Operand:
        def __init__(self, type_, *, imm=0):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self, address, mnemonic, operands=()):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

    jcc = _Insn(0x4020, "jbe", (_Operand(2, imm=0x4050),))
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._decode_block_and_jcc_index_8616",
        lambda _project, _block_addr, _jcc_addr, _debug: ((jcc,), 0),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpLE",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert isinstance(rewritten, CBinaryOp)
    assert rewritten.op == "CmpGT"
    assert rewritten.tags["inertia_jcc_materialized_8616"] is True


def test_rewrite_decoded_jcc_conditions_inverts_return_only_condition_pair(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(carrier, CStatements([CReturn(None, codegen=codegen)], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert isinstance(rewritten, CBinaryOp)
    assert rewritten.op == "CmpLE"
    assert getattr(codegen, "_inertia_jcc_rewrite_refused_unknown_polarity_8616", 0) == 0


def test_rewrite_decoded_jcc_preserves_nested_condition_provenance(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    tagged_carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    wrapped_carrier = CUnaryOp("Not", tagged_carrier, codegen=codegen, tags={})
    if_stmt = CIfElse(
        [(wrapped_carrier, CStatements([CReturn(None, codegen=codegen)], codegen=codegen))],
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert isinstance(rewritten, CBinaryOp)
    assert rewritten.tags["ins_addr"] == 0x4020
    assert rewritten.tags["vex_block_addr"] == 0x4000
    assert rewritten.tags["inertia_jcc_materialized_8616"] is True


def test_rewrite_decoded_jcc_conditions_preserves_call_cmp_under_not(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
    )
    carrier.tags = {"ins_addr": 0x4020, "vex_block_addr": 0x4000}
    cond = carrier
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = cond
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    call = CFunctionCall("clock", SimpleNamespace(name="clock", prototype=None), [], codegen=codegen)
    goal = CVariable(SimStackVariable(-4, 4, base="bp", name="goal", region=0x4010), codegen=codegen)
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=call,
            rhs=goal,
            op="CmpLE",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert isinstance(rewritten, CUnaryOp)
    assert rewritten.op == "Not"
    assert isinstance(rewritten.operand, CBinaryOp)
    assert rewritten.operand.op == "CmpLE"


def test_rewrite_decoded_jcc_conditions_inverts_explicit_call_cmp_break_pair(monkeypatch):
    project = _project()
    codegen = _codegen([])
    call = CFunctionCall("clock", SimpleNamespace(name="clock", prototype=None), [], codegen=codegen)
    goal = CVariable(SimStackVariable(-4, 4, base="bp", name="goal", region=0x4010), codegen=codegen)
    explicit_branch_cond = CBinaryOp(
        "CmpLE",
        call,
        goal,
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    body = CStatements([CBreak(codegen=codegen)], codegen=codegen)
    if_stmt = CIfElse([(explicit_branch_cond, body)], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = explicit_branch_cond
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=call,
            rhs=goal,
            op="CmpLE",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert rewritten is explicit_branch_cond
    assert if_stmt.condition is explicit_branch_cond
    assert getattr(codegen, "_inertia_jcc_rewrite_kept_explicit_cmp_with_decoded_evidence_8616", 0) >= 1


def test_rewrite_decoded_jcc_records_raw_decoded_fingerprint_for_validation(monkeypatch):
    project = _project()
    codegen = _codegen([])
    flags = _reg(project, "flags", codegen, var_name="flags_tmp")
    carrier = CITE(
        CBinaryOp(
            "CmpEQ",
            CBinaryOp("And", flags, _const(0x40, codegen), codegen=codegen),
            _const(0, codegen),
            codegen=codegen,
        ),
        _const(0, codegen),
        _const(1, codegen),
        codegen=codegen,
    )
    carrier.tags = {"ins_addr": 0x4020, "vex_block_addr": 0x4000}
    body = CStatements([CBreak(codegen=codegen)], codegen=codegen)
    if_stmt = CIfElse([(carrier, body)], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = carrier
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    ax = _reg(project, "ax", codegen)
    rhs = _const(69, codegen)
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=ax,
            rhs=rhs,
            op="CmpNE",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    raw_decoded = str(_expr_fingerprint(CBinaryOp("CmpNE", ax, rhs, codegen=codegen), project))
    assert raw_decoded in codegen._inertia_jcc_decoded_condition_fingerprints_8616
    validation = {
        "delta": {
            "conditions": {
                "added": (raw_decoded,),
                "removed": ("CmpNE(reg:ax,const:1)",),
            },
            "control_flow_effects": {
                "added": (f"if:{raw_decoded}",),
                "removed": ("if:CmpNE(reg:ax,const:1)",),
            },
        }
    }

    assert _is_jcc_condition_materialization_validation_delta_8616(project, codegen, validation) is True


def test_rewrite_decoded_jcc_conditions_rebinds_adjacent_call_return_register_condition(monkeypatch):
    project = _project()
    codegen = _codegen([])
    ret_var = CVariable(SimRegisterVariable(0x120, 2, name="vret"), codegen=codegen)
    call_assign = CAssignment(ret_var, CFunctionCall("sub_1234", None, [], codegen=codegen), codegen=codegen)
    ax = _reg(project, "ax", codegen)
    cond = CBinaryOp("CmpNE", ax, _const(35, codegen), codegen=codegen)
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition = cond
    codegen.cfunc.statements = CStatements([call_assign, if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setenv("INERTIA_ENABLE_JCC_CALL_RETURN_REBIND", "1")

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert rewritten is cond
    assert rewritten.lhs is ret_var
    assert if_stmt.condition.lhs is ret_var
    assert codegen._inertia_jcc_call_return_register_rebindings >= 1


def test_rewrite_decoded_jcc_conditions_replaces_unstable_stack_arg_placeholder(monkeypatch):
    project = _project()
    codegen = _codegen([])
    unstable_arg = _stack(6, codegen, "arg_6")
    stable_local = _stack(-8, codegen, "iSwitch")
    cond = CBinaryOp(
        "CmpEQ",
        unstable_arg,
        _const(0, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4000},
    )
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition = cond
    codegen.cfunc.arg_list = (unstable_arg,)
    codegen.cfunc.variables_in_use = {stable_local.variable: stable_local}
    codegen.cfunc.unified_local_vars = {}
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=stable_local,
            rhs=_const(0, codegen),
            op="CmpEQ",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    rewritten = if_stmt.condition_and_nodes[0][0]
    assert isinstance(rewritten, CBinaryOp)
    assert rewritten.op == "CmpEQ"
    assert rewritten.lhs is stable_local
    assert getattr(rewritten.lhs.variable, "offset", None) == -8
    assert if_stmt.condition.lhs is stable_local


def test_rewrite_decoded_jcc_conditions_allows_argument_bp_positive_slots(monkeypatch):
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
    arg = _stack(4, codegen, "arg_4")
    codegen.cfunc.arg_list = (arg,)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=arg,
            rhs=_const(5, codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_allows_argument_bp_positive_slots_from_variables_in_use(monkeypatch):
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
    arg_slot = _stack(6, codegen, "iSecond")
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {arg_slot.variable: arg_slot}
    codegen.cfunc.unified_local_vars = {}
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=arg_slot,
            rhs=_const(5, codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_rejects_nonargument_bp_positive_slots(monkeypatch):
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
    codegen.cfunc.arg_list = ()
    local = _stack(4, codegen, "tmp_4")
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=local,
            rhs=_const(5, codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond


def test_rewrite_decoded_jcc_conditions_rejects_nonargument_bp_positive_slots_in_variables_in_use(monkeypatch):
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
    local_slot = _stack(4, codegen, "tmp_4")
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {local_slot.variable: local_slot}
    codegen.cfunc.unified_local_vars = {}
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=local_slot,
            rhs=_const(5, codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is False
    assert if_stmt.condition_and_nodes[0][0] is cond


def test_rewrite_decoded_jcc_conditions_rewrites_tuple_condition_pairs(monkeypatch):
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
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes, tuple)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_handles_cycle_guard(monkeypatch):
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
    cycle_body = CStatements([if_stmt], codegen=codegen)
    if_stmt.iftrue = cycle_body
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_jcc._translate_cmp_jcc_guard_8616",
        lambda _project, _codegen, _block_addr, _jcc_addr: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=_reg(project, "bx", codegen),
            op="CmpGT",
        ),
    )

    changed = _rewrite_decoded_jcc_conditions_8616(project, codegen)

    assert changed is True
    assert isinstance(if_stmt.condition_and_nodes[0][0], CBinaryOp)
    assert if_stmt.condition_and_nodes[0][0].op == "CmpGT"


def test_rewrite_decoded_jcc_conditions_walks_deep_untagged_condition_linearly(monkeypatch):
    import angr_platforms.X86_16.decompiler_postprocess_jcc as jcc_module

    codegen = _codegen([])
    cond = _const(1, codegen)
    depth = 48
    for _ in range(depth):
        cond = CUnaryOp("Not", cond, codegen=codegen)
    if_stmt = CIfElse([(cond, CStatements([], codegen=codegen))], codegen=codegen)
    if_stmt.condition_and_nodes = tuple(if_stmt.condition_and_nodes)
    if_stmt.condition = cond
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    classify_calls = 0
    original_classifier = jcc_module.classify_condition_call_effects_8616

    def _counted_classifier(condition):
        nonlocal classify_calls
        classify_calls += 1
        return original_classifier(condition)

    monkeypatch.setattr(jcc_module, "classify_condition_call_effects_8616", _counted_classifier)

    changed = _rewrite_decoded_jcc_conditions_8616(_project(), codegen)

    assert changed is False
    assert classify_calls <= depth * 4


@pytest.mark.parametrize(
    ("mnemonic", "expected_op"),
    [
        ("jc", "CmpLT"),
        ("jnae", "CmpLT"),
        ("jnb", "CmpGE"),
        ("jnc", "CmpGE"),
        ("jna", "CmpLE"),
        ("jnbe", "CmpGT"),
        ("jnge", "CmpLT"),
        ("jnl", "CmpGE"),
        ("jng", "CmpLE"),
        ("jnle", "CmpGT"),
    ],
)
def test_translate_cmp_jcc_guard_supports_all_alias_mnemonics(monkeypatch, mnemonic, expected_op):
    project = _project()
    codegen = _codegen([])
    bp_arg = _stack(4, codegen, "iMaxLevel")
    local_i = _stack(-4, codegen, "i")
    local_parent = _stack(-2, codegen, "iParent")
    codegen.cfunc.arg_list = (bp_arg,)
    codegen.cfunc.variables_in_use = {
        bp_arg.variable: bp_arg,
        local_i.variable: local_i,
        local_parent.variable: local_parent,
    }
    codegen.cfunc.unified_local_vars = {}
    stale_al_rhs = CBinaryOp("Mul", _reg(project, "si", codegen), _const(2, codegen), codegen=codegen)
    stale_al = CAssignment(
        _reg(project, "al", codegen),
        stale_al_rhs,
        codegen=codegen,
        tags={"ins_addr": 0x400C, "vex_block_addr": 0x4000},
    )
    codegen.cfunc.statements = CStatements([stale_al], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "bx",
                3: "si",
                4: "al",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, 4), size=2))),
        _Insn(0x4002, "mov", (_Operand(3, mem=_Mem(5, -4), size=2), _Operand(1, reg=1, size=2))),
        _Insn(0x4004, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4006, "shl", (_Operand(1, reg=2, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4008, "mov", (_Operand(1, reg=3, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x400A, "shl", (_Operand(1, reg=3, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x400C, "mov", (_Operand(1, reg=4, size=1), _Operand(3, mem=_Mem(3, 0), size=1))),
        _Insn(0x400E, "cmp", (_Operand(3, mem=_Mem(2, 0), size=1), _Operand(1, reg=4, size=1))),
        _Insn(0x4010, mnemonic, (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4010)

    assert decoded is not None
    assert decoded.op == expected_op
    assert _expr_fingerprint(decoded.rhs, project) != _expr_fingerprint(stale_al_rhs, project)
    assert not _expr_contains_register(project, decoded.rhs, "si")


@pytest.mark.parametrize(
    ("mnemonic", "expected_op", "expected_mask"),
    [
        ("jo", "CmpNE", 0x800),
        ("jno", "CmpEQ", 0x800),
        ("js", "CmpNE", 0x80),
        ("jns", "CmpEQ", 0x80),
        ("jp", "CmpNE", 0x4),
        ("jpe", "CmpNE", 0x4),
        ("jnp", "CmpEQ", 0x4),
        ("jpo", "CmpEQ", 0x4),
    ],
)
def test_translate_cmp_jcc_guard_supports_flag_variants(monkeypatch, mnemonic, expected_op, expected_mask):
    project = _project()
    codegen = _codegen([])

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, imm=0, size=2):
            self.type = type_
            self.reg = 0
            self.imm = imm
            self.mem = _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

    insns = (
        _Insn(0x4000, "mov", (_Operand(2, imm=0x4000),)),
        _Insn(0x4002, mnemonic, (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4002)

    assert decoded is not None
    assert decoded.op == expected_op
    left = getattr(decoded, "lhs", None)
    assert isinstance(left, CBinaryOp)
    assert left.op == "And"
    masked = getattr(left, "rhs", None)
    assert isinstance(masked, CConstant)
    assert masked.value == expected_mask
    assert isinstance(decoded.rhs, CConstant)
    assert decoded.rhs.value == 0


def test_translate_cmp_jcc_guard_decodes_test_mask_on_bp_argument():
    project = _project()
    codegen = _codegen([])
    arg_x = _stack(4, codegen, "x")
    codegen.cfunc.arg_list = (arg_x,)
    codegen.cfunc.variables_in_use = {arg_x.variable: arg_x}
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "test", (_Operand(3, mem=_Mem(5, 4), size=1), _Operand(2, imm=1, size=1))),
        _Insn(0x4003, "jne", (_Operand(2, imm=0x4010, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4003)

    assert decoded is not None
    assert decoded.op == "CmpNE"
    assert isinstance(decoded.lhs, CBinaryOp)
    assert decoded.lhs.op == "And"
    assert _expr_fingerprint(decoded.lhs.lhs, project) == _expr_fingerprint(arg_x, project)
    assert isinstance(decoded.lhs.rhs, CConstant)
    assert decoded.lhs.rhs.value == 1
    assert isinstance(decoded.rhs, CConstant)
    assert decoded.rhs.value == 0


def test_translate_cmp_jcc_guard_uses_existing_bp_slot_variables_for_stack_loads(monkeypatch):
    project = _project()
    codegen = _codegen([])
    bp_arg = _stack(4, codegen, "iMaxLevel")
    local_i = _stack(-4, codegen, "i")
    local_parent = _stack(-2, codegen, "iParent")
    codegen.cfunc.arg_list = (bp_arg,)
    codegen.cfunc.variables_in_use = {
        bp_arg.variable: bp_arg,
        local_i.variable: local_i,
        local_parent.variable: local_parent,
    }
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "bx",
                3: "si",
                4: "al",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, 4), size=2))),
        _Insn(0x4002, "mov", (_Operand(3, mem=_Mem(5, -4), size=2), _Operand(1, reg=1, size=2))),
        _Insn(0x4004, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4006, "shl", (_Operand(1, reg=2, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4008, "mov", (_Operand(1, reg=3, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x400A, "shl", (_Operand(1, reg=3, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x400C, "mov", (_Operand(1, reg=4, size=1), _Operand(3, mem=_Mem(3, 0), size=1))),
        _Insn(0x400E, "cmp", (_Operand(3, mem=_Mem(2, 0), size=1), _Operand(1, reg=4, size=1))),
        _Insn(0x4010, "jg", (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4010)

    assert decoded is not None
    assert decoded.op == "CmpGT"


def test_translate_cmp_jcc_guard_keeps_distinct_bp_slot_operands():
    project = _project()
    codegen = _codegen([])
    bp_arg = _stack(4, codegen, "iMaxLevel")
    local_i = _stack(-4, codegen, "i")
    local_parent = _stack(-2, codegen, "iParent")
    codegen.cfunc.arg_list = (bp_arg,)
    codegen.cfunc.variables_in_use = {
        bp_arg.variable: bp_arg,
        local_i.variable: local_i,
        local_parent.variable: local_parent,
    }
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "bx",
                3: "si",
                4: "al",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4002, "shl", (_Operand(1, reg=2, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4004, "mov", (_Operand(1, reg=3, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x4006, "shl", (_Operand(1, reg=3, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4008, "mov", (_Operand(1, reg=4, size=1), _Operand(3, mem=_Mem(3, 0), size=1))),
        _Insn(0x400A, "cmp", (_Operand(3, mem=_Mem(2, 0), size=1), _Operand(1, reg=4, size=1))),
        _Insn(0x400C, "jg", (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x400C)

    assert decoded is not None
    assert decoded.op == "CmpGT"
    assert _expr_fingerprint(decoded.lhs, project) != _expr_fingerprint(decoded.rhs, project)


def test_translate_cmp_jcc_guard_synthesizes_distinct_bp_slots_when_locals_missing():
    project = _project()
    codegen = _codegen([])
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {}
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                2: "bx",
                3: "si",
                4: "al",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4002, "shl", (_Operand(1, reg=2, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4004, "mov", (_Operand(1, reg=3, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x4006, "shl", (_Operand(1, reg=3, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4008, "mov", (_Operand(1, reg=4, size=1), _Operand(3, mem=_Mem(3, 0), size=1))),
        _Insn(0x400A, "cmp", (_Operand(3, mem=_Mem(2, 0), size=1), _Operand(1, reg=4, size=1))),
        _Insn(0x400C, "jg", (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x400C)

    assert decoded is not None
    assert decoded.op == "CmpGT"
    assert _expr_fingerprint(decoded.lhs, project) != _expr_fingerprint(decoded.rhs, project)


def test_translate_cmp_jcc_guard_promotes_al_load_through_cwde():
    project = _project()
    codegen = _codegen([])
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {}
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "bx",
                4: "al",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -6), size=2))),
        _Insn(0x4003, "shl", (_Operand(1, reg=2, size=2), _Operand(2, imm=1, size=1))),
        _Insn(0x4005, "mov", (_Operand(1, reg=4, size=1), _Operand(3, mem=_Mem(2, 0xB4C), size=1))),
        _Insn(0x4009, "cwde", ()),
        _Insn(0x400A, "cmp", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x400D, "jle", (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x400D)

    assert decoded is not None
    assert decoded.op == "CmpLE"
    assert "Dereference(" in _expr_fingerprint(decoded.lhs, project)
    assert _expr_fingerprint(decoded.lhs, project) != "reg:ax"
    assert getattr(codegen, "_inertia_jcc_byte_extend_materialized_8616", 0) >= 1


def test_translate_cmp_jcc_guard_supports_cmp_reg_mem_operand_order():
    project = _project()
    codegen = _codegen([])
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {}
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "dx",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x4002, "cmp", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4004, "jle", (_Operand(2, imm=0x4010, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4004)

    assert decoded is not None
    assert decoded.op == "CmpLE"
    assert decoded.lhs is not None
    assert decoded.rhs is not None


def test_translate_cmp_jcc_guard_tracks_register_inc_before_cmp():
    project = _project()
    codegen = _codegen([])
    arg = _stack(4, codegen, "arg_4")
    child = _stack(-4, codegen, "iChild")
    codegen.cfunc.arg_list = (arg,)
    codegen.cfunc.variables_in_use = {arg.variable: arg, child.variable: child}
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                5: "bp",
            }.get(reg, "")

    insns = (
        _Insn(0x4000, "mov", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x4002, "inc", (_Operand(1, reg=1, size=2),)),
        _Insn(0x4003, "cmp", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, 4), size=2))),
        _Insn(0x4005, "jle", (_Operand(2, imm=0x4010, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x4000, 0x4005)

    assert decoded is not None
    assert decoded.op == "CmpLE"
    assert isinstance(decoded.lhs, CBinaryOp)
    assert decoded.lhs.op == "Add"
    assert _expr_fingerprint(decoded.lhs.lhs, project) == _expr_fingerprint(child, project)
    assert isinstance(decoded.lhs.rhs, CConstant)
    assert decoded.lhs.rhs.value == 1
    assert _expr_fingerprint(decoded.rhs, project) == _expr_fingerprint(arg, project)


def test_tail_validation_condition_context_prefers_direct_cmp_immediate_evidence(monkeypatch):
    project = _project()
    codegen = _codegen([])
    local = _stack(-4, codegen, "i")
    codegen.cfunc.variables_in_use = {local.variable: local}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {5: "bp"}.get(reg, "")

    insns = (
        _Insn(0x4010, "cmp", (_Operand(3, mem=_Mem(5, -4), size=2), _Operand(2, imm=0, size=2))),
        _Insn(0x4014, "jne", (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )
    project._inertia_tail_validation_active_codegen = codegen

    stale_decoded = _DecodedCmpGuard8616(
        lhs=local,
        rhs=CConstant(1, SimTypeShort(False), codegen=codegen),
        op="CmpNE",
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.tail_validation_condition_context._translate_cmp_jcc_guard_8616",
        lambda *_args, **_kwargs: stale_decoded,
    )

    condition = CBinaryOp("CmpNE", local, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen)
    condition.tags = {"ins_addr": 0x4014, "vex_block_addr": 0x4010}
    root = CStatements([CWhileLoop(condition, CStatements([], codegen=codegen), codegen=codegen)], codegen=codegen)

    mapping = build_x86_16_contextual_condition_fingerprints(root, project)

    assert mapping[id(condition)] == "CmpNE(stack_slot:SS:BP-0x4:size2,const:0)"
    assert codegen._inertia_tail_validation_direct_cmp_jcc_overrides_8616 == 1


def test_tail_validation_condition_context_refuses_raw_register_decoded_jcc(monkeypatch):
    project = _project()
    codegen = _codegen([])

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {1: "ax"}.get(reg, "")

    insns = (
        _Insn(0x4010, "cmp", (_Operand(1, reg=1, size=2), _Operand(2, imm=69, size=2))),
        _Insn(0x4013, "jne", (_Operand(2, imm=0x4020, size=2),)),
    )
    project.factory = SimpleNamespace(
        block=lambda _addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    )
    project._inertia_tail_validation_active_codegen = codegen

    monkeypatch.setattr(
        "angr_platforms.X86_16.tail_validation_condition_context._translate_cmp_jcc_guard_8616",
        lambda *_args, **_kwargs: _DecodedCmpGuard8616(
            lhs=_reg(project, "ax", codegen),
            rhs=CConstant(69, SimTypeShort(False), codegen=codegen),
            op="CmpNE",
        ),
    )

    condition = CBinaryOp(
        "CmpNE",
        _reg(project, "flags", codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    condition.tags = {"ins_addr": 0x4013, "vex_block_addr": 0x4010}
    root = CStatements([CWhileLoop(condition, CStatements([], codegen=codegen), codegen=codegen)], codegen=codegen)

    mapping = build_x86_16_contextual_condition_fingerprints(root, project)

    assert id(condition) not in mapping


def test_compare_jcc_mapping_stays_in_sync_with_condition_ir_aliases():
    expected = {
        mnemonic: _COND_TO_CMP_OP_8616[cond_op]
        for mnemonic, cond_op in JCC_TO_COND_8616.items()
        if cond_op in _COND_TO_CMP_OP_8616
    }
    assert expected == _JCC_COMPARE_OPS_8616


def test_translate_cmp_jcc_guard_decodes_32bit_le_chain():
    project = _project()
    codegen = _codegen([])
    hi = _stack(-2, codegen, "goal_hi")
    lo = _stack(-4, codegen, "goal_lo")
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {
        hi.variable: hi,
        lo.variable: lo,
    }
    codegen.cfunc.unified_local_vars = {}

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "dx",
                5: "bp",
            }.get(reg, "")

    block_hi = (
        _Insn(0x5000, "cmp", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x5002, "jle", (_Operand(2, imm=0x5010, size=2),)),
    )
    block_mid = (_Insn(0x5010, "jge", (_Operand(2, imm=0x5020, size=2),)),)
    block_lo = (
        _Insn(0x5020, "cmp", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x5022, "jbe", (_Operand(2, imm=0x5030, size=2),)),
    )
    blocks = {
        0x5000: block_hi,
        0x5010: block_mid,
        0x5020: block_lo,
    }
    project.factory = SimpleNamespace(
        block=lambda addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=blocks.get(addr, ())))
    )

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x5000, 0x5002)

    assert decoded is not None
    assert decoded.expr is not None
    assert isinstance(decoded.expr, CBinaryOp)


def test_translate_cmp_jcc_guard_decodes_32bit_call_return_stack_pair():
    project = _project()
    codegen = _codegen([])
    hi = _stack(-2, codegen, "goal_hi")
    lo = _stack(-4, codegen, "goal_lo")
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {
        hi.variable: hi,
        lo.variable: lo,
    }
    codegen.cfunc.unified_local_vars = {}
    codegen._func = SimpleNamespace(info={ANNOTATION_KEY: {"stack_vars": {-4: {"name": "goal"}}}})

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands
            self.size = 1

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "dx",
                5: "bp",
            }.get(reg, "")

    call_insn = _Insn(0x4FFE, "call", (_Operand(2, imm=0x6000, size=2),))
    block_hi = (
        _Insn(0x5000, "cmp", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x5002, "jle", (_Operand(2, imm=0x5010, size=2),)),
    )
    block_mid = (_Insn(0x5010, "jge", (_Operand(2, imm=0x5020, size=2),)),)
    block_lo = (
        _Insn(0x5020, "cmp", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x5022, "jbe", (_Operand(2, imm=0x5030, size=2),)),
    )
    blocks = {
        0x5000: block_hi,
        0x5010: block_mid,
        0x5020: block_lo,
    }
    project.factory = SimpleNamespace(
        block=lambda addr, opt_level=0: SimpleNamespace(capstone=SimpleNamespace(insns=blocks.get(addr, ())))
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: SimpleNamespace(name="clock") if addr == 0x6000 else None
        )
    )
    codegen._inertia_jcc_function_insns_8616 = (call_insn, *block_hi, *block_mid, *block_lo)

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x5000, 0x5002)

    assert decoded is not None
    assert decoded.expr is None
    assert decoded.op == "CmpLE"
    assert isinstance(decoded.lhs, CFunctionCall)
    assert getattr(decoded.lhs, "callee_target", None) == "clock"
    assert isinstance(decoded.rhs, CVariable)
    assert isinstance(decoded.rhs.variable, SimStackVariable)
    assert decoded.rhs.variable.offset == -4
    assert decoded.rhs.variable.size == 4
    assert decoded.rhs.variable.name == "stack_bp_m4_b4"
    assert decoded.consumed_branch_keys == ((0x5010, 0x5010), (0x5022, 0x5020))
    assert not _expr_contains_register(project, decoded.lhs, "dx")
    assert not _expr_contains_register(project, decoded.lhs, "ax")
    assert codegen._inertia_jcc_wide_call_return_pair_materialized_8616 == 1


def test_translate_cmp_jcc_guard_decodes_call_return_from_previous_linear_block():
    project = _project()
    codegen = _codegen([])
    codegen.cfunc.addr = 0x4FFA
    hi = _stack(-2, codegen, "goal_hi")
    lo = _stack(-4, codegen, "goal_lo")
    codegen.cfunc.arg_list = ()
    codegen.cfunc.variables_in_use = {
        hi.variable: hi,
        lo.variable: lo,
    }
    codegen.cfunc.unified_local_vars = {}
    codegen._func = SimpleNamespace(info={ANNOTATION_KEY: {"stack_vars": {-4: {"name": "goal"}}}})

    class _Mem:
        def __init__(self, base=0, disp=0):
            self.base = base
            self.disp = disp

    class _Operand:
        def __init__(self, type_, *, reg=0, imm=0, mem=None, size=2):
            self.type = type_
            self.reg = reg
            self.imm = imm
            self.mem = mem if mem is not None else _Mem()
            self.size = size

    class _Insn:
        def __init__(self, address, mnemonic, operands, *, size=1):
            self.address = address
            self.mnemonic = mnemonic
            self.operands = operands
            self.size = size

        @staticmethod
        def reg_name(reg):
            return {
                1: "ax",
                2: "dx",
                5: "bp",
            }.get(reg, "")

    store_lo = _Insn(0x4FFA, "mov", (_Operand(3, mem=_Mem(5, -4), size=2), _Operand(1, reg=1, size=2)), size=2)
    store_hi = _Insn(0x4FFC, "mov", (_Operand(3, mem=_Mem(5, -2), size=2), _Operand(1, reg=2, size=2)), size=2)
    call_insn = _Insn(0x4FFE, "call", (_Operand(2, imm=0x6000, size=2),), size=2)
    block_hi = (
        _Insn(0x5000, "cmp", (_Operand(1, reg=2, size=2), _Operand(3, mem=_Mem(5, -2), size=2))),
        _Insn(0x5002, "jle", (_Operand(2, imm=0x5010, size=2),)),
    )
    block_mid = (_Insn(0x5010, "jge", (_Operand(2, imm=0x5020, size=2),)),)
    block_lo = (
        _Insn(0x5020, "cmp", (_Operand(1, reg=1, size=2), _Operand(3, mem=_Mem(5, -4), size=2))),
        _Insn(0x5022, "jbe", (_Operand(2, imm=0x5030, size=2),)),
    )
    blocks = {
        0x4FFA: (store_lo,),
        0x4FFC: (store_hi,),
        0x4FFE: (call_insn,),
        0x5000: block_hi,
        0x5010: block_mid,
        0x5020: block_lo,
    }
    project.factory = SimpleNamespace(
        block=lambda addr, num_inst=None, opt_level=0: SimpleNamespace(
            capstone=SimpleNamespace(insns=blocks.get(addr, ()))
        )
    )
    project.loader = SimpleNamespace(main_object=SimpleNamespace(min_addr=0x1000), min_addr=0x1000)
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: (
                SimpleNamespace(name="clock", prototype=SimpleNamespace(args=())) if addr == 0x6000 else None
            )
        )
    )
    codegen._inertia_jcc_function_insns_8616 = (*block_hi, *block_mid, *block_lo)

    decoded = _translate_cmp_jcc_guard_8616(project, codegen, 0x5000, 0x5002)

    assert decoded is not None
    assert decoded.op == "CmpLE"
    assert isinstance(decoded.lhs, CFunctionCall)
    assert getattr(decoded.lhs, "callee_target", None) == "clock"
    assert isinstance(decoded.rhs, CVariable)
    assert isinstance(decoded.rhs.variable, SimStackVariable)
    assert decoded.rhs.variable.offset == -4
    assert decoded.rhs.variable.size == 4
    assert decoded.rhs.variable.name == "stack_bp_m4_b4"
    assert codegen._inertia_jcc_wide_call_return_pair_materialized_8616 == 1
