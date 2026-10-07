from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CBreak,
    CConstant,
    CDoWhileLoop,
    CExpressionStatement,
    CForLoop,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CReturn,
    CStatements,
    CSwitchCase,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.postprocess.decompiler_postprocess_stage import (
    _repair_conditional_continue_guards_from_evidence_pass_8616,
    _repair_hoisted_jcc_target_copies_from_evidence_pass_8616,
    _repair_pretest_loop_break_guards_from_evidence_pass_8616,
    _repair_switch_loop_exit_returns_from_evidence_pass_8616,
)
from inertia.postprocess.decompiler_postprocess_utils import _same_c_expression_8616
from inertia.structuring.decompiler_structuring_stage import _restore_not_shift_conditions_structuring_8616

from inertia.structuring.loop_body_repair import (
    ConditionalContinueEvidence8616,
    HoistedJccTargetCopyEvidence8616,
    PretestLoopGuardEvidence8616,
    SwitchLoopExitReturnEvidence8616,
    _classify_pretest_targets_from_cfg_8616,
    prune_redundant_loop_break_carriers_8616,
    recover_stack_accumulator_loop_evidence_8616,
    repair_conditional_continue_guards_from_evidence_8616,
    repair_empty_counted_loop_body_from_evidence_8616,
    repair_hoisted_jcc_target_copies_from_evidence_8616,
    repair_pretest_loop_break_guards_from_evidence_8616,
    repair_switch_loop_exit_returns_from_evidence_8616,
    repair_synthetic_internal_calls_from_evidence_8616,
)
from inertia.structuring.simple_loop_recovery import InsnSummary8616


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.cfunc = None
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


class _CfgNode:
    def __init__(self, addr: int, size: int = 1) -> None:
        self.addr = addr
        self.size = size


class _CfgGraph:
    def __init__(self, nodes: tuple[_CfgNode, ...], edges: dict[_CfgNode, tuple[_CfgNode, ...]]) -> None:
        self.nodes = nodes
        self._edges = edges

    def successors(self, node: _CfgNode) -> tuple[_CfgNode, ...]:
        return self._edges.get(node, ())


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def test_pretest_target_classification_uses_cfg_cycle_not_address_order() -> None:
    test = _CfgNode(0x1000, 8)
    lower_exit = _CfgNode(0x1010, 4)
    higher_body = _CfgNode(0x1020, 4)
    latch = _CfgNode(0x1030, 4)
    graph = _CfgGraph(
        (test, lower_exit, higher_body, latch),
        {
            test: (lower_exit, higher_body),
            higher_body: (latch,),
            latch: (test,),
        },
    )
    function = SimpleNamespace(graph=graph)

    classified = _classify_pretest_targets_from_cfg_8616(function, 0x1006, 0x1010, 0x1020)

    assert classified == (0x1020, 0x1010)


def test_pretest_target_classification_refuses_ambiguous_cfg_roles() -> None:
    test = _CfgNode(0x1000, 8)
    first = _CfgNode(0x1010, 4)
    second = _CfgNode(0x1020, 4)
    graph = _CfgGraph(
        (test, first, second),
        {
            first: (test,),
            second: (test,),
        },
    )
    function = SimpleNamespace(graph=graph)

    assert _classify_pretest_targets_from_cfg_8616(function, 0x1006, 0x1010, 0x1020) is None


def test_pretest_target_classification_refuses_function_without_cfg_graph() -> None:
    function = SimpleNamespace(addr=0x1000, size=0x40)

    assert _classify_pretest_targets_from_cfg_8616(function, 0x1006, 0x1010, 0x1020) is None


def test_pretest_evidence_recovers_short_circuit_predecessor(monkeypatch) -> None:
    import inertia.structuring.loop_body_repair as loop_body_repair

    predecessor = _CfgNode(0x1000, 0x10)
    continuation = _CfgNode(0x1010, 0x10)
    body = _CfgNode(0x1020, 0x10)
    exit_node = _CfgNode(0x1040, 0x10)
    graph = _CfgGraph(
        (predecessor, continuation, body, exit_node),
        {
            predecessor: (continuation, exit_node),
            continuation: (body, exit_node),
        },
    )
    function = SimpleNamespace(graph=graph)

    def branch(address: int, mnemonic: str, target: int) -> SimpleNamespace:
        return SimpleNamespace(
            address=address,
            mnemonic=mnemonic,
            operands=(SimpleNamespace(type=2, imm=target),),
        )

    monkeypatch.setattr(
        loop_body_repair,
        "_linear_capstone_insns_8616",
        lambda _project, _function: (
            branch(0x1006, "jg", 0x1010),
            branch(0x1008, "jmp", 0x1040),
        ),
    )
    seed = PretestLoopGuardEvidence8616(
        branch_addr=0x1016,
        body_target=0x1020,
        exit_target=0x1040,
        mnemonic="jle",
        body_condition_op="CmpLE",
    )

    recovered = loop_body_repair._recover_short_circuit_pretest_guard_evidence_8616(
        SimpleNamespace(),
        function,
        (seed,),
    )

    assert recovered == (
        PretestLoopGuardEvidence8616(
            branch_addr=0x1006,
            body_target=0x1010,
            exit_target=0x1040,
            mnemonic="jg",
            body_condition_op="CmpGT",
        ),
    )


def test_pretest_evidence_refuses_ambiguous_short_circuit_successor(monkeypatch) -> None:
    import inertia.structuring.loop_body_repair as loop_body_repair

    predecessor = _CfgNode(0x1000, 0x10)
    continuation = _CfgNode(0x1010, 0x10)
    exit_node = _CfgNode(0x1040, 0x10)
    function = SimpleNamespace(
        graph=_CfgGraph(
            (predecessor, continuation, exit_node),
            {predecessor: (continuation, exit_node)},
        )
    )
    operand = SimpleNamespace(type=2, imm=0x1010)
    jump_operand = SimpleNamespace(type=2, imm=0x1040)
    monkeypatch.setattr(
        loop_body_repair,
        "_linear_capstone_insns_8616",
        lambda _project, _function: (
            SimpleNamespace(address=0x1006, mnemonic="jg", operands=(operand,)),
            SimpleNamespace(address=0x1008, mnemonic="jmp", operands=(jump_operand,)),
        ),
    )
    seeds = (
        PretestLoopGuardEvidence8616(0x1014, 0x1020, 0x1040, "jle", "CmpLE"),
        PretestLoopGuardEvidence8616(0x1018, 0x1028, 0x1040, "jg", "CmpGT"),
    )

    recovered = loop_body_repair._recover_short_circuit_pretest_guard_evidence_8616(
        SimpleNamespace(),
        function,
        seeds,
    )

    assert recovered == ()


def _stack(offset: int, codegen, *, name: str = "local"):
    return CVariable(SimStackVariable(offset, 2, base="bp", name=name), codegen=codegen)


def _summary(mnemonic: str, op0_kind=None, op0_value=None, op1_kind=None, op1_value=None):
    return InsnSummary8616(
        mnemonic=mnemonic,
        op0_kind=op0_kind,
        op0_value=op0_value,
        op1_kind=op1_kind,
        op1_value=op1_value,
        op0_size=2,
        op1_size=2,
    )


def test_structuring_not_shift_restore_reaches_cfunc_body_root():
    codegen = _DummyCodegen()
    cl_pause = CVariable("clPause", codegen=codegen)
    condition = CBinaryOp(
        "Shr",
        CUnaryOp("Not", cl_pause, codegen=codegen),
        _const(16, codegen),
        codegen=codegen,
    )
    guarded = CIfElse(
        [(condition, CStatements([CReturn(_const(1, codegen), codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    body = CStatements([guarded], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=body)

    changed = _restore_not_shift_conditions_structuring_8616(codegen)

    assert changed is True
    restored = guarded.condition_and_nodes[0][0]
    assert isinstance(restored, CBinaryOp)
    assert restored.op == "CmpEQ"
    restored_operand = restored.lhs
    assert isinstance(restored_operand, CBinaryOp)
    assert restored_operand.op == "Shr"
    assert restored_operand.lhs is cl_pause
    assert isinstance(restored.rhs, CConstant)
    assert restored.rhs.value == 0


def test_stack_accumulator_loop_evidence_recovers_descending_sum_pattern():
    evidence = recover_stack_accumulator_loop_evidence_8616(
        [
            _summary("mov", "bp_mem", -2, "imm", 0),
            _summary("dec", "bp_mem", -4),
            _summary("mov", "reg", "ax", "bp_mem", -4),
            _summary("add", "bp_mem", -2, "reg", "ax"),
        ]
    )

    assert len(evidence) == 1
    assert evidence[0].accumulator_disp == -2
    assert evidence[0].induction_disp == -4
    assert evidence[0].step == -1


def test_empty_counted_loop_body_repair_uses_bp_slot_evidence(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    total_var = _stack(-2, codegen, name="total")
    update = CAssignment(
        total_var,
        CBinaryOp("Add", total_var, i_var, codegen=codegen),
        codegen=codegen,
    )
    loop = CForLoop(
        CAssignment(i_var, _stack(4, codegen, name="max_level"), codegen=codegen),
        CBinaryOp("CmpNE", i_var, _const(0, codegen), codegen=codegen),
        CAssignment(i_var, CBinaryOp("Sub", i_var, _const(1, codegen), codegen=codegen), codegen=codegen),
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    body = CStatements([loop, update, CReturn(total_var, codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=body, statements=body)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x40))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "_function_instruction_summaries_8616",
        lambda _project, _function: [
            _summary("mov", "bp_mem", -2, "imm", 0),
            _summary("dec", "bp_mem", -4),
            _summary("mov", "reg", "ax", "bp_mem", -4),
            _summary("add", "bp_mem", -2, "reg", "ax"),
        ],
    )

    changed = repair_empty_counted_loop_body_from_evidence_8616(project, codegen)

    assert changed is True
    assert isinstance(body.statements[0], CAssignment)
    assert body.statements[1] is loop
    assert tuple(loop.body.statements) == (update,)
    assert update not in body.statements[2:]
    stats = codegen._inertia_structuring_loop_body_repair_stats_8616
    assert stats.materialized_count == 1


def test_conditional_continue_repair_removes_false_break_guard(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    left = _stack(-8, codegen, name="left")
    right = _stack(-10, codegen, name="right")
    false_break = CIfBreak(CBinaryOp("CmpLE", left, right, codegen=codegen), codegen=codegen, cstyle_ifs=True)
    guarded_store = CAssignment(_stack(-2, codegen, name="tmp"), left, codegen=codegen)
    guarded = CIfElse(
        [
            (
                CBinaryOp("CmpGT", left, right, codegen=codegen),
                CStatements([guarded_store], codegen=codegen),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    loop = CForLoop(
        CAssignment(i_var, _const(1, codegen), codegen=codegen),
        CBinaryOp("CmpLT", i_var, _const(6, codegen), codegen=codegen),
        CAssignment(i_var, CBinaryOp("Add", i_var, _const(1, codegen), codegen=codegen), codegen=codegen),
        CStatements([false_break, guarded], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x40))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_conditional_continue_evidence_8616",
        lambda _project, _function: (ConditionalContinueEvidence8616(0x4020, 0x4030, 0x4040),),
    )

    changed = repair_conditional_continue_guards_from_evidence_8616(project, codegen)

    assert changed is True
    assert tuple(loop.body.statements) == (guarded,)
    stats = codegen._inertia_structuring_conditional_continue_stats_8616
    assert stats.materialized_count == 1


def test_conditional_continue_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    false_break = CIfBreak(CBinaryOp("CmpLE", _const(1, codegen), _const(2, codegen), codegen=codegen), codegen=codegen)
    loop = CWhileLoop(_const(1, codegen), CStatements([false_break], codegen=codegen), codegen=codegen)
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    codegen._inertia_conditional_continue_guard_structuring_pass_ran_8616 = True
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x40))
        ),
    )

    def fail_evidence_recovery(_project, _function):
        raise AssertionError("postprocess fallback should not recover evidence after structuring ran")

    monkeypatch.setattr(
        loop_body_repair,
        "recover_conditional_continue_evidence_8616",
        fail_evidence_recovery,
    )

    changed = _repair_conditional_continue_guards_from_evidence_pass_8616(project, codegen)

    assert changed is False
    assert tuple(loop.body.statements) == (false_break,)


def test_synthetic_internal_call_repair_prunes_no_summary_internal_target():
    codegen = _DummyCodegen()
    internal_call = CFunctionCall("sub_10032", None, [], codegen=codegen)
    internal_call.callee_func = SimpleNamespace(addr=0x10032, name="sub_10032")
    external_call = CFunctionCall("sub_105e6", None, [_const(618, codegen)], codegen=codegen)
    external_call.callee_func = SimpleNamespace(addr=0x105E6, name="sub_105e6")
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([CExpressionStatement(internal_call, codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop, CExpressionStatement(external_call, codegen=codegen)], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x10010, body=root, statements=root)
    codegen._inertia_callsite_summaries = {id(external_call): object()}

    function = SimpleNamespace(
        addr=0x10010,
        block_addrs_set={0x10010, 0x10028, 0x10038, 0x1003B},
        get_call_sites=lambda: (0x10042,),
        get_call_target=lambda _addr: 0x105E6,
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        _inertia_current_decompile_function_8616=function,
        factory=SimpleNamespace(block=lambda addr, **_kwargs: SimpleNamespace(size={0x10028: 0x10}.get(addr, 4))),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: function)),
    )

    changed = repair_synthetic_internal_calls_from_evidence_8616(project, codegen)

    assert changed is True
    assert tuple(loop.body.statements) == ()
    assert tuple(root.statements) == (loop, root.statements[1])
    assert root.statements[1].expr is external_call
    stats = codegen._inertia_structuring_synthetic_internal_call_stats_8616
    assert stats.materialized_count == 1
    assert stats.classified_fact_count == 1


def test_pretest_loop_guard_repair_inverts_body_edge_break_guard(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_var = _stack(-2, codegen, name="i")
    limit = CVariable("cszMenu", codegen=codegen)
    condition = CBinaryOp(
        "CmpLT",
        i_var,
        limit,
        codegen=codegen,
        tags={"ins_addr": 0x409d, "inertia_jcc_materialized_8616": True},
    )
    false_break = CIfBreak(condition, codegen=codegen, cstyle_ifs=True)
    body_call_seen = CAssignment(_stack(-4, codegen, name="call_seen"), i_var, codegen=codegen, tags={"ins_addr": 0x40a2})
    loop = CWhileLoop(_const(1, codegen), CStatements([false_break, body_call_seen], codegen=codegen), codegen=codegen)
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_pretest_loop_guard_evidence_8616",
        lambda _project, _function: (PretestLoopGuardEvidence8616(0x409d, 0x40a2, 0x40ca),),
    )

    changed = repair_pretest_loop_break_guards_from_evidence_8616(project, codegen)

    assert changed is True
    assert isinstance(false_break.condition, CUnaryOp)
    assert false_break.condition.op == "Not"
    assert false_break.condition.operand is condition
    stats = codegen._inertia_structuring_pretest_loop_guard_stats_8616
    assert stats.materialized_count == 1


def test_pretest_loop_guard_repair_refuses_already_complementary_break_guard(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_var = _stack(-2, codegen, name="i")
    limit = CVariable("limit", codegen=codegen)
    condition = CBinaryOp(
        "CmpGT",
        i_var,
        limit,
        codegen=codegen,
        tags={"ins_addr": 0x409D, "inertia_jcc_materialized_8616": True},
    )
    break_stmt = CIfElse(
        [(condition, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    body_update = CAssignment(
        i_var,
        CBinaryOp("Add", i_var, _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x40A2},
    )
    loop = CWhileLoop(_const(1, codegen), CStatements([break_stmt, body_update], codegen=codegen), codegen=codegen)
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_pretest_loop_guard_evidence_8616",
        lambda _project, _function: (PretestLoopGuardEvidence8616(0x409D, 0x40A2, 0x40CA, "jle"),),
    )

    changed = repair_pretest_loop_break_guards_from_evidence_8616(project, codegen)

    assert changed is False
    assert break_stmt.condition_and_nodes[0][0] is condition


def test_pretest_loop_guard_repair_prunes_body_break_before_complementary_return(monkeypatch) -> None:
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    arg = CVariable("arg", codegen=codegen)
    zero = _const(0, codegen)
    body_condition = CBinaryOp(
        "CmpGT",
        arg,
        zero,
        codegen=codegen,
        tags={"ins_addr": 0x1014, "inertia_jcc_materialized_8616": True},
    )
    false_break = CIfBreak(body_condition, codegen=codegen, cstyle_ifs=True)
    exit_condition = CBinaryOp("CmpLE", arg, zero, codegen=codegen)
    total = CVariable("total", codegen=codegen)
    return_guard = CIfElse(
        [(exit_condition, CStatements([CReturn(total, codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    body_update = CAssignment(total, arg, codegen=codegen, tags={"ins_addr": 0x101F})
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([false_break, return_guard, body_update], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x1000))),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_pretest_loop_guard_evidence_8616",
        lambda _project, _function: (
            PretestLoopGuardEvidence8616(0x1014, 0x101F, 0x1019, "jle", "CmpGT"),
        ),
    )

    changed = repair_pretest_loop_break_guards_from_evidence_8616(project, codegen)

    assert changed is True
    assert tuple(loop.body.statements) == (return_guard, body_update)
    stats = codegen._inertia_structuring_pretest_loop_guard_stats_8616
    assert stats.materialized_count == 1


def test_pretest_loop_guard_repair_flattens_wrapped_break_guard(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_var = _stack(-2, codegen, name="i")
    limit = CVariable("limit", codegen=codegen)
    condition = CBinaryOp(
        "CmpLT",
        i_var,
        limit,
        codegen=codegen,
        tags={"ins_addr": 0x409D, "inertia_jcc_materialized_8616": True},
    )
    false_break = CIfElse(
        [(condition, CStatements([CReturn(None, codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    body_update = CAssignment(
        i_var,
        CBinaryOp("Add", i_var, _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x40A2},
    )
    loop_body = CStatements(
        [CStatements([false_break], codegen=codegen), CStatements([body_update], codegen=codegen)],
        codegen=codegen,
    )
    loop = CWhileLoop(_const(1, codegen), loop_body, codegen=codegen)
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_pretest_loop_guard_evidence_8616",
        lambda _project, _function: (PretestLoopGuardEvidence8616(0x409D, 0x40A2, 0x40CA),),
    )

    changed = repair_pretest_loop_break_guards_from_evidence_8616(project, codegen)

    assert changed is True
    assert loop_body.statements == [false_break, body_update]
    restored = false_break.condition_and_nodes[0][0]
    assert isinstance(restored, CUnaryOp)
    assert restored.op == "Not"
    assert restored.operand is condition


def test_pretest_loop_guard_repair_reaches_while_nested_in_do_while(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_var = _stack(-2, codegen, name="i")
    limit = CVariable("limit", codegen=codegen)
    condition = CBinaryOp(
        "CmpLT",
        i_var,
        limit,
        codegen=codegen,
        tags={"ins_addr": 0x409D, "inertia_jcc_materialized_8616": True},
    )
    false_break = CIfElse(
        [(condition, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    body_update = CAssignment(
        i_var,
        CBinaryOp("Add", i_var, _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x40A2},
    )
    inner_loop = CWhileLoop(
        _const(1, codegen),
        CStatements([false_break, body_update], codegen=codegen),
        codegen=codegen,
    )
    outer_loop = CDoWhileLoop(
        CBinaryOp("CmpLT", i_var, limit, codegen=codegen),
        CStatements([CAssignment(_stack(-8, codegen, name="setup"), _const(0, codegen), codegen=codegen), inner_loop],
                    codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([outer_loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_pretest_loop_guard_evidence_8616",
        lambda _project, _function: (PretestLoopGuardEvidence8616(0x409D, 0x40A2, 0x40CA),),
    )

    changed = repair_pretest_loop_break_guards_from_evidence_8616(project, codegen)

    assert changed is True
    restored = false_break.condition_and_nodes[0][0]
    assert isinstance(restored, CUnaryOp)
    assert restored.op == "Not"
    assert restored.operand is condition


def test_pretest_loop_guard_repair_reaches_while_nested_in_for(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    outer_i = _stack(-6, codegen, name="outer_i")
    inner_i = _stack(-2, codegen, name="inner_i")
    limit = CVariable("limit", codegen=codegen)
    condition = CBinaryOp(
        "CmpLT",
        inner_i,
        limit,
        codegen=codegen,
        tags={"ins_addr": 0x409D, "inertia_jcc_materialized_8616": True},
    )
    false_break = CIfElse(
        [(condition, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    body_update = CAssignment(
        inner_i,
        CBinaryOp("Add", inner_i, _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x40A2},
    )
    inner_loop = CWhileLoop(
        _const(1, codegen),
        CStatements([false_break, body_update], codegen=codegen),
        codegen=codegen,
    )
    outer_loop = CForLoop(
        CAssignment(outer_i, _const(0, codegen), codegen=codegen),
        CBinaryOp("CmpLT", outer_i, limit, codegen=codegen),
        CAssignment(outer_i, CBinaryOp("Add", outer_i, _const(1, codegen), codegen=codegen), codegen=codegen),
        CStatements([CAssignment(inner_i, outer_i, codegen=codegen), inner_loop], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([outer_loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_pretest_loop_guard_evidence_8616",
        lambda _project, _function: (PretestLoopGuardEvidence8616(0x409D, 0x40A2, 0x40CA),),
    )

    changed = repair_pretest_loop_break_guards_from_evidence_8616(project, codegen)

    assert changed is True
    restored = false_break.condition_and_nodes[0][0]
    assert isinstance(restored, CUnaryOp)
    assert restored.op == "Not"
    assert restored.operand is condition


def test_pretest_loop_guard_repair_uses_guard_branch_tag_when_body_targets_are_ambiguous(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_var = _stack(-2, codegen, name="i")
    limit = CVariable("limit", codegen=codegen)
    condition = CBinaryOp("CmpLT", i_var, limit, codegen=codegen)
    false_break = CIfElse(
        [(condition, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    false_break.tags = {"ins_addr": 0x409D, "inertia_jcc_materialized_8616": True}
    first_body = CAssignment(
        i_var,
        CBinaryOp("Add", i_var, _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x40A2},
    )
    second_body = CAssignment(_stack(-4, codegen, name="other"), i_var, codegen=codegen, tags={"ins_addr": 0x40B0})
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([false_break, first_body, second_body], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_pretest_loop_guard_evidence_8616",
        lambda _project, _function: (
            PretestLoopGuardEvidence8616(0x409D, 0x40A2, 0x40CA),
            PretestLoopGuardEvidence8616(0x409E, 0x40B0, 0x40D0),
        ),
    )

    changed = repair_pretest_loop_break_guards_from_evidence_8616(project, codegen)

    assert changed is True
    restored = false_break.condition_and_nodes[0][0]
    assert isinstance(restored, CUnaryOp)
    assert restored.op == "Not"
    assert restored.operand is condition


def test_pretest_loop_guard_repair_prefers_guard_jcc_tag_over_condition_cmp_tag(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_var = _stack(-2, codegen, name="i")
    limit = CVariable("limit", codegen=codegen)
    condition = CBinaryOp(
        "CmpLT",
        i_var,
        limit,
        codegen=codegen,
        tags={"ins_addr": 0x4098},
    )
    false_break = CIfElse(
        [(condition, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    false_break.tags = {"ins_addr": 0x409D, "vex_block_addr": 0x4098}
    first_body = CAssignment(
        i_var,
        CBinaryOp("Add", i_var, _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x40A2},
    )
    second_body = CAssignment(_stack(-4, codegen, name="other"), i_var, codegen=codegen, tags={"ins_addr": 0x40B0})
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([false_break, first_body, second_body], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_pretest_loop_guard_evidence_8616",
        lambda _project, _function: (
            PretestLoopGuardEvidence8616(0x409D, 0x40A2, 0x40CA),
            PretestLoopGuardEvidence8616(0x409E, 0x40B0, 0x40D0),
        ),
    )

    changed = repair_pretest_loop_break_guards_from_evidence_8616(project, codegen)

    assert changed is True
    restored = false_break.condition_and_nodes[0][0]
    assert isinstance(restored, CUnaryOp)
    assert restored.op == "Not"
    assert restored.operand is condition


def test_pretest_loop_guard_repair_prefers_exact_body_target_without_branch_tag(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_var = _stack(-2, codegen, name="i")
    limit = CVariable("limit", codegen=codegen)
    condition = CBinaryOp("CmpLT", i_var, limit, codegen=codegen)
    false_break = CIfElse(
        [(condition, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    first_body = CAssignment(
        i_var,
        CBinaryOp("Add", i_var, _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x40A2},
    )
    later_body = CAssignment(_stack(-4, codegen, name="later"), i_var, codegen=codegen, tags={"ins_addr": 0x40B0})
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([false_break, first_body, later_body], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_pretest_loop_guard_evidence_8616",
        lambda _project, _function: (
            PretestLoopGuardEvidence8616(0x409D, 0x40A2, 0x40CA),
            PretestLoopGuardEvidence8616(0x409E, 0x40A4, 0x40D0),
        ),
    )

    changed = repair_pretest_loop_break_guards_from_evidence_8616(project, codegen)

    assert changed is True
    restored = false_break.condition_and_nodes[0][0]
    assert isinstance(restored, CUnaryOp)
    assert restored.op == "Not"
    assert restored.operand is condition


def test_pretest_loop_guard_evidence_refuses_body_fallback_for_mismatched_jcc_tag() -> None:
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    condition = CBinaryOp(
        "CmpLT",
        _stack(-2, codegen, name="i"),
        CVariable("limit", codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x4098},
    )
    guard = CIfElse(
        [(condition, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    guard.tags = {"ins_addr": 0x409D}
    body = CAssignment(
        _stack(-2, codegen, name="i"),
        _const(1, codegen),
        codegen=codegen,
        tags={"ins_addr": 0x40A2},
    )
    unrelated = PretestLoopGuardEvidence8616(0x409E, 0x40A2, 0x40CA)

    matched = loop_body_repair._pretest_evidence_for_loop_body_8616(
        condition,
        body,
        (unrelated,),
        guard=guard,
    )

    assert matched is None


def test_pretest_loop_guard_repair_advances_past_already_inverted_guard(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_var = _stack(-2, codegen, name="i")
    limit = CVariable("limit", codegen=codegen)
    first_condition = CBinaryOp(
        "CmpLT",
        i_var,
        limit,
        codegen=codegen,
        tags={"ins_addr": 0x409D, "inertia_jcc_materialized_8616": True},
    )
    second_condition = CBinaryOp(
        "CmpLE",
        CVariable("value", codegen=codegen),
        limit,
        codegen=codegen,
        tags={"ins_addr": 0x40A8, "inertia_jcc_materialized_8616": True},
    )
    first_break = CIfElse(
        [(CUnaryOp("Not", first_condition, codegen=codegen), CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    second_break = CIfElse(
        [(second_condition, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    pure_helper = CFunctionCall(None, SimpleNamespace(name="SEG_U16"), [_const(0, codegen), i_var], codegen=codegen)
    body_update = CAssignment(
        i_var,
        CBinaryOp("Add", i_var, _const(1, codegen), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x40B0},
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements(
            [
                CStatements([CAssignment(_stack(-8, codegen, name="prep1"), _const(0, codegen), codegen=codegen)],
                            codegen=codegen),
                first_break,
                CStatements([CAssignment(_stack(-10, codegen, name="prep2"), pure_helper, codegen=codegen)],
                            codegen=codegen),
                second_break,
                body_update,
            ],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_pretest_loop_guard_evidence_8616",
        lambda _project, _function: (PretestLoopGuardEvidence8616(0x40A8, 0x40B0, 0x40CA),),
    )

    changed = repair_pretest_loop_break_guards_from_evidence_8616(project, codegen)

    assert changed is True
    restored = second_break.condition_and_nodes[0][0]
    assert isinstance(restored, CUnaryOp)
    assert restored.op == "Not"
    assert restored.operand is second_condition


def test_switch_loop_exit_return_repair_adds_missing_return_case_and_prunes_tail(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    selector = CVariable("ax", codegen=codegen)
    case_body = CStatements(
        [CAssignment(_stack(-2, codegen, name="seen"), _const(1, codegen), codegen=codegen)],
        codegen=codegen,
    )
    switch = CSwitchCase(selector, [(69, case_body)], None, codegen=codegen)
    loop = CWhileLoop(_const(1, codegen), CStatements([switch], codegen=codegen), codegen=codegen)
    unresolved_tail = CReturn(
        CBinaryOp("Sub", CVariable("vvar_127", codegen=codegen), _const(27, codegen), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop, unresolved_tail], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_switch_loop_exit_return_evidence_8616",
        lambda _project, _function: (SwitchLoopExitReturnEvidence8616(27, 0x441A, 0x447B),),
    )

    changed = repair_switch_loop_exit_returns_from_evidence_8616(project, codegen)

    assert changed is True
    assert len(root.statements) == 1
    assert switch.cases[-1][0] == 27
    exit_body = switch.cases[-1][1]
    assert isinstance(exit_body, CStatements)
    assert len(exit_body.statements) == 1
    assert isinstance(exit_body.statements[0], CReturn)
    stats = codegen._inertia_structuring_switch_loop_exit_return_stats_8616
    assert stats.materialized_count == 1
    assert stats.trailing_unreachable_pruned_count == 1


def test_switch_loop_exit_return_repair_adds_case_to_unique_conditional_loop_and_keeps_tail(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    selector = CVariable("ax", codegen=codegen)
    condition = CBinaryOp("CmpNE", selector, _const(69, codegen), codegen=codegen)
    switch = CSwitchCase(
        selector,
        [(69, CStatements([], codegen=codegen))],
        None,
        codegen=codegen,
    )
    loop = CWhileLoop(condition, CStatements([switch], codegen=codegen), codegen=codegen)
    reachable_tail = CReturn(None, codegen=codegen)
    root = CStatements([loop, reachable_tail], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_switch_loop_exit_return_evidence_8616",
        lambda _project, _function: (SwitchLoopExitReturnEvidence8616(27, 0x441A, 0x447B),),
    )

    changed = repair_switch_loop_exit_returns_from_evidence_8616(project, codegen)

    assert changed is True
    assert root.statements == [loop, reachable_tail]
    assert switch.cases[-1][0] == 27
    assert isinstance(switch.cases[-1][1].statements[0], CReturn)
    stats = codegen._inertia_structuring_switch_loop_exit_return_stats_8616
    assert stats.materialized_count == 1
    assert stats.trailing_unreachable_pruned_count == 0


def test_switch_loop_exit_return_repair_refuses_ambiguous_conditional_loops(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    selector = CVariable("ax", codegen=codegen)
    condition = CBinaryOp("CmpNE", selector, _const(69, codegen), codegen=codegen)
    switches = [
        CSwitchCase(selector, [(69, CStatements([], codegen=codegen))], None, codegen=codegen)
        for _index in range(2)
    ]
    loops = [
        CWhileLoop(condition, CStatements([switch], codegen=codegen), codegen=codegen)
        for switch in switches
    ]
    root = CStatements(loops, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_switch_loop_exit_return_evidence_8616",
        lambda _project, _function: (SwitchLoopExitReturnEvidence8616(27, 0x441A, 0x447B),),
    )

    changed = repair_switch_loop_exit_returns_from_evidence_8616(project, codegen)

    assert changed is False
    assert all(tuple(value for value, _body in switch.cases) == (69,) for switch in switches)
    stats = codegen._inertia_structuring_switch_loop_exit_return_stats_8616
    assert stats.refused_ambiguous_loop == 1


def test_switch_loop_exit_return_repair_publishes_evidence_without_candidate(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    root = CStatements([CReturn(_const(0, codegen), codegen=codegen)], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )

    monkeypatch.setattr(
        loop_body_repair,
        "recover_switch_loop_exit_return_evidence_8616",
        lambda _project, _function: (
            SwitchLoopExitReturnEvidence8616(27, 0x441A, 0x447B),
        ),
    )

    changed = repair_switch_loop_exit_returns_from_evidence_8616(project, codegen)

    assert changed is False
    stats = codegen._inertia_structuring_switch_loop_exit_return_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.refused_no_matching_loop == 1
    assert codegen._inertia_structuring_switch_loop_exit_return_evidence_8616 == (
        SwitchLoopExitReturnEvidence8616(27, 0x441A, 0x447B),
    )


def test_switch_loop_exit_return_repair_prunes_wrapped_return_tail_when_case_already_present(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    selector = CVariable("ax", codegen=codegen)
    exit_body = CStatements([CReturn(None, codegen=codegen)], codegen=codegen)
    switch = CSwitchCase(selector, [(27, exit_body)], None, codegen=codegen)
    loop = CWhileLoop(_const(1, codegen), CStatements([switch], codegen=codegen), codegen=codegen)
    unresolved_tail = CStatements(
        [
            CReturn(CVariable("vvar_127", codegen=codegen), codegen=codegen),
            CReturn(selector, codegen=codegen),
        ],
        codegen=codegen,
    )
    root = CStatements([loop, unresolved_tail], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_switch_loop_exit_return_evidence_8616",
        lambda _project, _function: (SwitchLoopExitReturnEvidence8616(27, 0x441A, 0x447B),),
    )

    changed = repair_switch_loop_exit_returns_from_evidence_8616(project, codegen)

    assert changed is True
    assert root.statements == [loop]
    stats = codegen._inertia_structuring_switch_loop_exit_return_stats_8616
    assert stats.materialized_count == 1
    assert stats.trailing_unreachable_pruned_count == 1


def test_switch_loop_exit_return_repair_refuses_loop_with_break(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    selector = CVariable("ax", codegen=codegen)
    switch = CSwitchCase(selector, [(69, CStatements([], codegen=codegen))], None, codegen=codegen)
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([switch, CBreak(codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    tail = CReturn(CVariable("vvar_127", codegen=codegen), codegen=codegen)
    root = CStatements([loop, tail], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_switch_loop_exit_return_evidence_8616",
        lambda _project, _function: (SwitchLoopExitReturnEvidence8616(27, 0x441A, 0x447B),),
    )

    changed = repair_switch_loop_exit_returns_from_evidence_8616(project, codegen)

    assert changed is False
    assert root.statements == [loop, tail]
    stats = codegen._inertia_structuring_switch_loop_exit_return_stats_8616
    assert stats.refused_loop_has_break == 1


def test_switch_loop_exit_return_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    selector = CVariable("ax", codegen=codegen)
    switch = CSwitchCase(selector, [(69, CStatements([], codegen=codegen))], None, codegen=codegen)
    loop = CWhileLoop(_const(1, codegen), CStatements([switch], codegen=codegen), codegen=codegen)
    tail = CReturn(CVariable("vvar_127", codegen=codegen), codegen=codegen)
    root = CStatements([loop, tail], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    codegen._inertia_switch_loop_exit_return_structuring_pass_ran_8616 = True
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )

    def fail_evidence_recovery(_project, _function):
        raise AssertionError("postprocess fallback should not recover evidence after structuring ran")

    monkeypatch.setattr(
        loop_body_repair,
        "recover_switch_loop_exit_return_evidence_8616",
        fail_evidence_recovery,
    )

    changed = _repair_switch_loop_exit_returns_from_evidence_pass_8616(project, codegen)

    assert changed is False
    assert root.statements == [loop, tail]


def test_pretest_loop_guard_repair_allows_pure_condition_carrier_prefix(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_var = _stack(-2, codegen, name="i")
    limit = CVariable("cszMenu", codegen=codegen)
    condition = CBinaryOp(
        "CmpLT",
        i_var,
        limit,
        codegen=codegen,
        tags={"ins_addr": 0x409d, "inertia_jcc_materialized_8616": True},
    )
    carrier = CStatements(
        [CAssignment(_stack(-6, codegen, name="tmp"), condition, codegen=codegen)],
        codegen=codegen,
    )
    false_break = CIfElse(
        [(condition, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    body_call_seen = CAssignment(_stack(-4, codegen, name="call_seen"), i_var, codegen=codegen, tags={"ins_addr": 0x40a2})
    loop = CWhileLoop(_const(1, codegen), CStatements([carrier, false_break, body_call_seen], codegen=codegen), codegen=codegen)
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_pretest_loop_guard_evidence_8616",
        lambda _project, _function: (PretestLoopGuardEvidence8616(0x409d, 0x40a2, 0x40ca),),
    )

    changed = repair_pretest_loop_break_guards_from_evidence_8616(project, codegen)

    assert changed is True
    restored = false_break.condition_and_nodes[0][0]
    assert isinstance(restored, CUnaryOp)
    assert restored.op == "Not"
    assert restored.operand is condition


def test_pretest_loop_guard_repair_moves_iterator_when_guard_is_already_exit_edge(monkeypatch) -> None:
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    induction = _stack(-2, codegen, name="i")
    limit = CVariable("limit", codegen=codegen)
    body_condition = CBinaryOp("CmpLT", induction, limit, codegen=codegen)
    first_break = CIfBreak(CUnaryOp("Not", body_condition, codegen=codegen), codegen=codegen)
    exit_condition = CBinaryOp(
        "CmpGE",
        induction,
        limit,
        codegen=codegen,
        tags={"ins_addr": 0x409D, "inertia_jcc_materialized_8616": True},
    )
    second_break = CIfBreak(exit_condition, codegen=codegen)
    iterator = CAssignment(
        induction,
        CBinaryOp("Add", induction, _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    body_statement = CAssignment(
        _stack(-4, codegen, name="seen"),
        induction,
        codegen=codegen,
        tags={"ins_addr": 0x40A2},
    )
    loop_body = CStatements(
        [CStatements([iterator], codegen=codegen), first_break, second_break, body_statement],
        codegen=codegen,
    )
    root = CStatements([CWhileLoop(_const(1, codegen), loop_body, codegen=codegen)], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_pretest_loop_guard_evidence_8616",
        lambda _project, _function: (
            PretestLoopGuardEvidence8616(
                0x409D,
                0x40A2,
                0x40CA,
                body_condition_op="CmpLT",
            ),
        ),
    )

    changed = repair_pretest_loop_break_guards_from_evidence_8616(project, codegen)

    assert changed is True
    assert loop_body.statements == [first_break, second_break, body_statement, iterator]
    stats = codegen._inertia_structuring_pretest_loop_guard_stats_8616
    assert stats.iterator_moved_count == 1
    assert stats.materialized_count == 1


def test_redundant_loop_break_carrier_prunes_exact_ssa_duplicate() -> None:
    codegen = _DummyCodegen()
    induction = _stack(-2, codegen, name="i")
    direct_global = CVariable(SimMemoryVariable(0x160, 2, name="cszMenu"), codegen=codegen)
    loaded_global = CVariable(SimMemoryVariable(0x160, 2, name="cszMenu"), codegen=codegen)
    first_carrier = CVariable(SimRegisterVariable(0, 2, name="vvar_356"), codegen=codegen)
    second_carrier = CVariable(SimRegisterVariable(2, 2, name="vvar_69"), codegen=codegen)
    prefix = CStatements(
        [
            CAssignment(first_carrier, loaded_global, codegen=codegen),
            CAssignment(second_carrier, first_carrier, codegen=codegen),
        ],
        codegen=codegen,
    )
    first_break = CIfElse(
        [
            (
                CUnaryOp(
                    "Not",
                    CBinaryOp("CmpLT", induction, direct_global, codegen=codegen),
                    codegen=codegen,
                ),
                CStatements([CBreak(codegen=codegen)], codegen=codegen),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    duplicate_break = CIfBreak(
        CBinaryOp("CmpGE", induction, second_carrier, codegen=codegen),
        codegen=codegen,
        cstyle_ifs=True,
    )
    body_statement = CAssignment(_stack(-4, codegen, name="seen"), induction, codegen=codegen)
    loop_body = CStatements([prefix, first_break, duplicate_break, body_statement], codegen=codegen)
    loop = CWhileLoop(_const(1, codegen), loop_body, codegen=codegen)
    root = CStatements([loop], codegen=codegen)
    codegen.cfunc = SimpleNamespace(body=root, statements=root)

    changed = prune_redundant_loop_break_carriers_8616(codegen)

    assert changed is True
    assert loop_body.statements == [prefix, first_break, body_statement]
    stats = codegen._inertia_redundant_loop_break_carrier_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_redundant_loop_break_carrier_refuses_different_global() -> None:
    codegen = _DummyCodegen()
    induction = _stack(-2, codegen, name="i")
    first_global = CVariable(SimMemoryVariable(0x160, 2, name="cszMenu"), codegen=codegen)
    second_global = CVariable(SimMemoryVariable(0x162, 2, name="otherLimit"), codegen=codegen)
    carrier = CVariable(SimRegisterVariable(0, 2, name="vvar_356"), codegen=codegen)
    prefix = CStatements([CAssignment(carrier, second_global, codegen=codegen)], codegen=codegen)
    first_break = CIfBreak(CBinaryOp("CmpGE", induction, first_global, codegen=codegen), codegen=codegen)
    second_break = CIfBreak(CBinaryOp("CmpGE", induction, carrier, codegen=codegen), codegen=codegen)
    loop_body = CStatements([prefix, first_break, second_break], codegen=codegen)
    root = CStatements([CWhileLoop(_const(1, codegen), loop_body, codegen=codegen)], codegen=codegen)
    codegen.cfunc = SimpleNamespace(body=root, statements=root)

    changed = prune_redundant_loop_break_carriers_8616(codegen)

    assert changed is False
    assert loop_body.statements == [prefix, first_break, second_break]
    stats = codegen._inertia_redundant_loop_break_carrier_stats_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1


def test_redundant_loop_break_carrier_preserves_prior_memory_effect() -> None:
    codegen = _DummyCodegen()
    induction = _stack(-2, codegen, name="i")
    global_value = CVariable(SimMemoryVariable(0x160, 2, name="cszMenu"), codegen=codegen)
    memory_store = CAssignment(global_value, _const(4, codegen), codegen=codegen)
    condition = CBinaryOp("CmpGE", induction, global_value, codegen=codegen)
    first_break = CIfBreak(condition, codegen=codegen)
    second_break = CIfBreak(condition, codegen=codegen)
    loop_body = CStatements([memory_store, first_break, second_break], codegen=codegen)
    root = CStatements([CWhileLoop(_const(1, codegen), loop_body, codegen=codegen)], codegen=codegen)
    codegen.cfunc = SimpleNamespace(body=root, statements=root)

    changed = prune_redundant_loop_break_carriers_8616(codegen)

    assert changed is True
    assert loop_body.statements == [memory_store, first_break]
    stats = codegen._inertia_redundant_loop_break_carrier_stats_8616
    assert stats.normalized_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_pretest_loop_guard_repair_consumes_call_return_carrier_for_empty_body(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    goal = CVariable(SimStackVariable(-4, 4, base="bp", name="goal"), codegen=codegen)
    call_target = SimpleNamespace(name="clock", prototype=None)
    carrier_call = CFunctionCall("clock", call_target, [], codegen=codegen, tags={"ins_addr": 0x401D})
    guard_call = CFunctionCall("clock", call_target, [], codegen=codegen, tags={"ins_addr": 0x401D})
    carrier_lhs = CVariable(SimRegisterVariable(0, 4, name="v15"), codegen=codegen)
    carrier = CAssignment(carrier_lhs, carrier_call, codegen=codegen, tags={"ins_addr": 0x401D})
    condition = CBinaryOp(
        "CmpLE",
        guard_call,
        goal,
        codegen=codegen,
        tags={"ins_addr": 0x4020, "inertia_jcc_materialized_8616": True},
    )
    false_break = CIfElse(
        [(condition, CStatements([CBreak(codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    loop_body = CStatements([carrier, false_break], codegen=codegen)
    loop = CWhileLoop(_const(1, codegen), loop_body, codegen=codegen)
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x100))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_pretest_loop_guard_evidence_8616",
        lambda _project, _function: (PretestLoopGuardEvidence8616(0x4020, 0x4028, 0x4030),),
    )

    changed = repair_pretest_loop_break_guards_from_evidence_8616(project, codegen)

    assert changed is True
    assert loop_body.statements == [false_break]
    restored = false_break.condition_and_nodes[0][0]
    assert isinstance(restored, CUnaryOp)
    assert restored.op == "Not"
    assert restored.operand is condition
    stats = codegen._inertia_structuring_pretest_loop_guard_stats_8616
    assert stats.materialized_count == 1
    assert stats.call_return_carriers_removed_count == 1


def test_pretest_loop_guard_postprocess_replays_after_structuring_ast_regeneration(monkeypatch) -> None:
    import inertia.postprocess.decompiler_postprocess_stage as postprocess_stage

    project = SimpleNamespace()
    codegen = _DummyCodegen()
    codegen._inertia_pretest_loop_break_guard_structuring_pass_ran_8616 = True
    calls: list[tuple[object, object]] = []

    def replay(replay_project: object, replay_codegen: object) -> bool:
        calls.append((replay_project, replay_codegen))
        return True

    monkeypatch.setattr(postprocess_stage, "repair_pretest_loop_break_guards_from_evidence_8616", replay)

    changed = _repair_pretest_loop_break_guards_from_evidence_pass_8616(project, codegen)

    assert changed is True
    assert calls == [(project, codegen)]


def test_conditional_continue_repair_removes_false_break_branch_in_multi_ifelse(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    left = _stack(-8, codegen, name="left")
    right = _stack(-10, codegen, name="right")
    false_cond = CBinaryOp("CmpLE", left, right, codegen=codegen)
    true_cond = CBinaryOp("CmpGT", left, right, codegen=codegen)
    guarded_store = CAssignment(_stack(-2, codegen, name="tmp"), left, codegen=codegen)
    multi_if = CIfElse(
        [
            (false_cond, CStatements([CBreak(codegen=codegen)], codegen=codegen)),
            (true_cond, CStatements([guarded_store], codegen=codegen)),
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    loop = CForLoop(
        CAssignment(i_var, _const(1, codegen), codegen=codegen),
        CBinaryOp("CmpLT", i_var, _const(6, codegen), codegen=codegen),
        CAssignment(i_var, CBinaryOp("Add", i_var, _const(1, codegen), codegen=codegen), codegen=codegen),
        CStatements([multi_if], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x40))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_conditional_continue_evidence_8616",
        lambda _project, _function: (ConditionalContinueEvidence8616(0x4020, 0x4030, 0x4040),),
    )

    changed = repair_conditional_continue_guards_from_evidence_8616(project, codegen)

    assert changed is True
    assert tuple(multi_if.condition_and_nodes) == ((true_cond, multi_if.condition_and_nodes[0][1]),)
    assert tuple(loop.body.statements) == (multi_if,)
    stats = codegen._inertia_structuring_conditional_continue_stats_8616
    assert stats.materialized_count == 1


def test_conditional_continue_repair_reaches_for_loop_nested_in_do_while(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    changed_var = _stack(-6, codegen, name="changed")
    left = _stack(-8, codegen, name="left")
    right = _stack(-10, codegen, name="right")
    false_break = CIfBreak(CBinaryOp("CmpLE", left, right, codegen=codegen), codegen=codegen, cstyle_ifs=True)
    guarded_store = CAssignment(_stack(-2, codegen, name="tmp"), left, codegen=codegen)
    guarded = CIfElse(
        [
            (
                CBinaryOp("CmpGT", left, right, codegen=codegen),
                CStatements([guarded_store], codegen=codegen),
            )
        ],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    loop = CForLoop(
        CAssignment(i_var, _const(1, codegen), codegen=codegen),
        CBinaryOp("CmpLT", i_var, _const(6, codegen), codegen=codegen),
        CAssignment(i_var, CBinaryOp("Add", i_var, _const(1, codegen), codegen=codegen), codegen=codegen),
        CStatements([false_break, guarded], codegen=codegen),
        codegen=codegen,
    )
    do_loop = CDoWhileLoop(changed_var, CStatements([loop], codegen=codegen), codegen=codegen)
    root = CStatements([do_loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x40))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_conditional_continue_evidence_8616",
        lambda _project, _function: (ConditionalContinueEvidence8616(0x4020, 0x4030, 0x4040),),
    )

    changed = repair_conditional_continue_guards_from_evidence_8616(project, codegen)

    assert changed is True
    assert tuple(loop.body.statements) == (guarded,)
    stats = codegen._inertia_structuring_conditional_continue_stats_8616
    assert stats.materialized_count == 1


def test_hoisted_jcc_target_copy_repair_moves_proven_stack_copy_into_guard(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_var = _stack(-4, codegen, name="i")
    i_min = _stack(-6, codegen, name="i_min")
    i_next = _stack(-2, codegen, name="i_next")
    unrelated_precondition = CAssignment(
        _stack(-12, codegen, name="tmp"),
        i_min,
        codegen=codegen,
        tags={"ins_addr": 0x4010},
    )
    hoisted_target_copy = CAssignment(
        i_min,
        i_next,
        codegen=codegen,
        tags={"ins_addr": 0x4031},
    )
    condition = CBinaryOp(
        "CmpGT",
        i_min,
        i_next,
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4018, "inertia_jcc_materialized_8616": True},
    )
    guarded_call = CAssignment(
        _stack(-14, codegen, name="call_seen"),
        i_next,
        codegen=codegen,
        tags={"ins_addr": 0x4035},
    )
    guarded = CIfElse(
        [(condition, CStatements([guarded_call], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    loop = CForLoop(
        CAssignment(i_var, _const(1, codegen), codegen=codegen),
        CBinaryOp("CmpLT", i_var, _const(6, codegen), codegen=codegen),
        CAssignment(i_var, CBinaryOp("Add", i_var, _const(1, codegen), codegen=codegen), codegen=codegen),
        CStatements([unrelated_precondition, hoisted_target_copy, guarded], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x80))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_hoisted_jcc_target_copy_evidence_8616",
        lambda _project, _function: (HoistedJccTargetCopyEvidence8616(0x4020, 0x4030, 0x4031, -6, -2),),
    )

    changed = repair_hoisted_jcc_target_copies_from_evidence_8616(project, codegen)

    assert changed is True
    assert tuple(loop.body.statements) == (unrelated_precondition, guarded)
    guarded_body = guarded.condition_and_nodes[0][1]
    assert tuple(guarded_body.statements) == (hoisted_target_copy, guarded_call)
    stats = codegen._inertia_structuring_hoisted_jcc_target_copy_stats_8616
    assert stats.materialized_count == 1


def test_displaced_jcc_target_copy_repair_moves_proven_following_copy_into_guard(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_min = _stack(-6, codegen, name="i_min")
    i_next = _stack(-2, codegen, name="i_next")
    condition = CBinaryOp(
        "CmpGT",
        i_min,
        i_next,
        codegen=codegen,
        tags={"ins_addr": 0x4020, "vex_block_addr": 0x4018, "inertia_jcc_materialized_8616": True},
    )
    guarded_call = CAssignment(
        _stack(-14, codegen, name="call_seen"),
        i_next,
        codegen=codegen,
        tags={"ins_addr": 0x4035},
    )
    guarded = CIfElse(
        [(condition, CStatements([guarded_call], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    displaced_target_copy = CAssignment(
        i_min,
        i_next,
        codegen=codegen,
        tags={"ins_addr": 0x4031},
    )
    root = CStatements([guarded, displaced_target_copy], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x80))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_hoisted_jcc_target_copy_evidence_8616",
        lambda _project, _function: (HoistedJccTargetCopyEvidence8616(0x4020, 0x4030, 0x4031, -6, -2),),
    )

    changed = repair_hoisted_jcc_target_copies_from_evidence_8616(project, codegen)

    assert changed is True
    assert tuple(root.statements) == (guarded,)
    guarded_body = guarded.condition_and_nodes[0][1]
    assert tuple(guarded_body.statements) == (displaced_target_copy, guarded_call)
    stats = codegen._inertia_structuring_hoisted_jcc_target_copy_stats_8616
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_displaced_jcc_target_copy_repair_refuses_ambiguous_siblings(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    i_min = _stack(-6, codegen, name="i_min")
    i_next = _stack(-2, codegen, name="i_next")
    condition = CBinaryOp(
        "CmpGT",
        i_min,
        i_next,
        codegen=codegen,
        tags={"ins_addr": 0x4020, "inertia_jcc_materialized_8616": True},
    )
    guarded = CIfElse(
        [(condition, CStatements([CAssignment(_stack(-14, codegen), i_next, codegen=codegen, tags={"ins_addr": 0x4035})], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    first = CAssignment(i_min, i_next, codegen=codegen, tags={"ins_addr": 0x4031})
    second = CAssignment(i_min, i_next, codegen=codegen, tags={"ins_addr": 0x4031})
    root = CStatements([first, guarded, second], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x80))
        ),
    )
    monkeypatch.setattr(
        loop_body_repair,
        "recover_hoisted_jcc_target_copy_evidence_8616",
        lambda _project, _function: (HoistedJccTargetCopyEvidence8616(0x4020, 0x4030, 0x4031, -6, -2),),
    )

    changed = repair_hoisted_jcc_target_copies_from_evidence_8616(project, codegen)

    assert changed is False
    assert tuple(root.statements) == (first, guarded, second)
    stats = codegen._inertia_structuring_hoisted_jcc_target_copy_stats_8616
    assert stats.refused_ambiguous_copy == 1
    assert stats.materialized_count == 0


def test_hoisted_jcc_target_copy_postprocess_fallback_refuses_after_structuring_pass(monkeypatch):
    import inertia.structuring.loop_body_repair as loop_body_repair

    codegen = _DummyCodegen()
    condition = CBinaryOp("CmpGT", _const(2, codegen), _const(1, codegen), codegen=codegen)
    guarded = CIfElse(
        [(condition, CStatements([CAssignment(_stack(-2, codegen, name="dst"), _const(1, codegen), codegen=codegen)], codegen=codegen))],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    root = CStatements([guarded], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, body=root, statements=root)
    codegen._inertia_hoisted_jcc_target_copy_structuring_pass_ran_8616 = True
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(
            functions=SimpleNamespace(function=lambda **_kwargs: SimpleNamespace(addr=0x4010, size=0x40))
        ),
    )

    def fail_evidence_recovery(_project, _function):
        raise AssertionError("postprocess fallback should not recover evidence after structuring ran")

    monkeypatch.setattr(
        loop_body_repair,
        "recover_hoisted_jcc_target_copy_evidence_8616",
        fail_evidence_recovery,
    )

    changed = _repair_hoisted_jcc_target_copies_from_evidence_pass_8616(project, codegen)

    assert changed is False
    assert tuple(root.statements) == (guarded,)


def test_same_c_expression_matches_structured_function_call_operands():
    codegen = _DummyCodegen()
    helper_func = SimpleNamespace(name="SEG_U16", addr=None)
    ds = CVariable("ds", codegen=codegen)
    offset_a = CBinaryOp("Add", _const(66, codegen), _stack(-4, codegen, name="i"), codegen=codegen)
    offset_b = CBinaryOp("Add", _const(66, codegen), _stack(-4, codegen, name="i"), codegen=codegen)
    left = CFunctionCall(None, helper_func, [ds, offset_a], codegen=codegen)
    right = CFunctionCall(None, helper_func, [ds, offset_b], codegen=codegen)

    assert _same_c_expression_8616(left, right)
