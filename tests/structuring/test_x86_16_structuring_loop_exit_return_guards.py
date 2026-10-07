from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIfBreak,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.structuring.loop_exit_return_guards import (
    LoopExitReturnGuardCallbacks8616,
    default_loop_exit_return_guard_callbacks_8616,
    repair_loop_exit_return_guards_8616,
)


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


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _stack(offset: int, codegen, *, name: str = "local"):
    return CVariable(SimStackVariable(offset, 2, base="bp", name=name), codegen=codegen)


def _callbacks() -> LoopExitReturnGuardCallbacks8616:
    return LoopExitReturnGuardCallbacks8616(
        is_runtime_segment_helper_call=lambda _call: False,
        call_node_name=lambda call: str(getattr(call, "callee", None)),
    )


def test_loop_exit_return_guard_repair_preserves_exit_condition_polarity():
    codegen = _DummyCodegen()
    exit_cond = CBinaryOp(
        "CmpGT",
        CFunctionCall("clock", SimpleNamespace(name="clock", prototype=None), [], codegen=codegen),
        _stack(-4, codegen, name="goal"),
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
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = repair_loop_exit_return_guards_8616(codegen, _callbacks())

    assert changed is True
    rewritten = loop.body.statements[0]
    assert isinstance(rewritten, CIfBreak)
    assert rewritten.condition is exit_cond
    assert codegen._inertia_loop_exit_guard_stats_8616["preserved_exit_polarity"] == 1


def test_loop_exit_return_guard_repair_refuses_non_return_post_loop_flow():
    codegen = _DummyCodegen()
    exit_cond = _const(1, codegen)
    if_stmt = CIfElse(
        [(exit_cond, CStatements([CReturn(None, codegen=codegen)], codegen=codegen))],
        codegen=codegen,
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([if_stmt, CFunctionCall("tick", None, [], codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    tail_assignment = CAssignment(_stack(-2, codegen), _const(7, codegen), codegen=codegen)
    root = CStatements([loop, tail_assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = repair_loop_exit_return_guards_8616(codegen, _callbacks())

    assert changed is False
    assert loop.body.statements[0] is if_stmt
    assert codegen._inertia_loop_exit_guard_stats_8616["refused_post_loop_flow"] == 1


def test_loop_exit_return_guard_repair_preserves_executable_else_body():
    codegen = _DummyCodegen()
    exit_cond = _const(1, codegen)
    else_call = CFunctionCall("tick", None, [], codegen=codegen)
    else_assignment = CAssignment(_stack(-2, codegen), _const(7, codegen), codegen=codegen)
    else_body = CStatements([else_call, else_assignment], codegen=codegen)
    if_stmt = CIfElse(
        [(exit_cond, CStatements([CReturn(None, codegen=codegen)], codegen=codegen))],
        else_node=else_body,
        codegen=codegen,
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([if_stmt], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop, CReturn(None, codegen=codegen)], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = repair_loop_exit_return_guards_8616(codegen, _callbacks())

    assert changed is False
    assert loop.body.statements[0] is if_stmt
    assert if_stmt.else_node is else_body
    assert else_body.statements == [else_call, else_assignment]


def test_loop_exit_return_guard_repair_accepts_recursively_empty_else_body():
    codegen = _DummyCodegen()
    exit_cond = _const(1, codegen)
    empty_else = CStatements([CStatements([], codegen=codegen)], codegen=codegen)
    if_stmt = CIfElse(
        [(exit_cond, CStatements([CReturn(None, codegen=codegen)], codegen=codegen))],
        else_node=empty_else,
        codegen=codegen,
    )
    loop = CWhileLoop(
        _const(1, codegen),
        CStatements([if_stmt, CFunctionCall("tick", None, [], codegen=codegen)], codegen=codegen),
        codegen=codegen,
    )
    root = CStatements([loop, CReturn(None, codegen=codegen)], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    changed = repair_loop_exit_return_guards_8616(codegen, _callbacks())

    assert changed is True
    assert isinstance(loop.body.statements[0], CIfBreak)
    assert loop.body.statements[0].condition is exit_cond


def test_default_loop_exit_callbacks_classify_runtime_segment_helpers():
    codegen = _DummyCodegen()
    callbacks = default_loop_exit_return_guard_callbacks_8616()
    helper = CFunctionCall("SEG_U16", None, [], codegen=codegen)
    helper.tags = {"inertia_x86_16_runtime_segment_helper": "SEG_U16"}
    user_call = CFunctionCall("tick", SimpleNamespace(name="tick", prototype=None), [], codegen=codegen)

    assert callbacks.is_runtime_segment_helper_call(helper) is True
    assert callbacks.is_runtime_segment_helper_call(user_call) is False
    assert callbacks.call_node_name(user_call) == "tick"
