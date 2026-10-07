"""Tests for project-owned postprocess validation snapshot boundaries."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall, CReturn, CStatements
from angr.sim_type import SimTypeLong
from inertia.postprocess.decompiler_postprocess_stage import _deepcopy_cfunc_for_validation_8616
from inertia.lowering.semantic_cast import CSemanticCast8616
from archinfo import ArchX86

from inertia.frontend.x86_16.render_compat import repair_cfunctioncall_render_targets_8616


class _FunctionLookup:
    def __init__(self, function: object) -> None:
        self._function = function

    def function(self, *, addr: int, create: bool) -> object:
        del addr, create
        return self._function


def _codegen(project: object) -> SimpleNamespace:
    return SimpleNamespace(project=project, next_idx=lambda _kind: 0, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 0)


def test_validation_snapshot_preserves_callee_function_identity() -> None:
    project = SimpleNamespace(arch=object())
    codegen = _codegen(project)
    callee = SimpleNamespace(name="clock", project=project)
    call = CFunctionCall("clock", callee, [], codegen=codegen)
    cfunc = SimpleNamespace(codegen=codegen, statements=CStatements([call], codegen=codegen))

    cloned = _deepcopy_cfunc_for_validation_8616(cfunc)
    cloned_call = cloned.statements.statements[0]

    assert cloned_call is not call
    assert cloned_call.callee_func is callee
    assert cloned_call.callee_func.project is project


def test_render_repair_reaches_call_inside_project_c_expression() -> None:
    project = SimpleNamespace(arch=ArchX86())
    live_callee = SimpleNamespace(addr=0x1234, project=project)
    project.kb = SimpleNamespace(functions=_FunctionLookup(live_callee))
    detached_callee = SimpleNamespace(addr=0x1234, project=None)
    codegen = _codegen(project)
    call = CFunctionCall("clock", detached_callee, [], codegen=codegen)
    long_type = SimTypeLong()
    wrapped = CSemanticCast8616(long_type, long_type, call, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([CReturn(wrapped, codegen=codegen)], codegen=codegen),
    )

    assert repair_cfunctioncall_render_targets_8616(codegen) == 1
    assert call.callee_func is live_callee
