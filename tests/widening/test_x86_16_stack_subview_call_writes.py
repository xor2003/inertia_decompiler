from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRCallStackEffect8616,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa

from inertia.alias.stack_memory_ssa import (
    build_x86_16_stack_memory_ssa_alias_artifact,
)
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.widening.stack_memory_objects import (
    build_x86_16_stack_memory_object_widening_artifact,
)
from inertia.widening.stack_subview_projection import (
    materialize_contained_stack_subviews_8616,
)

FUNCTION_ADDR = 0x4010
CALLSITE_ADDR = 0x4018
OWNER_OFFSET = -4


class _DummyCodegen:
    def __init__(self) -> None:
        self._idx = 0
        self.cfunc: SimpleNamespace | None = None
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _bp_slot(offset: int, size: int) -> IRAddress:
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.DEFAULTED,
    )


def _stack_var(offset: int, size: int, name: str, codegen: _DummyCodegen) -> CVariable:
    return CVariable(
        SimStackVariable(offset, size, base="bp", name=name, region=FUNCTION_ADDR),
        codegen=codegen,
    )


def _attach_call_proof(
    codegen: _DummyCodegen,
    *,
    effect_complete: bool = True,
    owner_preserved: bool = True,
) -> None:
    owner = _bp_slot(OWNER_OFFSET, 2)
    view = _bp_slot(OWNER_OFFSET + 1, 1)
    effect = IRCallStackEffect8616(
        net_stack_delta=0,
        preserved_ranges=(owner, view) if owner_preserved else (),
        complete=effect_complete,
    )
    function_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            function_addr=FUNCTION_ADDR,
            blocks=(
                IRBlock(
                    addr=FUNCTION_ADDR,
                    instrs=(
                        IRInstr(
                            "STORE",
                            None,
                            (owner, IRValue(MemSpace.CONST, const=1, size=2)),
                            size=2,
                        ),
                        IRInstr(
                            "CALL",
                            None,
                            (),
                            addr=CALLSITE_ADDR,
                            call_stack_effect=effect,
                        ),
                        IRInstr(
                            "LOAD",
                            IRValue(MemSpace.REG, name="ax", size=1),
                            (view,),
                            size=1,
                        ),
                    ),
                ),
            ),
        )
    )
    alias = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)
    codegen._inertia_stack_memory_ssa_alias_artifact = alias
    codegen._inertia_stack_memory_object_widening_artifact = (
        build_x86_16_stack_memory_object_widening_artifact(alias)
    )


def _call_write(codegen: _DummyCodegen, callsite_addr: int) -> CAssignment:
    owner = _stack_var(OWNER_OFFSET, 2, "owner", codegen)
    view = _stack_var(OWNER_OFFSET + 1, 1, "view", codegen)
    call = CFunctionCall(
        "callee",
        SimpleNamespace(addr=0x5000, name="callee", prototype=None),
        [],
        codegen=codegen,
        tags={"ins_addr": callsite_addr},
    )
    assignment = CAssignment(view, call, codegen=codegen, tags={"ins_addr": 0x401B})
    codegen.cfunc = SimpleNamespace(
        addr=FUNCTION_ADDR,
        statements=CStatements([assignment], codegen=codegen),
        variables_in_use={owner.variable: owner, view.variable: view},
    )
    return assignment


def test_exact_owner_preserving_call_projects_scalar_view_write() -> None:
    codegen = _DummyCodegen()
    assignment = _call_write(codegen, CALLSITE_ADDR)
    _attach_call_proof(codegen)

    assert materialize_contained_stack_subviews_8616(codegen) is True

    projected = codegen.cfunc.statements.statements[0]
    assert isinstance(projected, CAssignment) and projected.tags == assignment.tags
    assert isinstance(projected.lhs, CVariable) and projected.lhs.variable.size == 2
    assert isinstance(projected.rhs, CBinaryOp) and projected.rhs.op == "Or"
    calls = tuple(
        node for node in _iter_c_nodes_deep_8616(projected) if isinstance(node, CFunctionCall)
    )
    assert len(calls) == 1
    candidate = codegen._inertia_stack_memory_object_widening_artifact.candidates[0]
    assert candidate.calls_preserve_owner((CALLSITE_ADDR,)) is True
    assert candidate.calls_preserve_owner((CALLSITE_ADDR, CALLSITE_ADDR)) is False


def test_mismatched_callsite_refuses_scalar_view_write() -> None:
    codegen = _DummyCodegen()
    assignment = _call_write(codegen, CALLSITE_ADDR + 1)
    _attach_call_proof(codegen)

    assert materialize_contained_stack_subviews_8616(codegen) is False
    assert codegen.cfunc.statements.statements[0] is assignment
    assert codegen._inertia_stack_subview_last_stats_8616.failure_count == 1


@pytest.mark.parametrize(
    ("effect_complete", "owner_preserved"),
    ((False, False), (True, False)),
    ids=("incomplete", "clobbering"),
)
def test_unpreserved_call_effect_refuses_stack_object_before_projection(
    effect_complete: bool,
    owner_preserved: bool,
) -> None:
    codegen = _DummyCodegen()
    assignment = _call_write(codegen, CALLSITE_ADDR)
    _attach_call_proof(
        codegen,
        effect_complete=effect_complete,
        owner_preserved=owner_preserved,
    )

    widening = codegen._inertia_stack_memory_object_widening_artifact
    assert widening.candidates == ()
    assert widening.source_alias.refusals
    assert materialize_contained_stack_subviews_8616(codegen) is False
    assert codegen.cfunc.statements.statements[0] is assignment
