from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.postprocess.decompiler_postprocess_calls import (
    CallsiteMaterializationDecision8616,
    _materialize_callsite_stack_arguments_8616,
)


class _DummyCodegen:
    def __init__(self, project: object) -> None:
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def test_callsite_replay_refuses_stale_summary_without_live_call(monkeypatch) -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = _DummyCodegen(project)
    local = SimStackVariable(-2, 2, base="bp", name="local_2", region=0x1000)
    local_expr = CVariable(local, variable_type=SimTypeShort(False), codegen=codegen)
    arithmetic = CAssignment(
        local_expr,
        CBinaryOp(
            "Div",
            local_expr,
            CConstant(3, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x1040},
    )
    root = CStatements([arithmetic], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=root,
        body=root,
        variables_in_use={local: local_expr},
        unified_local_vars={},
    )
    stale_summary = CallsiteSummary8616(
        callsite_addr=0x1006,
        target_addr=0x2000,
        return_addr=0x1009,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
        stack_probe_helper=True,
        stack_probe_allocation_size=4,
        helper_return_state="stack_address",
        helper_return_space="ss",
        helper_return_width=2,
        helper_return_address_kind="stack",
    )
    codegen._inertia_callsite_summaries = {0xDEAD: stale_summary}
    monkeypatch.setattr(
        "inertia.postprocess.decompiler_postprocess_calls._replay_fixed_stack_probe_frame_lowerer_8616",
        lambda _codegen: False,
    )

    before = tuple(root.statements)
    changed = _materialize_callsite_stack_arguments_8616(project, codegen)

    assert changed is False
    assert tuple(root.statements) == before
    assert codegen._inertia_callsite_summaries == {0xDEAD: stale_summary}
    assert (
        codegen._inertia_callsite_materialization_last_decision_8616
        is CallsiteMaterializationDecision8616.REFUSED_NO_LIVE_SUMMARIZED_CALL
    )
    assert codegen._inertia_callsite_materialization_stats.no_live_summarized_call_refusal_count == 1
