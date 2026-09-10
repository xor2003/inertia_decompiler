from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CFunctionCall,
    CIfElse,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import (
    CallsiteMachineFrameKind8616,
    CallsiteSummary8616,
    callsite_machine_frame_kind_8616,
)
from angr_platforms.X86_16.lowering.call_execution_frame_carriers import (
    CallExecutionFrameCarrierStatus8616,
    prune_consumed_call_execution_frame_carriers_8616,
)
from angr_platforms.X86_16.lowering.call_execution_frame_replay import (
    prune_materialized_call_execution_frames_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_node_idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc = SimpleNamespace(statements=None)

    def next_idx(self, _kind: str) -> int:
        self._next_node_idx += 1
        return self._next_node_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _dirty(
    codegen: _Codegen,
    varid: int,
    *,
    register_name: str = "sp",
) -> CDirtyExpression:
    register_offset, register_size = codegen.project.arch.registers[register_name]
    return CDirtyExpression(
        SimpleNamespace(
            varid=varid,
            reg_offset=register_offset,
            bits=register_size * 8,
        ),
        codegen=codegen,
    )


def _fixture(
    *,
    register_name: str = "sp",
    decrement: int = 2,
    attach_call: bool = True,
    extra_use: bool = False,
) -> tuple[_Codegen, CFunctionCall, CAssignment, CAssignment]:
    codegen = _Codegen()
    base = _dirty(codegen, 1, register_name=register_name)
    decremented = _dirty(codegen, 23, register_name=register_name)
    pre = CAssignment(
        decremented,
        CBinaryOp(
            "Sub",
            _dirty(codegen, 1, register_name=register_name),
            CConstant(decrement, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        tags={"ins_addr": 0x1052},
        codegen=codegen,
    )
    call = CFunctionCall("clock", None, [], codegen=codegen)
    middle = (
        CIfElse(
            [(call, CStatements([], codegen=codegen))],
            codegen=codegen,
        )
        if attach_call
        else CStatements([], codegen=codegen)
    )
    restore = CAssignment(
        base,
        _dirty(codegen, 23, register_name=register_name),
        tags={"dephi": True},
        codegen=codegen,
    )
    statements: list[object] = [pre, middle, restore]
    if extra_use:
        statements.append(
            CAssignment(
                _dirty(codegen, 99, register_name=register_name),
                _dirty(codegen, 23, register_name=register_name),
                codegen=codegen,
            )
        )
    codegen.cfunc.statements = CStatements(statements, codegen=codegen)
    return codegen, call, pre, restore


def _runtime_sp_call_fixture(
    *,
    decrement: int = 2,
    attach_call: bool = True,
) -> tuple[_Codegen, CFunctionCall, CAssignment]:
    codegen = _Codegen()
    runtime_sp = CVariable(
        SimMemoryVariable(
            0x10018,
            4,
            name="inertia_esp",
            region=0x1000,
            category="inertia_gp_register_state",
        ),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )
    stack_slot = CVariable(
        SimStackVariable(-0x14, 1, name="s_14", base="bp"),
        codegen=codegen,
    )
    low_sp = CBinaryOp(
        "Sub",
        CUnaryOp("Reference", stack_slot, codegen=codegen),
        CConstant(decrement, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    pre = CAssignment(
        runtime_sp,
        CBinaryOp(
            "Or",
            CBinaryOp(
                "And",
                runtime_sp,
                CConstant(0xFFFF0000, SimTypeLong(False), codegen=codegen),
                codegen=codegen,
            ),
            CBinaryOp(
                "And",
                low_sp,
                CConstant(0xFFFF, SimTypeLong(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        tags={"ins_addr": 0x1052},
        codegen=codegen,
    )
    call = CFunctionCall("clock", None, [], codegen=codegen)
    statements: list[object] = [pre]
    if attach_call:
        statements.append(call)
    codegen.cfunc.statements = CStatements(statements, codegen=codegen)
    return codegen, call, pre


def test_consumed_call_execution_frame_prunes_exact_sp_pair() -> None:
    codegen, call, pre, restore = _fixture()

    result = prune_consumed_call_execution_frame_carriers_8616(
        codegen,
        call,
        callsite_addr=0x1052,
        return_frame_width=2,
    )

    assert result.status is CallExecutionFrameCarrierStatus8616.MATERIALIZED
    assert result.stats.raw_fact_count == 1
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0
    assert result.stats.removed_statement_count == 2
    assert pre not in codegen.cfunc.statements.statements
    assert restore not in codegen.cfunc.statements.statements


def test_consumed_call_execution_frame_prunes_owned_runtime_sp_write() -> None:
    codegen, call, pre = _runtime_sp_call_fixture()

    result = prune_consumed_call_execution_frame_carriers_8616(
        codegen,
        call,
        callsite_addr=0x1052,
        return_frame_width=2,
    )

    assert result.status is CallExecutionFrameCarrierStatus8616.MATERIALIZED
    assert result.stats.raw_fact_count == 1
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0
    assert result.stats.removed_statement_count == 1
    assert pre not in codegen.cfunc.statements.statements
    assert call in codegen.cfunc.statements.statements


def test_consumed_call_execution_frame_refuses_unattached_runtime_sp_write() -> None:
    codegen, call, pre = _runtime_sp_call_fixture(attach_call=False)

    result = prune_consumed_call_execution_frame_carriers_8616(
        codegen,
        call,
        callsite_addr=0x1052,
        return_frame_width=2,
    )

    assert result.status is CallExecutionFrameCarrierStatus8616.REFUSED
    assert result.stats.failure_count == 1
    assert pre in codegen.cfunc.statements.statements


def test_materialized_call_replay_consumes_runtime_sp_write_from_summary() -> None:
    codegen, call, pre = _runtime_sp_call_fixture()
    summary = CallsiteSummary8616(
        callsite_addr=0x1052,
        target_addr=0x2000,
        return_addr=0x1055,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
    )

    changed = prune_materialized_call_execution_frames_8616(
        codegen,
        ((call, summary),),
    )

    assert changed is True
    assert pre not in codegen.cfunc.statements.statements
    stats = codegen._inertia_call_execution_frame_carrier_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_consumed_call_execution_frame_refuses_external_carrier_use() -> None:
    codegen, call, pre, restore = _fixture(extra_use=True)

    result = prune_consumed_call_execution_frame_carriers_8616(
        codegen,
        call,
        callsite_addr=0x1052,
        return_frame_width=2,
    )

    assert result.status is CallExecutionFrameCarrierStatus8616.REFUSED
    assert result.stats.failure_count == 1
    assert pre in codegen.cfunc.statements.statements
    assert restore in codegen.cfunc.statements.statements


@pytest.mark.parametrize("observer", ["argument", "after", "branch"])
@pytest.mark.parametrize("width", [2, 4])
def test_runtime_call_frame_refuses_external_sp_observer(observer, width):
    codegen, call, pre = _runtime_sp_call_fixture()
    value = pre.lhs
    if width == 2:
        value = CBinaryOp(
            "And", value, CConstant(0xFFFF, SimTypeLong(False), codegen=codegen), codegen=codegen,
        )
    if observer == "argument":
        call.args = [value]
    else:
        assignment = CAssignment(_dirty(codegen, 99, register_name="ax"), value, codegen=codegen)
        statement = assignment if observer == "after" else CIfElse(
            [(CConstant(1, SimTypeShort(False), codegen=codegen), CStatements([assignment], codegen=codegen))],
            codegen=codegen,
        )
        codegen.cfunc.statements.statements.append(statement)
    original = tuple(codegen.cfunc.statements.statements)
    result = prune_consumed_call_execution_frame_carriers_8616(
        codegen, call, callsite_addr=0x1052, return_frame_width=2,
    )
    assert result.status is CallExecutionFrameCarrierStatus8616.REFUSED
    assert result.stats.classified_fact_count == 0
    assert result.stats.removed_statement_count == 0
    assert tuple(codegen.cfunc.statements.statements) == original


def test_consumed_call_execution_frame_refuses_non_sp_pair() -> None:
    codegen, call, pre, restore = _fixture(register_name="ax")

    result = prune_consumed_call_execution_frame_carriers_8616(
        codegen,
        call,
        callsite_addr=0x1052,
        return_frame_width=2,
    )

    assert result.status is CallExecutionFrameCarrierStatus8616.REFUSED
    assert pre in codegen.cfunc.statements.statements
    assert restore in codegen.cfunc.statements.statements


def test_consumed_call_execution_frame_refuses_frame_width_mismatch() -> None:
    codegen, call, pre, restore = _fixture(decrement=4)

    result = prune_consumed_call_execution_frame_carriers_8616(
        codegen,
        call,
        callsite_addr=0x1052,
        return_frame_width=2,
    )

    assert result.status is CallExecutionFrameCarrierStatus8616.REFUSED
    assert pre in codegen.cfunc.statements.statements
    assert restore in codegen.cfunc.statements.statements


def test_consumed_call_execution_frame_refuses_unattached_call() -> None:
    codegen, call, pre, restore = _fixture(attach_call=False)

    result = prune_consumed_call_execution_frame_carriers_8616(
        codegen,
        call,
        callsite_addr=0x1052,
        return_frame_width=2,
    )

    assert result.status is CallExecutionFrameCarrierStatus8616.REFUSED
    assert pre in codegen.cfunc.statements.statements
    assert restore in codegen.cfunc.statements.statements


def test_callsite_machine_frame_kind_normalizes_legacy_spellings() -> None:
    def summary(kind: str | None) -> CallsiteSummary8616:
        return CallsiteSummary8616(
            callsite_addr=0x1052,
            target_addr=0x2000,
            return_addr=0x1055,
            kind=kind,
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
        )

    assert (
        callsite_machine_frame_kind_8616(summary("direct_near"))
        is CallsiteMachineFrameKind8616.NEAR
    )
    assert (
        callsite_machine_frame_kind_8616(summary("direct_far"))
        is CallsiteMachineFrameKind8616.FAR
    )
    assert callsite_machine_frame_kind_8616(summary(None)) is None
    assert CallsiteMachineFrameKind8616.NEAR.return_frame_width == 2
    assert CallsiteMachineFrameKind8616.FAR.return_frame_width == 4
