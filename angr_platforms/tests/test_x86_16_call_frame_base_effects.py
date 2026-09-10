"""Reject effectful or unproven bases when consuming runtime CALL carriers."""

from itertools import count
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.call_execution_frame_carriers import (
    CallExecutionFrameCarrierStatus8616,
    prune_consumed_call_execution_frame_carriers_8616,
)
from angr_platforms.X86_16.lowering.gp_register_state import (
    runtime_gp_state_assignment_8616,
    runtime_gp_state_expr_8616,
)


@pytest.mark.parametrize("base_kind", ["call", "load", "division", "other_register", "sp", "stack"])
def test_runtime_call_frame_requires_passive_stack_base(base_kind):
    """A consumed CALL cannot authorize dropping effects in its SP expression."""
    indices = count()
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()), cfunc=SimpleNamespace(statements=None),
        next_node_idx=lambda: next(indices), next_idx=lambda name: next(indices),
        next_ident=lambda name: name, cstyle_null_cmp=False,
    )
    constant = c.CConstant(2, SimTypeShort(False), codegen=codegen)
    if base_kind == "call":
        base = c.CFunctionCall("producer", None, [], codegen=codegen)
    elif base_kind == "load":
        base = c.CUnaryOp("Dereference", constant, codegen=codegen)
    elif base_kind == "division":
        base = c.CBinaryOp("Div", constant, c.CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen)
    elif base_kind in {"sp", "other_register"}:
        base = runtime_gp_state_expr_8616(
            "sp" if base_kind == "sp" else "ax", codegen=codegen, function_addr=0x1000,
        )
        assert base is not None
    else:
        local = c.CVariable(SimStackVariable(-2, 2, base="bp"), codegen=codegen)
        base = c.CUnaryOp("Reference", local, codegen=codegen)
    value = c.CBinaryOp("Sub", base, constant, codegen=codegen)
    carrier = runtime_gp_state_assignment_8616("sp", value, codegen=codegen, function_addr=0x1000)
    assert carrier is not None
    carrier.tags = {"ins_addr": 0x1052}
    call = c.CFunctionCall("consumer", None, [], codegen=codegen)
    root = c.CStatements([carrier, call], codegen=codegen)
    codegen.cfunc.statements = root

    result = prune_consumed_call_execution_frame_carriers_8616(
        codegen, call, callsite_addr=0x1052, return_frame_width=2,
    )

    if base_kind in {"sp", "stack"}:
        assert result.status is CallExecutionFrameCarrierStatus8616.MATERIALIZED
        assert root.statements == [call]
    else:
        assert result.status is CallExecutionFrameCarrierStatus8616.REFUSED
        assert result.stats.classified_fact_count == 0
        assert result.stats.failure_count == 1
        assert root.statements == [carrier, call]
