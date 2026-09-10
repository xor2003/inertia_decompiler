"""Keep scalar call-result definitions alive when a return store is bound."""

from itertools import count
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteReturnUseKind8616, CallsiteSummary8616
from angr_platforms.X86_16.structuring.stored_call_result_assignments import (
    materialize_stored_call_result_assignments_8616,
)


@pytest.mark.parametrize("owner_address", [0x100E, 0x1014])
def test_return_store_rebinding_retains_scalar_definition_before_stack_overwrite(owner_address):
    """Later SSA reads need the captured call result, not the current stack slot."""
    indices = count()
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()), cstyle_null_cmp=True,
        next_node_idx=lambda: next(indices), next_idx=lambda name: next(indices),
        next_ident=lambda name: name,
    )
    local = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="value"),
        variable_type=SimTypeShort(False), codegen=codegen,
    )
    register = structured_c.CVariable(
        SimRegisterVariable(codegen.project.arch.get_register_offset("ax"), 2, ident="result", region=0x1000),
        variable_type=SimTypeShort(False), codegen=codegen,
    )
    call = structured_c.CFunctionCall(
        "fn", SimpleNamespace(addr=None, name="fn"), [local],
        tags={"ins_addr": 0x100E}, codegen=codegen,
    )
    owner = structured_c.CAssignment(register, call, tags={"ins_addr": owner_address}, codegen=codegen)
    overwrite = structured_c.CAssignment(
        local, structured_c.CConstant(7, SimTypeShort(False), codegen=codegen), codegen=codegen,
    )
    use = structured_c.CReturn(register, codegen=codegen)
    root = structured_c.CStatements([owner, overwrite, use], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_callsite_summaries = {id(call): CallsiteSummary8616(
        callsite_addr=0x100E, target_addr=None, return_addr=0x1011, kind="near",
        arg_count=1, arg_widths=(2,), stack_cleanup=2, return_register="ax",
        return_used=True, return_store_destination=("bp", 6), return_store_width=2,
        return_store_instruction_addr=0x1014, return_use_kind=CallsiteReturnUseKind8616.VALUE,
    )}

    result = materialize_stored_call_result_assignments_8616(codegen)

    assert result.changed and result.stats.failure_count == 0
    assert owner.rhs is call
    assert owner.lhs.variable == local.variable
    assert len(root.statements) == 4
    capture = root.statements[1]
    assert isinstance(capture, structured_c.CAssignment)
    assert isinstance(capture.lhs, structured_c.CVariable)
    assert capture.lhs.variable == register.variable
    assert isinstance(capture.rhs, structured_c.CVariable)
    assert capture.rhs.variable == local.variable
    assert root.statements[2] is overwrite
    assert root.statements[3] is use
    assert use.retval is register

    replay = materialize_stored_call_result_assignments_8616(codegen)
    assert not replay.changed
    assert len(root.statements) == 4
