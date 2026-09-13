"""Switch diagnostics must recognize proven lowered segment state."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.segment_register_state import runtime_segment_state_cvar_8616

from inertia_decompiler.cli_decompilation import _typed_switch_seqnode_case_segment_quality_8616


@pytest.mark.parametrize("carrier", ["physical", "lowered", "unknown", "misleading_name"])
def test_switch_segment_diagnostic_preserves_lowered_identity(carrier):
    arch = Arch86_16()
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        cfunc=SimpleNamespace(statements=None),
        _inertia_seqnode_case_segment_replay_applied_8616=True,
        next_node_idx=lambda: 0,
        next_ident=lambda name: name,
    )
    value_type = SimTypeShort(False)
    if carrier == "lowered":
        segment = runtime_segment_state_cvar_8616(
            "ds", codegen=codegen, variable_type=value_type, function_addr=0x1000,
        )
    else:
        variable = (
            SimRegisterVariable(arch.registers["ds"][0], 2, name="ds")
            if carrier == "physical"
            else SimMemoryVariable(
                0x200, 2, name="inertia_ds" if carrier == "misleading_name" else "unknown",
            )
        )
        segment = structured_c.CVariable(variable, variable_type=value_type, codegen=codegen)
    offset = structured_c.CConstant(0x306, value_type, codegen=codegen)
    call = structured_c.CFunctionCall("SEG_U8", None, [segment, offset], codegen=codegen)
    body = structured_c.CStatements([call], codegen=codegen)
    switch = structured_c.CSwitchCase(offset, [(1, body)], None, codegen=codegen)
    codegen.cfunc.statements = structured_c.CStatements([switch], codegen=codegen)

    result = _typed_switch_seqnode_case_segment_quality_8616(codegen)

    assert result["case_runtime_segment_helper_unresolved_count"] == int(
        carrier in {"unknown", "misleading_name"}
    )
