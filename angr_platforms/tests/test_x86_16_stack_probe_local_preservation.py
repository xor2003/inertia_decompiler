"""Stack-probe cleanup must not infer dead stack storage from local suffixes."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatement,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.c_ast_utils import _iter_c_nodes_deep_8616
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.decompiler_postprocess_calls import (
    _bind_call_argument_setup_liveness_classifier_8616,
    _materialize_callsite_stack_arguments_8616,
)
from angr_platforms.X86_16.lowering.call_argument_carrier_liveness import call_argument_setup_is_proven_dead_8616
from test_x86_16_stack_probe_return_state_regression import _DummyCodegen, _project


class _Codegen(_DummyCodegen):
    cfunc: SimpleNamespace
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("external_read", [False, True])
def test_probe_cleanup_preserves_stack_storage_without_deadness_proof(nested, external_read):
    project = _project()
    codegen = _Codegen(project)
    _bind_call_argument_setup_liveness_classifier_8616(codegen, call_argument_setup_is_proven_dead_8616)
    value_type = SimTypeShort(False)
    slot = CVariable(
        SimStackVariable(-8, 2, base="bp", name="local_6", region=0x4010),
        variable_type=value_type,
        codegen=codegen,
    )
    initializer = CAssignment(slot, CConstant(0, value_type, codegen=codegen), codegen=codegen)
    probe_call = CFunctionCall("probe", SimpleNamespace(name="probe"), [], codegen=codegen)
    probe = CExpressionStatement(probe_call, codegen=codegen)
    prefix = CStatements([probe, initializer], codegen=codegen)
    statements: list[CStatement] = [prefix] if nested else [probe, initializer]
    root = CStatements(statements, codegen=codegen)
    if external_read:
        destination = CVariable(
            SimRegisterVariable(project.arch.registers["ax"][0], 2, name="result"),
            variable_type=value_type,
            codegen=codegen,
        )
        root.statements.append(CAssignment(destination, slot, codegen=codegen))
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(probe_call): CallsiteSummary8616(
            callsite_addr=0x4010, target_addr=0x1001, return_addr=0x4012,
            kind="direct_near", arg_count=0, arg_widths=(), stack_cleanup=0,
            return_register="ax", return_used=True, stack_probe_helper=True,
            helper_return_state="stack_address", helper_return_space="ss",
            helper_return_width=2, helper_return_address_kind="stack",
        ),
    }

    _materialize_callsite_stack_arguments_8616(project, codegen)

    assert any(node is initializer for node in _iter_c_nodes_deep_8616(root))
