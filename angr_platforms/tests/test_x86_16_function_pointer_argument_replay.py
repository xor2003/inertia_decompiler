"""Binary-proven pointer slots survive scalar-view argument reconstruction."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CStatements, CVariable
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.lowering.function_pointer_parameters import (
    FunctionPointerParameterFailure8616,
    materialize_function_pointer_parameters_8616,
    materialized_function_pointer_slots_8616,
)
from angr_platforms.X86_16.lowering.positive_bp_arguments import (
    materialize_positive_bp_arguments_8616,
)
from test_x86_16_function_pointer_parameters import _far_fixture, _fixture


def test_binary_far_pointer_width_survives_positive_bp_replay() -> None:
    project, codegen, function = _far_fixture()
    function.info = {}
    function.prototype_source = PrototypeSource.CCA_DECOMPILER
    word = SimTypeShort(False).with_arch(project.arch)
    fn_use = codegen.cfunc.body
    value_use = CVariable(
        SimStackVariable(8, 2, base="bp", name="value", region=0x1000),
        variable_type=word,
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([fn_use, value_use], codegen=codegen)
    codegen.cfunc.variables_in_use = {
        fn_use.variable: fn_use,
        value_use.variable: value_use,
    }
    codegen.cfunc.unified_local_vars = {}
    codegen.cfunc.prototype = function.prototype

    assert materialize_function_pointer_parameters_8616(project, codegen)
    assert tuple((v.variable.offset, v.variable.size) for v in codegen.cfunc.arg_list) == (
        (4, 4), (8, 2),
    )

    materialize_positive_bp_arguments_8616(project, codegen)

    assert tuple((v.variable.offset, v.variable.size) for v in codegen.cfunc.arg_list) == (
        (4, 4), (8, 2),
    )
    assert function.prototype_source == PrototypeSource.CCA_DECOMPILER
    assert not materialize_function_pointer_parameters_8616(project, codegen)


@pytest.mark.parametrize("far", [False, True])
def test_closed_pointer_evidence_projects_only_proven_slots(far: bool) -> None:
    if far:
        project, codegen, _function = _far_fixture()
    else:
        project, codegen, _function, _manager, _use = _fixture()
    assert materialize_function_pointer_parameters_8616(project, codegen)
    slots = materialized_function_pointer_slots_8616(codegen, project.arch)
    assert [(slot.offset, slot.storage_width) for slot in slots] == [
        (6, 4) if far else (4, 2),
    ]
    assert slots[0].argument_type.size == (32 if far else 16)


@pytest.mark.parametrize(
    "override",
    [
        {"materialized_count": 0},
        {"classified_fact_count": 0},
        {"failure_count": 1},
        {"failures": (FunctionPointerParameterFailure8616.PARAMETER_SLOT_MISSING,)},
    ],
)
def test_unclosed_pointer_evidence_cannot_constrain_argument_layout(override: dict) -> None:
    project, codegen, _function = _far_fixture()
    assert materialize_function_pointer_parameters_8616(project, codegen)
    codegen._inertia_function_pointer_parameter_evidence_8616 = replace(
        codegen._inertia_function_pointer_parameter_evidence_8616, **override,
    )
    assert materialized_function_pointer_slots_8616(codegen, project.arch) == ()


def test_absent_or_untyped_pointer_evidence_does_not_supply_layout() -> None:
    project, _codegen, _function = _far_fixture()
    assert materialized_function_pointer_slots_8616(SimpleNamespace(), project.arch) == ()
    assert materialized_function_pointer_slots_8616(
        SimpleNamespace(_inertia_function_pointer_parameter_evidence_8616={}), project.arch,
    ) == ()
