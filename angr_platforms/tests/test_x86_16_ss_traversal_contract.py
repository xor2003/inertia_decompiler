"""A proven SS load must be visited in every covered expression position."""

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.lowering import real_mode_linear
from angr_platforms.X86_16.lowering.real_mode_linear import lower_stable_ss_linear_stack_dereferences_8616
from test_x86_16_segmented_runtime_lowering import _project


@pytest.mark.parametrize("unified", [False, True])
@pytest.mark.parametrize("existing_name", [None, "existing"])
def test_stack_identifier_updates_native_storage_not_read_only_cvar_name(monkeypatch, unified, existing_name):
    _project_instance, codegen = _project()
    variable = SimStackVariable(2, 2, base="bp", name=existing_name, region=0x4010)
    owner = c.CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
    if unified:
        owner.unified_variable = SimStackVariable(2, 2, base="bp", name=existing_name, region=0x4010)
    monkeypatch.setattr(real_mode_linear, "_preferred_stack_object_name_8616", lambda *_args, **_kwargs: "arg_4")
    real_mode_linear._ensure_stack_cvar_has_identifier_8616(codegen, owner, 4)
    expected = existing_name or "arg_4"
    assert variable.name == expected
    assert owner.name == expected
    if unified:
        assert owner.unified_variable.name == expected


@pytest.mark.parametrize("position", [
    "return", "expression", "call-argument", "switch-selector", "switch-case", "switch-default",
    "while-condition", "for-condition", "for-initializer", "for-iterator",
])
def test_ss_load_traversal_contract(position):
    project, codegen = _project()
    word = SimTypeShort(False)
    variable = SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010)
    owner = c.CVariable(variable, variable_type=word, codegen=codegen)
    codegen.cfunc.variables_in_use[variable] = owner

    def register(name):
        return c.CVariable(
            SimRegisterVariable(project.arch.registers[name][0], 2, name=name),
            variable_type=word, codegen=codegen,
        )

    linear = c.CBinaryOp(
        "Add",
        c.CBinaryOp("Shl", register("ss"), c.CConstant(4, word, codegen=codegen), codegen=codegen),
        c.CBinaryOp("Sub", register("bp"), c.CConstant(2, word, codegen=codegen), codegen=codegen),
        codegen=codegen,
    )
    load = c.CUnaryOp("Dereference", linear, codegen=codegen)
    body = c.CStatements([], codegen=codegen)
    switch_body = c.CStatements([c.CExpressionStatement(load, codegen=codegen)], codegen=codegen)
    containers = {
        "return": (c.CReturn(load, codegen=codegen), "retval"),
        "expression": (c.CExpressionStatement(load, codegen=codegen), "expr"),
        "call-argument": (c.CFunctionCall("callee", None, [load], codegen=codegen), "args"),
        "switch-selector": (c.CSwitchCase(load, {}, None, codegen=codegen), "switch"),
        "switch-case": (c.CSwitchCase(c.CConstant(0, word, codegen=codegen), {0: switch_body}, None, codegen=codegen), "cases"),
        "switch-default": (c.CSwitchCase(c.CConstant(0, word, codegen=codegen), {}, switch_body, codegen=codegen), "default"),
        "while-condition": (c.CWhileLoop(load, body, codegen=codegen), "condition"),
        "for-condition": (c.CForLoop(None, load, None, body, codegen=codegen), "condition"),
        "for-initializer": (c.CForLoop(load, None, None, body, codegen=codegen), "initializer"),
        "for-iterator": (c.CForLoop(None, None, load, body, codegen=codegen), "iterator"),
    }
    container, field = containers[position]
    codegen.cfunc.statements.statements.append(container)
    lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)
    result = getattr(container, field)
    if position == "switch-case":
        result = result[0].statements[0].expr
    elif position == "switch-default":
        result = result.statements[0].expr
    assert (result[0] if isinstance(result, list) else result) is owner
