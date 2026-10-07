from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeFunction
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.postprocess.decompiler_postprocess_stage import (
    _normalize_stack_variable_identifiers_8616,
    _terminal_stack_arg_expr_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    publish_selected_stack_cvar_projection_8616,
)

from inertia.lowering.annotations import ANNOTATION_KEY


def test_terminal_return_reuses_entry_sp_argument_by_machine_bp_coordinate() -> None:
    """Do not append a duplicate argument when angr and machine coordinates differ."""
    arch = Arch86_16()
    function = SimpleNamespace(
        info={
            ANNOTATION_KEY: {
                "stack_vars": {
                    2: {"name": "a"},
                    4: {"name": "b"},
                }
            }
        }
    )
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda *, addr, create: function,
            )
        ),
    )
    codegen = SimpleNamespace(
        project=project,
        next_idx=lambda _name: 1,
        next_ident=lambda name: name,
        next_node_idx=lambda: 1,
        cstyle_null_cmp=False,
    )
    first_variable = SimStackVariable(2, 2, base="bp", name="a", region=0x1000)
    second_variable = SimStackVariable(4, 2, base="bp", name="b", region=0x1000)
    first_cvar = structured_c.CVariable(
        first_variable,
        variable_type=SimTypeChar(),
        codegen=codegen,
    )
    second_cvar = structured_c.CVariable(
        second_variable,
        variable_type=SimTypeChar(),
        codegen=codegen,
    )
    prototype = SimTypeFunction(
        [SimTypeChar(), SimTypeChar()],
        SimTypeChar(),
        arg_names=["a", "b"],
    ).with_arch(arch)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=[first_cvar, second_cvar],
        variables_in_use={
            first_variable: first_cvar,
            second_variable: second_cvar,
        },
        unified_local_vars={},
        functy=prototype,
        prototype=prototype,
    )
    publish_selected_stack_cvar_projection_8616(
        codegen,
        first_cvar,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    publish_selected_stack_cvar_projection_8616(
        codegen,
        second_cvar,
        bp_offset=6,
        entry_sp_offset=4,
        size=2,
    )

    expression = _terminal_stack_arg_expr_8616(project, codegen, 6, 1)
    _normalize_stack_variable_identifiers_8616(codegen)

    assert isinstance(expression, structured_c.CVariable)
    assert expression.variable is second_variable
    assert codegen.cfunc.arg_list == [first_cvar, second_cvar]
    assert len(codegen.cfunc.functy.args) == 2
    assert first_variable.name == "a"
    assert second_variable.name == "b"
