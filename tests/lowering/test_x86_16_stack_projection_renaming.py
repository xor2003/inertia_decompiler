from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable
from inertia.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_projection_8616,
    stack_variable_coordinate_registry_8616,
)
from inertia.lowering.stack_variable_display_names import (
    publish_prototype_argument_projection_names_8616,
)


def test_prototype_argument_rename_preserves_machine_bp_projection() -> None:
    codegen = SimpleNamespace(
        next_ident=lambda name: name,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
    )
    formal = SimStackVariable(2, 2, base="bp", name="arg_4", ident="arg_0")
    cvar = structured_c.CVariable(formal, codegen=codegen)
    codegen.cfunc = SimpleNamespace(arg_list=[cvar])
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=formal,
        cvar=cvar,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
        display_name="arg_4",
    )

    assert publish_prototype_argument_projection_names_8616(codegen, ["arg"]) == 1
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(formal)
    assert projection is not None
    assert projection.display_name == "arg"

    regenerated = SimStackVariable(2, 2, base="bp", name="arg", ident="regenerated")
    unrelated = SimStackVariable(2, 2, base="bp", name="other", ident="other")
    assert machine_bp_offset_for_stack_variable_8616(codegen, regenerated) == 4
    assert machine_bp_offset_for_stack_variable_8616(codegen, unrelated) == 2
