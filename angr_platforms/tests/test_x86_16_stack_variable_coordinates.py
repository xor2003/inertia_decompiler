from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFixedSizeArray, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.decompiler_postprocess_calls import (
    _bind_call_argument_setup_liveness_classifier_8616,
    _materialize_callsite_stack_arguments_8616,
)
from angr_platforms.X86_16.lowering.call_argument_carrier_liveness import (
    call_argument_setup_is_proven_dead_8616,
)
from angr_platforms.X86_16.lowering.real_mode_linear import (
    RealModeLinearStackAccess8616,
    _resolve_direct_stack_update_cvar_8616,
    stack_cvar_for_stable_ss_linear_access_8616,
)
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from angr_platforms.X86_16.lowering.stack_function_coordinates import (
    final_c_function_machine_bp_offset_8616,
)
from angr_platforms.X86_16.lowering.stack_lowering_from_facts import (
    materialize_stack_cvar_at_offset_from_facts_8616,
)
from angr_platforms.X86_16.lowering.stack_prototype_materialization import (
    _existing_stack_cvars_by_offset_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    publish_selected_stack_cvar_projection_8616,
    record_stack_variable_coordinate_projection_8616,
    reset_stack_variable_coordinate_registry_8616,
    stack_cvar_for_machine_bp_range_8616,
    stack_variable_coordinate_registry_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_display_names import (
    reapply_stack_variable_projection_names_8616,
)


def test_stack_variable_coordinate_registry_keeps_bp_and_entry_sp_distinct() -> None:
    codegen = SimpleNamespace()
    variable = SimStackVariable(-4, 2, base="bp", name="local_2", ident="is_3")
    cvar = object()

    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=cvar,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )

    assert machine_bp_offset_for_stack_variable_8616(codegen, variable) == -2
    assert stack_cvar_for_machine_bp_range_8616(codegen, -2, 2) is cvar
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(variable)
    assert projection is not None
    assert projection.entry_sp_offset == -4
    cloned_variable = SimStackVariable(-4, 2, base="bp", name="local_2", ident="is_3")
    assert machine_bp_offset_for_stack_variable_8616(codegen, cloned_variable) == -2


def test_stack_variable_coordinate_registry_refuses_numeric_domain_collision() -> None:
    codegen = SimpleNamespace()
    projected = SimStackVariable(-4, 2, base="bp", name="total", ident="is_3")
    raw_bp_variable = SimStackVariable(-4, 2, base="bp", name="index", ident="is_4")

    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected,
        cvar=object(),
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )

    assert machine_bp_offset_for_stack_variable_8616(codegen, raw_bp_variable) == -4


def test_selected_formal_publishes_proven_entry_sp_coordinate() -> None:
    codegen = SimpleNamespace(
        next_ident=lambda name: name,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
    )
    formal = SimStackVariable(4, 2, base="bp", name="value", ident="arg_0")
    cvar = structured_c.CVariable(formal, codegen=codegen)

    projection = publish_selected_stack_cvar_projection_8616(
        codegen,
        cvar,
        bp_offset=4,
        size=2,
        entry_sp_offset=2,
    )

    assert projection is not None
    assert projection.entry_sp_offset == 2
    body_clone = SimStackVariable(2, 2, base="bp", name="value", ident="arg_0")
    assert machine_bp_offset_for_stack_variable_8616(codegen, body_clone) == 4


def test_selected_formal_replaces_conflicting_stale_projection() -> None:
    codegen = SimpleNamespace(
        next_ident=lambda name: name,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
    )
    stale = SimStackVariable(6, 2, base="bp", name="arg_6")
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=stale,
        cvar=object(),
        bp_offset=6,
        entry_sp_offset=6,
        size=2,
    )
    selected = SimStackVariable(4, 2, base="bp", name="arg_6", ident="arg_1")
    cvar = structured_c.CVariable(selected, codegen=codegen)

    projection = publish_selected_stack_cvar_projection_8616(
        codegen,
        cvar,
        bp_offset=6,
        size=2,
        entry_sp_offset=4,
    )

    assert projection is not None
    assert projection.variable is selected
    assert projection.entry_sp_offset == 4
    clone = SimStackVariable(4, 2, base="bp", name="arg_6", ident="arg_1")
    assert machine_bp_offset_for_stack_variable_8616(codegen, clone) == 6


def test_stack_prototype_indexes_existing_cvars_by_machine_bp_coordinate() -> None:
    codegen = SimpleNamespace(
        next_ident=lambda name: name,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
    )
    body_variable = SimStackVariable(2, 2, base="bp", name="value", ident="arg_0")
    body_cvar = structured_c.CVariable(body_variable, codegen=codegen)
    codegen.cfunc = SimpleNamespace(variables_in_use={body_variable: body_cvar}, arg_list=[])
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=body_variable,
        cvar=body_cvar,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )

    indexed = _existing_stack_cvars_by_offset_8616(codegen)

    assert indexed == {4: body_cvar}


def test_stack_prototype_indexes_canonical_values_not_stale_map_keys() -> None:
    codegen = SimpleNamespace(
        next_ident=lambda name: name,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
    )
    first_variable = SimStackVariable(2, 2, base="bp", name="a", ident="arg_0")
    first_cvar = structured_c.CVariable(first_variable, codegen=codegen)
    second_variable = SimStackVariable(4, 2, base="bp", name="b", ident="arg_1")
    second_cvar = structured_c.CVariable(second_variable, codegen=codegen)
    first_key = SimStackVariable(2, 2, base="bp", name="stale_0")
    second_key = SimStackVariable(4, 2, base="bp", name="stale_2")
    codegen.cfunc = SimpleNamespace(
        variables_in_use={first_key: first_cvar, second_key: second_cvar},
        arg_list=[],
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=first_variable,
        cvar=first_cvar,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=second_variable,
        cvar=second_cvar,
        bp_offset=6,
        entry_sp_offset=4,
        size=2,
    )

    indexed = _existing_stack_cvars_by_offset_8616(codegen)

    assert indexed == {4: first_cvar, 6: second_cvar}


def test_stack_variable_coordinate_registry_maps_named_snapshot_clone() -> None:
    codegen = SimpleNamespace()
    raw_bp_variable = SimStackVariable(-6, 2, base="bp", name="local_4")
    projected = SimStackVariable(-4, 2, base="bp", name="local_2")
    cloned_projection = SimStackVariable(-4, 2, base="bp", name="local_2", ident="")

    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=raw_bp_variable,
        cvar=object(),
        bp_offset=-4,
        entry_sp_offset=-6,
        size=2,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected,
        cvar=object(),
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )

    assert machine_bp_offset_for_stack_variable_8616(codegen, cloned_projection) == -2


def test_stack_variable_coordinate_registry_preserves_legacy_unprojected_offset() -> None:
    codegen = SimpleNamespace()
    variable = SimStackVariable(-6, 2, base="bp", name="legacy")

    assert machine_bp_offset_for_stack_variable_8616(codegen, variable) == -6

    reset_stack_variable_coordinate_registry_8616(codegen)
    assert stack_variable_coordinate_registry_8616(codegen).projections == ()


def test_typed_function_interface_projects_unregistered_entry_sp_variables() -> None:
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    short_type = SimTypeShort(False)
    argument_variable = SimStackVariable(2, 2, base="bp", name="arg_4")
    argument = structured_c.CVariable(
        argument_variable,
        variable_type=short_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=(argument,),
        functy=SimTypeFunction((short_type,), short_type),
    )
    local_clone = SimStackVariable(-0x2E, 2, base="bp", name="local_2c")

    assert final_c_function_machine_bp_offset_8616(codegen, argument_variable) == 4
    assert final_c_function_machine_bp_offset_8616(codegen, local_clone) == -0x2C
    assert machine_bp_offset_for_stack_variable_8616(codegen, local_clone) == -0x2C


def test_function_interface_does_not_project_unregistered_positive_slots() -> None:
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    short_type = SimTypeShort(False)
    arguments = tuple(
        structured_c.CVariable(
            SimStackVariable(offset, 2, base="bp", name=f"arg_{offset:x}"),
            variable_type=short_type,
            codegen=codegen,
        )
        for offset in (2, 4, 6, 8)
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=arguments,
        functy=SimTypeFunction((short_type,) * 4, short_type),
    )

    split_wide_slot = SimStackVariable(6, 2, base="bp", name="arg_8")
    assert machine_bp_offset_for_stack_variable_8616(codegen, split_wide_slot) == 6


def test_final_argument_storage_projects_without_transient_function_type() -> None:
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    argument = structured_c.CVariable(
        SimStackVariable(2, 2, base="bp", name="arg_4"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(arg_list=(argument,))
    local = SimStackVariable(-0x2E, 1, base="bp", name="local_2c")

    assert final_c_function_machine_bp_offset_8616(codegen, local) == -0x2C


def test_inconsistent_function_interface_refuses_coordinate_projection() -> None:
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    short_type = SimTypeShort(False)
    first = structured_c.CVariable(
        SimStackVariable(2, 2, base="bp", name="arg_4"),
        variable_type=short_type,
        codegen=codegen,
    )
    second = structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="arg_6"),
        variable_type=short_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=(first, second),
        functy=SimTypeFunction((short_type, short_type), short_type),
    )

    unresolved = SimStackVariable(-0x2E, 2, base="bp", name="local_2e")
    assert machine_bp_offset_for_stack_variable_8616(codegen, unresolved) == -0x2E


def test_machine_bp_function_interface_is_not_shifted_twice() -> None:
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    short_type = SimTypeShort(False)
    argument = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_4"),
        variable_type=short_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=(argument,),
        functy=SimTypeFunction((short_type,), short_type),
    )

    local = SimStackVariable(-2, 2, base="bp", name="local_2")
    assert machine_bp_offset_for_stack_variable_8616(codegen, argument.variable) == 4
    assert machine_bp_offset_for_stack_variable_8616(codegen, local) == -2


def test_bound_machine_bp_argument_projects_final_entry_sp_local() -> None:
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    short_type = SimTypeShort(False)
    entry_sp_argument = SimStackVariable(2, 2, base="bp", name="arg_4")
    machine_bp_argument = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="arg_4"),
        variable_type=short_type,
        codegen=codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=entry_sp_argument,
        cvar=machine_bp_argument,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=(machine_bp_argument,),
        functy=SimTypeFunction((short_type,), short_type),
    )
    local = SimStackVariable(-0x2E, 2, base="bp", name="local_2c")

    assert final_c_function_machine_bp_offset_8616(codegen, local) == -0x2C
    assert machine_bp_offset_for_stack_variable_8616(codegen, local) == -0x2C


def test_stack_variable_coordinate_registry_maps_contained_high_byte() -> None:
    codegen = SimpleNamespace()
    owner = SimStackVariable(-6, 2, base="bp", name="local_4")
    high_byte = SimStackVariable(-5, 1, base="bp", name="local_5")

    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=owner,
        cvar=object(),
        bp_offset=-4,
        entry_sp_offset=-6,
        size=2,
    )

    assert machine_bp_offset_for_stack_variable_8616(codegen, high_byte) == -3


def test_projection_name_replay_wins_over_generated_frame_carrier() -> None:
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(variables_in_use={}, unified_local_vars={}),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    projected = SimStackVariable(-6, 2, base="bp", name="local_2")
    projected_cvar = structured_c.CVariable(projected, codegen=codegen)
    carrier = SimStackVariable(-2, 1, base="bp", name="local_2")
    carrier_cvar = structured_c.CVariable(carrier, codegen=codegen)
    contained = SimStackVariable(-5, 1, base="bp", name="local_2")
    contained_cvar = structured_c.CVariable(contained, codegen=codegen)
    projected_clone = SimStackVariable(-6, 2, base="bp", name="local_6")
    codegen.cfunc.statements = structured_c.CVariable(projected_clone, codegen=codegen)
    codegen.cfunc.variables_in_use.update(
        {projected: projected_cvar, carrier: carrier_cvar, contained: contained_cvar}
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected,
        cvar=projected_cvar,
        bp_offset=-2,
        entry_sp_offset=-6,
        size=2,
        display_name="local_2",
    )
    projected.name = "local_6"

    assert reapply_stack_variable_projection_names_8616(codegen) is True
    assert projected.name == "local_2"
    assert projected_clone.name == "local_2"
    assert carrier.name == "stack_sp_m2_1"
    assert contained.name == "stack_sp_m5_1"


def test_projection_name_replay_uses_logical_aggregate_extent() -> None:
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        cfunc=SimpleNamespace(variables_in_use={}, unified_local_vars={}),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    projected = SimStackVariable(-92, 2, base="bp", name="stack_sp_m5c_2")
    projected_cvar = structured_c.CVariable(
        projected,
        variable_type=SimTypeFixedSizeArray(SimTypeShort(False), 43),
        codegen=codegen,
    )
    codegen.cfunc.statements = projected_cvar
    codegen.cfunc.variables_in_use[projected] = projected_cvar
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected,
        cvar=projected_cvar,
        bp_offset=-90,
        entry_sp_offset=-92,
        size=86,
        display_name="local_5a",
    )

    assert reapply_stack_variable_projection_names_8616(codegen) is True
    assert projected.name == "local_5a"


def test_projected_word_reconciles_regenerated_byte_views() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(
            addr=0x1000,
            variables_in_use={},
            unified_local_vars={},
            arg_list=(),
        ),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    owner = SimStackVariable(-6, 2, base="bp", name="local_4")
    owner_cvar = structured_c.CVariable(
        owner,
        variable_type=SimTypeShort(False).with_arch(project.arch),
        codegen=codegen,
    )
    regenerated = SimStackVariable(-6, 1, base="bp", name="local_6")
    regenerated_unified = SimStackVariable(-6, 1, base="bp", name="v4")
    regenerated_cvar = structured_c.CVariable(
        regenerated,
        unified_variable=regenerated_unified,
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use.update(
        {owner: owner_cvar, regenerated: regenerated_cvar}
    )
    codegen.cfunc.unified_local_vars[regenerated] = {
        (regenerated_cvar, regenerated_cvar.variable_type)
    }

    resolved = materialize_stack_cvar_at_offset_from_facts_8616(
        codegen,
        -6,
        size=2,
        machine_bp_offset=-4,
        preferred_name="local_4",
    )

    assert resolved is owner_cvar
    assert regenerated.size == regenerated_unified.size == 2
    assert regenerated.name == regenerated_unified.name == "local_4"
    assert isinstance(regenerated_cvar.variable_type, SimTypeShort)
    assert machine_bp_offset_for_stack_variable_8616(codegen, regenerated) == -4


def test_projected_local_uses_machine_bp_name_and_entry_sp_storage() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    physical_variable = SimStackVariable(-4, 2, base="bp", name="local_4")
    unified_variable = SimStackVariable(-4, 2, base="bp", name="local_4")
    codegen = SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(
            addr=0x1000,
            variables_in_use=None,
            unified_local_vars=None,
            arg_list=(),
        ),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    existing_cvar = structured_c.CVariable(
        physical_variable,
        unified_variable=unified_variable,
        variable_type=SimTypeShort(False).with_arch(project.arch),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use = {physical_variable: existing_cvar}
    codegen.cfunc.unified_local_vars = {
        unified_variable: {(existing_cvar, existing_cvar.variable_type)}
    }

    cvar = materialize_stack_cvar_at_offset_from_facts_8616(
        codegen,
        -4,
        size=2,
        machine_bp_offset=-2,
        preferred_name="var_2",
    )

    assert isinstance(cvar, structured_c.CVariable)
    assert cvar is existing_cvar
    assert isinstance(cvar.variable, SimStackVariable)
    assert cvar.variable.offset == -4
    assert cvar.variable.name == "local_2"
    assert cvar.unified_variable is unified_variable
    assert unified_variable.name == "local_2"
    assert next(iter(codegen.cfunc.unified_local_vars)).name == "local_2"
    assert machine_bp_offset_for_stack_variable_8616(codegen, cvar.variable) == -2


def test_direct_stack_update_reuses_projected_machine_bp_variable() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(
            addr=0x1000,
            variables_in_use={},
            unified_local_vars={},
            arg_list=(),
            statements=None,
        ),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    variable = SimStackVariable(-4, 2, base="bp", name="local_2")
    cvar = structured_c.CVariable(
        variable,
        variable_type=SimTypeShort(False).with_arch(project.arch),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[variable] = cvar
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=cvar,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )

    resolved = _resolve_direct_stack_update_cvar_8616(codegen, -2, 2)

    assert resolved is cvar
    assert tuple(codegen.cfunc.variables_in_use) == (variable,)


def test_selected_projected_cvar_is_published_on_regenerated_codegen() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    source_codegen = SimpleNamespace(
        project=project,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    variable = SimStackVariable(-4, 2, base="bp", name="local_2")
    cvar = structured_c.CVariable(
        variable,
        variable_type=SimTypeShort(False).with_arch(project.arch),
        codegen=source_codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        source_codegen,
        variable=variable,
        cvar=cvar,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )
    regenerated_codegen = SimpleNamespace()

    projection = publish_selected_stack_cvar_projection_8616(
        regenerated_codegen,
        cvar,
        bp_offset=-2,
        size=2,
    )

    assert projection is not None
    assert projection.entry_sp_offset == -4
    assert stack_cvar_for_machine_bp_range_8616(regenerated_codegen, -2, 2) is cvar


def test_selected_cvar_preserves_existing_coordinate_projection() -> None:
    codegen = SimpleNamespace()
    projected = SimStackVariable(-8, 2, base="bp", name="j", ident="is_3")
    selected = SimStackVariable(-6, 2, base="bp", name="j", ident="is_4")
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected,
        cvar=object(),
        bp_offset=-6,
        entry_sp_offset=-8,
        size=2,
    )
    selected_cvar = SimpleNamespace(variable=selected)

    projection = publish_selected_stack_cvar_projection_8616(
        codegen,
        selected_cvar,
        bp_offset=-6,
        size=2,
    )

    assert projection is not None
    assert projection.variable is projected
    assert projection.entry_sp_offset == -8
    assert projection.equivalent_variables == (selected,)
    assert projection.cvar is selected_cvar
    assert machine_bp_offset_for_stack_variable_8616(codegen, selected) == -6


def test_stable_stack_access_prefers_exact_projection_over_legacy_raw_offset() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(
            addr=0x1000,
            variables_in_use={},
            unified_local_vars={},
            arg_list=(),
            statements=None,
        ),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    raw_variable = SimStackVariable(-2, 2, base="bp", name="legacy_local_2")
    raw_cvar = structured_c.CVariable(
        raw_variable,
        variable_type=SimTypeShort(False).with_arch(project.arch),
        codegen=codegen,
    )
    projected_variable = SimStackVariable(-4, 2, base="bp", name="local_2")
    projected_cvar = structured_c.CVariable(
        projected_variable,
        variable_type=SimTypeShort(False).with_arch(project.arch),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use.update(
        {
            raw_variable: raw_cvar,
            projected_variable: projected_cvar,
        }
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected_variable,
        cvar=projected_cvar,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )

    resolved = stack_cvar_for_stable_ss_linear_access_8616(
        codegen,
        RealModeLinearStackAccess8616(-2, 2),
    )

    assert isinstance(resolved, CSemanticCast8616)
    assert resolved.expr is projected_cvar


def test_direct_bp_call_source_keeps_exact_projected_stack_variable() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(
        project=project,
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )
    _bind_call_argument_setup_liveness_classifier_8616(
        codegen,
        call_argument_setup_is_proven_dead_8616,
    )
    raw_variable = SimStackVariable(-2, 2, base="bp", name="legacy_local_2")
    raw_cvar = structured_c.CVariable(
        raw_variable,
        variable_type=SimTypeShort(False).with_arch(project.arch),
        codegen=codegen,
    )
    projected_variable = SimStackVariable(-4, 2, base="bp", name="local_2")
    projected_cvar = structured_c.CVariable(
        projected_variable,
        variable_type=SimTypeShort(False).with_arch(project.arch),
        codegen=codegen,
    )
    call = structured_c.CFunctionCall(
        "sub_128e4",
        SimpleNamespace(name="sub_128e4", prototype=None),
        [raw_cvar],
        codegen=codegen,
    )
    statements = structured_c.CStatements(
        [structured_c.CExpressionStatement(call, codegen=codegen)],
        addr=0x1000,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={raw_variable: raw_cvar, projected_variable: projected_cvar},
        unified_local_vars={},
        arg_list=(),
        statements=statements,
        body=statements,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected_variable,
        cvar=projected_cvar,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
    )
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x1010,
            target_addr=0x128E4,
            return_addr=0x1013,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
            push_arg_sources=(("bp", -2, 2),),
        )
    }

    assert _materialize_callsite_stack_arguments_8616(project, codegen) is True
    assert call.args[0].variable is projected_variable


def test_scalar_clone_cannot_be_reinterpreted_as_neighboring_array() -> None:
    """Competing raw-BP storage blocks numeric entry-SP containment recovery."""
    codegen = SimpleNamespace()
    scalar = SimStackVariable(-20, 1, base="bp", ident="saved", region=0x1000)
    buffer = SimStackVariable(-20, 16, base="bp", ident="buffer", region=0x1000)
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=scalar, cvar=object(), bp_offset=-20,
        entry_sp_offset=-22, size=1,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=buffer, cvar=object(), bp_offset=-18,
        entry_sp_offset=-20, size=16,
    )
    clone = SimStackVariable(-20, 1, base="bp", ident="saved", region=0x1000)

    assert machine_bp_offset_for_stack_variable_8616(codegen, scalar) == -20
    assert machine_bp_offset_for_stack_variable_8616(codegen, buffer) == -18
    assert machine_bp_offset_for_stack_variable_8616(codegen, clone) in (None, -20)
