"""Regress stack-coordinate ownership across validation AST rollback."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeFixedSizeArray, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
import inertia.postprocess.decompiler_postprocess_stage as postprocess_stage
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.stack_coordinate_rebinding import (
    rebind_restored_stack_coordinate_registry_8616,
)
from inertia.lowering.stack_prototype_materialization import (
    _iter_existing_stack_cvars_at_offset_8616,
    materialize_annotated_stack_prototype_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_projection_8616,
    stack_cvar_for_machine_bp_range_8616,
    stack_variable_coordinate_registry_8616,
)
from inertia.lowering.stack_variable_display_names import (
    publish_stack_variable_projection_display_names_8616,
    reapply_stack_variable_projection_names_8616,
)

from inertia.lowering.annotations import ANNOTATION_KEY


def _codegen() -> SimpleNamespace:
    return SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
    )


@pytest.mark.parametrize("backing_offset", [-18, -20])
@pytest.mark.parametrize("matching_ident", [False, True])
def test_restored_aggregate_rebinds_exact_narrow_backing_view(backing_offset, matching_ident):
    """A wide projection retains its proven narrow backing identity across clones."""
    codegen = _codegen()
    array = SimTypeFixedSizeArray(SimTypeChar(False), 16).with_arch(codegen.project.arch)
    stale = SimStackVariable(backing_offset, 1, base="bp", ident="buffer-view")
    restored = SimStackVariable(
        backing_offset, 1, base="bp", ident="buffer-view" if matching_ident else "other-view",
    )
    stale_cvar = structured_c.CVariable(stale, variable_type=array, codegen=codegen)
    restored_cvar = structured_c.CVariable(restored, variable_type=array, codegen=codegen)
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=stale, cvar=stale_cvar, bp_offset=-18,
        entry_sp_offset=-20, size=16,
    )
    root = structured_c.CStatements([restored_cvar], codegen=codegen)

    report = rebind_restored_stack_coordinate_registry_8616(codegen, root)

    assert report.materialized_count == int(matching_ident)
    projection = stack_variable_coordinate_registry_8616(codegen).for_bp_range(-18, 16)
    assert projection is not None
    assert projection.cvar is (restored_cvar if matching_ident else stale_cvar)
    assert projection.size == 16
    assert projection.value_size == 16
    if matching_ident:
        assert machine_bp_offset_for_stack_variable_8616(codegen, restored) == -18


def test_restored_ast_rebinds_projection_away_from_stale_cvar() -> None:
    codegen = _codegen()
    word_type = SimTypeShort(False).with_arch(codegen.project.arch)
    stale_variable = SimStackVariable(
        -4,
        2,
        base="bp",
        name="err",
        ident="is_3",
    )
    stale_cvar = structured_c.CVariable(
        stale_variable,
        variable_type=word_type,
        codegen=codegen,
    )
    restored_variable = SimStackVariable(
        -4,
        2,
        base="bp",
        name="err_2",
        ident="is_3",
    )
    restored_cvar = structured_c.CVariable(
        restored_variable,
        variable_type=word_type,
        codegen=codegen,
    )
    root = structured_c.CStatements([restored_cvar], codegen=codegen)
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=stale_variable,
        cvar=stale_cvar,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
        display_name="err",
    )

    report = rebind_restored_stack_coordinate_registry_8616(codegen, root)

    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.failure_count == 0
    assert stack_cvar_for_machine_bp_range_8616(codegen, -2, 2) is restored_cvar
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(
        restored_variable,
    )
    assert projection is not None
    assert projection.cvar is restored_cvar
    assert projection.display_name == "err"

    codegen.cfunc = SimpleNamespace(
        variables_in_use={restored_variable: restored_cvar},
        unified_local_vars={},
        statements=root,
    )
    assert reapply_stack_variable_projection_names_8616(codegen) is True
    assert restored_variable.name == "err"


def test_machine_bp_name_map_updates_only_unique_projection() -> None:
    codegen = _codegen()
    word_type = SimTypeShort(False).with_arch(codegen.project.arch)
    variable = SimStackVariable(-4, 2, base="bp", name="local_2", ident="is_3")
    cvar = structured_c.CVariable(variable, variable_type=word_type, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        variables_in_use={variable: cvar},
        unified_local_vars={},
        statements=structured_c.CStatements([cvar], codegen=codegen),
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=cvar,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
        display_name="local_2",
    )

    assert publish_stack_variable_projection_display_names_8616(codegen, {-2: "err"}) == 1
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(variable)
    assert projection is not None
    assert projection.display_name == "err"
    assert reapply_stack_variable_projection_names_8616(codegen) is True
    assert variable.name == "err"


def test_machine_bp_name_map_refuses_ambiguous_projection_widths() -> None:
    codegen = _codegen()
    word = SimStackVariable(-4, 2, base="bp", name="local_2", ident="is_3")
    byte = SimStackVariable(-4, 1, base="bp", name="local_2", ident="is_4")
    for variable in (word, byte):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=object(),
            bp_offset=-2,
            entry_sp_offset=-4,
            size=variable.size,
            display_name="local_2",
        )

    assert publish_stack_variable_projection_display_names_8616(codegen, {-2: "err"}) == 0
    assert {
        projection.display_name
        for projection in stack_variable_coordinate_registry_8616(codegen).projections
    } == {"local_2"}


def test_ambiguous_entry_sp_clone_does_not_alias_lower_bp_argument() -> None:
    codegen = _codegen()
    arch = codegen.project.arch
    word_type = SimTypeShort(False).with_arch(arch)
    first = SimStackVariable(2, 2, base="bp", name="a", ident="arg_0")
    second = SimStackVariable(4, 2, base="bp", name="arg_6", ident="arg_1")
    ambiguous_clone = SimStackVariable(
        4,
        2,
        base="bp",
        name="arg_6",
        ident="regenerated_arg_1",
    )
    first_cvar = structured_c.CVariable(first, variable_type=word_type, codegen=codegen)
    second_cvar = structured_c.CVariable(second, variable_type=word_type, codegen=codegen)
    clone_cvar = structured_c.CVariable(
        ambiguous_clone,
        variable_type=word_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        variables_in_use={first: first_cvar, second: second_cvar},
        arg_list=[first_cvar, clone_cvar],
    )
    for variable, cvar, bp_offset, entry_sp_offset in (
        (first, first_cvar, 4, 2),
        (second, second_cvar, 6, 4),
    ):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=cvar,
            bp_offset=bp_offset,
            entry_sp_offset=entry_sp_offset,
            size=2,
            display_name="arg_5" if bp_offset == 6 else "a",
        )

    assert machine_bp_offset_for_stack_variable_8616(codegen, ambiguous_clone) is None
    assert _iter_existing_stack_cvars_at_offset_8616(codegen, 4) == (first_cvar,)
    assert _iter_existing_stack_cvars_at_offset_8616(codegen, 6) == (second_cvar,)


def test_stack_prototype_materialization_preserves_colliding_entry_sp_clone() -> None:
    codegen = _codegen()
    arch = codegen.project.arch
    word_type = SimTypeShort(False).with_arch(arch)
    prototype = SimTypeFunction(
        [word_type, word_type],
        word_type,
        arg_names=("a", "arg_6"),
    ).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        prototype=prototype,
        is_prototype_guessed=True,
        info={
            ANNOTATION_KEY: {
                "stack_vars": {2: {"name": "a"}, 4: {"name": "b"}},
            }
        },
    )
    codegen.project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda addr, create=False: function),
    )
    first = SimStackVariable(2, 2, base="bp", name="a", ident="arg_0")
    second = SimStackVariable(4, 2, base="bp", name="arg_6", ident="arg_1")
    ambiguous_clone = SimStackVariable(
        4,
        2,
        base="bp",
        name="arg_6",
        ident="regenerated_arg_1",
    )
    first_cvar = structured_c.CVariable(first, variable_type=word_type, codegen=codegen)
    second_cvar = structured_c.CVariable(second, variable_type=word_type, codegen=codegen)
    clone_cvar = structured_c.CVariable(
        ambiguous_clone,
        variable_type=word_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        variables_in_use={first: first_cvar, second: second_cvar},
        unified_local_vars={},
        arg_list=[first_cvar, clone_cvar],
        functy=prototype,
        prototype=prototype,
        statements=structured_c.CStatements(
            [first_cvar, clone_cvar],
            codegen=codegen,
        ),
    )
    for variable, cvar, bp_offset, entry_sp_offset in (
        (first, first_cvar, 4, 2),
        (second, second_cvar, 6, 4),
    ):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=cvar,
            bp_offset=bp_offset,
            entry_sp_offset=entry_sp_offset,
            size=2,
            display_name="arg_5" if bp_offset == 6 else "a",
        )

    assert materialize_annotated_stack_prototype_8616(codegen.project, codegen) is True
    assert codegen.cfunc.arg_list == [first_cvar, second_cvar]
    assert [argument.variable.name for argument in codegen.cfunc.arg_list] == [
        "a",
        "b",
    ]
    assert ambiguous_clone.name == "arg_6"
    assert [
        machine_bp_offset_for_stack_variable_8616(codegen, argument.variable)
        for argument in codegen.cfunc.arg_list
    ] == [4, 6]


def test_validation_codegen_clone_rebinds_stack_coordinates_to_cloned_arguments() -> None:
    """Keep validation-clone storage identity independent from the live AST."""
    codegen = _codegen()
    word_type = SimTypeShort(False).with_arch(codegen.project.arch)
    lhs = SimStackVariable(2, 2, base="bp", name="a", ident="arg_0")
    rhs = SimStackVariable(4, 2, base="bp", name="b", ident="arg_1")
    lhs_cvar = structured_c.CVariable(lhs, variable_type=word_type, codegen=codegen)
    rhs_cvar = structured_c.CVariable(rhs, variable_type=word_type, codegen=codegen)
    statements = structured_c.CStatements(
        [lhs_cvar, rhs_cvar],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=[lhs_cvar, rhs_cvar],
        statements=statements,
        body=statements,
        unified_local_vars={},
        variables_in_use={lhs: lhs_cvar, rhs: rhs_cvar},
        codegen=codegen,
    )
    for variable, cvar, bp_offset in (
        (lhs, lhs_cvar, 4),
        (rhs, rhs_cvar, 6),
    ):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=cvar,
            bp_offset=bp_offset,
            entry_sp_offset=variable.offset,
            size=variable.size,
            display_name=variable.name,
        )

    cloned = postprocess_stage._clone_codegen_for_validation_summary_8616(codegen)

    assert cloned is not None
    assert cloned.cfunc.arg_list[0] is not lhs_cvar
    assert cloned.cfunc.arg_list[1] is not rhs_cvar
    assert all(
        isinstance(argument.variable, SimStackVariable)
        for argument in cloned.cfunc.arg_list
    )
    assert [argument.variable.offset for argument in cloned.cfunc.arg_list] == [2, 4]
    assert stack_cvar_for_machine_bp_range_8616(cloned, 4, 2) is cloned.cfunc.arg_list[0]
    assert stack_cvar_for_machine_bp_range_8616(cloned, 6, 2) is cloned.cfunc.arg_list[1]
