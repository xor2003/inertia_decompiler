"""Call-output fields must retain their binary-proven machine-BP coordinates."""

from dataclasses import replace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CFunction, CVariable, CVariableField
from angr.sim_type import SimStruct, SimTypeBottom, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.lowering.call_output_object_projection import publish_call_output_object_projection_8616
from angr_platforms.X86_16.lowering.call_output_stack_object_replay import reapply_call_output_stack_object_types_8616
from angr_platforms.X86_16.lowering.call_output_stack_objects import (
    lower_call_output_stack_fields_in_condition_8616,
)
from angr_platforms.X86_16.lowering.stack_coordinate_rebinding import reset_local_stack_coordinate_projections_8616
from angr_platforms.X86_16.lowering.stack_lowering_impl import _canonicalize_stack_cvar_expr
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    StackCoordinateProducer8616,
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_projection_8616,
    stack_variable_coordinate_registry_8616,
)
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from test_x86_16_call_output_stack_objects import _condition, _fixture, _VariableManager

_OBJECT_BP = -112
_OBJECT_SIZE = 22
_BACKING_SIZE = 112
_FIRST_FIELD_BP = -94
_FIELD_COUNT = 2


def test_call_output_publishes_missing_projection_before_field_materialization():
    codegen, condition, _carriers = _fixture(include_array_boundary=True, entry_sp_bias=-2)
    call = codegen.cfunc.statements.statements[0].expr
    old_base = call.args[0].operand
    registry = stack_variable_coordinate_registry_8616(codegen)
    codegen._inertia_stack_variable_coordinate_registry_8616 = replace(
        registry, projections=tuple(item for item in registry.projections if item.variable is not old_base.variable)
    )
    codegen.cfunc.variables_in_use.pop(old_base.variable)
    narrow = SimStackVariable(-114, 1, base="bp", name="config", region=0x1000)
    base = CVariable(narrow, variable_type=SimTypeBottom(), codegen=codegen)
    call.args[0].operand = base
    codegen.cfunc.variables_in_use[narrow] = base
    conditions = (_condition(-94, 0x103F), _condition(-98, 0x1048))

    result = lower_call_output_stack_fields_in_condition_8616(codegen, condition, conditions)

    assert result.stats.materialized_count == _FIELD_COUNT
    field = result.expression.lhs.lhs
    assert isinstance(field, CVariableField)
    bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, field.variable.variable)
    assert bp_offset == _OBJECT_BP
    assert bp_offset + field.field.offset == _FIRST_FIELD_BP
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(narrow)
    assert projection is not None
    assert (projection.bp_offset, projection.entry_sp_offset, projection.size) == (-112, -114, 22)
    assert narrow.size == 1


def test_local_storage_replay_keeps_call_object_coordinate_owner():
    codegen, _condition_expr, _carriers = _fixture(include_array_boundary=True, entry_sp_bias=-2)
    base = codegen.cfunc.statements.statements[0].expr.args[0].operand
    publish_call_output_object_projection_8616(codegen, base, bp_offset=-112, byte_size=22)
    scalar = SimStackVariable(-10, 2, base="bp", name="scalar")
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=scalar, cvar=CVariable(scalar, codegen=codegen),
        bp_offset=-8, entry_sp_offset=-10, size=2,
    )

    reset_local_stack_coordinate_projections_8616(codegen, replaced_bp_ranges=frozenset({(-8, 2)}))

    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(base.variable)
    assert projection is not None
    assert (projection.bp_offset, projection.entry_sp_offset, projection.size) == (-112, -114, 22)
    assert projection.producer is StackCoordinateProducer8616.CALL_OUTPUT_OBJECT
    assert stack_variable_coordinate_registry_8616(codegen).for_variable(scalar) is None
    assert machine_bp_offset_for_stack_variable_8616(codegen, base.variable) == _OBJECT_BP


def test_partial_replay_preserves_distinct_coordinates_with_equal_numeric_offsets():
    codegen, _condition_expr, _carriers = _fixture(include_array_boundary=True, entry_sp_bias=-2)
    saved_bp, buffer_bp = -20, -18
    saved = SimStackVariable(saved_bp, 1, base="bp", name="saved")
    buffer = SimStackVariable(saved_bp, 16, base="bp", name="buffer")
    replaced = SimStackVariable(-4, 2, base="bp", name="counter")
    for variable, bp_offset in ((saved, saved_bp), (buffer, buffer_bp), (replaced, -2)):
        record_stack_variable_coordinate_projection_8616(
            codegen, variable=variable, cvar=CVariable(variable, codegen=codegen),
            bp_offset=bp_offset, entry_sp_offset=variable.offset, size=variable.size,
        )

    reset_local_stack_coordinate_projections_8616(codegen, replaced_bp_ranges=frozenset({(-2, 2)}))

    registry = stack_variable_coordinate_registry_8616(codegen)
    assert registry.for_variable(replaced) is None
    assert registry.for_variable(saved) is not None
    assert registry.for_variable(buffer) is not None
    assert machine_bp_offset_for_stack_variable_8616(codegen, saved) == saved_bp
    assert machine_bp_offset_for_stack_variable_8616(codegen, buffer) == buffer_bp


def test_canonical_stack_view_never_falls_through_to_numeric_lookup():
    codegen, _condition_expr, _carriers = _fixture(include_array_boundary=True, entry_sp_bias=-2)
    saved = SimStackVariable(-20, 1, base="bp", name="saved")
    view = CVariable(saved, variable_type=SimTypeShort(False), codegen=codegen)
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=saved, cvar=view, bp_offset=-20, entry_sp_offset=-20, size=1,
    )

    def forbidden_lookup(*args, **kwargs):
        pytest.fail("an authoritative canonical view must not use raw-offset lookup")

    result = _canonicalize_stack_cvar_expr(
        view, codegen, unwrap_c_casts=lambda value: value,
        resolve_stack_cvar_at_offset=forbidden_lookup,
    )
    assert result is view


@pytest.mark.parametrize("byte_size,bp_offset", [(0, -112), (-1, -112), (22, -110)])
def test_call_output_projection_refuses_invalid_or_conflicting_facts(byte_size, bp_offset):
    codegen, _condition_expr, _carriers = _fixture(include_array_boundary=True, entry_sp_bias=-2)
    base = codegen.cfunc.statements.statements[0].expr.args[0].operand
    previous = stack_variable_coordinate_registry_8616(codegen)

    with pytest.raises(PipelineHardError):
        publish_call_output_object_projection_8616(codegen, base, bp_offset=bp_offset, byte_size=byte_size)

    assert stack_variable_coordinate_registry_8616(codegen) is previous


@pytest.mark.parametrize("bias", [0, -2])
def test_call_output_projection_replay_preserves_existing_aliases(bias):
    codegen, _condition_expr, _carriers = _fixture(include_array_boundary=True, entry_sp_bias=bias)
    base = codegen.cfunc.statements.statements[0].expr.args[0].operand
    first = publish_call_output_object_projection_8616(codegen, base, bp_offset=-112, byte_size=22)
    alias_variable = SimStackVariable(-112 + bias, 1, base="bp", name="config_alias", region=0x1000)
    alias = CVariable(alias_variable, variable_type=base.variable_type, codegen=codegen)

    rebound = publish_call_output_object_projection_8616(codegen, alias, bp_offset=-112, byte_size=22)
    replayed = publish_call_output_object_projection_8616(codegen, base, bp_offset=-112, byte_size=22)

    assert rebound.variable is first.variable
    assert replayed.variable is first.variable
    assert alias_variable in replayed.equivalent_variables
    assert replayed.size == _OBJECT_SIZE
    assert base.variable.size == _BACKING_SIZE
    assert alias_variable.size == 1
    assert machine_bp_offset_for_stack_variable_8616(codegen, alias_variable) == _OBJECT_BP


@pytest.mark.parametrize("stale_ast", [False, True])
def test_call_output_replay_refreshes_real_cfunction_declaration_types(stale_ast):
    class VariableManager(_VariableManager):
        def unified_variable(self, _variable):
            return None

        def get_variable_type(self, variable):
            return self.variable_types.get(variable)

    codegen, condition, _carriers = _fixture(include_array_boundary=True, entry_sp_bias=-2)
    previous = codegen.cfunc
    manager = VariableManager()
    codegen.cfunc = CFunction(
        previous.addr, "example", SimTypeFunction([], SimTypeBottom(label="void")), [],
        previous.statements, previous.variables_in_use, manager, codegen=codegen,
    )
    result = lower_call_output_stack_fields_in_condition_8616(
        codegen, condition, (_condition(-94, 0x103F), _condition(-98, 0x1048)),
    )
    base = result.facts[0].base_cvar
    if stale_ast:
        base.variable_type = SimTypeShort(False)
    manager.set_variable_type(base.variable, SimTypeShort(False))
    codegen.cfunc.refresh()
    assert all(isinstance(type_, SimTypeShort) for _, type_ in codegen.cfunc.unified_local_vars[base.variable])
    unrelated = {variable: entries for variable, entries in codegen.cfunc.unified_local_vars.items()
                 if variable is not base.variable}

    assert reapply_call_output_stack_object_types_8616(codegen)

    assert isinstance(base.variable_type, SimStruct)
    assert isinstance(manager.get_variable_type(base.variable), SimStruct)
    assert all(isinstance(type_, SimStruct) for _, type_ in codegen.cfunc.unified_local_vars[base.variable])
    assert all(codegen.cfunc.unified_local_vars[variable] is entries for variable, entries in unrelated.items())
    assert not reapply_call_output_stack_object_types_8616(codegen)
