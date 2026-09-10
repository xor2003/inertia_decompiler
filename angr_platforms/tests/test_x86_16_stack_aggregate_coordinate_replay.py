"""Keep aggregate coordinate identity stable across declaration replay."""
from copy import copy

import pytest
from angr.analyses.decompiler.structured_codegen.c import CStatements, CUnaryOp, CVariable
from angr.sim_type import SimTypeChar, SimTypeFixedSizeArray
from angr_platforms.X86_16.lowering.stack_aggregate_objects import (
    StackAggregateObjectFact8616,
    _materialize_fact,
)
from angr_platforms.X86_16.lowering.stack_aggregate_projection import (
    restore_live_stack_aggregate_declaration_8616,
    select_stack_aggregate_projection_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_alias_8616,
    record_stack_variable_coordinate_projection_8616,
    reset_stack_variable_coordinate_registry_8616,
    stack_variable_coordinate_registry_8616,
)
from test_x86_16_stack_aggregate_objects import _AggregateCodegen, _stack_cvar


@pytest.mark.parametrize("live", [True, False])
@pytest.mark.parametrize("declared", [True, False])
@pytest.mark.parametrize("backing_size", [1, 16], ids=["narrow-backing", "full-backing"])
def test_aggregate_replay_restores_only_exact_live_tracked_storage(live, declared, backing_size, monkeypatch):
    monkeypatch.setattr(
        "angr_platforms.X86_16.lowering.stack_aggregate_objects.entry_sp_offset_for_machine_bp_range_8616",
        lambda *_args: -20,
    )
    codegen = _AggregateCodegen()
    array_type = SimTypeFixedSizeArray(SimTypeChar(False), 16)
    variable, array = _stack_cvar(codegen, -20, backing_size, "buffer", array_type)
    codegen._inertia_stack_aggregate_cvars_8616 = {-18: array}
    codegen.cfunc.statements = CStatements([array] if live else [], codegen=codegen)
    if not declared:
        codegen.cfunc.variables_in_use.clear()
    codegen.cfunc.unified_local_vars.clear()
    reset_stack_variable_coordinate_registry_8616(codegen)
    fact = StackAggregateObjectFact8616(-18, 16, 1, 18, 1, 2, (-18,), -2, 2)

    assert _materialize_fact(codegen, fact)[0]
    projection = stack_variable_coordinate_registry_8616(codegen).for_bp_range(-18, 16)
    assert projection is not None
    if live or declared:
        assert projection.variable is variable
        assert variable in codegen.cfunc.variables_in_use
        assert projection.bp_offset == -18 and projection.entry_sp_offset == -20
    else:
        assert projection.variable is not variable


@pytest.mark.parametrize(
    "failure", ["region", "width", "coordinate", "unknown_frame", "lookalike", "narrow_untyped", "narrow_extent"],
)
def test_live_aggregate_restore_refuses_unproven_identity(failure):
    codegen = _AggregateCodegen()
    variable, array = _stack_cvar(codegen, -20, 16, "buffer", SimTypeFixedSizeArray(SimTypeChar(False), 16))
    codegen.cfunc.variables_in_use.clear()
    codegen.cfunc.statements = CStatements([array], codegen=codegen)
    if failure == "region":
        variable.region = 0x2000
    elif failure in {"narrow_untyped", "narrow_extent"}:
        variable.size = 1
        array.variable_type = (
            SimTypeChar(False) if failure == "narrow_untyped" else SimTypeFixedSizeArray(SimTypeChar(False), 8)
        )
    elif failure == "lookalike":
        codegen.cfunc.statements = CStatements([
            CVariable(copy(variable), variable_type=array.variable_type, codegen=codegen),
        ], codegen=codegen)
    entry_sp = None if failure == "unknown_frame" else -22 if failure == "coordinate" else -20
    assert not restore_live_stack_aggregate_declaration_8616(
        codegen, array, bp_offset=-18, entry_sp_offset=entry_sp, size=8 if failure == "width" else 16,
    )
    assert not codegen.cfunc.variables_in_use
    assert not stack_variable_coordinate_registry_8616(codegen).projections


def test_aggregate_replay_prefers_entry_sp_when_multiple_proven_views_exist():
    """Equivalent entry-SP fragments must not trigger a raw-BP fallback."""
    codegen = _AggregateCodegen()
    byte = SimTypeChar(False)
    _, raw = _stack_cvar(codegen, -18, 1, "raw", byte)
    _, first = _stack_cvar(codegen, -20, 1, "first", byte)
    _, second = _stack_cvar(codegen, -20, 2, "second", byte)

    selected = select_stack_aggregate_projection_8616(
        codegen, [raw, first, second], None,
        bp_offset=-18, entry_sp_offset=-20, size=16,
    )

    assert selected is first or selected is second
    assert selected.variable.offset == -20


@pytest.mark.parametrize("regenerated", [False, True])
def test_aggregate_replay_preserves_canonical_entry_sp_projection(regenerated):
    codegen = _AggregateCodegen()
    byte = SimTypeChar(False)
    legacy, _ = _stack_cvar(codegen, -18, 1, "fragment", byte)
    canonical, canonical_cvar = _stack_cvar(
        codegen, -20, 16, "buffer", SimTypeFixedSizeArray(byte, 16),
    )
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=canonical, cvar=canonical_cvar,
        bp_offset=-18, entry_sp_offset=-20, size=16,
    )
    record_stack_variable_coordinate_alias_8616(
        codegen, bp_offset=-18, size=16, variable=legacy,
    )
    if regenerated:
        del codegen.cfunc.variables_in_use[canonical]
        _, canonical_cvar = _stack_cvar(
            codegen, -20, 16, "buffer", SimTypeFixedSizeArray(byte, 16),
        )
    fact = StackAggregateObjectFact8616(-18, 16, 1, 18, 1, 2, (-18,), -2, 2)

    materialized, _ = _materialize_fact(codegen, fact)

    assert materialized
    projection = stack_variable_coordinate_registry_8616(codegen).for_bp_range(-18, 16)
    assert projection is not None
    assert projection.variable is canonical
    assert projection.variable.offset == projection.entry_sp_offset
    assert projection.cvar is canonical_cvar
    assert legacy in projection.equivalent_variables


def test_aggregate_replay_rebinds_proven_views_but_keeps_unrelated_storage():
    """A frame partition must have one declared variable across all AST views."""
    codegen = _AggregateCodegen()
    byte = SimTypeChar(False)
    canonical, array = _stack_cvar(codegen, -20, 16, "array", SimTypeFixedSizeArray(byte, 16))
    alias, view = _stack_cvar(codegen, -20, 2, "carrier", byte)
    unrelated, other = _stack_cvar(codegen, -30, 2, "other", byte)
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=canonical, cvar=array,
        bp_offset=-18, entry_sp_offset=-20, size=16,
    )
    record_stack_variable_coordinate_alias_8616(codegen, bp_offset=-18, size=16, variable=alias)
    reference = CUnaryOp("Reference", view, codegen=codegen)
    codegen.cfunc.statements = CStatements([reference, other], codegen=codegen)
    fact = StackAggregateObjectFact8616(-18, 16, 1, 18, 1, 2, (-18,), -2, 2)

    assert _materialize_fact(codegen, fact)[0]

    assert reference.operand.variable is canonical
    assert codegen.cfunc.statements.statements[1] is other
    assert alias not in codegen.cfunc.variables_in_use
    assert unrelated in codegen.cfunc.variables_in_use
    assert not _materialize_fact(codegen, fact)[1]
