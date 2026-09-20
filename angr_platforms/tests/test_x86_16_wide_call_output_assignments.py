"""Types/Lowering regressions for exact wide call-output C assignments."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeLong
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    stack_variable_coordinate_registry_8616,
)
from angr_platforms.X86_16.lowering.wide_call_output_assignment_contracts import (
    WideCallOutputAssignmentFailure8616,
)
from angr_platforms.X86_16.lowering.wide_call_output_assignments import (
    lower_wide_call_output_stack_assignments_8616,
)
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from x86_16_carry_borrow_call_output_support import wide_assignment_fixture

_DESTINATION_ENTRY_SP_OFFSET = -6
_SOURCE_ENTRY_SP_OFFSET = 2
_EXPECTED_CARRIER_STATEMENT_COUNT = 4


def test_lowering_materializes_wide_call_output_assignment_once() -> None:
    codegen, root, call, source = wide_assignment_fixture()

    artifact = lower_wide_call_output_stack_assignments_8616(codegen)

    assert artifact is not None and artifact.complete
    assert artifact.stats.changed_count == artifact.stats.materialized_count == 1
    assert len(root.statements) == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == "Add"
    assert assignment.rhs.lhs is call
    assert assignment.rhs.rhs is source
    registry = stack_variable_coordinate_registry_8616(codegen)
    assert registry.for_bp_range(-4, 4).entry_sp_offset == _DESTINATION_ENTRY_SP_OFFSET
    assert registry.for_bp_range(4, 4).entry_sp_offset == _SOURCE_ENTRY_SP_OFFSET

    replayed = lower_wide_call_output_stack_assignments_8616(codegen)
    assert replayed is not None and replayed.complete
    assert replayed.stats.changed_count == 0
    assert replayed.stats.already_materialized_count == 1
    assert root.statements == [assignment]


def test_lowering_prunes_fact_owned_carrier_regenerated_after_materialization() -> None:
    """Keep one evaluation when angr regenerates the same machine callsite."""
    codegen, root, call, source = wide_assignment_fixture()
    first = lower_wide_call_output_stack_assignments_8616(codegen)
    assert first is not None and first.complete
    canonical = root.statements[0]
    duplicate_call = CFunctionCall(
        0x2000,
        None,
        [],
        tags={"ins_addr": 0xFF0},
        codegen=codegen,
    )
    duplicate = CAssignment(
        canonical.lhs,
        CBinaryOp(
            "Add",
            duplicate_call,
            source,
            tags={"ins_addr": 0xFF0},
            codegen=codegen,
        ),
        tags={"ins_addr": 0xFF0},
        codegen=codegen,
    )
    root.statements.append(duplicate)
    codegen._inertia_callsite_summary_inventory_8616 = {
        0xFF0: CallsiteSummary8616(
            callsite_addr=0xFF0,
            target_addr=0x2000,
            return_addr=0x1000,
            kind="near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
        )
    }

    replayed = lower_wide_call_output_stack_assignments_8616(codegen)

    assert replayed is not None and replayed.complete
    assert replayed.stats.changed_count == replayed.stats.already_materialized_count == 1
    assert root.statements == [canonical]
    assert canonical.rhs.lhs is call


def test_lowering_matches_typed_constant_call_target() -> None:
    codegen, root, call, _source = wide_assignment_fixture()
    call.callee_target = CConstant(
        0x1000,
        SimTypeLong(False),
        tags={"ins_addr": 0xFF0},
        codegen=codegen,
    )
    codegen.project.loader = SimpleNamespace(
        main_object=SimpleNamespace(min_addr=0x1000),
    )

    artifact = lower_wide_call_output_stack_assignments_8616(codegen)

    assert artifact is not None and artifact.complete
    assert artifact.stats.changed_count == artifact.stats.materialized_count == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.lhs is call


@pytest.mark.parametrize(("target", "attached", "callsite", "accepted"), [
    ("arbitrary_label", 0x2000, 0xFF0, True),
    ("clock", None, 0xFF0, False),
    ("clock", 0x3000, 0xFF0, False),
    ("clock", True, 0xFF0, False),
    ("clock", "8192", 0xFF0, False),
    ("clock", 0x2000, 0xFE0, False),
    (0x2000, 0x2000, 0xFF0, True),
    (0x2000, 0x3000, 0xFF0, False),
    (0x3000, 0x2000, 0xFF0, False),
])
def test_named_call_preserves_binary_identity_without_trusting_its_name(
    target, attached, callsite, accepted,
) -> None:
    codegen, root, call, _source = wide_assignment_fixture(callsite_tag=callsite)
    call.callee_target = target
    if attached is not None:
        call.tags["inertia_target_addr_8616"] = attached
    original = tuple(root.statements)

    artifact = lower_wide_call_output_stack_assignments_8616(codegen)

    assert artifact is not None and artifact.complete
    assert artifact.stats.materialized_count == int(accepted)
    if accepted:
        assert root.statements[0].rhs.lhs is call
        replayed = lower_wide_call_output_stack_assignments_8616(codegen)
        assert replayed.stats.already_materialized_count == 1
        assert replayed.stats.changed_count == 0
    else:
        assert artifact.resolutions[0].failure is WideCallOutputAssignmentFailure8616.CALLSITE_MISSING
        assert tuple(root.statements) == original


def test_lowering_materializes_exact_adjacent_nested_carrier_group() -> None:
    codegen, root, call, source = wide_assignment_fixture(nested_carrier_group=True)
    call_group, carrier_group = root.statements
    assert isinstance(call_group, CStatements)
    assert isinstance(carrier_group, CStatements)

    artifact = lower_wide_call_output_stack_assignments_8616(codegen)

    assert artifact is not None and artifact.complete
    assert artifact.stats.changed_count == artifact.stats.materialized_count == 1
    assert root.statements == [call_group, carrier_group]
    assert len(call_group.statements) == 1
    assignment = call_group.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.lhs is call
    assert assignment.rhs.rhs is source
    assert carrier_group.statements == []

    replayed = lower_wide_call_output_stack_assignments_8616(codegen)
    assert replayed is not None and replayed.complete
    assert replayed.stats.already_materialized_count == 1
    assert root.statements == [call_group, carrier_group]


def test_lowering_materializes_carriers_split_across_nested_groups() -> None:
    """Join complete exact carriers after Structuring separates their groups."""
    codegen, root, call, source = wide_assignment_fixture(nested_carrier_group=True)
    call_group, carrier_group = root.statements
    assert isinstance(call_group, CStatements)
    assert isinstance(carrier_group, CStatements)
    first_carrier = carrier_group.statements.pop(0)
    first_group = CStatements([first_carrier], codegen=codegen)
    nested_call = CStatements([call_group, first_group], codegen=codegen)
    root.statements = [nested_call, carrier_group]

    artifact = lower_wide_call_output_stack_assignments_8616(codegen)

    assert artifact is not None and artifact.complete
    assert artifact.stats.changed_count == artifact.stats.materialized_count == 1
    assert root.statements == [nested_call]
    assert nested_call.statements == [call_group]
    assignment = call_group.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.lhs is call
    assert assignment.rhs.rhs is source


def test_lowering_refuses_unjoined_callsite_without_mutation() -> None:
    codegen, root, _call, _source = wide_assignment_fixture(callsite_tag=0xFE0)
    original = tuple(root.statements)

    artifact = lower_wide_call_output_stack_assignments_8616(codegen)

    assert artifact is not None and artifact.complete
    assert artifact.stats.normalized_fact_count == artifact.stats.failure_count == 1
    assert artifact.stats.classified_fact_count == artifact.stats.materialized_count == 0
    assert artifact.resolutions[0].failure is WideCallOutputAssignmentFailure8616.CALLSITE_MISSING
    assert tuple(root.statements) == original


def test_lowering_materializes_missing_exact_source_object_from_fact() -> None:
    codegen, root, _call, _source = wide_assignment_fixture(include_source=False)

    artifact = lower_wide_call_output_stack_assignments_8616(codegen)

    assert artifact is not None and artifact.complete
    assert artifact.stats.materialized_count == artifact.stats.changed_count == 1
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.rhs, CBinaryOp)
    source = assignment.rhs.rhs
    assert isinstance(source, CVariable)
    assert isinstance(source.variable, SimStackVariable)
    assert (source.variable.base, source.variable.offset, source.variable.size) == (
        "bp",
        2,
        4,
    )


def test_lowering_hard_fails_classified_mixed_carrier_ownership() -> None:
    codegen, root, _call, _source = wide_assignment_fixture(mixed_carrier=True)
    original = tuple(root.statements)

    with pytest.raises(PipelineHardError, match="accounting is incomplete"):
        lower_wide_call_output_stack_assignments_8616(codegen)

    artifact = codegen._inertia_wide_call_output_assignment_artifact_8616
    assert artifact.stats.classified_fact_count == artifact.stats.failure_count == 1
    assert artifact.stats.materialized_count == 0
    assert artifact.resolutions[0].failure is WideCallOutputAssignmentFailure8616.MIXED_STATEMENT_OWNERSHIP
    assert tuple(root.statements) == original


@pytest.mark.parametrize(
    "fixture_kwargs",
    (
        {"unrelated_nested_statement": True},
        {"mixed_carrier": True},
    ),
)
def test_lowering_refuses_noncarrier_effects_in_nested_group(
    fixture_kwargs: dict[str, bool],
) -> None:
    codegen, root, _call, _source = wide_assignment_fixture(
        nested_carrier_group=True,
        **fixture_kwargs,
    )
    call_group, carrier_group = root.statements
    assert isinstance(call_group, CStatements)
    assert isinstance(carrier_group, CStatements)
    original_call = tuple(call_group.statements)
    original_carriers = tuple(carrier_group.statements)

    with pytest.raises(PipelineHardError, match="accounting is incomplete"):
        lower_wide_call_output_stack_assignments_8616(codegen)

    artifact = codegen._inertia_wide_call_output_assignment_artifact_8616
    assert artifact.resolutions[0].failure is WideCallOutputAssignmentFailure8616.MIXED_STATEMENT_OWNERSHIP
    assert tuple(call_group.statements) == original_call
    assert tuple(carrier_group.statements) == original_carriers


def test_lowering_refuses_ambiguous_nested_carrier_parent() -> None:
    codegen, root, _call, _source = wide_assignment_fixture(nested_carrier_group=True)
    call_group, carrier_group = root.statements
    assert isinstance(call_group, CStatements)
    assert isinstance(carrier_group, CStatements)
    duplicate_parent = CStatements([call_group, CStatements([], codegen=codegen)], codegen=codegen)
    root.statements.append(duplicate_parent)

    with pytest.raises(PipelineHardError, match="accounting is incomplete"):
        lower_wide_call_output_stack_assignments_8616(codegen)

    artifact = codegen._inertia_wide_call_output_assignment_artifact_8616
    assert (
        artifact.resolutions[0].failure
        is WideCallOutputAssignmentFailure8616.CARRIER_PLACEMENT_AMBIGUOUS
    )
    assert len(call_group.statements) == 1
    assert len(carrier_group.statements) == _EXPECTED_CARRIER_STATEMENT_COUNT
