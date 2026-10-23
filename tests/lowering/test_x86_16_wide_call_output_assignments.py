"""Types/Lowering regressions for exact wide call-output C assignments."""

from __future__ import annotations

from dataclasses import replace
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

from inertia.ir import MemSpace
from inertia.lowering.stack_variable_coordinates import (
    stack_variable_coordinate_registry_8616,
)
from inertia.lowering.wide_call_output_assignment_contracts import (
    WideCallOutputAssignmentArtifact8616,
    WideCallOutputAssignmentFact8616,
    WideCallOutputAssignmentFailure8616,
    WideCallOutputAssignmentResolution8616,
    WideCallOutputAssignmentStats8616,
    WideCallOutputAssignmentVerdict8616,
)
from inertia.lowering.wide_call_output_assignment_evidence import (
    normalize_wide_call_output_assignment_fact_8616,
)
from inertia.lowering.wide_call_output_assignment_placement import (
    materialize_wide_call_output_assignment_8616,
)
from inertia.lowering.wide_call_output_assignment_replay import (
    _EVIDENCE_TAG_8616,
    WideCallOutputAuthoritativeOwnershipStatus8616,
    WideCallOutputReplayFailure8616,
    WideCallOutputReplayStatus8616,
    classify_authoritative_wide_call_output_projection_8616,
    reconcile_materialized_wide_call_output_assignment_8616,
)
from inertia.lowering.wide_call_output_assignments import (
    lower_wide_call_output_stack_assignments_8616,
)
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.semantics.carry_borrow_contracts import CarryBorrowKind8616
from inertia.widening.pair_type_contracts import WidePairState8616
from tests.fixtures.x86_16_carry_borrow_call_output_support import (
    WIDE_STACK_ADD,
    WIDE_STACK_SUB,
    wide_assignment_fixture,
    wide_assignment_storage,
)

_DESTINATION_ENTRY_SP_OFFSET = -6
_SOURCE_ENTRY_SP_OFFSET = 2
_EXPECTED_CARRIER_STATEMENT_COUNT = 4


def test_lowering_materializes_wide_call_output_assignment_once() -> None:
    codegen, root, call, source = wide_assignment_fixture()
    _pipeline, storage = wide_assignment_storage(codegen)

    artifact = lower_wide_call_output_stack_assignments_8616(codegen)

    assert artifact is not None and artifact.complete
    assert artifact.stats.changed_count == artifact.stats.materialized_count == 1
    fact = artifact.resolutions[0].fact
    assert fact is not None and fact.pair is storage.pair
    assert fact.pair.combine_authorized
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


def test_normalizer_retains_named_pair_through_fact() -> None:
    """The authoritative fact carries the retained PAIRED legality evidence."""
    codegen, _root, _call, _source = wide_assignment_fixture()
    pipeline, storage = wide_assignment_storage(codegen)

    fact = normalize_wide_call_output_assignment_fact_8616(pipeline, storage)

    assert isinstance(fact, WideCallOutputAssignmentFact8616)
    assert fact.pair is storage.pair
    assert fact.pair.state is WidePairState8616.PAIRED
    assert fact.pair.combine_authorized
    assert fact.pair.type.total_size == storage.address.size == 4


@pytest.mark.parametrize(
    "corrupt",
    (
        pytest.param(
            lambda storage: replace(storage, value=replace(storage.value, size=2)),
            id="shrunk-total",
        ),
        pytest.param(
            lambda storage: replace(
                storage,
                value=replace(
                    storage.value,
                    low=replace(
                        storage.value.low,
                        result=replace(storage.value.low.result, size=1),
                    ),
                ),
            ),
            id="shrunk-low-half",
        ),
        pytest.param(
            lambda storage: replace(
                storage,
                value=replace(
                    storage.value, low=storage.value.high, high=storage.value.low
                ),
            ),
            id="swapped-halves",
        ),
        pytest.param(
            lambda storage: replace(
                storage,
                value=replace(
                    storage.value,
                    high=replace(
                        storage.value.high,
                        result=replace(storage.value.high.result, name="si"),
                    ),
                ),
            ),
            id="foreign-half",
        ),
        pytest.param(
            lambda storage: replace(storage, value=replace(storage.value, pair=None)),
            id="missing-pair",
        ),
        pytest.param(
            lambda storage: replace(
                storage,
                value=replace(
                    storage.value,
                    pair=replace(storage.value.pair, state=WidePairState8616.UNPAIRED),
                ),
            ),
            id="unpaired-state",
        ),
        pytest.param(
            lambda storage: replace(
                storage, source_versions=storage.source_versions[:1]
            ),
            id="truncated-versions",
        ),
        pytest.param(
            lambda storage: replace(
                storage,
                value=replace(
                    storage.value, kind=CarryBorrowKind8616.SUB_WITH_BORROW
                ),
            ),
            id="foreign-kind",
        ),
        pytest.param(
            lambda storage: replace(
                storage,
                value=replace(
                    storage.value,
                    source_memory=replace(
                        storage.value.source_memory, space=MemSpace.DS
                    ),
                ),
            ),
            id="foreign-space",
        ),
    ),
)
def test_normalizer_refuses_corrupted_pair_preimages(corrupt) -> None:
    """Malformed, partial, swapped, or foreign pair evidence yields no fact."""
    codegen, root, _call, _source = wide_assignment_fixture()
    original = tuple(root.statements)
    pipeline, storage = wide_assignment_storage(codegen)

    result = normalize_wide_call_output_assignment_fact_8616(
        pipeline, corrupt(storage)
    )

    assert result is WideCallOutputAssignmentFailure8616.PAIR_LEGALITY_UNPROVEN
    assert tuple(root.statements) == original


def test_normalizer_refuses_shrunken_source_range() -> None:
    """A source range narrower than the retained pair width still refuses."""
    codegen, root, _call, _source = wide_assignment_fixture()
    original = tuple(root.statements)
    pipeline, storage = wide_assignment_storage(codegen)
    source_memory = storage.value.source_memory
    assert source_memory is not None
    corrupted = replace(
        storage,
        value=replace(
            storage.value,
            source_memory=replace(
                source_memory,
                addresses=(
                    replace(source_memory.addresses[0], size=1),
                    *source_memory.addresses[1:],
                ),
            ),
        ),
    )

    result = normalize_wide_call_output_assignment_fact_8616(pipeline, corrupted)

    assert result is WideCallOutputAssignmentFailure8616.SOURCE_RANGE_MISMATCH
    assert tuple(root.statements) == original


def test_lowering_refuses_corrupted_pair_preimage_without_mutation() -> None:
    """A corrupted retained pair never reaches C materialization."""
    codegen, root, _call, _source = wide_assignment_fixture()
    original = tuple(root.statements)
    pipeline, storage = wide_assignment_storage(codegen)
    corrupted = replace(storage, value=replace(storage.value, size=2))
    widening = pipeline.storage_widening
    resolutions = tuple(
        replace(resolution, value=corrupted)
        if resolution.value is storage
        else resolution
        for resolution in widening.resolutions
    )
    codegen._inertia_carry_borrow_widening_pipeline_8616 = replace(
        pipeline, storage_widening=replace(widening, resolutions=resolutions)
    )
    wide_stack = codegen._inertia_wide_carry_borrow_stack_artifact
    codegen._inertia_wide_carry_borrow_stack_artifact = replace(
        wide_stack,
        candidates=tuple(
            replace(candidate, source=corrupted)
            for candidate in wide_stack.candidates
        ),
    )

    artifact = lower_wide_call_output_stack_assignments_8616(codegen)

    assert artifact is not None and artifact.complete
    assert artifact.stats.materialized_count == artifact.stats.changed_count == 0
    assert (
        artifact.resolutions[0].failure
        is WideCallOutputAssignmentFailure8616.PAIR_LEGALITY_UNPROVEN
    )
    assert tuple(root.statements) == original


@pytest.mark.parametrize(
    "corrupt",
    (
        pytest.param(lambda fact: replace(fact, pair=None), id="pairless"),
        pytest.param(
            lambda fact: replace(
                fact, pair=replace(fact.pair, state=WidePairState8616.UNPAIRED)
            ),
            id="unpaired",
        ),
        pytest.param(
            lambda fact: replace(
                fact, pair=replace(fact.pair, state=WidePairState8616.SPLIT)
            ),
            id="split-only",
        ),
        pytest.param(
            lambda fact: replace(
                fact,
                pair=replace(fact.pair, low=fact.pair.high, high=fact.pair.low),
            ),
            id="swapped-pair",
        ),
        pytest.param(
            lambda fact: replace(
                fact, call_output=replace(fact.call_output, callsite_addr=0x9999)
            ),
            id="forged-callsite",
        ),
        pytest.param(
            lambda fact: replace(
                fact, destination_offset=fact.destination_offset + 2
            ),
            id="shifted-destination",
        ),
        pytest.param(
            lambda fact: replace(
                fact, kind=CarryBorrowKind8616.SUB_WITH_BORROW
            ),
            id="forged-kind",
        ),
    ),
)
def test_materializer_refuses_facts_without_pair_legality(corrupt) -> None:
    """A fact without authorized retained pair evidence never mutates C."""
    codegen, root, _call, _source = wide_assignment_fixture()
    original = tuple(root.statements)
    pipeline, storage = wide_assignment_storage(codegen)
    fact = normalize_wide_call_output_assignment_fact_8616(pipeline, storage)
    assert isinstance(fact, WideCallOutputAssignmentFact8616)

    resolution = materialize_wide_call_output_assignment_8616(
        codegen, codegen.cfunc, storage, corrupt(fact)
    )

    assert resolution.verdict is WideCallOutputAssignmentVerdict8616.UNKNOWN_REFUSE
    assert (
        resolution.failure
        is WideCallOutputAssignmentFailure8616.PAIR_LEGALITY_UNPROVEN
    )
    assert tuple(root.statements) == original


def test_replay_refuses_pairless_canonical_fact() -> None:
    """A canonical statement tagged without pair legality is never trusted."""
    codegen, root, call, source = wide_assignment_fixture()
    artifact = lower_wide_call_output_stack_assignments_8616(codegen)
    assert artifact is not None
    fact = artifact.resolutions[0].fact
    assert fact is not None
    stable = reconcile_materialized_wide_call_output_assignment_8616(
        codegen, root, fact
    )
    assert stable.status is WideCallOutputReplayStatus8616.STABLE

    pairless = replace(fact, pair=None)
    forged = CAssignment(
        root.statements[0].lhs,
        CBinaryOp("Add", call, source, tags={"ins_addr": 0xFF0}, codegen=codegen),
        tags={"ins_addr": 0xFF0, _EVIDENCE_TAG_8616: pairless},
        codegen=codegen,
    )
    root.statements.append(forged)

    replay = reconcile_materialized_wide_call_output_assignment_8616(
        codegen, root, pairless
    )

    assert replay.status is WideCallOutputReplayStatus8616.REFUSED
    assert replay.failure is WideCallOutputReplayFailure8616.PAIR_LEGALITY_UNPROVEN
    assert forged in root.statements


@pytest.mark.parametrize(
    "corrupt",
    (
        pytest.param(lambda fact: fact, id="paired"),
        pytest.param(lambda fact: replace(fact, pair=None), id="missing"),
        pytest.param(
            lambda fact: replace(
                fact, pair=replace(fact.pair, state=WidePairState8616.UNPAIRED)
            ),
            id="unpaired",
        ),
        pytest.param(
            lambda fact: replace(
                fact, pair=replace(fact.pair, state=WidePairState8616.SPLIT)
            ),
            id="split-only",
        ),
        pytest.param(
            lambda fact: replace(
                fact,
                pair=replace(fact.pair, low=fact.pair.high, high=fact.pair.low),
            ),
            id="foreign-halves",
        ),
    ),
)
def test_authoritative_classifier_requires_combine_legal_pair(corrupt) -> None:
    """A MATERIALIZED verdict is authoritative only with combine-legal pair."""
    codegen, _root, _call, _source = wide_assignment_fixture()
    pipeline, storage = wide_assignment_storage(codegen)
    fact = normalize_wide_call_output_assignment_fact_8616(pipeline, storage)
    assert isinstance(fact, WideCallOutputAssignmentFact8616)
    arithmetic = sorted(
        set(fact.carrier_ins_addrs)
        - {fact.call_output.callsite_addr}
        - set(fact.store_ins_addrs)
    )
    expected_carrier = tuple(
        sorted(
            {
                fact.call_output.callsite_addr,
                arithmetic[0],
                arithmetic[-1],
                *fact.store_ins_addrs,
            }
        )
    )
    resolution = WideCallOutputAssignmentResolution8616(
        source=storage,
        verdict=WideCallOutputAssignmentVerdict8616.MATERIALIZED,
        fact=replace(corrupt(fact), carrier_ins_addrs=expected_carrier),
        placement_classified=True,
    )
    codegen._inertia_wide_call_output_assignment_artifact_8616 = (
        WideCallOutputAssignmentArtifact8616(
            function_addr=pipeline.function_addr,
            resolutions=(resolution,),
            stats=WideCallOutputAssignmentStats8616(
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
            ),
        )
    )

    ownership = classify_authoritative_wide_call_output_projection_8616(
        codegen,
        callsite_addr=fact.call_output.callsite_addr,
        target_addr=fact.call_output.target_addr,
        kind=fact.kind,
        source_offset=fact.source_offset,
        destination_offset=fact.destination_offset,
        low_arithmetic_addr=arithmetic[0],
        high_arithmetic_addr=arithmetic[-1],
        low_store_addr=fact.store_ins_addrs[0],
        high_store_addr=fact.store_ins_addrs[1],
    )

    legal = resolution.fact.pair is not None and resolution.fact.pair.combine_authorized
    expected_status = (
        WideCallOutputAuthoritativeOwnershipStatus8616.MATERIALIZED
        if legal
        else WideCallOutputAuthoritativeOwnershipStatus8616.REFUSED
    )
    assert ownership.status is expected_status
    assert ownership.blocks_legacy_materialization
    assert ownership.materialized is legal


@pytest.mark.parametrize(
    ("code", "operation", "kind"),
    (
        pytest.param(WIDE_STACK_ADD, "Add", CarryBorrowKind8616.ADD_WITH_CARRY, id="add"),
        pytest.param(WIDE_STACK_SUB, "Sub", CarryBorrowKind8616.SUB_WITH_BORROW, id="sub"),
    ),
)
def test_lowering_materializes_normalized_operation_kind(code, operation, kind) -> None:
    """The emitted scalar operator is the proven arithmetic kind only."""
    codegen, root, call, source = wide_assignment_fixture(code=code)
    _pipeline, storage = wide_assignment_storage(codegen)

    artifact = lower_wide_call_output_stack_assignments_8616(codegen)

    assert artifact is not None and artifact.complete
    assert artifact.stats.materialized_count == artifact.stats.changed_count == 1
    fact = artifact.resolutions[0].fact
    assert fact is not None and fact.kind is kind
    assert fact.pair is storage.pair and fact.pair.kind is kind
    assignment = root.statements[0]
    assert isinstance(assignment, CAssignment)
    assert isinstance(assignment.rhs, CBinaryOp)
    assert assignment.rhs.op == operation
    assert assignment.rhs.lhs is call and assignment.rhs.rhs is source


@pytest.mark.parametrize(
    "corrupt",
    (
        pytest.param(
            lambda storage: replace(
                storage, source_versions=storage.source_versions[:1]
            ),
            id="truncated-versions",
        ),
        pytest.param(
            lambda storage: replace(
                storage, address=replace(storage.address, space=MemSpace.DS)
            ),
            id="foreign-destination-space",
        ),
        pytest.param(
            lambda storage: replace(
                storage,
                value=replace(
                    storage.value,
                    source_memory=replace(
                        storage.value.source_memory, space=MemSpace.DS
                    ),
                ),
            ),
            id="foreign-source-space",
        ),
        pytest.param(
            lambda storage: replace(
                storage, address=replace(storage.address, base=("bx",))
            ),
            id="foreign-destination-base",
        ),
    ),
)
def test_materializer_refuses_mutated_source_proof(corrupt) -> None:
    """A source mutated after normalization never inherits the earlier proof."""
    codegen, root, _call, _source = wide_assignment_fixture()
    original = tuple(root.statements)
    pipeline, storage = wide_assignment_storage(codegen)
    fact = normalize_wide_call_output_assignment_fact_8616(pipeline, storage)
    assert isinstance(fact, WideCallOutputAssignmentFact8616)

    resolution = materialize_wide_call_output_assignment_8616(
        codegen, codegen.cfunc, corrupt(storage), fact
    )

    assert resolution.verdict is WideCallOutputAssignmentVerdict8616.UNKNOWN_REFUSE
    assert (
        resolution.failure
        is WideCallOutputAssignmentFailure8616.PAIR_LEGALITY_UNPROVEN
    )
    assert tuple(root.statements) == original


def test_authoritative_classifier_refuses_forged_operation_kind() -> None:
    """A resolution claiming a different arithmetic kind is never authoritative."""
    codegen, _root, _call, _source = wide_assignment_fixture()
    pipeline, storage = wide_assignment_storage(codegen)
    fact = normalize_wide_call_output_assignment_fact_8616(pipeline, storage)
    assert isinstance(fact, WideCallOutputAssignmentFact8616)
    forged = replace(fact, kind=CarryBorrowKind8616.SUB_WITH_BORROW)
    arithmetic = sorted(
        set(fact.carrier_ins_addrs)
        - {fact.call_output.callsite_addr}
        - set(fact.store_ins_addrs)
    )
    codegen._inertia_wide_call_output_assignment_artifact_8616 = (
        WideCallOutputAssignmentArtifact8616(
            function_addr=pipeline.function_addr,
            resolutions=(
                WideCallOutputAssignmentResolution8616(
                    source=storage,
                    verdict=WideCallOutputAssignmentVerdict8616.MATERIALIZED,
                    fact=forged,
                    placement_classified=True,
                ),
            ),
            stats=WideCallOutputAssignmentStats8616(
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
            ),
        )
    )

    ownership = classify_authoritative_wide_call_output_projection_8616(
        codegen,
        callsite_addr=forged.call_output.callsite_addr,
        target_addr=forged.call_output.target_addr,
        kind=forged.kind,
        source_offset=forged.source_offset,
        destination_offset=forged.destination_offset,
        low_arithmetic_addr=arithmetic[0],
        high_arithmetic_addr=arithmetic[-1],
        low_store_addr=forged.store_ins_addrs[0],
        high_store_addr=forged.store_ins_addrs[1],
    )

    assert ownership.status is WideCallOutputAuthoritativeOwnershipStatus8616.REFUSED
    assert ownership.blocks_legacy_materialization
    assert not ownership.materialized


def test_materializer_refuses_coherent_shifted_destination() -> None:
    """A destination range agreeing with itself but not the stores refuses."""
    codegen, root, _call, _source = wide_assignment_fixture()
    original = tuple(root.statements)
    pipeline, storage = wide_assignment_storage(codegen)
    fact = normalize_wide_call_output_assignment_fact_8616(pipeline, storage)
    assert isinstance(fact, WideCallOutputAssignmentFact8616)
    forged_source = replace(
        storage, address=replace(storage.address, offset=2)
    )
    forged = replace(fact, destination_offset=2)

    resolution = materialize_wide_call_output_assignment_8616(
        codegen, codegen.cfunc, forged_source, forged
    )

    assert resolution.verdict is WideCallOutputAssignmentVerdict8616.UNKNOWN_REFUSE
    assert (
        resolution.failure
        is WideCallOutputAssignmentFailure8616.PAIR_LEGALITY_UNPROVEN
    )
    assert tuple(root.statements) == original


def test_replay_refuses_kind_mismatched_canonical_fact() -> None:
    """A canonical fact whose kind disagrees with its pair is never trusted."""
    codegen, root, call, source = wide_assignment_fixture()
    artifact = lower_wide_call_output_stack_assignments_8616(codegen)
    assert artifact is not None
    fact = artifact.resolutions[0].fact
    assert fact is not None
    mismatched = replace(fact, kind=CarryBorrowKind8616.SUB_WITH_BORROW)
    forged = CAssignment(
        root.statements[0].lhs,
        CBinaryOp("Sub", call, source, tags={"ins_addr": 0xFF0}, codegen=codegen),
        tags={"ins_addr": 0xFF0, _EVIDENCE_TAG_8616: mismatched},
        codegen=codegen,
    )
    root.statements.append(forged)

    replay = reconcile_materialized_wide_call_output_assignment_8616(
        codegen, root, mismatched
    )

    assert replay.status is WideCallOutputReplayStatus8616.REFUSED
    assert replay.failure is WideCallOutputReplayFailure8616.PAIR_LEGALITY_UNPROVEN
    assert forged in root.statements
