"""Layer: IR tests.
Responsibility: preserve sparse selector and fetch census obligations in fused visits.
"""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir import declared_selector_native_effects as effects
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.declared_selector_invariant import (
    ObligationKind,
    _Budget,
    _record_fetch,
    _record_fetch_census,
    _selector_rows_from_survey_8616,
)
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize('refused,stale', [(True, False), (False, False), (False, True)])
def test_only_positive_candidates_pay_final_native_seal(
    monkeypatch: pytest.MonkeyPatch, refused: bool, stale: bool,
) -> None:
    """Refusal saves shared work; potentially positive proofs still reject stale IR."""
    from inertia.frontend.x86_16.control_transfer_geometry import (
        ControlCheck8616,
        ControlKind8616,
        ControlVerdict8616,
    )
    from inertia.frontend.x86_16.declared_function_entry import (
        DeclaredEntryReturn8616,
        DeclaredEntryReturnKind8616,
        DeclaredFunctionEntryAdmission8616,
        DeclaredFunctionEntrySpec8616,
    )
    from inertia.ir import declared_selector_invariant as owner
    from inertia.ir.entry_domain_call_preservation import Real16InvocationSource8616

    spec = DeclaredFunctionEntrySpec8616(
        1, 's' * 64, 'r' * 64, 0x100, 0x100, 0x10, 0x1010, 0x1020,
        'n' * 64, 'e' * 64, False, (('ss', 0x100), ('ds', 0x100)), (),
        DeclaredEntryReturn8616(DeclaredEntryReturnKind8616.NEAR, 0, 0),
    )
    admission = DeclaredFunctionEntryAdmission8616(spec, b'src', b'mod', 'e' * 64, 'd' * 64)
    source = Real16InvocationSource8616(object(), None, object())
    monkeypatch.setattr(owner, '_BootEvidence8616', SimpleNamespace)
    monkeypatch.setattr(owner, '_invocation_boot_evidence_8616',
                        lambda boot: SimpleNamespace(image=object()))
    auth_calls = []
    seal_calls = []

    def authenticate(*args, recompute_boot=True):
        auth_calls.append(recompute_boot)
        return None

    def walk(project, spec, head, seed, budget, image, **outputs):
        budget.charge(5, head)
        if refused:
            outputs['obligations'].append(owner.Obligation(ObligationKind.CALLEE_MISSING, head, None))
        outputs['geometry'].append(ControlCheck8616(
            ControlVerdict8616.CLOSED, ControlKind8616.CALL, head, head + 3, head + 5, ''))
        return 1, 0

    def seal(project, consumed, head, budget, obligations, snapshots):
        seal_calls.append(head)
        budget.charge(50, head)
        if stale:
            obligations.append(owner.Obligation(ObligationKind.CONSUMED_SURFACE_STALE, head, None))

    monkeypatch.setattr(owner, '_authenticate_authority', authenticate)
    monkeypatch.setattr(owner, '_walk_surfaces', walk)
    monkeypatch.setattr(owner, '_rebind_consumed_surfaces', seal)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        result = owner._prove_invariant_inner(
            object(), source, admission, deadline_seconds=60, work_limit=20000)
        assert traversal.census_work_units == result.work_units
    expected = owner.InvariantStatus.REFUSED if refused or stale else owner.InvariantStatus.PROVEN_CONDITIONAL
    assert result.status is expected
    assert seal_calls == ([] if refused else [0x1010])
    assert auth_calls == ([True, True] if refused else [True, True, False])
    assert result.work_units == (5 if refused else 56)
    if refused or stale:
        kind = ObligationKind.CALLEE_MISSING if refused else ObligationKind.CONSUMED_SURFACE_STALE
        assert [obligation.kind for obligation in result.obligations] == [kind]


@pytest.mark.parametrize('refusal', ['missing', 'budget', None])
def test_phase_a_stops_resolving_callees_after_first_refusal(
    monkeypatch: pytest.MonkeyPatch, refusal: str | None,
) -> None:
    """A failed whole-surface premise must not exhaust later proof work."""
    from inertia.ir import declared_selector_invariant as owner

    instructions = tuple(IRInstr('CALL', None, (), addr=addr) for addr in (0x1000, 0x1003))
    artifact = SimpleNamespace(blocks=(IRBlock(0x1000, instructions),))
    machine = dict.fromkeys((4096, 4099), (3, b'\xe8\x00\x00'))
    monkeypatch.setattr(owner, '_decoded_block', lambda *args: machine)
    visited = []
    obligations = []
    fetched = set()
    budget = _Budget(float('inf'), 100)

    def resolve(project, head, instr, encoded, request_budget, failures, consumed,
                *, scoped_calls=None, universal=None, snapshots=None):
        visited.append(instr.addr)
        if refusal == 'missing':
            failures.append(owner.Obligation(ObligationKind.CALLEE_MISSING, head, instr.addr))
        elif refusal == 'budget':
            request_budget.obligations.append(owner.Obligation(ObligationKind.BUDGET_EXCEEDED, head, instr.addr))
        return instr.addr + 3, frozenset({'cs'})

    monkeypatch.setattr(owner, '_resolve_callsite', resolve)
    result = owner._prepare_machine(object(), 0x1000, artifact, object(), budget,
                                    object(), fetched, obligations, {})
    assert fetched == {(0x1000, 3), (0x1003, 3)}
    if refusal is None:
        assert result is not None and set(result[2]) == {0x1000, 0x1003}
        assert visited == [0x1000, 0x1003]
    else:
        assert result is None
        assert visited == [0x1000]
        assert len(obligations if refusal == 'missing' else budget.obligations) == 1


def _blocks() -> tuple[IRBlock, ...]:
    """Include ordinary rows, selector writes, calls, controls and unknown effects."""
    value = IRValue(MemSpace.CONST, const=1, size=2)
    ordinary = IRInstr('MOV', IRValue(MemSpace.REG, name='ax', size=2), (value,), size=2, addr=0x1000)
    selector = IRInstr('MOV', IRValue(MemSpace.REG, name='cs', size=2), (value,), size=2, addr=0x1001)
    call = IRInstr('CALL', None, (), addr=0x1002)
    control = IRInstr('RET', None, (), addr=0x1003)
    unknown = IRInstr('UNKNOWN_NATIVE_EFFECT', None, (), addr=0x1004)
    return (IRBlock(0x1000, (ordinary, selector, call, control)),
            IRBlock(0x1004, (unknown,)))


def test_survey_emits_exact_sparse_projection_in_one_classification_visit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every row is classified once; only selector-relevant identities are retained."""
    blocks = _blocks()
    classified = []
    original = effects.classify_native_row_8616

    def classify(instruction: IRInstr) -> effects.NativeRowJudgement8616:
        classified.append(instruction)
        return original(instruction)

    monkeypatch.setattr(effects, 'classify_native_row_8616', classify)
    survey = effects.survey_native_effects_8616(blocks, range(0x1000, 0x1005))
    assert len(classified) == survey.raw == survey.classified == 5
    assert survey.census_covered and survey.unclassified == 1
    assert survey.selector_blocks[0].block is blocks[0]
    assert survey.selector_blocks[1].block is blocks[1]
    assert survey.selector_blocks[0].rows == blocks[0].instrs[1:3]
    assert survey.selector_blocks[1].rows == blocks[1].instrs
    assert all(left is right for left, right in zip(
        survey.selector_blocks[0].rows, blocks[0].instrs[1:3], strict=True))


def test_sparse_projection_charges_blocks_and_never_reclassifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Consumption traverses retained block headers, without a second full-row pass."""
    blocks = _blocks()
    survey = effects.survey_native_effects_8616(blocks)

    def forbidden(instruction: IRInstr) -> effects.NativeRowJudgement8616:
        raise AssertionError('projection reclassified a native row')

    monkeypatch.setattr(effects, 'classify_native_row_8616', forbidden)
    budget = _Budget(float('inf'), 100)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        rows = _selector_rows_from_survey_8616(0x1000, {block.addr: block for block in blocks}, survey, budget)
        assert rows is not None and rows[0x1000] == blocks[0].instrs[1:3]
        assert traversal.census_work_units == budget.units == len(blocks)


@pytest.mark.parametrize('corruption', ['foreign', 'duplicate', 'missing', 'budget'])
def test_sparse_projection_refuses_foreign_or_incomplete_ownership(corruption: str) -> None:
    """Only complete exact block identities enter selector induction."""
    blocks = _blocks()
    survey = effects.survey_native_effects_8616(blocks)
    selected = survey.selector_blocks
    if corruption == 'foreign':
        selected = (replace(selected[0], block=replace(blocks[0])), selected[1])
    elif corruption == 'duplicate':
        selected = (selected[0], selected[0], selected[1])
    elif corruption == 'missing':
        selected = selected[:1]
    budget = _Budget(float('inf'), 0 if corruption == 'budget' else 100)
    with segment_call_dependency_traversal_scope_8616():
        assert _selector_rows_from_survey_8616(
            0x1000, {block.addr: block for block in blocks},
            replace(survey, selector_blocks=selected), budget) is None


def test_fetch_union_is_collected_during_unique_fetch_visit() -> None:
    """Repeated IR rows do not duplicate fetch work or weaken exact census checks."""
    row = IRInstr('NOP', None, (), addr=0x1000)
    seen: set[int] = set()
    covered: set[int] = set()
    budget = _Budget(float('inf'), 100)
    obligations = []
    with segment_call_dependency_traversal_scope_8616():
        for _ in range(2):
            assert _record_fetch(0x1000, row, b'\x90', {'cs': 0x100}, seen,
                                 budget, obligations, covered=covered)
        assert budget.units == 1 and seen == covered == {0x1000}
        assert _record_fetch_census(0x1000, 0x1000, {0x1000}, covered, budget, obligations)
        assert not _record_fetch_census(0x1000, 0x1000, {0x1000, 0x1001}, covered, budget, obligations)
    assert obligations[-1].kind is ObligationKind.DECODE_MISMATCH


def test_refused_fetch_never_enters_global_census() -> None:
    """An invalid selector still records the fetch refusal and cannot close coverage."""
    row = IRInstr('NOP', None, (), addr=0x1000)
    covered: set[int] = set()
    obligations = []
    with segment_call_dependency_traversal_scope_8616():
        assert not _record_fetch(0x1000, row, b'\x90', {'cs': 0x101}, set(),
                                 _Budget(float('inf'), 100), obligations, covered=covered)
    assert not covered and obligations[0].kind is ObligationKind.FETCH_OUT_OF_WINDOW


def test_record_projection_keeps_every_effect_and_first_native_fetch() -> None:
    """Only later selector-inert scalar rows at an already retained head disappear."""
    blocks = _blocks()
    first = blocks[0].instrs[0]
    redundant = replace(first, dst=IRValue(MemSpace.REG, name='dx', size=2))
    noninteger = replace(first, addr=None)
    conservative = replace(first, dst=IRValue(MemSpace.TMP, name='cs', size=2, source_tmp=8))
    block = replace(blocks[0], instrs=(first, redundant, conservative, *blocks[0].instrs[1:], noninteger))
    survey = effects.survey_native_effects_8616((block, blocks[1]))
    recorded = survey.selector_blocks[0].record_rows
    assert recorded == (first, conservative, *blocks[0].instrs[1:], noninteger)
    assert all(item is not redundant for item in recorded)
    assert survey.selector_blocks[1].record_rows == blocks[1].instrs
    assert len(block.instrs) == 7  # The authoritative IR remains untouched.


@pytest.mark.parametrize('mutation', ['none', 'store', 'selector', 'provenance'])
def test_record_projection_initial_native_snapshot_rejects_later_mutation(
    monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """Skipping inert replay rows never hides changes after their original survey."""
    from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
    from inertia.ir import declared_selector_invariant as owner
    from inertia.ir import real16_invocation_domain as native_owner
    from inertia.ir.core import IRFunctionArtifact

    project = object()
    value = IRValue(MemSpace.CONST, const=1, size=2)
    first = IRInstr('MOV', IRValue(MemSpace.REG, name='ax', size=2), (value,), size=2, addr=0x1000)
    omitted = replace(first, dst=IRValue(MemSpace.REG, name='dx', size=2))
    block = IRBlock(0x1000, (first, omitted))
    artifact = IRFunctionArtifact(0x1000, (block,))
    boundary = ExactFunctionRangeBoundary8616(
        project, 0x1000, 1, frozenset({0x1000}), frozenset({0x1000}), ())
    snapshot = owner._capture_scoped_native_surface_8616(boundary, artifact)
    survey = effects.survey_native_effects_8616((block,))
    assert survey.selector_blocks[0].record_rows == (first,)
    if mutation == 'store':
        object.__setattr__(omitted, 'op', 'STORE')
    elif mutation == 'selector':
        object.__setattr__(omitted, 'dst', IRValue(MemSpace.REG, name='cs', size=2))
    elif mutation == 'provenance':
        assert omitted.dst is not None
        object.__setattr__(omitted.dst, 'source_tmp', 99)

    def native(project_arg: object, boundary_arg: ExactFunctionRangeBoundary8616) -> IRFunctionArtifact:
        assert project_arg is project and boundary_arg is boundary
        return artifact

    monkeypatch.setattr(native_owner, 'real16_native_census_import_8616', native)
    key = id(boundary), id(artifact)
    obligations = []
    with segment_call_dependency_traversal_scope_8616():
        owner._rebind_consumed_surfaces(project, {key: (boundary, artifact)}, 0x1000,
                                        _Budget(float('inf'), 100), obligations, {key: snapshot})
    assert bool(obligations) == (mutation != 'none')
    if obligations:
        assert obligations[0].kind is ObligationKind.CONSUMED_SURFACE_STALE


def test_phase_a_surface_transport_keeps_exact_objects_and_charges_search() -> None:
    """Source identity reuse saves duplicate final rebinds, not fresh induction gates."""
    from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
    from inertia.ir import declared_selector_invariant as owner
    from inertia.ir.core import IRFunctionArtifact

    project = object()
    blocks = _blocks()
    artifact = IRFunctionArtifact(0x1000, blocks)
    boundary = ExactFunctionRangeBoundary8616(
        project, 0x1000, 5, frozenset({0x1000, 0x1004}),
        frozenset(range(0x1000, 0x1005)), ())
    surfaces = {(id(boundary), id(artifact)): (boundary, artifact)}
    budget = _Budget(float('inf'), 100)
    with segment_call_dependency_traversal_scope_8616():
        selected = owner._consumed_surface_for_head_8616(surfaces, 0x1000, budget)
        assert selected is not None and selected[0] is boundary and selected[1] is artifact
        assert budget.units == 1
        assert owner._consumed_surface_for_head_8616(surfaces, 0x999, budget) is None
        assert owner._consumed_surface_for_head_8616(surfaces, 0x1000, _Budget(float('inf'), 0)) is None
    assert len(surfaces) == 1


def _bound_fixture() -> tuple[object, IRFunctionArtifact, ExactFunctionRangeBoundary8616]:
    """Build the byte-exact closed pair shared by deferred-survey tests."""
    project = object()
    artifact = IRFunctionArtifact(0x1000, _blocks())
    boundary = ExactFunctionRangeBoundary8616(
        project, 0x1000, 5, frozenset({0x1000, 0x1004}),
        frozenset(range(0x1000, 0x1005)), ())
    return project, artifact, boundary


def test_reinduction_retains_earliest_source_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    """A second selector seed cannot overwrite evidence captured before callbacks."""
    from typing import cast

    from inertia.ir import declared_selector_invariant as owner
    from inertia.ir.real16_invocation_domain import _BootImageSurface8616

    project, artifact, boundary = _bound_fixture()
    initial = owner._capture_scoped_native_surface_8616(boundary, artifact)
    first_value = artifact.blocks[0].instrs[0].args[0]
    assert isinstance(first_value, IRValue)
    object.__setattr__(first_value, 'const', 99)
    later = owner._capture_scoped_native_surface_8616(boundary, artifact)
    survey = effects.survey_native_effects_8616(artifact.blocks)
    fresh_surfaces = iter((initial, later))

    def native(*args: object, **kwargs: object) -> object:
        return boundary, artifact, next(fresh_surfaces)

    monkeypatch.setattr(owner, '_native_blocks', native)
    monkeypatch.setattr(
        owner, 'survey_native_effects_8616',
        lambda *args, **kwargs: replace(survey, census_covered=True, unclassified=0))
    monkeypatch.setattr(owner, '_prepare_machine', lambda *args, **kwargs: ({}, {}, {}))
    monkeypatch.setattr(owner, '_stabilize', lambda *args, **kwargs: ({}, set()))
    monkeypatch.setattr(owner, '_record_instructions', lambda *args, **kwargs: True)
    snapshots = {}
    consumed = {}
    with segment_call_dependency_traversal_scope_8616():
        for cs in (0x100, 0x101):
            assert owner._induce(
                project, 0x1000, {'cs': cs}, budget=_Budget(float('inf'), 100),
                image=cast(_BootImageSurface8616, object()), fetched=set(),
                stores=[], calls=[], terminals=[], geometry=[], obligations=[],
                discovered=[], consumed=consumed, states={}, snapshots=snapshots)
    assert snapshots[id(boundary), id(artifact)] is initial
    assert initial.graph != later.graph


def test_refused_machine_preparation_never_runs_native_survey(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused callee premise cannot pay census units for rows nobody reads."""
    from typing import cast

    from inertia.ir import declared_selector_invariant as owner
    from inertia.ir.declared_selector_native_effects import NativeEffectSurvey8616
    from inertia.ir.real16_invocation_domain import _BootImageSurface8616

    project, artifact, boundary = _bound_fixture()
    snapshot = owner._capture_scoped_native_surface_8616(boundary, artifact)

    def refuse_prepare(
        project_arg: object, head: int, artifact_arg: object,
        boundary_arg: object, budget: _Budget, image: object,
        fetched: set[tuple[int, int]], obligations: list,
        consumed: dict,
        *, scoped_calls=None, active_blocks=None, snapshots=None,
    ) -> None:
        obligations.append(
            owner.Obligation(ObligationKind.CALLEE_MISSING, head, 0x1002))
        return None

    def forbidden_survey(*args: object, **kwargs: object) -> NativeEffectSurvey8616:
        raise AssertionError('native census classified rows whose machine refused')

    def prepare_rebind(actual_project: object, actual_boundary: object, *, caller: IRFunctionArtifact) -> object:
        assert actual_project is project and actual_boundary is boundary
        assert caller is artifact
        return object()

    monkeypatch.setattr(owner, '_prepare_scoped_native_rebind_8616', prepare_rebind)
    monkeypatch.setattr(owner, '_scoped_native_rebind_failure_8616', lambda *args: None)
    monkeypatch.setattr(owner, 'closed_ir_boundary_cfg_8616', lambda *args: True)
    monkeypatch.setattr(owner, '_prepare_machine', refuse_prepare)
    monkeypatch.setattr(owner, 'survey_native_effects_8616', forbidden_survey)
    budget = _Budget(float('inf'), 100)
    obligations: list = []
    snapshots: dict = {}
    consumed: dict = {}
    with segment_call_dependency_traversal_scope_8616() as traversal:
        assert not owner._induce(
            project, 0x1000, {'cs': 0x100}, budget=budget,
            image=cast(_BootImageSurface8616, object()), fetched=set(),
            stores=[], calls=[], terminals=[], geometry=[],
            obligations=obligations, discovered=[], consumed=consumed,
            states={}, snapshots=snapshots, supplied=(boundary, artifact))
        assert traversal.census_work_units == budget.units == 0
    assert [item.kind for item in obligations] == [ObligationKind.CALLEE_MISSING]
    key = id(boundary), id(artifact)
    assert snapshots[key] == snapshot
    assert consumed[key] == (boundary, artifact)


@pytest.mark.parametrize('control', ['positive', 'unclassified', 'budget'])
def test_deferred_survey_keeps_census_and_budget_gates(
    monkeypatch: pytest.MonkeyPatch, control: str,
) -> None:
    """Deferred census still charges, requires coverage and zero unclassified."""
    from typing import cast

    from inertia.ir import declared_selector_invariant as owner
    from inertia.ir.real16_invocation_domain import _BootImageSurface8616

    project, artifact, boundary = _bound_fixture()
    covered = replace(
        effects.survey_native_effects_8616(artifact.blocks),
        census_covered=True, unclassified=0)
    surveyed: list[tuple[object, ...]] = []

    def survey(*args: object, **kwargs: object) -> object:
        surveyed.append(args)
        return covered if control != 'unclassified' else replace(covered, unclassified=1)

    monkeypatch.setattr(owner, 'survey_native_effects_8616', survey)
    def prepare_rebind(actual_project: object, actual_boundary: object, *, caller: IRFunctionArtifact) -> object:
        assert actual_project is project and actual_boundary is boundary
        assert caller is artifact
        return object()

    monkeypatch.setattr(owner, '_prepare_scoped_native_rebind_8616', prepare_rebind)
    monkeypatch.setattr(owner, '_scoped_native_rebind_failure_8616', lambda *args: None)
    monkeypatch.setattr(owner, 'closed_ir_boundary_cfg_8616', lambda *args: True)
    monkeypatch.setattr(owner, '_prepare_machine', lambda *args, **kwargs: ({}, {}, {}))
    monkeypatch.setattr(owner, '_stabilize', lambda *args, **kwargs: ({}, set()))
    monkeypatch.setattr(owner, '_record_instructions', lambda *args, **kwargs: True)
    budget = _Budget(float('inf'), 0 if control == 'budget' else 100)
    obligations: list = []
    with segment_call_dependency_traversal_scope_8616():
        result = owner._induce(
            project, 0x1000, {'cs': 0x100}, budget=budget,
            image=cast(_BootImageSurface8616, object()), fetched=set(),
            stores=[], calls=[], terminals=[], geometry=[],
            obligations=obligations, discovered=[], consumed={},
            states={}, snapshots={}, supplied=(boundary, artifact))
    expected_calls = [] if control == 'budget' else [
        (artifact.blocks, boundary.reachable_instruction_addrs)]
    assert surveyed == expected_calls
    if control == 'positive':
        assert result and not obligations
    elif control == 'unclassified':
        assert not result
        assert [item.kind for item in obligations] == [
            ObligationKind.NATIVE_EFFECT_UNPROVEN]
    else:
        assert not result
        assert [item.kind for item in obligations] == [
            ObligationKind.BUDGET_EXCEEDED]


@pytest.mark.parametrize('exhaustion', ['deadline', 'local_work', 'shared_work'])
def test_deferred_survey_keeps_preparation_budget_admission(
    monkeypatch: pytest.MonkeyPatch, exhaustion: str,
) -> None:
    """Deferring classification must not start preparation on an exhausted ledger."""
    from inertia.ir import declared_selector_invariant as owner

    project, artifact, boundary = _bound_fixture()
    def prepare_rebind(actual_project: object, actual_boundary: object, *, caller: IRFunctionArtifact) -> object:
        assert actual_project is project and actual_boundary is boundary
        assert caller is artifact
        return object()

    monkeypatch.setattr(owner, '_prepare_scoped_native_rebind_8616', prepare_rebind)
    monkeypatch.setattr(owner, '_scoped_native_rebind_failure_8616', lambda *args: None)
    monkeypatch.setattr(owner, 'closed_ir_boundary_cfg_8616', lambda *args: True)
    budget = _Budget(0 if exhaustion == 'deadline' else float('inf'), 100)
    if exhaustion == 'local_work':
        budget.units = 101
    with segment_call_dependency_traversal_scope_8616() as traversal:
        if exhaustion == 'shared_work':
            traversal.census_work_units = owner._SHARED_WORK_LIMIT_8616 + 1
        before = traversal.census_work_units
        result = owner._native_blocks(project, 0x1000, budget, supplied=(boundary, artifact))
        assert isinstance(result, owner.Obligation)
        expected = (ObligationKind.DEADLINE_EXCEEDED if exhaustion == 'deadline'
                    else ObligationKind.BUDGET_EXCEEDED)
        assert result.kind is expected
        assert traversal.census_work_units == before
