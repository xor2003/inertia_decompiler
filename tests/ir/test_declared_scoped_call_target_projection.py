"""Layer: IR tests.
Responsibility: retain scoped callee evidence while admitting declared CALL targets.
"""

from dataclasses import replace

import pytest

from inertia.ir import declared_entry_pipeline as pipeline
from inertia.ir import entry_domain_call_preservation as preservation
from inertia.ir.entry_jump_domain import (
    EntryJumpDomainBudget8616,
    ScopedCallTargetStatus8616,
    _ProofRun8616,
    apply_entry_jump_domain_8616,
)
from inertia.ir.entry_projection_mode import EntryProjectionMode8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.segment_call_preservation import declared_entry_dependency_traversal_scope_8616
from tests.ir.test_forward_declared_call_scope import _forward_world

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("mutation", [None, "caller_bytes", "callee_bytes", "foreign_scope", "target"])
def test_native_scoped_callee_records_admit_declared_call_targets(mutation: str | None) -> None:
    """Retain exact conditional records and refuse changed native or scope evidence."""
    project, _boot, _artifact, _boundary, _resolver, admission = _forward_world(guarded=False)
    source = preservation._invocation_premise_source_8616(project)
    assert source is not None
    with native_import_request_8616(), declared_entry_dependency_traversal_scope_8616():
        result = pipeline._prepare_native_entry_8616(project, source, admission)
        assert isinstance(result, pipeline.DeclaredEntryPipeline8616)
        assert result.view.proof.invocation_scope is result.scope
        records = result.view.proof.call_preservations
        assert len(records) == 2
        assert all(record.required_scope is not None for record in records)
        assert all(record.selector_projection is None for record in records)
        original_args = tuple(record.instruction.args for record in records)
        scope = result.scope
        if mutation in ("caller_bytes", "callee_bytes"):
            address = records[0].callsite_addr if mutation == "caller_bytes" else records[0].target_addr
            assert isinstance(address, int)
            old = project.loader.memory.load(address, 1)
            project.loader.memory.store(address, bytes((old[0] ^ 1,)))
        elif mutation == "foreign_scope":
            assert scope.chain is not None
            scope = replace(scope, chain=replace(scope.chain))
        elif mutation == "target":
            assert isinstance(records[0].target_addr, int)
            object.__setattr__(records[0], "target_addr", records[0].target_addr + 1)
        application = apply_entry_jump_domain_8616(
            result.bundle.artifact, result.view.proof, invocation_scope=scope,
            projection_mode=EntryProjectionMode8616.CALL_TARGETS,
        )
    assert all(record.instruction.args is args for record, args in zip(records, original_args, strict=True))
    if mutation is not None:
        assert application.call_target_status is not ScopedCallTargetStatus8616.ADMITTED
        assert application.call_targets == ()
        return
    assert application.call_target_status is ScopedCallTargetStatus8616.ADMITTED
    assert len(application.call_targets) == len(records)
    assert {target.target for target in application.call_targets} == {record.target_addr for record in records}
    assert all(
        target.block is record.block and target.instruction is record.instruction and target.scope is scope
        for target, record in zip(application.call_targets, records, strict=True)
    )
    stats = application.call_target_stats
    assert (stats.raw_fact_count, stats.normalized_fact_count, stats.classified_fact_count,
            stats.materialized_count, stats.failure_count) == (2, 2, 2, 2, 0)


def test_scoped_target_mutation_after_continuation_preparation_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fresh dependency admission must reject changes after coordinate preparation."""
    from inertia.ir import entry_jump_domain as jump

    project, _boot, _artifact, _boundary, _resolver, admission = _forward_world(guarded=False)
    source = preservation._invocation_premise_source_8616(project)
    assert source is not None
    with native_import_request_8616(), declared_entry_dependency_traversal_scope_8616():
        result = pipeline._prepare_native_entry_8616(project, source, admission)
        assert isinstance(result, pipeline.DeclaredEntryPipeline8616)
        records = result.view.proof.call_preservations
        original = jump._declared_call_continuations_8616
        mutated = False

        def change_target_after_preparation(
            offered: tuple[preservation.EntryDomainCallPreservation8616, ...],
        ) -> tuple[int, ...] | None:
            """Change one owned receipt only after the actual native preparation."""
            nonlocal mutated
            coordinates = original(offered)
            if offered is records and coordinates is not None:
                assert isinstance(records[0].target_addr, int)
                object.__setattr__(records[0], "target_addr", records[0].target_addr + 1)
                mutated = True
            return coordinates

        monkeypatch.setattr(jump, "_declared_call_continuations_8616", change_target_after_preparation)
        application = jump.apply_entry_jump_domain_8616(
            result.bundle.artifact, result.view.proof, invocation_scope=result.scope,
            projection_mode=EntryProjectionMode8616.CALL_TARGETS,
        )
    assert mutated
    assert application.call_target_status is not ScopedCallTargetStatus8616.ADMITTED
    assert application.call_targets == ()


def test_mixed_scoped_and_selector_records_admit_all_declared_targets() -> None:
    """One application must retain full callee and selector-only CALL dependencies."""
    caller = bytes.fromhex("b83412e80a00e80700e82400c3")
    project, _boot, _artifact, _boundary, _resolver, admission = _forward_world(
        guarded=False, caller_bytes=caller,
    )
    source = preservation._invocation_premise_source_8616(project)
    assert source is not None
    with native_import_request_8616(), declared_entry_dependency_traversal_scope_8616():
        result = pipeline._prepare_native_entry_8616(project, source, admission)
        assert isinstance(result, pipeline.DeclaredEntryPipeline8616)
        records = result.view.proof.call_preservations
        assert len(records) == 3
        assert any(record.selector_projection is None for record in records)
        assert any(record.selector_projection is not None for record in records)
        application = apply_entry_jump_domain_8616(
            result.bundle.artifact, result.view.proof, invocation_scope=result.scope,
            projection_mode=EntryProjectionMode8616.CALL_TARGETS,
        )
    assert application.call_target_status is ScopedCallTargetStatus8616.ADMITTED
    assert len(application.call_targets) == 3
    assert {target.target for target in application.call_targets} == {0x1050, 0x1070}
    stats = application.call_target_stats
    assert (stats.raw_fact_count, stats.normalized_fact_count, stats.classified_fact_count,
            stats.materialized_count, stats.failure_count) == (3, 3, 3, 3, 0)


def test_scoped_register_projection_preserves_single_proof_budget() -> None:
    """Consume no more proof work than the owned projection, and reject stale bytes."""
    from inertia.ir import entry_jump_domain as jump

    project, _boot, _artifact, _boundary, _resolver, admission = _forward_world(guarded=False)
    source = preservation._invocation_premise_source_8616(project)
    assert source is not None
    with native_import_request_8616(), declared_entry_dependency_traversal_scope_8616():
        result = pipeline._prepare_native_entry_8616(project, source, admission)
        assert isinstance(result, pipeline.DeclaredEntryPipeline8616)
        record = result.view.proof.call_preservations[0]
    with native_import_request_8616(), declared_entry_dependency_traversal_scope_8616() as reference:
        expected = frozenset(record.preserved_registers_for(result.scope))
        reference_work = reference.census_work_units
    with native_import_request_8616(), declared_entry_dependency_traversal_scope_8616() as consumed:
        actual = jump._call_preserved_registers_8616(record, result.scope)
        consumed_work = consumed.census_work_units
    assert "cs" in expected
    assert actual == expected
    assert consumed_work <= reference_work
    address = record.callsite_addr
    assert isinstance(address, int)
    old = project.loader.memory.load(address, 1)
    project.loader.memory.store(address, bytes((old[0] ^ 1,)))
    with native_import_request_8616(), declared_entry_dependency_traversal_scope_8616():
        assert not jump._call_preserved_registers_8616(record, result.scope)


@pytest.mark.parametrize("guarded", [False, True])
@pytest.mark.parametrize("mutation", [None, "missing_scope", "foreign_scope", "caller_bytes", "callee_bytes"])
def test_jump_path_consumes_explicit_scoped_callee_root(mutation: str | None, guarded: bool) -> None:
    """Only an authentic explicit entry admits preserved effects on a jump path."""
    project, _boot, _artifact, _boundary, _resolver, admission = _forward_world(
        guarded=guarded,
    )
    source = preservation._invocation_premise_source_8616(project)
    assert source is not None
    with native_import_request_8616(), declared_entry_dependency_traversal_scope_8616():
        result = pipeline._prepare_native_entry_8616(project, source, admission)
        assert isinstance(result, pipeline.DeclaredEntryPipeline8616)
        records = result.view.proof.call_preservations
        assert len(records) == 2
        scope = result.scope
        if mutation == "missing_scope":
            scope = None
        elif mutation == "foreign_scope":
            foreign_project, _, _, _, _, foreign_admission = _forward_world(guarded=False)
            foreign_source = preservation._invocation_premise_source_8616(foreign_project)
            assert foreign_source is not None
            foreign = pipeline._prepare_native_entry_8616(foreign_project, foreign_source, foreign_admission)
            assert isinstance(foreign, pipeline.DeclaredEntryPipeline8616)
            scope = foreign.scope
        elif mutation in ("caller_bytes", "callee_bytes"):
            address = records[0].callsite_addr if mutation == "caller_bytes" else records[0].target_addr
            assert isinstance(address, int)
            old = project.loader.memory.load(address, 1)
            project.loader.memory.store(address, bytes((old[0] ^ 1,)))
        run = _ProofRun8616(
            result.bundle.artifact, {}, 0, 0, project, result.view.proof.source_binding,
            EntryJumpDomainBudget8616(), call_preservations=records,
            offered_invocation_scope=scope,
        )
        record = records[0]
        projected = run._call_substitutes_8616(record.block, record.instruction)
    if mutation is None:
        assert projected != (record.instruction,)
        assert record.callsite_addr in run.call_dependencies
    else:
        assert projected == (record.instruction,)
        assert not run.call_dependencies
