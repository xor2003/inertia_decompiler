"""Layer: IR tests.
Responsibility: retain selector CALL accounting under honest shared limits.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import cast

import pytest

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
)
from inertia.ir import declared_selector_call_preservation as collector
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.declared_selector_invariant import (
    Cohort,
    DeclaredSegmentInvariant,
    DeclaredSelectorCallsite8616,
    InvariantStatus,
)
from inertia.ir.entry_domain_call_preservation import EntryDomainCallPreservationFailure8616 as Failure
from inertia.ir.real16_invocation_domain import DeclaredFunctionEntryLink8616
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from inertia.ir.segment_effect_closure import SegmentEffectClosureResult8616

pytestmark = pytest.mark.decompiler


def _scope(project: object) -> DeclaredSegmentInvariant:
    """Retain real CALL identities without claiming native authentication."""
    block = IRBlock(0x100, (
        IRInstr("CALL", None, (), addr=0x100),
        IRInstr("CALL", None, (), addr=0x103),
        IRInstr("RET", None, (), addr=0x106),
    ))
    artifact = IRFunctionArtifact(block.addr, (block,))
    link = cast(DeclaredFunctionEntryLink8616, SimpleNamespace(
        artifact=artifact, boundary=object()))
    zero = Cohort(0, 0, 0, 0)
    return DeclaredSegmentInvariant(
        status=InvariantStatus.PROVEN_CONDITIONAL, stores=zero, controls=zero,
        surfaces=zero, obligations=(), store_rows=(), call_edges=(), terminal_edges=(),
        fetched_span_count=0, bound_entry_selectors={}, work_units=0,
        shared_work_units=0, declared_entry=block.addr, admission=None,
        project=project, root_link=link,
    )


def _index(monkeypatch: pytest.MonkeyPatch) -> DecodedDirectCallsiteIndex8616:
    """Isolate collector accounting from third-party native decoding."""
    index = DecodedDirectCallsiteIndex8616(
        {}, DecodedDirectCallsiteIndexStats8616(0, 0, 0, 0, 0), ())
    monkeypatch.setattr(collector, "_premise_target_resolver_8616", lambda _project: object())
    monkeypatch.setattr(collector, "decoded_callsite_index_for_boundary_8616",
                        lambda *_args, **_kwargs: SimpleNamespace(index=index))
    return index


def test_charge_refuses_expired_shared_deadline_without_direct_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(collector, "direct_evidence_deadline_expired_8616", lambda _project: False)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_deadline = 0.0
        assert not collector._charge_collection_8616(object(), 1)
        assert traversal.census_work_units == 1


def test_charge_refuses_direct_deadline_and_preserves_existing_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(collector, "direct_evidence_deadline_expired_8616", lambda _project: True)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_work_units = 9
        assert not collector._charge_collection_8616(object(), 2)
        assert traversal.census_work_units == 11


@pytest.mark.parametrize("foreign", [True, False])
def test_invalid_selector_scope_accounts_calls_without_budget_reason(
    monkeypatch: pytest.MonkeyPatch, foreign: bool,
) -> None:
    project = object()
    scope = _scope(project)
    scope = replace(scope, project=object()) if foreign else replace(scope, status=InvariantStatus.REFUSED)
    monkeypatch.setattr(collector, "decoded_callsite_index_for_boundary_8616",
                        lambda *_args, **_kwargs: pytest.fail("invalid scope must not decode"))
    records = collector.collect_declared_selector_call_preservations_8616(project, scope)
    assert len(records) == 2
    assert all(record.failure is Failure.CALLER_BINDING_MISMATCH for record in records)
    assert all(record.raw_fact_count == 1 and record.failure_count == 1 for record in records)
    assert all(record.materialized_count == 0 for record in records)


def test_standalone_collection_shares_one_budget_across_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    project = object()
    _index(monkeypatch)
    scope = _scope(project)
    with segment_call_dependency_traversal_scope_8616(census_work_limit=3):
        records = collector.collect_declared_selector_call_preservations_8616(project, scope)
    assert len(records) == 2
    assert records[0].failure is Failure.TARGET_MISMATCH
    assert records[1].failure is Failure.BUDGET_EXHAUSTED


def test_expired_index_callback_accounts_every_remaining_call(monkeypatch: pytest.MonkeyPatch) -> None:
    project = object()
    index = _index(monkeypatch)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        def expired_index(*_args: object, **_kwargs: object) -> object:
            traversal.census_deadline = 0.0
            return SimpleNamespace(index=index)

        monkeypatch.setattr(collector, "decoded_callsite_index_for_boundary_8616", expired_index)
        records = collector.collect_declared_selector_call_preservations_8616(project, _scope(project))
    assert len(records) == 2
    assert all(record.failure is Failure.BUDGET_EXHAUSTED for record in records)


@pytest.mark.parametrize("expires", [False, True])
def test_conditional_callee_closure_never_becomes_selector_preservation(
    monkeypatch: pytest.MonkeyPatch, expires: bool,
) -> None:
    project = object()
    scope = _scope(project)
    assert scope.root_link is not None
    block = scope.root_link.artifact.blocks[0]
    projection = DeclaredSelectorCallsite8616(scope, block, block.instrs[0], 0x100, 0x200, 0x103, 0)
    index = _index(monkeypatch)
    callee = cast(SegmentEffectClosureResult8616, SimpleNamespace(complete=False))
    artifact = IRFunctionArtifact(0x200, (IRBlock(0x200),))
    monkeypatch.setattr(collector, "_caller_premise_surface_8616",
                        lambda *_args: (artifact, object(), object()))
    monkeypatch.setattr(collector, "prove_ir_boundary_coverage_8616", lambda *_args: object())
    monkeypatch.setattr(collector, "build_x86_16_segment_state_artifact", lambda *_args: object())
    monkeypatch.setattr(collector, "prepare_declared_near_call_target_binding_pending_8616",
                        lambda *_args, **_kwargs: pytest.fail("conditional callee must not bind"))
    entry = cast(DecodedDirectCallsite8616, object())
    with segment_call_dependency_traversal_scope_8616() as traversal:
        def closure(*_args: object) -> SegmentEffectClosureResult8616:
            if expires:
                traversal.census_deadline = 0.0
            return callee

        monkeypatch.setattr(collector, "prove_segment_effect_closure_8616", closure)
        record = collector._callee_record_8616(project, scope, index, entry, projection)
    assert record.failure is (Failure.BUDGET_EXHAUSTED if expires else Failure.CALLEE_INCOMPLETE)
    if not expires:
        assert record.callee is callee
    assert record.materialized_count == 0


def test_expired_missing_callee_callback_reports_budget_not_unresolved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = object()
    scope = _scope(project)
    assert scope.root_link is not None
    block = scope.root_link.artifact.blocks[0]
    projection = DeclaredSelectorCallsite8616(scope, block, block.instrs[0], 0x100, 0x200, 0x103, 0)
    index = _index(monkeypatch)
    with segment_call_dependency_traversal_scope_8616() as traversal:
        def expired_surface(*_args: object) -> None:
            traversal.census_deadline = 0.0

        monkeypatch.setattr(collector, "_caller_premise_surface_8616", expired_surface)
        record = collector._callee_record_8616(
            project, scope, index, cast(DecodedDirectCallsite8616, object()), projection)
    assert record.failure is Failure.BUDGET_EXHAUSTED


@pytest.mark.parametrize('exhausted', [True, False])
def test_batch_resource_refusal_is_distinct_from_callee_refusal(
    monkeypatch: pytest.MonkeyPatch, exhausted: bool,
) -> None:
    """Keep resource exhaustion typed through the final collector seal."""
    project = object()
    scope = _scope(project)
    assert scope.root_link is not None
    artifact = scope.root_link.artifact
    block = artifact.blocks[0]
    instruction = block.instrs[0]
    index = _index(monkeypatch)
    projection = DeclaredSelectorCallsite8616(scope, block, instruction, 0x100, 0x200, 0x103, 0)
    record = collector._refused_result_8616(
        artifact, scope.root_link.boundary, block, instruction, index, None, None,
        0x100, 0x200, Failure.CALLEE_INCOMPLETE,
    )
    position = collector._capture_caller_instruction_position_8616(artifact, block, instruction)
    assert position is not None
    prepared = collector._PreparedCall8616(record, projection, None, (), (), 0, position, cs_only=True)

    def consume(_project: object, _projections: tuple, *, obligations: list) -> tuple[bool]:
        if exhausted:
            obligations.append(collector.Obligation(collector.ObligationKind.BUDGET_EXCEEDED, 0x100, None))
        return (False,)

    monkeypatch.setattr(collector, 'consume_declared_selector_cs_preservation_batch_8616', consume)
    refused: set[int] = set()
    admitted = collector._admit_prepared_calls_8616(project, (prepared,), budget_refused=refused)
    result = collector._seal_call_8616(
        project, prepared, admitted[id(prepared)], budget_exhausted=id(prepared) in refused,
    )
    assert result.failure is (Failure.BUDGET_EXHAUSTED if exhausted else Failure.CALLEE_INCOMPLETE)
    assert result.materialized_count == 0


def test_genuine_incomplete_callee_is_not_reported_as_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A canonical coverage refusal keeps its semantic reason without resource exhaustion."""
    from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
    from inertia.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
    from inertia.ir.segment_effect_closure import prove_segment_effect_closure_8616
    from inertia.ir.segment_state import build_x86_16_segment_state_artifact

    project = SimpleNamespace()
    scope = _scope(project)
    assert scope.root_link is not None
    block = scope.root_link.artifact.blocks[0]
    projection = DeclaredSelectorCallsite8616(scope, block, block.instrs[0], 0x100, 0x200, 0x103, 0)
    artifact = IRFunctionArtifact(0x200, (IRBlock(0x200, (IRInstr('RET', None, (), addr=0x200),)),))
    boundary = ExactFunctionRangeBoundary8616(project, 0x200, 1, frozenset({0x200}), frozenset({0x200}), ())
    coverage = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    callee = prove_segment_effect_closure_8616(coverage, build_x86_16_segment_state_artifact(artifact))
    assert callee.failure is not None
    monkeypatch.setattr(collector, '_caller_premise_surface_8616', lambda *_: (artifact, boundary, coverage))
    record = collector._callee_record_8616(
        project, scope, _index(monkeypatch), cast(DecodedDirectCallsite8616, object()), projection,
    )
    assert record.failure is Failure.CALLEE_INCOMPLETE
    assert record.callee is not None and record.callee.failure is callee.failure
