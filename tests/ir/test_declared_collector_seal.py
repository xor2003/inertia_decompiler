"""Layer: IR tests.
Responsibility: reject post-callback changes to prepared selector callee effects.
"""
from __future__ import annotations

from typing import cast

import pytest

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir import declared_selector_call_preservation as collector
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace, SegmentOrigin
from inertia.ir.declared_selector_invariant import DeclaredSelectorCallsite8616
from inertia.ir.entry_domain_call_preservation import (
    EntryDomainCallPreservation8616,
    EntryDomainCallPreservationFailure8616,
)
from inertia.ir.ir_boundary_cfg import IRBoundaryCoverageResult8616
from inertia.ir.segment_effect_closure import SegmentEffectClosureResult8616
from inertia.ir.segment_state import SegmentStateArtifact
from inertia.ir.segment_state_transfer import SegmentRegisterState, SegmentValueKind8616

pytestmark = pytest.mark.decompiler


def _prepared(project: object) -> collector._PreparedCall8616:
    """Retain typed detached callee facts without claiming a native proof."""
    instruction = IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=0x200),), addr=0x100)
    block = IRBlock(0x100, (instruction,))
    artifact = IRFunctionArtifact(0x100, (block,))
    boundary = ExactFunctionRangeBoundary8616(project, 0x100, 3, frozenset({0x100}),
                                             frozenset({0x100}), ())
    callee_artifact = IRFunctionArtifact(0x200, (IRBlock(0x200, (IRInstr("RET", None, (), addr=0x200),)),))
    callee_boundary = ExactFunctionRangeBoundary8616(project, 0x200, 1, frozenset({0x200}),
                                                    frozenset({0x200}), ())
    coverage = IRBoundaryCoverageResult8616(callee_artifact, callee_boundary, None, 1, 1, 1, 1, 0)
    cs = SegmentRegisterState("cs", SegmentValueKind8616.ARCHITECTURAL_LIVE_IN, "cs.entry", SegmentOrigin.PROVEN)
    state = SegmentStateArtifact(
        {0x200: {"cs": cs}}, {0x200: {"cs": cs}}, {"effects": {"cs": "preserved"}},
        {0x200: {"cs": cs}}, {0x200: {"cs": cs}}, source_artifact=callee_artifact,
    )
    callee = SegmentEffectClosureResult8616(coverage, state, None, (), (0x200,), 1, 1, 1, 1, 0)
    index = DecodedDirectCallsiteIndex8616({}, DecodedDirectCallsiteIndexStats8616(0, 0, 0, 0, 0))
    result = EntryDomainCallPreservation8616(
        artifact, boundary, block, instruction, index, cast(DecodedDirectCallsite8616, object()),
        callee, None, 0x100, 0x200, None, 1, 1, 1, 1, 0,
    )
    position = collector._capture_caller_instruction_position_8616(artifact, block, instruction)
    assert position is not None
    return collector._PreparedCall8616(
        result, cast(DeclaredSelectorCallsite8616, object()), None,
        collector._callee_facts_8616(callee), collector._index_facts_8616(index), 1, position,
    )


@pytest.mark.parametrize("mutation", ["entry", "exit", "instruction_entry", "instruction_exit", "summary", "closure", "boundary", "callee_ir"])
def test_pure_final_seal_rejects_mutated_callee_obligations(
    monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    project = object()
    prepared = _prepared(project)
    callee = prepared.record.callee
    assert callee is not None
    monkeypatch.setattr(collector, "_caller_surface_failure_8616", lambda _record, **_kwargs: None)
    monkeypatch.setattr(collector, "_callsite_entry_failure_8616", lambda _record, **_kwargs: None)
    monkeypatch.setattr(SegmentEffectClosureResult8616, "complete", property(
        lambda _self: pytest.fail("final seal must not invoke complete")))
    state = callee.state
    if mutation == "entry":
        state.entry_states.clear()
    elif mutation == "exit":
        state.exit_states.clear()
    elif mutation == "instruction_entry":
        state.instruction_entry_states.clear()
    elif mutation == "instruction_exit":
        state.instruction_exit_states.clear()
    elif mutation == "summary":
        cast(dict[str, object], state.summary["effects"])["cs"] = "clobbered"
    elif mutation == "closure":
        object.__setattr__(callee, "return_block_addrs", ())
    elif mutation == "boundary":
        object.__setattr__(callee.coverage.boundary, "size", 2)
    else:
        object.__setattr__(callee.coverage.artifact.blocks[0].instrs[0], "op", "JMP")
    result = collector._seal_call_8616(project, prepared, True)
    assert result.failure is EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE
    assert result.materialized_count == 0


def test_pure_final_seal_accepts_unchanged_effects_without_callbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    project = object()
    prepared = _prepared(project)
    monkeypatch.setattr(collector, "_caller_surface_failure_8616", lambda _record, **_kwargs: None)
    monkeypatch.setattr(collector, "_callsite_entry_failure_8616", lambda _record, **_kwargs: None)
    monkeypatch.setattr(SegmentEffectClosureResult8616, "complete", property(
        lambda _self: pytest.fail("final seal must not invoke complete")))
    assert collector._seal_call_8616(project, prepared, True) is prepared.record


@pytest.mark.parametrize("field,value", [("address", 0x101), ("size", 2), ("bytes", b"\x90\x90\x90")])
def test_pure_final_seal_rejects_mutated_decoded_native_entry(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object,
) -> None:
    from dataclasses import replace
    from types import SimpleNamespace

    project = object()
    prepared = _prepared(project)
    native = SimpleNamespace(address=0x100, size=3, bytes=b"\xe8\xfd\x00")
    entry = DecodedDirectCallsite8616(0x100, (native,), 0, 0x100, 0x200)
    index = DecodedDirectCallsiteIndex8616(
        {0x200: (entry,)}, DecodedDirectCallsiteIndexStats8616(1, 1, 1, 1, 0))
    result = replace(prepared.record, index=index, entry=entry)
    prepared = replace(prepared, record=result, index_facts=collector._index_facts_8616(index))
    monkeypatch.setattr(collector, "_caller_surface_failure_8616", lambda _record, **_kwargs: None)
    monkeypatch.setattr(collector, "_callsite_entry_failure_8616", lambda _record, **_kwargs: None)
    setattr(native, field, value)
    sealed = collector._seal_call_8616(project, prepared, True)
    assert sealed.failure is EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE


@pytest.mark.parametrize("corruption", ["bool_count", "open_count", "failure", "conditional"])
def test_factory_pending_gate_rejects_nonuniversal_or_open_closure(corruption: str) -> None:
    from dataclasses import replace

    callee = _prepared(object()).record.callee
    assert callee is not None
    assert collector._fresh_universal_closure_8616(callee)
    if corruption == "bool_count":
        object.__setattr__(callee, "materialized_count", True)
    elif corruption == "open_count":
        callee = replace(callee, failure_count=1)
    elif corruption == "failure":
        from inertia.ir.segment_effect_closure import SegmentEffectClosureFailure8616
        callee = replace(callee, failure=SegmentEffectClosureFailure8616.COVERAGE_INCOMPLETE)
    else:
        object.__setattr__(callee.state, "invocation_scope", object())
    assert not collector._fresh_universal_closure_8616(callee)


def test_malformed_final_callee_ir_refuses_without_swallowing_unrelated_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    project = object()
    prepared = _prepared(project)
    callee = prepared.record.callee
    assert callee is not None
    monkeypatch.setattr(collector, "_caller_surface_failure_8616", lambda _record, **_kwargs: None)
    monkeypatch.setattr(collector, "_callsite_entry_failure_8616", lambda _record, **_kwargs: None)
    object.__setattr__(callee.coverage.artifact.blocks[0].instrs[0], "args", [])
    result = collector._seal_call_8616(project, prepared, True)
    assert result.failure is EntryDomainCallPreservationFailure8616.CALLEE_INCOMPLETE


@pytest.mark.parametrize("mutate", [False, True])
def test_shared_callee_final_reconcile_visits_once_and_refuses_all_dependents(
    monkeypatch: pytest.MonkeyPatch, mutate: bool,
) -> None:
    from dataclasses import replace

    project = object()
    first = _prepared(project)
    second = replace(first, record=replace(first.record, callsite_addr=0x103))
    callee = first.record.callee
    assert callee is not None
    if mutate:
        cast(dict[str, object], callee.state.summary["effects"])["cs"] = "changed"
    calls = []
    original = collector._callee_facts_match_8616

    def count(prepared: collector._PreparedCall8616) -> bool:
        calls.append(prepared.record.callee)
        return original(prepared)

    monkeypatch.setattr(collector, "_callee_facts_match_8616", count)
    verdicts = collector._seal_shared_callees_8616(
        project, (first, second), {id(first): True, id(second): True})
    assert verdicts == {id(callee): not mutate}
    assert calls == [callee]


def test_same_selector_target_prepares_one_callee_despite_fresh_lookup_wrappers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeated callsites share preparation, not only a final identity-based seal."""
    from dataclasses import replace

    from tests.ir.test_declared_selector_call_preservation import _scope

    project = object()
    scope = _scope(project)
    assert scope.root_link is not None
    block = scope.root_link.artifact.blocks[0]
    lookups: list[int] = []
    closures: list[SegmentEffectClosureResult8616] = []
    pending: list[collector._PreparedCall8616] = []

    def surface(_project: object, target: int) -> tuple[object, object, object]:
        lookups.append(target)
        callee = _prepared(project).record.callee
        assert callee is not None
        closures.append(callee)
        return callee.coverage.artifact, callee.coverage.boundary, callee.coverage

    def bound(*args: object, **kwargs: object) -> collector._PreparedCall8616:
        callee = cast(SegmentEffectClosureResult8616, args[5])
        row = _prepared(project)
        facts = kwargs.get("callee_facts")
        row = replace(row, record=replace(row.record, callee=callee),
                      callee_facts=collector._callee_facts_8616(callee) if facts is None
                      else cast(tuple[object, ...], facts))
        pending.append(row)
        return row

    monkeypatch.setattr(collector, "_caller_premise_surface_8616", surface)
    monkeypatch.setattr(collector, "build_x86_16_segment_state_artifact", lambda _artifact: None)
    monkeypatch.setattr(collector, "prove_segment_effect_closure_8616", lambda *_args: closures[-1])
    monkeypatch.setattr(collector, "_bound_record_8616", bound)
    shared: dict[tuple[int, int, int, int], collector._PreparedCall8616] = {}
    prepared = _prepared(project)
    for instruction in block.instrs[:2]:
        assert instruction.addr is not None
        projection = DeclaredSelectorCallsite8616(
            scope, block, instruction, instruction.addr, 0x200, instruction.addr + 3, 0)
        collector._callee_record_8616(
            project, scope, prepared.record.index, prepared.record.entry, projection,
            callees=shared,
        )
    assert lookups == [0x200]
    assert len(pending) == 2
    assert pending[0].record.callee is pending[1].record.callee
    assert pending[0].callee_facts is pending[1].callee_facts
