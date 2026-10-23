"""Scratch range compaction preserves every protected byte and honest budgets."""


import pytest

from inertia.ir import real16_invocation_domain as owner
from inertia.ir.real16_scratch_protection import ScratchCallerRange8616
from tests.ir.test_fused_callee_transfer import _world

pytestmark = pytest.mark.decompiler


def _attempt(monkeypatch, spans, caller_range, *, budget=10000, write_offset=None, exercise_union=True):
    ctx, artifact, block, seed = _world()
    ctx.callsite_addr = 0x1100
    ctx.work_limit = budget
    seen = []
    def effect(scratch, artifact, block, instruction, state, *, caller_range=None):
        seen.append(set(scratch.manifest))
        if write_offset is not None:
            state.memory.apply_write(0x1000 + write_offset, 1, b"x")
            return owner._feasibility_code_unmodified_8616(scratch, state.memory, caller_range=caller_range)
        if not exercise_union:
            return True
        union = owner._feasibility_protected_union_8616(scratch, caller_range=caller_range)
        if union is not None:
            seen[-1] = {(start, end - start) for start, end in union}
        return union is not None
    monkeypatch.setattr(owner, "_feasibility_call_effect_8616", effect)
    before = set(ctx.manifest)
    result = owner._feasibility_call_scratch_8616(
        ctx, artifact, block, block.instrs[0], seed.registers, seed.memory,
        spans, caller_range=caller_range,
    )
    assert ctx.manifest == before
    return result, seen, ctx


def _bytes(spans):
    return {address for start, size in spans for address in range(start, start + size)}


def test_redundant_caller_subspans_fit_existing_small_budget(monkeypatch):
    spans = (*( (0x1000 + index, 1) for index in range(50)), (0x1000, 100))
    result, seen, ctx = _attempt(monkeypatch, spans, ScratchCallerRange8616(0x1000, 0x1064), budget=120)
    assert result
    assert _bytes(seen[0]) == _bytes(spans)
    assert ctx.work_units <= ctx.work_limit


@pytest.mark.parametrize("extra", [(), ((0x0fff, 1),), ((0x1064, 1),), ((0x0fff, 2),), ((0x1063, 2),)])
def test_exact_union_preserves_gaps_outside_boundaries_and_partial_overlap(monkeypatch, extra):
    spans = ((0x1000, 1), (0x1050, 1), (0x1000, 100), *extra)
    result, seen, _ = _attempt(monkeypatch, spans, ScratchCallerRange8616(0x1000, 0x1064))
    assert result and _bytes(seen[0]) == _bytes(spans)
    assert _bytes(extra) <= _bytes(seen[0])
    assert 0x1020 in _bytes(seen[0])


@pytest.mark.parametrize("caller_range", [None, ScratchCallerRange8616(0x1000, 0x1000), ScratchCallerRange8616(True, 0x1064)])
def test_unknown_or_absent_range_keeps_original_protection(monkeypatch, caller_range):
    spans = ((0x1000, 1), (0x1000, 100))
    result, seen, _ = _attempt(monkeypatch, spans, caller_range)
    assert result and _bytes(seen[0]) == _bytes(spans)


def test_missing_complete_range_never_deletes_subspans(monkeypatch):
    spans = ((0x1000, 1), (0x1050, 1))
    result, seen, _ = _attempt(monkeypatch, spans, ScratchCallerRange8616(0x1000, 0x1064), exercise_union=False)
    assert result and seen[0] == set(spans)


@pytest.mark.parametrize("extra", [((0x1001, True),), ((0x1001, 0),), ((0x1001, 1, 7),)])
def test_malformed_span_metadata_keeps_original_surface(monkeypatch, extra):
    spans = ((0x1000, 1), (0x1000, 100), *extra)
    result, seen, _ = _attempt(monkeypatch, spans, ScratchCallerRange8616(0x1000, 0x1064), exercise_union=False)
    assert result and seen[0] == set(spans)


def test_copy_work_refusal_is_charged_without_publishing_effects(monkeypatch):
    spans = (*( (0x1000 + index, 1) for index in range(50)), (0x1000, 100))
    result, seen, ctx = _attempt(monkeypatch, spans, ScratchCallerRange8616(0x1000, 0x1064), budget=10)
    assert not result and not seen and ctx.work_units > ctx.work_limit
    assert not ctx.raw_facts and not ctx.normalized_facts and not ctx.classified_facts
    assert not ctx.materialized_facts and ctx.failures == 0


def test_expired_deadline_never_runs_preparation_or_effect(monkeypatch):
    ctx, artifact, block, seed = _world()
    ctx.callsite_addr = 0x1100
    ctx.deadline = 0
    def forbidden(*args, **kwargs):
        raise AssertionError("expired scratch must refuse before effects")
    monkeypatch.setattr(owner, "_feasibility_call_effect_8616", forbidden)
    assert not owner._feasibility_call_scratch_8616(
        ctx, artifact, block, block.instrs[0], seed.registers, seed.memory,
        ((0x1000, 100),), caller_range=ScratchCallerRange8616(0x1000, 0x1064),
    )
    assert ctx.work_units == 0


@pytest.mark.parametrize("offset,extra,allowed", [(0x20, (), False), (0x64, (), True), (0x65, (), True), (0x64, ((0x1064, 1),), False)])
def test_store_verdicts_keep_caller_gap_and_outside_boundary_protection(monkeypatch, offset, extra, allowed):
    spans = ((0x1000, 1), (0x1050, 1), (0x1000, 100), *extra)
    result, seen, _ = _attempt(monkeypatch, spans, ScratchCallerRange8616(0x1000, 0x1064), write_offset=offset)
    assert result is allowed and _bytes(seen[0]) == _bytes(spans)


def test_early_unknown_call_proof_keeps_original_work(monkeypatch):
    spans = (*( (0x1000 + index, 1) for index in range(50)), (0x1000, 100))
    monkeypatch.setattr(owner, "_consume_cross_call_boundary_8616", lambda *args: None)
    costs = []
    for caller_range in (None, ScratchCallerRange8616(0x1000, 0x1064)):
        ctx, artifact, block, seed = _world()
        ctx.callsite_addr = 0x1100
        assert not owner._feasibility_call_scratch_8616(
            ctx, artifact, block, block.instrs[0], seed.registers, seed.memory,
            spans, caller_range=caller_range,
        )
        costs.append(ctx.work_units)
    assert costs[0] == costs[1]


@pytest.mark.parametrize("extra", [((0x1001, True),), ((0x1001, 0),), ((0x1001, 1, 7),)])
def test_unknown_interval_metadata_selects_original_union_route(extra):
    from inertia.ir.real16_scratch_protection import CallerIntervalSelectionStatus8616, select_caller_intervals_8616
    ctx, _, _, _ = _world()
    spans = {(0x1000, 1), (0x1000, 100), *extra}
    before = spans.copy()
    selected = select_caller_intervals_8616(ctx, spans, ScratchCallerRange8616(0x1000, 0x1064), owner._census_work_exceeded_8616)
    assert selected.status is CallerIntervalSelectionStatus8616.ORIGINAL and selected.intervals is None
    assert spans == before
