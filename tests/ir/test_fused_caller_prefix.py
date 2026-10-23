"""Native caller prefix fusion preserves complete binding and effect evidence."""
from __future__ import annotations

from dataclasses import replace

import pytest

from inertia.ir import real16_invocation_domain as owner
from inertia.ir.real16_path_memory8616 import PathMemory8616
from tests.ir.test_fused_callee_transfer import _world

pytestmark = pytest.mark.decompiler


def test_native_caller_prefix_fits_one_walk_budget():
    """A requested native CALL retains its frame and state under the lower budget."""
    code = bytes.fromhex("b80100") + bytes.fromhex("83c001") * 80 + bytes.fromhex("e80000c3")
    ctx, artifact, block, seed = _world(code, single_block=False)
    assert block.instrs[-1].op == "CALL"
    ctx.callsite_addr = block.instrs[-1].addr
    # CALL's real stack stores require the fetched addressing-domain bytes.
    ctx.machine_bytes[ctx.callsite_addr] = ctx.project.loader.memory.load(ctx.callsite_addr, 3)
    ctx.manifest.add((artifact.function_addr, len(code)))
    baseline = owner._simulate_path_block_8616(ctx, artifact, block, seed, stop_after=ctx.callsite_addr)
    assert isinstance(baseline, owner._PathState8616)
    assert ctx.callsite_call_state is not None and ctx.callsite_call_state["ax"] == 81
    original_counts = tuple(len(values) for values in (
        ctx.raw_facts, ctx.normalized_facts, ctx.classified_facts, ctx.materialized_facts,
    ))
    fresh = replace(
        ctx, raw_facts=set(), normalized_facts=set(), classified_facts=set(),
        materialized_facts=set(), work_units=0, accounted_work_units=0,
        callsite_call_state=None, callsite_memory=None, checked_stores=0,
        work_limit=len(block.instrs) + len(owner._BASE_FUSED_CALLEE_OPERATIONS_8616.producers) + 30,
    )
    result = owner._simulate_path_block_8616(
        fresh, artifact, block, seed, stop_after=fresh.callsite_addr,
    )
    assert isinstance(result, owner._PathState8616)
    assert result.registers == baseline.registers and result.memory == baseline.memory
    assert fresh.callsite_call_state == ctx.callsite_call_state
    assert fresh.callsite_memory == ctx.callsite_memory
    assert tuple(len(values) for values in (
        fresh.raw_facts, fresh.normalized_facts, fresh.classified_facts, fresh.materialized_facts,
    )) == original_counts
    assert fresh.checked_stores == ctx.checked_stores
    assert fresh.failures == ctx.failures == 0


def _caller_world():
    code = bytes.fromhex("b80100") + bytes.fromhex("83c001") * 80 + bytes.fromhex("e80000c3")
    ctx, artifact, block, seed = _world(code, single_block=False)
    ctx.callsite_addr = block.instrs[-1].addr
    ctx.machine_bytes[ctx.callsite_addr] = ctx.project.loader.memory.load(ctx.callsite_addr, 3)
    ctx.manifest.add((artifact.function_addr, len(code)))
    return ctx, artifact, block, seed


def test_caller_late_native_mismatch_revokes_provisional_stack_store():
    """A mismatch after the first CALL-frame byte retains all-row refusal priority."""
    ctx, artifact, block, seed = _caller_world()
    stores = [index for index, row in enumerate(block.instrs) if row.op == "STORE"]
    assert len(stores) == 2
    rows = list(block.instrs)
    rows[stores[1]] = replace(rows[stores[1]], size=2)
    changed = replace(block, instrs=tuple(rows))
    result = owner._simulate_path_block_8616(ctx, artifact, changed, seed, stop_after=ctx.callsite_addr)
    assert result is owner.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN
    assert ctx.checked_stores == 0 and ctx.failures == len(block.instrs)
    assert not ctx.materialized_facts and ctx.callsite_call_state is None
    assert seed.memory == PathMemory8616() and seed.registers["sp"] == 0x200


def test_caller_late_mismatch_precedes_foreign_call_callback(monkeypatch):
    """No CALL observer sees state from an incompletely bound native block."""
    ctx, artifact, block, seed = _caller_world()
    rows = list(block.instrs)
    rows[-2] = replace(rows[-2], size=rows[-2].size + 1)
    changed = replace(block, instrs=tuple(rows))
    def forbidden(*args, **kwargs):
        raise AssertionError("CALL callback ran before whole-block binding")
    monkeypatch.setattr(owner, "_cross_call_8616", forbidden)
    result = owner._simulate_path_block_8616(ctx, artifact, changed, seed, stop_after=ctx.callsite_addr)
    assert result is owner.Real16InvocationFailure8616.NATIVE_EFFECT_UNPROVEN


@pytest.mark.parametrize("resource", ["work", "deadline"])
def test_caller_fusion_resource_refusal_never_publishes_state(resource):
    ctx, artifact, block, seed = _caller_world()
    if resource == "work":
        ctx.work_limit = len(owner._BASE_FUSED_CALLEE_OPERATIONS_8616.producers) + 30
        expected = owner.Real16InvocationFailure8616.CENSUS_WORK_EXCEEDED
    else:
        ctx.deadline = 0
        expected = owner.Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    before = dict(seed.registers), seed.memory.copy()
    assert owner._simulate_path_block_8616(ctx, artifact, block, seed, stop_after=ctx.callsite_addr) is expected
    assert (seed.registers, seed.memory) == before and ctx.callsite_call_state is None


def test_caller_interior_cutoff_does_not_authorize_changed_suffix():
    """Prefix-only consumers ignore the suffix and retain ordinary semantics."""
    ctx, artifact, block, seed = _caller_world()
    stop = block.addr + 3
    rows = list(block.instrs)
    rows[-2] = replace(rows[-2], size=rows[-2].size + 1)
    changed = replace(block, instrs=tuple(rows))
    result = owner._simulate_path_block_8616(ctx, artifact, changed, seed, stop_after=stop)
    assert isinstance(result, owner._PathState8616) and result.registers["ax"] == 2
    assert ctx.callsite_call_state is None and ctx.failures == 0


def test_caller_foreign_producer_builder_falls_back_without_calling_it(monkeypatch):
    ctx, artifact, block, seed = _caller_world()
    def forbidden():
        raise AssertionError("foreign producer builder must not execute")
    monkeypatch.setattr(owner.caller_prefix_owner_8616, "fused_caller_prefix_producers_8616", forbidden)
    result = owner._simulate_path_block_8616(ctx, artifact, block, seed, stop_after=ctx.callsite_addr)
    assert isinstance(result, owner._PathState8616)
    assert ctx.callsite_call_state["ax"] == 81


def test_caller_expired_deadline_precedes_exhausted_work():
    """Fused admission preserves the ordinary deadline-first failure contract."""
    ctx, artifact, block, seed = _caller_world()
    ctx.deadline = 0
    ctx.work_limit = 0
    result = owner._simulate_path_block_8616(ctx, artifact, block, seed, stop_after=ctx.callsite_addr)
    assert result is owner.Real16InvocationFailure8616.CENSUS_DEADLINE_EXCEEDED
    assert not ctx.materialized_facts and ctx.callsite_call_state is None


def test_caller_scalar_failure_binds_suffix_without_classifying_it():
    """Real self-modifying STORE retains the ordinary first-failure ledger."""
    code = bytes.fromhex("c70604000100b80100") + bytes.fromhex("83c001") * 80 + bytes.fromhex("e80000c3")
    ctx, artifact, block, seed = _world(code, single_block=False)
    callsite = block.instrs[-1].addr
    ctx.machine_bytes[block.addr] = ctx.project.loader.memory.load(block.addr, 6)
    ctx.machine_bytes[callsite] = ctx.project.loader.memory.load(callsite, 3)
    ctx.manifest.add((artifact.function_addr, len(code)))
    ordinary = owner._simulate_path_block_8616(ctx, artifact, block, seed, stop_after=callsite)
    assert ordinary is owner.Real16InvocationFailure8616.CODE_WRITE_VIOLATION
    fresh = replace(
        ctx, callsite_addr=callsite, raw_facts=set(), normalized_facts=set(),
        classified_facts=set(), materialized_facts=set(), work_units=0,
        accounted_work_units=0, checked_stores=0, failures=0, first_failure_site=None,
    )
    fused = owner._simulate_path_block_8616(fresh, artifact, block, seed, stop_after=callsite)
    assert fused is ordinary
    assert (fresh.raw_facts, fresh.normalized_facts, fresh.classified_facts, fresh.materialized_facts,
            fresh.failures, fresh.first_failure_site) == (
        ctx.raw_facts, ctx.normalized_facts, ctx.classified_facts, ctx.materialized_facts,
        ctx.failures, ctx.first_failure_site,
    )
    assert not fresh.callsite_call_state and seed.memory == PathMemory8616()
