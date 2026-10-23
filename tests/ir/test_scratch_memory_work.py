"""Scratch memory stays independent and charges work on every exit."""

from __future__ import annotations

import pytest

from inertia.ir import real16_invocation_domain as owner
from tests.ir.test_fused_callee_transfer import _world

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("outcome", ["success", "refusal", "exception"])
def test_scratch_retains_work_and_isolates_unpublished_memory(monkeypatch, outcome):
    """Rejected or raising speculation retains its cost but cannot publish writes."""
    ctx, artifact, block, seed = _world()
    ctx.callsite_addr = 0x1100
    seed.memory.apply_write(0x2000, 1, b"a")
    seed.memory.unknown.add(0x3000)

    def effect(scratch, _artifact, _block, _instruction, state):
        scratch.work_units += 19
        state.memory.known[0x2000] = ord("b")
        state.memory.unknown.add(0x3001)
        if outcome == "exception":
            raise ValueError("after charged speculative work")
        return outcome == "success"

    monkeypatch.setattr(owner, "_feasibility_call_effect_8616", effect)

    def attempt():
        return owner._feasibility_call_scratch_8616(
            ctx, artifact, block, block.instrs[0], seed.registers, seed.memory, (),
        )

    if outcome == "exception":
        with pytest.raises(ValueError, match="after charged speculative work"):
            attempt()
    else:
        assert attempt() is (outcome == "success")
    assert ctx.work_units >= 19
    assert seed.memory.known[0x2000] == ord("b" if outcome == "success" else "a")
    assert (0x3001 in seed.memory.unknown) is (outcome == "success")


@pytest.mark.parametrize("unknown_bytes", [0, 128])
def test_large_known_snapshot_keeps_unknown_copy_budget(monkeypatch, unknown_bytes):
    """Cheap known-byte snapshots do not waive copying the ordinary unknown set."""
    ctx, artifact, block, seed = _world()
    ctx.callsite_addr = 0x1100
    ctx.work_limit = 64
    seed.memory.apply_write(0x2000, 4096, bytes(4096))
    seed.memory.unknown.update(range(0x4000, 0x4000 + unknown_bytes))
    calls = []

    def effect(_scratch, _artifact, _block, _instruction, state):
        calls.append(1)
        assert state.memory.known[0x2000] == 0
        assert len(state.memory.known) == 4096
        return True

    monkeypatch.setattr(owner, "_feasibility_call_effect_8616", effect)
    accepted = owner._feasibility_call_scratch_8616(
        ctx, artifact, block, block.instrs[0], seed.registers, seed.memory, (),
    )
    assert accepted is (unknown_bytes == 0)
    assert bool(calls) is accepted
    assert (ctx.work_units > ctx.work_limit) is (not accepted)
