"""Tests for CFG-aware call clobber liveness in function memory SSA."""

from __future__ import annotations

from inertia.ir import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa


def _slot() -> IRAddress:
    """Return one exact caller-frame word used by the liveness fixtures."""
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=-2,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def _store(slot: IRAddress) -> IRInstr:
    """Store one proven word into the fixture slot."""
    return IRInstr(
        "STORE",
        None,
        (slot, IRValue(MemSpace.CONST, const=1, size=2)),
        size=2,
    )


def _load(slot: IRAddress) -> IRInstr:
    """Load one word from the fixture slot."""
    return IRInstr(
        "LOAD",
        IRValue(MemSpace.REG, name="ax", size=2),
        (slot,),
        size=2,
    )


def _unknown_call() -> IRInstr:
    """Return a call with no preservation proof."""
    return IRInstr(
        "CALL",
        None,
        (IRValue(MemSpace.CONST, const=0x2000, size=2),),
    )


def _assert_slot_materialized(artifact: IRFunctionArtifact) -> None:
    """Assert that one store/load lifetime entered function memory SSA."""
    function_ssa = build_x86_16_function_ssa(artifact)

    assert function_ssa.memory_stats.failure_count == 0
    assert len(function_ssa.memory_bindings) == 1
    assert len(function_ssa.memory_accesses) == 2


def test_unknown_call_before_complete_store_does_not_poison_later_load() -> None:
    """A proven store kills any possible earlier call write."""
    slot = _slot()
    _assert_slot_materialized(
        IRFunctionArtifact(
            0x1000,
            (
                IRBlock(
                    0x1000,
                    (_unknown_call(), _store(slot), _load(slot)),
                ),
            ),
        )
    )


def test_unknown_call_after_last_load_does_not_poison_completed_lifetime() -> None:
    """A later call cannot alter a value already loaded into a register."""
    slot = _slot()
    _assert_slot_materialized(
        IRFunctionArtifact(
            0x1000,
            (
                IRBlock(
                    0x1000,
                    (_store(slot), _load(slot), _unknown_call()),
                ),
            ),
        )
    )


def test_unknown_call_on_one_branch_refuses_joined_load() -> None:
    """A possible clobber on either reaching path keeps the joined load ugly."""
    slot = _slot()
    function_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            0x1000,
            (
                IRBlock(0x1000, (_store(slot),), successor_addrs=(0x1010, 0x1020)),
                IRBlock(0x1010, (_unknown_call(),), successor_addrs=(0x1030,)),
                IRBlock(0x1020, (), successor_addrs=(0x1030,)),
                IRBlock(0x1030, (_load(slot),)),
            ),
        )
    )

    assert function_ssa.memory_bindings == ()
    assert {item.kind for item in function_ssa.memory_refusals} == {
        "unknown_call_stack_effect"
    }


def test_unknown_call_after_loop_load_refuses_next_iteration() -> None:
    """A loop backedge carries a trailing call clobber into the next load."""
    slot = _slot()
    function_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            0x1000,
            (
                IRBlock(0x1000, (_store(slot),), successor_addrs=(0x1010,)),
                IRBlock(
                    0x1010,
                    (_load(slot), _unknown_call()),
                    successor_addrs=(0x1010, 0x1020),
                ),
                IRBlock(0x1020, ()),
            ),
        )
    )

    assert function_ssa.memory_bindings == ()
    assert {item.kind for item in function_ssa.memory_refusals} == {
        "unknown_call_stack_effect"
    }
