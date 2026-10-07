"""Native repeated-store footprint and authenticated state controls."""
from dataclasses import replace

import pytest
import tests.ir.test_x86_16_declared_resize_boundary as native
import inertia.ir.real16_invocation_domain as census
from inertia.ir.real16_invocation_domain import Real16InvocationFailure8616
from inertia.ir.real16_path_memory8616 import path_memory_initial_8616
from inertia.ir.real16_repeated_store8616 import (
    RepeatedStore8616,
    repeated_store_effect_8616,
)


def test_second_rep_iteration_cannot_modify_fetched_code() -> None:
    """The complete repeated footprint must stay disjoint from fetched bytes."""
    # ES100:00ff is below module1100; only the second write hits fetched code.
    caller=bytes.fromhex("b80001 8ec0 bfff00 b90200 31c0 fc f3aa e80100 c3")
    boot=native._boot(caller)
    project, _raw, coverage=native._world(boot,len(caller))
    premise=native._resize_premise(project,coverage,native.MODULE_BASE+16,boot,())
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.CODE_WRITE_VIOLATION


def test_native_cld_repeat_changes_second_loaded_byte() -> None:
    """All iterations update later LOAD; CLD proves DF under unknown FLAGS."""
    allocation=bytearray(native._environment().allocation)
    allocation[0x201]=0x99
    env=replace(native._environment(), allocation=bytes(allocation))
    caller=bytes.fromhex("b80001 8ec0 8ed8 bf0002 b90200 b000 fc f3aa 8b0e0102 e302 ffd1 e80100 c3")
    boot=native._boot(caller,env)
    project,raw,coverage=native._world(boot,len(caller))
    premise=native._resize_premise(project,coverage,native.MODULE_BASE+26,boot,())
    assert premise.complete, premise.failure
    assert (native.MODULE_BASE+18,native.MODULE_BASE+24) in premise.infeasible_edges
    store = next(row for block in raw.blocks for row in block.instrs if row.op == "STORE")
    address, value = store.args
    object.__setattr__(store, "args", (replace(address, offset=address.offset+1), value))
    assert not premise.complete



@pytest.mark.parametrize("setup", [
    "bfff ff b90200 fc",  # forward index wrap
    "bf0000 b90200 fd",  # backward index wrap
    "bf0002 b90200",  # unknown direction
    "bf0002 648b0e0005 fc",  # unknown count from undeclared bytes
])
def test_native_unbounded_repeat_refuses(setup: str) -> None:
    """Unknown inputs and wrapping repeated footprints cannot gain authority."""
    caller=bytes.fromhex("b80001 8ec0 " + setup + " f3aa e80100 c3")
    boot=native._boot(caller)
    project,_raw,coverage=native._world(boot,len(caller))
    premise=native._resize_premise(project,coverage,native.MODULE_BASE+len(caller)-4,boot,())
    assert not premise.complete


@pytest.mark.parametrize("count, direction", [(0,None),(2,False),(2,True)])
def test_complete_repeat_span_and_final_state(count: int, direction: bool | None) -> None:
    """A whole transfer includes all bytes, direction, and final index/count."""
    spec=RepeatedStore8616(0x1100,b"\xf3\xaa",1)
    effect=repeated_store_effect_8616(spec,{"cx":count,"es":0x100,"di":0x200,"al":7},direction)
    assert effect is not None
    assert effect.size==count
    assert effect.data==bytes([7])*count
    assert effect.final_di==0x200 + (-count if direction else count)
    if count:
        assert effect.base==0x1200-(count-1 if direction else 0)


def test_direction_must_meet_and_unknown_data() -> None:
    """Disagreeing directions vanish; unknown source bytes remain unknown."""
    left=census._PathState8616({},path_memory_initial_8616(),False)
    right=census._PathState8616({},path_memory_initial_8616(),True)
    assert census._meet_path_state_8616([left,right]).direction is None
    assert census._meet_path_state_8616([left,left]).direction is False
    effect=repeated_store_effect_8616(RepeatedStore8616(0,b"\xf3\xaa",1),{"cx":2,"es":0x100,"di":0x200},False)
    assert effect is not None and effect.data is None and effect.size==2


def test_native_reverse_repeat_changes_both_bytes() -> None:
    """STD is a proved direction; both decreasing-index stores reach LOAD."""
    allocation=bytearray(native._environment().allocation)
    allocation[0x200:0x202]=b"\x99\x99"
    env=replace(native._environment(),allocation=bytes(allocation))
    caller=bytes.fromhex("b80001 8ec0 8ed8 bf0102 b90200 b000 fd f3aa 8b0e0002 e302 ffd1 e80100 c3")
    boot=native._boot(caller,env)
    project,_raw,coverage=native._world(boot,len(caller))
    premise=native._resize_premise(project,coverage,native.MODULE_BASE+26,boot,())
    assert premise.complete, premise.failure


def test_native_zero_count_preserves_code() -> None:
    """Zero REP performs no store even with unknown direction at a code address."""
    caller=bytes.fromhex("b81001 8ec0 bf0000 b90000 f3aa e80100 c3")
    boot=native._boot(caller)
    project,_raw,coverage=native._world(boot,len(caller))
    premise=native._resize_premise(project,coverage,native.MODULE_BASE+13,boot,())
    assert premise.complete, premise.failure


def test_partial_direction_does_not_cross_unknown_call() -> None:
    """A returned lane set without DF cannot inherit a caller-only partial fact."""
    from inertia.ir.core import IRInstr
    from inertia.ir.real16_edge_feasibility8616 import DirectionTracker8616
    tracker=DirectionTracker8616({},False)
    assert tracker.direction() is False
    tracker.step(IRInstr("CALL",None,(),addr=0x100),{}, {})
    assert tracker.direction() is None


def test_native_unknown_repeat_data_does_not_prune() -> None:
    """An unknown AL invalidates every written byte, including later iterations."""
    caller=bytes.fromhex("b80001 8ec0 8ed8 bf0002 b90200 64a00005 fc f3aa 8b0e0102 e302 ffd1 e80100 c3")
    # No relocation may alter this longer caller's code.
    image=caller+b"\xc3"
    mz=bytearray(native._mz(image))
    mz[6:8]=b"\0\0"
    boot=native.program_from_mz_bytes(bytes(mz),native._environment(),code_ranges=(native.LinearRange(native.MODULE_BASE,len(image)),))
    project,_raw,coverage=native._world(boot,len(caller))
    premise=native._resize_premise(project,coverage,native.MODULE_BASE+len(caller)-4,boot,())
    assert not premise.complete
    assert premise.failure is Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN


def test_native_word_repeat_changes_second_word() -> None:
    """REP STOSW writes the full second word before the later LOAD/JCXZ."""
    allocation = bytearray(native._environment().allocation)
    allocation[0x202:0x204] = b"\x99\x99"
    environment = replace(native._environment(), allocation=bytes(allocation))
    caller = bytes.fromhex(
        "b80001 8ec0 8ed8 bf0002 b90200 31c0 fc f3ab 8b0e0202 e302 ffd1 e80100 c3"
    )
    boot = native._boot(caller, environment)
    project, _raw, coverage = native._world(boot, len(caller))
    premise = native._resize_premise(project, coverage, native.MODULE_BASE + 26, boot, ())
    assert premise.complete, premise.failure
    assert (native.MODULE_BASE + 18, native.MODULE_BASE + 24) in premise.infeasible_edges


def test_unsupported_repeat_width_refuses() -> None:
    """A fabricated or unsupported element width cannot create an empty write."""
    assert repeated_store_effect_8616(RepeatedStore8616(0,b"",0),{"cx":2,"es":0x100,"di":0x200,"al":0},False) is None
