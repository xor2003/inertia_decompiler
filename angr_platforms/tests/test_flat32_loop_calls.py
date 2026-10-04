"""Closed matched-loop induction controls for flat32 loops with direct calls.

Both staged drivers lift real i386 bytes through pyvex/angr and prove or
refuse with real Z3 through the shared ``compare_flat32_loop_calls`` owner.
A caller loop that calls a complete declared acyclic callee is out of scope
for both prior lanes: call composition refuses the cycle and the matched-CFG
lane refuses the call boundary. Concrete Unicorn replay at zero/one/many
trips is independent execution evidence, never part of the symbolic proof.
"""
from typing import Any

import pytest
from test_flat32_comparator_lane import DriverLane, _project

from tools.dosunit.flat32_call_contracts import CallCompositionLimits
from tools.dosunit.flat32_loop_calls import compare_flat32_loop_calls
from tools.dosunit.flat32_proof_retry import retry_function_proof
from tools.dosunit.flat32_replay import (
    MemoryRange,
    ReplayImage,
    ReplayStatus,
    ReplayVector,
    compare_replays,
    replay,
)

pytest_plugins = ["test_flat32_comparator_lane"]

BASE = 0x100000

# caller: test ecx,ecx; jz done; call callee; dec ecx; jmp loop; done: ret
CALLER = "85c9 7408 e804000000 49 ebf4 c3"
# callee: inc ebx; ret
CALLEE = "43c3"
CODE = f"{CALLER} {CALLEE}"
CALLER_SIZE = len(bytes.fromhex(CALLER))

# inc ebx via the ModRM form: different bytes, identical register/flag effect.
CALLEE_EQUIVALENT = "ffc3c3"
# dec ebx: changed register and flag effects.
CALLEE_EFFECT = "4bc3"
# mov dword [esp+4], 0x2a; ret: extra caller-frame store, return slot intact.
CALLEE_STORE = "c74424042a000000 c3"
# mov dword [esp], 0x2a; ret: corrupts the return slot itself.
CALLEE_RET_CORRUPT = "c704242a000000 c3"
# test edx,edx instead of test ecx,ecx: changed loop guard predicate with the
# same graph shape, so the paired transition itself must fail to compare.
CALLER_GUARD = "85d2 7408 e804000000 49 ebf4 c3"
# callee calls its own entry: recursive.
CALLEE_RECURSIVE = "e8fbffffff c3"
# jmp $: cyclic callee body.
CALLEE_LOOP = "ebfe"
# callee calls a target outside every declared range.
CALLEE_UNDECLARED_CALL = "e810000000 c3"
# caller: test ecx,ecx; jz done; call ecx; dec ecx; jmp loop; done: ret
CALLER_INDIRECT = "85c9 7405 ffd1 49 ebf7 c3"
INDIRECT_SIZE = len(bytes.fromhex(CALLER_INDIRECT))
# hlt: unsupported jumpkind inside the callee.
CALLEE_HALT = "f4"


def _functions(base: int, callee_size: int) -> dict[int, int]:
    """Declared complete byte ranges for the caller/callee fixture."""
    return {base: CALLER_SIZE, base + CALLER_SIZE: callee_size}


def _compare_loop_calls(
    lane: DriverLane,
    oracle_code: str,
    candidate_code: str,
    *,
    oracle_functions: dict[int, int] | None = None,
    candidate_functions: dict[int, int] | None = None,
    limits: CallCompositionLimits | None = None,
    timeout_ms: int = 20000,
) -> dict[str, Any]:
    """Run the shared closed call-loop induction under this driver's seams."""
    oracle = _project(oracle_code, BASE)
    candidate = _project(candidate_code, BASE)
    with lane.adapter.installed(region=True):
        return compare_flat32_loop_calls(
            (oracle, candidate),
            (BASE, len(bytes.fromhex(oracle_code))),
            (BASE, len(bytes.fromhex(candidate_code))),
            lane.adapter.OUTPUT_REGS,
            timeout_ms,
            name="loop_call",
            oracle_functions=(
                oracle_functions or _functions(BASE, len(bytes.fromhex(CALLEE)))
            ),
            candidate_functions=(
                candidate_functions or _functions(BASE, len(bytes.fromhex(CALLEE)))
            ),
            limits=limits,
        )


def test_call_loop_induction_proves(lane: DriverLane) -> None:
    """A loop calling a complete mapped acyclic callee proves under both drivers."""
    result = _compare_loop_calls(lane, CODE, CODE)
    assert result["status"] is lane.verdict.Status.PASSED, result
    assert result["reason"] == "call_loop_induction", result
    assert result["oracle_inlined_calls"] == 1
    assert result["candidate_inlined_calls"] == 1
    assert result["return_targets_proved"] == 2
    assert result["graph_evidence"]["paired_cutpoints"] >= 2
    assert all(
        row["status"] is lane.verdict.Status.PASSED
        for row in result["block_verdicts"]
    )


def test_call_loop_equivalent_callee_encoding_proves(lane: DriverLane) -> None:
    """A different byte encoding with identical effects still proves."""
    candidate_code = f"{CALLER} {CALLEE_EQUIVALENT}"
    result = _compare_loop_calls(
        lane,
        CODE,
        candidate_code,
        candidate_functions=_functions(
            BASE, len(bytes.fromhex(CALLEE_EQUIVALENT))
        ),
    )
    assert result["status"] is lane.verdict.Status.PASSED, result
    assert result["reason"] == "call_loop_induction", result


@pytest.mark.parametrize(
    ("callee", "size"),
    [
        (CALLEE_EFFECT, 2),
        (CALLEE_STORE, 9),
    ],
    ids=["callee_effect", "callee_store"],
)
def test_changed_callee_rejected(
    lane: DriverLane, callee: str, size: int
) -> None:
    """A changed callee register effect or memory store must not prove."""
    result = _compare_loop_calls(
        lane,
        CODE,
        f"{CALLER} {callee}",
        candidate_functions=_functions(BASE, size),
    )
    assert result["status"] is lane.verdict.Status.REFUSED, result
    assert result["reason"] == "call_loop_transitions_unproved", result
    assert any(
        row["status"] is lane.verdict.Status.FAILED
        for row in result["block_verdicts"]
    ), result


def test_corrupted_return_slot_refuses(lane: DriverLane) -> None:
    """A callee store over the return slot fails the return-target proof."""
    result = _compare_loop_calls(
        lane,
        CODE,
        f"{CALLER} {CALLEE_RET_CORRUPT}",
        candidate_functions=_functions(
            BASE, len(bytes.fromhex(CALLEE_RET_CORRUPT))
        ),
    )
    assert result["status"] is lane.verdict.Status.REFUSED, result
    assert result["reason"] == "call_return_target_mismatch", result


def test_changed_loop_guard_rejected(lane: DriverLane) -> None:
    """A changed loop-guard predicate must not prove."""
    result = _compare_loop_calls(
        lane, CODE, f"{CALLER_GUARD} {CALLEE}"
    )
    assert result["status"] is lane.verdict.Status.REFUSED, result
    assert result["reason"] == "call_loop_transitions_unproved", result
    assert any(
        row["status"] is lane.verdict.Status.FAILED
        for row in result["block_verdicts"]
    ), result


@pytest.mark.parametrize(
    ("callee", "size", "reason_prefix"),
    [
        (CALLEE_RECURSIVE, 6, "recursive_call:"),
        (CALLEE_LOOP, 2, "loop_requires_inductive_proof"),
        (CALLEE_UNDECLARED_CALL, 6, "call_target_unmapped:"),
        (CALLEE_HALT, 1, "unsupported_jumpkind:"),
    ],
    ids=["recursive", "cyclic", "undeclared_target", "unsupported_jumpkind"],
)
def test_unproved_callee_refuses(
    lane: DriverLane, callee: str, size: int, reason_prefix: str
) -> None:
    """Recursive, cyclic, unmapped or unsupported callees refuse honestly."""
    result = _compare_loop_calls(
        lane,
        CODE,
        f"{CALLER} {callee}",
        candidate_functions=_functions(BASE, size),
    )
    assert result["status"] is lane.verdict.Status.REFUSED, result
    assert str(result["reason"]).startswith(reason_prefix), result


def test_indirect_call_refuses(lane: DriverLane) -> None:
    """An indirect call in the loop is never admitted as a transition."""
    code = CALLER_INDIRECT
    result = _compare_loop_calls(
        lane,
        code,
        code,
        oracle_functions={BASE: INDIRECT_SIZE},
        candidate_functions={BASE: INDIRECT_SIZE},
    )
    assert result["status"] is lane.verdict.Status.REFUSED, result
    assert result["reason"] == "call_indirect_target", result


def test_undeclared_callee_refuses(lane: DriverLane) -> None:
    """A call to bytes outside the declared complete ranges refuses."""
    result = _compare_loop_calls(
        lane,
        CODE,
        CODE,
        oracle_functions={BASE: CALLER_SIZE},
        candidate_functions={BASE: CALLER_SIZE},
    )
    assert result["status"] is lane.verdict.Status.REFUSED, result
    assert str(result["reason"]).startswith("call_target_unmapped:"), result


def test_inline_budget_exhaustion_refuses(lane: DriverLane) -> None:
    """An exhausted call-inline budget refuses before composing the callee."""
    result = _compare_loop_calls(
        lane,
        CODE,
        CODE,
        limits=CallCompositionLimits(max_inlined_calls=0),
    )
    assert result["status"] is lane.verdict.Status.REFUSED, result
    assert result["reason"] == "call_inline_budget", result


def test_retry_reaches_closed_call_loop_induction(lane: DriverLane) -> None:
    """The shared retry orders the call-loop lane after calls and reblocked CFG."""
    oracle_ranges = {
        "main": (BASE, CALLER_SIZE),
        "callee": (BASE + CALLER_SIZE, len(bytes.fromhex(CALLEE))),
    }
    candidate_ranges = {
        "main": (BASE, CALLER_SIZE),
        "callee": (BASE + CALLER_SIZE, len(bytes.fromhex(CALLEE))),
    }
    context = (
        _project(CODE, BASE),
        _project(CODE, BASE),
        oracle_ranges,
        candidate_ranges,
    )
    with lane.adapter.installed(region=True):
        result = retry_function_proof(
            "main",
            {"status": "refused", "reason": "call_or_exception_boundary"},
            context,
            lane.adapter.OUTPUT_REGS,
            20000,
        )
    assert result["status"] == "passed", result
    assert result["proof_method"] == "closed_call_loop_induction", result
    attempts = result["additional_proof_attempts"]
    assert attempts["calls"]["reason"] == "loop_requires_inductive_proof", result
    assert attempts["reblocked_cfg"]["reason"] == "call_or_exception_boundary", result
    assert attempts["call_loop"]["status"] == "passed", result
    assert "macro_step" not in attempts, result


@pytest.mark.parametrize("trips", [0, 1, 5], ids=["zero", "one", "many"])
def test_call_loop_replay_execution_controls(lane: DriverLane, trips: int) -> None:
    """Independent Unicorn replay agrees at zero, one and many loop trips.

    Concrete execution is evidence alongside the proof: it can never stand in
    for the closed induction and is asserted only over these three vectors.
    """
    image_code = bytes.fromhex(CODE)
    oracle = ReplayImage(
        ((0x10000, image_code),), (MemoryRange(0x10000, len(image_code)),)
    )
    equivalent = bytes.fromhex(f"{CALLER} {CALLEE_EQUIVALENT}")
    candidate = ReplayImage(
        ((0x10000, equivalent),), (MemoryRange(0x10000, len(equivalent)),)
    )
    vector = ReplayVector((("ecx", trips), ("ebx", 7), ("esp", 0x28000)))
    first = replay(oracle, 0x10000, vector, instruction_limit=200)
    second = replay(candidate, 0x10000, vector, instruction_limit=200)
    assert first.status is ReplayStatus.RETURNED, first
    assert second.status is ReplayStatus.RETURNED, second
    assert dict(first.registers)["ebx"] == 7 + trips, first
    assert dict(first.registers)["ecx"] == 0, first
    assert dict(second.registers)["ebx"] == 7 + trips, second
    assert dict(second.registers)["ecx"] == 0, second
    assert compare_replays(first, second).value == "agreed", (first, second)
