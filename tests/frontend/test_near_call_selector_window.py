"""Controls for the conditional near-CALL selector window projection.

Real 16-bit Capstone decodings supply row/index fixtures; the canonical
premise owner re-proves every input. The production fetch/control gates
cross-check admitted and refused selectors, and Z3 verifies each accepted
interval against real 16-bit IP arithmetic under an arbitrary selector.
"""

from __future__ import annotations

from dataclasses import replace

import capstone
import pytest
import z3

import inertia.frontend.x86_16.near_call_selector_window as nsw
from inertia.frontend.x86_16.control_transfer_geometry import (
    ControlVerdict8616,
    check_control_transfer_8616,
)
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
)
from inertia.frontend.x86_16.frontend_near_return_continuation import (
    prove_near_call_frame_premise_8616,
)
from inertia.frontend.x86_16.instruction_fetch_geometry import (
    FetchVerdict8616,
    check_instruction_fetch_8616,
)

_WORD = 0x10000
_CALL_SIZE = 3
_FAILURE = nsw.NearCallSelectorWindowFailure8616

pytestmark = pytest.mark.decompiler


def _decode(code: bytes, address: int) -> object:
    """Decode one real 16-bit instruction for a callsite row."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
    decoder.detail = True
    (instruction,) = tuple(decoder.disasm(code, address))
    return instruction


def _call_encoding(callsite_addr: int, target_addr: int) -> bytes:
    """Compute the exact ``E8`` word bytes from coordinates, never guessed."""
    return b"\xe8" + (
        (target_addr - (callsite_addr + _CALL_SIZE)) & 0xFFFF
    ).to_bytes(2, "little")


def _row(code: bytes, callsite_addr: int, target_addr: int) -> DecodedDirectCallsite8616:
    """Retain one real decoded instruction as a callsite row."""
    return DecodedDirectCallsite8616(
        caller_start=callsite_addr,
        instructions=(_decode(code, callsite_addr),),
        instruction_index=0,
        callsite_addr=callsite_addr,
        target_addr=target_addr,
    )


def _index(
    row: DecodedDirectCallsite8616, target_addr: int, *, closed: bool = True
) -> DecodedDirectCallsiteIndex8616:
    """Retain one row under its normalized near-target key."""
    stats = DecodedDirectCallsiteIndexStats8616(
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1 if closed else 0,
        materialized_count=1 if closed else 0,
        failure_count=0,
    )
    return DecodedDirectCallsiteIndex8616({target_addr & 0xFFFF: (row,)}, stats)


def _premise(
    callsite_addr: int, target_addr: int
) -> nsw.NearCallFramePremise8616:
    """Prove the canonical source-bound premise for one near-CALL row."""
    code = _call_encoding(callsite_addr, target_addr)
    row = _row(code, callsite_addr, target_addr)
    premise = prove_near_call_frame_premise_8616(
        row, _index(row, target_addr), target_addr
    )
    assert premise is not None
    return premise


def _window(
    callsite_addr: int, target_addr: int
) -> nsw.NearCallSelectorWindow8616:
    """Project the selector window for one proven premise."""
    projection = nsw.project_near_call_selector_window_8616(
        _premise(callsite_addr, target_addr)
    )
    assert type(projection) is nsw.NearCallSelectorWindow8616
    return projection


def _fetch_verdict(callsite_addr: int, target_addr: int, selector: int) -> FetchVerdict8616:
    """Ask the production fetch gate for one selector's verdict."""
    return check_instruction_fetch_8616(
        callsite_addr, _call_encoding(callsite_addr, target_addr), selector
    ).verdict


def test_bitnbr_caller_window_bounds() -> None:
    """The BITNBR startup caller 0x1b78 -> main 0x1d43 window is [0, 0x1B7]."""
    window = _window(0x1B78, 0x1D43)
    assert (window.selector_low, window.selector_high) == (0, 0x1B7)
    assert window.callsite_addr == 0x1B78
    assert window.next_addr == 0x1B7B
    assert window.target_addr == 0x1D43 == window.callee_addr
    assert window.cs_preservation_required
    assert window.premise.callee_addr == 0x1D43
    # If CS is preserved, every admitted selector permits main's inner
    # CALL 0x1d97 -> 0x1d12 (its destination lies in every window).
    assert window.admits_linear_destination(0x1D12)
    assert not window.admits_linear_destination(0x10000)
    assert not window.admits_linear_destination(0x1B6F)
    assert not window.admits_linear_destination("0x1d12")


def test_bitnbr_inner_call_gate_agrees_with_window() -> None:
    """The production control gate binds the inner CALL only inside the window."""
    inner_addr, inner_target = 0x1D97, 0x1D12
    code = _call_encoding(inner_addr, inner_target)
    census = {inner_addr + _CALL_SIZE, inner_target}
    inside = check_control_transfer_8616(
        addr=inner_addr, encoded=code, known_cs=0x1B7, ir_op="CALL",
        successors=None, call_target=inner_target, census_addrs=census,
    )
    assert inside.verdict is ControlVerdict8616.CLOSED
    assert inside.target == inner_target
    # The head-only gate's selector CS=0x1d9 (above the retained window)
    # decodes the inner call to linear 0x11D12 and correctly refuses.
    outside = check_control_transfer_8616(
        addr=inner_addr, encoded=code, known_cs=0x1D9, ir_op="CALL",
        successors=None, call_target=inner_target, census_addrs=census,
    )
    assert outside.verdict is ControlVerdict8616.REFUSED
    assert outside.detail == "call_target_mismatch"
    assert (0x1D9 << 4) + ((inner_target - (0x1D9 << 4)) & 0xFFFF) == 0x11D12


def test_window_edges_match_production_fetch_gate() -> None:
    """Every retained selector fetches; the adjacent outside ones refuse."""
    callsite_addr, target_addr = 0x1B78, 0x1D43
    window = _window(callsite_addr, target_addr)
    for selector in (window.selector_low, (window.selector_low + window.selector_high) // 2, window.selector_high):
        assert _fetch_verdict(callsite_addr, target_addr, selector) is FetchVerdict8616.CLOSED
    assert _fetch_verdict(callsite_addr, target_addr, window.selector_high + 1) is FetchVerdict8616.REFUSED


def test_exact_bound_extremes() -> None:
    """Boundary selectors quantize to paragraph edges exactly."""
    # callsite just above a 64 KiB boundary: window excludes selectors
    # whose CS window cannot hold the final byte.
    window = _window(0x10000, 0x10003 - 1)
    assert (window.selector_low, window.selector_high) == (1, 0x1000)
    # Fetch legality ends exactly one byte below 1 MiB.
    high = _window(0xFFFFC, 0xFFFFF)
    assert (high.selector_low, high.selector_high) == (0xF000, 0xFFFF)
    assert _fetch_verdict(0xFFFFC, 0xFFFFF, 0xFFFF) is FetchVerdict8616.CLOSED
    # One byte further cannot fetch under any selector: A20 refusal.
    projection = nsw.project_near_call_selector_window_8616(_premise(0xFFFFE, 0xFFFFF))
    assert type(projection) is nsw.NearCallSelectorWindowRefusal8616
    assert projection.failure is _FAILURE.FETCH_A20_AMBIGUOUS


def test_instruction_end_straddle_excludes_selector() -> None:
    """A selector whose CS window clips the instruction end is excluded."""
    callsite_addr, target_addr = 0x2FFFE, 0x30000
    window = _window(callsite_addr, target_addr)
    # CS=0x2000's window ends at 0x30000, before the third byte 0x30000.
    assert window.selector_low == 0x2001
    assert _fetch_verdict(callsite_addr, target_addr, 0x2000) is FetchVerdict8616.REFUSED
    assert _fetch_verdict(callsite_addr, target_addr, 0x2001) is FetchVerdict8616.CLOSED


def test_target_not_window_invariant_refuses() -> None:
    """A destination that wraps under some admitted selector refuses."""
    # Forward: the raw target exceeds what selector 0's window can hold.
    projection = nsw.project_near_call_selector_window_8616(
        _premise(0x9000, 0x10FFF)
    )
    assert type(projection) is nsw.NearCallSelectorWindowRefusal8616
    assert projection.failure is _FAILURE.TARGET_NOT_WINDOW_INVARIANT
    # Backward: the raw target sits below the largest admitted CS base.
    projection = nsw.project_near_call_selector_window_8616(
        _premise(0x14000, 0xC003)
    )
    assert type(projection) is nsw.NearCallSelectorWindowRefusal8616
    assert projection.failure is _FAILURE.TARGET_NOT_WINDOW_INVARIANT


def test_negative_raw_destination_refuses() -> None:
    """The raw decoded destination, not the bound callee, faces A20/domain."""
    code = b"\xe8\x00\x80"  # signed disp -0x8000 from next_addr 0x103
    instruction = _decode(code, 0x100)
    assert instruction.operands[0].imm & 0xFFFF == 0x8103  # 16-bit wrap
    row = DecodedDirectCallsite8616(
        caller_start=0x100,
        instructions=(instruction,),
        instruction_index=0,
        callsite_addr=0x100,
        target_addr=0x8103,
    )
    premise = prove_near_call_frame_premise_8616(row, _index(row, 0x8103), 0x8103)
    assert premise is not None
    projection = nsw.project_near_call_selector_window_8616(premise)
    assert type(projection) is nsw.NearCallSelectorWindowRefusal8616
    assert projection.failure is _FAILURE.TARGET_A20_AMBIGUOUS


def test_forged_coordinates_refuse() -> None:
    """A premise whose retained coordinates differ from its row refuses."""
    premise = _premise(0x1B78, 0x1D43)
    for field_name in ("callsite_addr", "caller_start", "return_addr"):
        forged = replace(premise, **{field_name: getattr(premise, field_name) + 1})
        projection = nsw.project_near_call_selector_window_8616(forged)
        assert type(projection) is nsw.NearCallSelectorWindowRefusal8616
        assert projection.failure is _FAILURE.PREMISE_COORDINATE_FORGERY
    forged = replace(premise, callee_addr=0x1D44)
    projection = nsw.project_near_call_selector_window_8616(forged)
    assert type(projection) is nsw.NearCallSelectorWindowRefusal8616
    assert projection.failure is _FAILURE.PREMISE_REPROOF_FAILED


def test_foreign_row_and_open_census_refuse() -> None:
    """An unindexed twin row or an open index revokes the premise's authority."""
    callsite_addr, target_addr = 0x1B78, 0x1D43
    premise = _premise(callsite_addr, target_addr)
    code = _call_encoding(callsite_addr, target_addr)
    twin = _row(code, callsite_addr, target_addr)  # equal data, foreign object
    foreign = replace(premise, callsite=twin)
    projection = nsw.project_near_call_selector_window_8616(foreign)
    assert type(projection) is nsw.NearCallSelectorWindowRefusal8616
    assert projection.failure is _FAILURE.PREMISE_REPROOF_FAILED
    row = _row(code, callsite_addr, target_addr)
    open_index = _index(row, target_addr, closed=False)
    stale = replace(premise, callsite=row, callsite_index=open_index)
    projection = nsw.project_near_call_selector_window_8616(stale)
    assert type(projection) is nsw.NearCallSelectorWindowRefusal8616
    assert projection.failure is _FAILURE.PREMISE_REPROOF_FAILED


def test_prefixed_near_form_refuses() -> None:
    """A REP-prefixed word CALL keeps its premise but no window."""
    callsite_addr, target_addr = 0x1B78, 0x1D44  # prefix counts in size
    code = b"\xf3\xe8" + (
        (target_addr - (callsite_addr + 4)) & 0xFFFF
    ).to_bytes(2, "little")
    row = _row(code, callsite_addr, target_addr)
    instruction = row.instructions[0]
    assert instruction.size == 4 and instruction.mnemonic == "call"
    assert instruction.operands[0].imm == target_addr
    premise = prove_near_call_frame_premise_8616(
        row, _index(row, target_addr), target_addr
    )
    assert premise is not None  # still a word-width push
    projection = nsw.project_near_call_selector_window_8616(premise)
    assert type(projection) is nsw.NearCallSelectorWindowRefusal8616
    assert projection.failure is _FAILURE.UNSUPPORTED_NEAR_FORM


def test_wide_66_e8_row_fails_premise_reproof() -> None:
    """A 66 E8 dword-push row swapped into a premise fails reproof."""
    callsite_addr, target_addr = 0x1B78, 0x1D43
    premise = _premise(callsite_addr, target_addr)
    wide = _row(
        b"\x66\xe8" + b"\x00" * 4, callsite_addr, target_addr
    )
    forged = replace(premise, callsite=wide)
    projection = nsw.project_near_call_selector_window_8616(forged)
    assert type(projection) is nsw.NearCallSelectorWindowRefusal8616
    assert projection.failure is _FAILURE.PREMISE_REPROOF_FAILED


def test_non_premise_input_refuses() -> None:
    """Untyped or wrong-kind input never yields a window."""
    projection = nsw.project_near_call_selector_window_8616(object())
    assert type(projection) is nsw.NearCallSelectorWindowRefusal8616
    assert projection.failure is _FAILURE.PREMISE_ABSENT


def test_z3_verifies_accepted_interval() -> None:
    """Z3 proves the interval exactly characterizes legal invariant fetches."""
    callsite_addr, target_addr = 0x1B78, 0x1D43
    window = _window(callsite_addr, target_addr)
    size = _CALL_SIZE
    next_addr = callsite_addr + size
    disp = target_addr - next_addr
    s = z3.Int("s")
    base = s * 16
    fetch_ok = z3.And(
        base <= callsite_addr,
        callsite_addr + size <= base + _WORD,
        callsite_addr + size <= 0x100000,
    )
    decoded = base + ((next_addr - base + disp) % _WORD)
    inside = z3.And(window.selector_low <= s, s <= window.selector_high)
    domain = z3.And(s >= 0, s <= 0xFFFF)
    # Every admitted selector fetches legally and decodes the same target.
    solver = z3.Solver()
    solver.add(z3.Not(z3.Implies(inside, z3.And(fetch_ok, decoded == target_addr))))
    assert solver.check() == z3.unsat
    # No selector outside the interval both fetches and hits the target.
    solver.reset()
    solver.add(domain, z3.Not(inside), fetch_ok, decoded == target_addr)
    assert solver.check() == z3.unsat


def test_z3_verifies_destination_membership() -> None:
    """Z3 agrees with admits_linear_destination under arbitrary selectors."""
    window = _window(0x1B78, 0x1D43)
    s = z3.Int("s")
    inside = z3.And(window.selector_low <= s, s <= window.selector_high)
    for destination in (0x1D12, 0x1B70, 0xFFFF, 0x10000, 0x1B6F, 0, 0x11D12):
        solver = z3.Solver()
        # Counterexample selector: in-window but destination out of reach.
        solver.add(
            inside, z3.Or(destination - s * 16 < 0, destination - s * 16 > 0xFFFF)
        )
        expected = solver.check() == z3.unsat
        assert window.admits_linear_destination(destination) is expected
