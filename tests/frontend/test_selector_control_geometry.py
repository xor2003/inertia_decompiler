"""Behavioral controls for the canonical near-transfer coordinate geometry.

Covers ``inertia.frontend.x86_16.control_transfer_geometry`` boundary
refusals and the IR binding helper
``inertia.ir.declared_selector_control_binding.check_bound_control_8616``
against synthetic exact-CFG cases. Geometry consumes native encoded bytes
only; control class comes from the canonical IR row op.
"""

from __future__ import annotations

import pytest

from inertia.frontend.x86_16.control_transfer_geometry import (
    ControlVerdict8616,
    check_block_fallthrough_8616,
    check_control_transfer_8616,
)
from inertia.ir.core import IRBlock, IRInstr
from inertia.ir.declared_selector_control_binding import check_bound_control_8616

pytestmark = pytest.mark.decompiler


def test_ip_relative_target_wraps_16bit_not_linear() -> None:
    """A near target wraps architectural IP inside its original CS."""
    # csbase 0x90000, instr at offset 0xfff0 size 3, disp +0x200.
    # naive linear: 0x9fff0+3+0x200 = 0xa01f3 (outside window, wrong);
    # wrapped IP: (0xfff0+3+0x200)&0xffff = 0x01f3 -> target 0x901f3.
    out = check_control_transfer_8616(addr=0x9FFF0, encoded=b"\xe9\x00\x02", known_cs=0x9000,
                 ir_op="JMP", successors=(0x901F3,), call_target=None,
                 census_addrs={0x901F3})
    assert out.verdict is ControlVerdict8616.CLOSED
    assert out.target == 0x901F3


def test_fetch_straddle_cs_end_and_a20_refuse() -> None:
    """An instruction cannot straddle the CS window or ambiguous A20 range."""
    straddle = check_control_transfer_8616(addr=0x9FFFE, encoded=b"\xe9\x00\x02", known_cs=0x9000,
                      ir_op="JMP", successors=(), call_target=None,
                      census_addrs=set())
    assert straddle.verdict is ControlVerdict8616.REFUSED
    assert straddle.detail == "fetch_outside_cs_window"
    a20 = check_control_transfer_8616(addr=0xFFFF0, encoded=b"\xeb\x40", known_cs=0xFFFF,
                 ir_op="JMP", successors=(), call_target=None,
                 census_addrs=set())
    assert a20.verdict is ControlVerdict8616.REFUSED
    assert a20.detail == "target_a20_ambiguous"


def test_missing_branch_target_or_fallthrough_refuses() -> None:
    """Both original conditional edges must survive coordinate binding."""
    # CJMP 0x74 +0x10 at 0x1200: target 0x1212, fallthrough 0x1202.
    missing_target = check_control_transfer_8616(addr=0x1200, encoded=b"\x74\x10", known_cs=0x100,
                            ir_op="CJMP", successors=(0x1202,),
                            call_target=None, census_addrs=set())
    assert missing_target.verdict is ControlVerdict8616.REFUSED
    missing_ft = check_control_transfer_8616(addr=0x1200, encoded=b"\x74\x10", known_cs=0x100,
                        ir_op="CJMP", successors=(0x1212,),
                        call_target=None, census_addrs=set())
    assert missing_ft.verdict is ControlVerdict8616.REFUSED
    closed = check_control_transfer_8616(addr=0x1200, encoded=b"\x74\x10", known_cs=0x100,
                    ir_op="CJMP", successors=(0x1212, 0x1202),
                    call_target=None, census_addrs=set())
    assert closed.verdict is ControlVerdict8616.CLOSED
    assert closed.fallthrough == 0x1202


def test_conditional_fallthrough_wraps_to_cs_zero() -> None:
    """The fallthrough arm wraps at the end of the CS window."""
    # 0x74 +5 in the last two CS bytes: next IP is 0x10000 -> wraps to
    # CS:0; the taken target wraps to CS:5. Both arms bind exactly.
    out = check_control_transfer_8616(addr=0x1FFFE, encoded=b"\x74\x05", known_cs=0x1000,
                 ir_op="CJMP", successors=(0x10005, 0x10000),
                 call_target=None, census_addrs={0x10005, 0x10000})
    assert out.verdict is ControlVerdict8616.CLOSED
    assert out.target == 0x10005 and out.fallthrough == 0x10000


def test_conditional_0f_form_binds_both_wrapped_arms() -> None:
    """The two-byte conditional form retains both wrapped coordinates."""
    # 0F 84 +0x10 at 0x2100: target 0x2114, fallthrough 0x2104.
    out = check_control_transfer_8616(addr=0x2100, encoded=b"\x0f\x84\x10\x00", known_cs=0x100,
                 ir_op="CJMP", successors=(0x2114, 0x2104),
                 call_target=None, census_addrs={0x2114, 0x2104})
    assert out.verdict is ControlVerdict8616.CLOSED
    assert out.target == 0x2114 and out.fallthrough == 0x2104


def test_unknown_guard_pending_terminal_needs_both_edges_retained() -> None:
    """Pending terminals cannot drop either possible fetched successor."""
    # successors=None: pending terminal; both candidates must be fetched.
    refused = check_control_transfer_8616(addr=0x1200, encoded=b"\x74\x10", known_cs=0x100,
                     ir_op="CJMP", successors=None, call_target=None,
                     census_addrs={0x1212})
    assert refused.verdict is ControlVerdict8616.REFUSED
    assert refused.detail == "edge_not_retained"
    closed = check_control_transfer_8616(addr=0x1200, encoded=b"\x74\x10", known_cs=0x100,
                    ir_op="CJMP", successors=None, call_target=None,
                    census_addrs={0x1212, 0x1202})
    assert closed.verdict is ControlVerdict8616.CLOSED


def test_call_target_pair_must_match_and_fallthrough_retained() -> None:
    """A direct call requires its mapped target and retained continuation."""
    ok = check_control_transfer_8616(addr=0x1D97, encoded=b"\xe8\x7a\xff", known_cs=0x1A2,
                ir_op="CALL", successors=(0x1D9A,), call_target=0x1D14,
                census_addrs={0x1D9A, 0x1D14})
    assert ok.verdict is ControlVerdict8616.CLOSED and ok.target == 0x1D14
    mismatch = check_control_transfer_8616(addr=0x1D97, encoded=b"\xe8\x7a\xff", known_cs=0x1A2,
                      ir_op="CALL", successors=(0x1D9A,), call_target=0x1D15,
                      census_addrs={0x1D9A})
    assert mismatch.verdict is ControlVerdict8616.REFUSED
    assert mismatch.detail == "call_target_mismatch"
    no_ft = check_control_transfer_8616(addr=0x1D97, encoded=b"\xe8\x7a\xff", known_cs=0x1A2,
                   ir_op="CALL", successors=(), call_target=0x1D14,
                   census_addrs=set())
    assert no_ft.verdict is ControlVerdict8616.REFUSED
    assert no_ft.detail == "call_fallthrough_unbound"


@pytest.mark.parametrize("op,encoded", [
    ("CALL", b"\x66\xe8\x7a\xff\x00"),       # operand32 call
    ("CALL", b"\x9a\x00\x20\x00\x10"),       # far call
    ("CALL", b"\xff\x1e\x00\x00"),           # indirect far call
    ("JMP", b"\xea\x00\x20\x00\x10"),        # far jmp
    ("JMP", b"\xff\x26\x00\x00"),            # indirect near jmp
    ("JMP", b"\x67\xe9\x00\x00"),            # addr32 prefix
    ("CJMP", b"\x0f\x34"),                   # sysenter bytes
    ("RET", b"\xcb"),                        # retf
    ("RET", b"\xcf"),                        # iret
    ("FOO", b"\x90"),                        # unsupported op lane
])
def test_far_indirect_system_and_32bit_refuse(op: str, encoded: bytes) -> None:
    """Unsupported transfer classes retain explicit refusal."""
    out = check_control_transfer_8616(addr=0x1200, encoded=encoded, known_cs=0x100, ir_op=op,
                 successors=(), call_target=None, census_addrs=set())
    assert out.verdict is ControlVerdict8616.REFUSED, (op, encoded, out)


def test_near_ret_is_cs_only_obligation_not_full_state() -> None:
    """A near return never proves its stack frame or return offset."""
    out = check_control_transfer_8616(addr=0x1200, encoded=b"\xc3", known_cs=0x100, ir_op="RET",
                 successors=(), call_target=None, census_addrs=set())
    assert out.verdict is ControlVerdict8616.RETURN_OBLIGATION
    assert out.verdict is not ControlVerdict8616.CLOSED
    imm = check_control_transfer_8616(addr=0x1200, encoded=b"\xc2\x04\x00", known_cs=0x100,
                 ir_op="RET", successors=(), call_target=None,
                 census_addrs=set())
    assert imm.verdict is ControlVerdict8616.RETURN_OBLIGATION


def test_implicit_block_fallthrough_requires_exact_end() -> None:
    """An ordinary terminal requires its exact original fallthrough edge."""
    ok = check_block_fallthrough_8616(last_addr=0x1200, last_size=2,
                                    successors=(0x1202,), known_cs=0x100,
                                    census_addrs={0x1202})
    assert ok.verdict is ControlVerdict8616.CLOSED and ok.fallthrough == 0x1202
    bad = check_block_fallthrough_8616(last_addr=0x1200, last_size=2,
                                       successors=(0x1203,), known_cs=0x100,
                                       census_addrs={0x1203})
    assert bad.verdict is ControlVerdict8616.REFUSED
    extra = check_block_fallthrough_8616(last_addr=0x1200, last_size=2,
                                         successors=(0x1202, 0x1204),
                                         known_cs=0x100,
                                         census_addrs={0x1202, 0x1204})
    assert extra.verdict is ControlVerdict8616.REFUSED


def test_implicit_fallthrough_wraps_to_cs_zero() -> None:
    """An implicit fallthrough wraps architectural IP at the window end."""
    # A 1-byte non-control instruction in the last CS byte: the wrapped
    # architectural end (CS:0) must be the exact claimed edge.
    out = check_block_fallthrough_8616(
        last_addr=0x1FFFF, last_size=1, successors=(0x10000,),
        census_addrs={0x10000}, known_cs=0x1000)
    assert out.verdict is ControlVerdict8616.CLOSED
    assert out.fallthrough == 0x10000


def test_conditional_cannot_accept_linear_fallthrough_past_ip_wrap() -> None:
    """Both Jcc successors must use the architectural wrapped IP."""
    base = 0x1000
    row = check_control_transfer_8616(addr=base + 0xFFFE, encoded=b"\x75\x00",
        known_cs=0x100, ir_op="CJMP", successors=(base, base + 0x10000),
        call_target=None, census_addrs=frozenset({base, base + 0x10000}))
    assert row.verdict is ControlVerdict8616.REFUSED


def test_implicit_fallthrough_cannot_accept_linear_ip_overflow() -> None:
    """A native last-byte NOP falls through to CS:0."""
    base = 0x1000
    row = check_block_fallthrough_8616(last_addr=base + 0xFFFF, last_size=1,
        known_cs=0x100, successors=(base + 0x10000,),
        census_addrs=frozenset({base + 0x10000}))
    assert row.verdict is ControlVerdict8616.REFUSED


def test_fallthrough_a20_ambiguity_refuses() -> None:
    """A safe taken branch cannot authorize an A20-ambiguous fallthrough."""
    addr = 0xFFFFE
    row = check_control_transfer_8616(addr=addr, encoded=b"\x75\xfe",
        known_cs=0xFFFF, ir_op="CJMP", successors=(addr, 0x100000),
        call_target=None, census_addrs=frozenset({addr, 0x100000}))
    assert row.verdict is ControlVerdict8616.REFUSED


def test_zero_length_instruction_is_not_fetch_evidence() -> None:
    """An empty span cannot certify a native instruction."""
    row = check_block_fallthrough_8616(last_addr=0x100, last_size=0,
        known_cs=0x10, successors=(0x100,), census_addrs=frozenset({0x100}))
    assert row.verdict is ControlVerdict8616.REFUSED


def test_locked_branch_is_not_assumed_nonfaulting() -> None:
    """LOCK on a branch cannot silently inherit ordinary near geometry."""
    row = check_control_transfer_8616(addr=0x110, encoded=b"\xf0\x75\x00",
        known_cs=0x10, ir_op="CJMP", successors=(0x113,),
        call_target=None, census_addrs=frozenset({0x113}))
    assert row.verdict is ControlVerdict8616.REFUSED


def _instr(op: str, addr: int) -> IRInstr:
    """One minimal typed IR row for binding-helper controls."""
    return IRInstr(op, None, (), addr=addr)


def test_bound_call_requires_exact_original_continuation() -> None:
    """The bound CALL keeps its mapped target only with the exact CFG edge."""
    instr = _instr("CALL", 0x1D97)
    closed = check_bound_control_8616(
        IRBlock(0x1D97, (instr,), successor_addrs=(0x1D9A,)),
        instr, b"\xe8\x7a\xff", 0x1A2, 0x1D14, {0x1D9A, 0x1D14})
    assert closed.verdict is ControlVerdict8616.CLOSED
    assert closed.target == 0x1D14 and closed.fallthrough == 0x1D9A
    dropped = check_bound_control_8616(
        IRBlock(0x1D97, (instr,), successor_addrs=()),
        instr, b"\xe8\x7a\xff", 0x1A2, 0x1D14, {0x1D9A, 0x1D14})
    assert dropped.verdict is ControlVerdict8616.REFUSED
    assert dropped.detail == "call_continuation_cfg_mismatch"


def test_bound_ret_never_gains_a_cfg_successor() -> None:
    """A near RET stays an obligation and any claimed edge refuses."""
    instr = _instr("RET", 0x1200)
    obligation = check_bound_control_8616(
        IRBlock(0x1200, (instr,)), instr, b"\xc3", 0x100, None, {0x1200})
    assert obligation.verdict is ControlVerdict8616.RETURN_OBLIGATION
    claimed = check_bound_control_8616(
        IRBlock(0x1200, (instr,), successor_addrs=(0x1201,)),
        instr, b"\xc3", 0x100, None, {0x1200, 0x1201})
    assert claimed.verdict is ControlVerdict8616.REFUSED
    assert claimed.detail == "return_has_cfg_successor"


def test_bound_jmp_edge_must_be_retained() -> None:
    """A bound JMP whose exact CFG target left the census refuses."""
    instr = _instr("JMP", 0x9FFF0)
    closed = check_bound_control_8616(
        IRBlock(0x9FFF0, (instr,), successor_addrs=(0x901F3,)),
        instr, b"\xe9\x00\x02", 0x9000, None, {0x901F3})
    assert closed.verdict is ControlVerdict8616.CLOSED
    dropped = check_bound_control_8616(
        IRBlock(0x9FFF0, (instr,), successor_addrs=(0x901F3,)),
        instr, b"\xe9\x00\x02", 0x9000, None, set())
    assert dropped.verdict is ControlVerdict8616.REFUSED
    assert dropped.detail == "edge_not_retained"
