"""Focused M5 slice tests: matching processor-fault outcomes on native bytes.

Every case builds actual MZ or PE32 serialized bytes and declared
environments, traces lanes with ``symbolic_terminal``, and checks typed
verdicts. The admitted fault scope is the divide-error exception (#DE,
vector 0) of decoded ``DIV``/``IDIV``/zero-``AAM`` instructions, decided at
intake against the complete architectural fault condition — including the
quotient-overflow case the flat32 VEX guest does not guard. A fault is a
nonreturning stop: no IVT/IDT handler dispatch is modeled, the outcome is
never conflated with a declared process exit, and the post-fault normal
path is never lowered or compared.
"""

from __future__ import annotations

import struct
from dataclasses import replace

import pytest
from test_symbolic_terminal import (
    ENTRY,
    STACK,
    compare_mz,
    compare_pe,
    dos_environment,
    exit_code,
    mz,
    pe32_bytes,
    pe_environment,
)

from tools.dosunit import straightline_ssa as S
from tools.dosunit import symbolic_terminal as ST
from tools.dosunit.proof_public_domain import OutcomeAdmission
from tools.dosunit.terminal_fault import FaultGate, _guard_divisor

# ---------------------------------------------------------------------------
# Real16 (MZ) divide-error fault outcomes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flat32", [False, True], ids=["mz16", "pe32"])
def test_x87_self_comparison_refuses_unmodeled_state(flat32: bool) -> None:
    """FLD1 before a declared exit cannot prove equality in the integer model."""
    code = exit_code(prefix=bytes.fromhex("d9e8")) if flat32 else bytes.fromhex("d9e8b8004ccd21")
    result = (compare_pe if flat32 else compare_mz)(code, code)
    assert result.status is ST.TerminalComparisonStatus.REFUSED
    for lane in (result.oracle, result.candidate):
        assert lane.trace is None
        assert lane.refusal is not None
        assert lane.refusal.kind is ST.TerminalRefusalKind.INSTRUCTION_SCOPE


def test_mz_div_zero_fault_is_typed_outcome_not_exit() -> None:
    """``xor cx,cx; div cl`` stops on #DE — a CPU fault, never DOS exit."""
    trace = ST.trace_real16_terminal(mz(bytes.fromhex("31c9f6f1")), dos_environment())
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    assert trace.event_kind.name == "CPU_FAULT"
    assert trace.service is ST.TerminalService.DOS_TERMINATE
    assert trace.site is None
    assert trace.fault is not None
    assert trace.fault.kind.name == "DIVIDE_ERROR"
    assert trace.fault.vector == 0
    assert trace.fault.reason == "zero_divisor"
    assert trace.fault.encoding == bytes.fromhex("f6f1")
    assert trace.fault.site_address - trace.entry == 2
    assert trace.document["outputs"]["terminal_payload"] == {
        "op": "const",
        "value": "0x0",
        "width": 32,
    }
    assert "memory" in trace.document["outputs"]
    kinds = {premise.get("kind") for premise in trace.premises}
    assert "exception_scope" in kinds
    assert "terminal_service_contract" not in kinds


def test_mz_idiv_zero_fault() -> None:
    """``idiv cl`` with a zero divisor is the same admitted #DE outcome."""
    trace = ST.trace_real16_terminal(mz(bytes.fromhex("f6f9")), dos_environment())
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    assert trace.fault is not None and trace.fault.vector == 0


def test_mz_aam_zero_fault() -> None:
    """``aam 0`` divides by zero — a #DE decided from the decoded encoding."""
    trace = ST.trace_real16_terminal(mz(bytes.fromhex("d400")), dos_environment())
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    assert trace.fault is not None
    assert trace.fault.reason == "zero_divisor"
    assert trace.fault.encoding == bytes.fromhex("d400")


def test_mz_fault_self_equivalent() -> None:
    """Identical divide-error programs compare EQUIVALENT on the fault."""
    result = compare_mz(bytes.fromhex("31c9f6f1"), bytes.fromhex("31c9f6f1"))
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    for lane in (result.oracle, result.candidate):
        assert lane.trace is not None
        assert lane.trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    assert result.environment_model().faults is OutcomeAdmission.COMPARED
    assert any(
        premise.get("kind") == "joint_premise"
        and premise.get("outcome") == "processor_fault"
        for premise in result.assumptions
    )
    assert any(
        premise.get("kind") == "fault_site_relation"
        and premise.get("relation") == "entry_relative_instruction_offset"
        for premise in result.assumptions
    )


def test_mz_fault_changed_equivalent() -> None:
    """Reordered non-faulting prefixes with equal effects prove EQUIVALENT."""
    oracle = bytes.fromhex("31c9bb0500f6f1")   # xor cx,cx; mov bx,5; div cl
    candidate = bytes.fromhex("bb050031c9f6f1")  # mov bx,5; xor cx,cx; div cl
    result = compare_mz(oracle, candidate)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT


def test_mz_normal_vs_fault_is_counterexample() -> None:
    """A declared exit and a processor fault are different terminal events."""
    result = compare_mz(bytes.fromhex("b8074ccd21"), bytes.fromhex("31c9f6f1"))
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "terminal_outcome" in result.diverged
    assert result.environment_model().faults is OutcomeAdmission.NOT_ESTABLISHED


def test_mz_wrong_fault_site_is_counterexample() -> None:
    """A fault at a different instruction-stream offset diverges on the site."""
    result = compare_mz(bytes.fromhex("31c9f6f1"), bytes.fromhex("31c990f6f1"))
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "fault_site" in result.diverged


def test_mz_fault_extra_register_effect() -> None:
    """A differing prefix register effect diverges on that register."""
    result = compare_mz(
        bytes.fromhex("31c9bb0500f6f1"),  # mov bx,5 before div
        bytes.fromhex("31c9ba0500f6f1"),  # mov dx,5 before div
    )
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert {"bx", "dx"}.intersection(result.diverged)


def test_mz_fault_memory_divergence() -> None:
    """A differing prefix byte store diverges on the memory output."""
    result = compare_mz(
        bytes.fromhex("31c9c606001204f6f1"),
        bytes.fromhex("31c9c606001205f6f1"),
    )
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "memory" in result.diverged


def test_mz_fault_prefix_code_write_still_refused() -> None:
    """A store onto declared code before the fault stays a refusal."""
    result = compare_mz(
        bytes.fromhex("31c9c606000104f6f1"), bytes.fromhex("31c9c606000104f6f1")
    )
    assert result.status is ST.TerminalComparisonStatus.REFUSED
    assert "code_write" in result.detail


def test_mz_quotient_overflow_fault() -> None:
    """``div cl`` overflowing the 8-bit quotient is the admitted #DE outcome."""
    trace = ST.trace_real16_terminal(mz(bytes.fromhex("b8ffffb101f6f1")), dos_environment())
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    assert trace.fault is not None
    assert trace.fault.reason == "quotient_out_of_range"


def test_mz_overflow_fault_equivalent_and_corruption() -> None:
    """Equal overflow faults prove equal; overflow versus exit diverges."""
    faulting = bytes.fromhex("b8ffffb101f6f1")
    result = compare_mz(faulting, faulting)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    normal = bytes.fromhex("b80400b102f6f1b8074ccd21")  # ax=4,cl=2: no fault
    result = compare_mz(faulting, normal)
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "terminal_outcome" in result.diverged


def test_mz_zero_divisor_with_unproved_dividend() -> None:
    """A proved-zero divisor decides #DE alone — the dividend need not resolve.

    ``mov [0x1100],5; mov al,[0x1100]`` leaves ``AX`` reading through a
    store chain, so the dividend is unprovable; ``div cl`` still faults
    because ``cl == 0`` is decided under the declared state.
    """
    trace = ST.trace_real16_terminal(
        mz(bytes.fromhex("c606001105a0001131c9f6f1")), dos_environment()
    )
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    assert trace.fault is not None
    assert trace.fault.reason == "zero_divisor"
    assert trace.fault.site_address - trace.entry == 0xA


def test_mz_divisor_undeclared_read_refused() -> None:
    """A divisor load outside declared readable memory is never admitted."""
    result = compare_mz(
        bytes.fromhex("31c9f63600f0"), bytes.fromhex("31c9f63600f0")
    )
    assert result.status is ST.TerminalComparisonStatus.REFUSED
    assert "undeclared_read" in result.detail


def test_mz_fault_divisor_read_still_audited() -> None:
    """The divisor's initial-memory read is recorded even when it faults.

    ``div word [0x0101]`` reads the two zero bytes of ``mov bx,0``'s
    immediate inside the declared image — a proved zero divisor whose read
    sites remain obligations of the shared-initial-data relation.
    """
    trace = ST.trace_real16_terminal(
        mz(bytes.fromhex("bb0000f7360101")), dos_environment()
    )
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    sites = {(site.address, site.size) for site in trace.initial_read_sites}
    assert (0x10101, 1) in sites and (0x10102, 1) in sites


def test_mz_fault_unknown_guard_refused() -> None:
    """A divisor through a store chain cannot be proved — typed refusal."""
    result = compare_mz(
        bytes.fromhex("c606001200f6360012"), bytes.fromhex("c606001200f6360012")
    )
    assert result.status is ST.TerminalComparisonStatus.REFUSED
    assert "fault_guard_unproved" in result.detail


def test_mz_fault_dead_read_still_accounted() -> None:
    """A discarded initial-memory read before the fault remains a read site."""
    trace = ST.trace_real16_terminal(
        mz(bytes.fromhex("a1001031c031c9f6f1")), dos_environment()
    )
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    assert any(site.address == 0x11000 for site in trace.initial_read_sites)


def test_mz_fault_preempts_later_service_boundary() -> None:
    """Trailing bytes after the fault — even an exit — are never executed."""
    trace = ST.trace_real16_terminal(
        mz(bytes.fromhex("31c9f6f1b8074ccd21")), dos_environment()
    )
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    assert trace.site is None
    # The int 21h is inside the same lifted block but beyond the fault:
    # its service payload is never materialized.
    assert trace.document["outputs"]["terminal_payload"]["value"] == "0x0"


def test_mz_post_fault_writes_not_compared() -> None:
    """Different unexecuted bytes after equal faults cannot diverge."""
    result = compare_mz(
        bytes.fromhex("31c9f6f1bb0500"),  # mov bx,5 after the fault
        bytes.fromhex("31c9f6f1ba0500"),  # mov dx,5 after the fault
    )
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT


def test_mz_fault_stale_evidence_refused() -> None:
    """A fault trace re-verified against mutated bytes refuses."""
    trace = ST.trace_real16_terminal(mz(bytes.fromhex("31c9f6f1")), dos_environment())
    stale = replace(trace, source=mz(bytes.fromhex("31c9f7f1")))
    refusal = ST.verify_terminal_trace(stale)
    assert refusal is not None
    assert refusal.kind is ST.TerminalRefusalKind.STALE_EVIDENCE
    assert ST.verify_terminal_trace(trace) is None


def test_mz_fault_exhausted_budget_refused() -> None:
    """A zero block budget refuses before any lane outcome is trusted."""
    result = ST.compare_symbolic_terminals(
        mz(bytes.fromhex("31c9f6f1")),
        dos_environment(),
        mz(bytes.fromhex("31c9f6f1")),
        dos_environment(),
        limits=ST.TerminalLimits(max_blocks=0),
    )
    assert result.status is ST.TerminalComparisonStatus.REFUSED
    assert "block_limit" in result.detail


def test_mz_unadmitted_signal_kind_refused() -> None:
    """``into`` traps through a different signal vector — outside #DE scope."""
    result = compare_mz(bytes.fromhex("ce"), bytes.fromhex("ce"))
    assert result.status is ST.TerminalComparisonStatus.REFUSED


# ---------------------------------------------------------------------------
# Flat32 (PE32) divide-error fault outcomes
# ---------------------------------------------------------------------------


def test_pe_div_zero_fault_is_typed_outcome_not_exit() -> None:
    """``xor ebx,ebx; div ebx`` stops on #DE — a CPU fault, never PE exit."""
    trace = ST.trace_flat32_terminal(pe32_bytes(b"\x31\xdb\xf7\xf3"), pe_environment())
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    assert trace.event_kind.name == "CPU_FAULT"
    assert trace.service is ST.TerminalService.PE_DECLARED_EXIT
    assert trace.site is None
    assert trace.fault is not None
    assert trace.fault.kind.name == "DIVIDE_ERROR"
    assert trace.fault.vector == 0
    assert trace.fault.reason == "zero_divisor"
    assert trace.fault.encoding == b"\xf7\xf3"
    assert trace.fault.site_address - trace.entry == 2
    assert trace.document["outputs"]["terminal_payload"]["value"] == "0x0"
    assert "memory" in trace.document["outputs"]


def test_pe_fault_self_equivalent() -> None:
    """Identical divide-error programs compare EQUIVALENT on the fault."""
    result = compare_pe(b"\x31\xdb\xf7\xf3", b"\x31\xdb\xf7\xf3")
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    assert result.environment_model().faults is OutcomeAdmission.COMPARED


def test_pe_fault_changed_equivalent() -> None:
    """Reordered non-faulting prefixes with equal effects prove EQUIVALENT."""
    oracle = b"\x31\xdb\xb9\x05\x00\x00\x00\xf7\xf3"    # xor ebx,ebx; mov ecx,5; div ebx
    candidate = b"\xb9\x05\x00\x00\x00\x31\xdb\xf7\xf3"  # mov ecx,5; xor ebx,ebx; div ebx
    result = compare_pe(oracle, candidate)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT


def test_pe_normal_vs_fault_is_counterexample() -> None:
    """A declared gateway exit and a processor fault are different events."""
    result = compare_pe(exit_code(), b"\x31\xdb\xf7\xf3")
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "terminal_outcome" in result.diverged


def test_pe_wrong_fault_site_is_counterexample() -> None:
    """A fault at a different instruction-stream offset diverges on the site."""
    result = compare_pe(b"\x31\xdb\xf7\xf3", b"\x31\xdb\x90\xf7\xf3")
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "fault_site" in result.diverged


def test_pe_fault_extra_register_effect() -> None:
    """A differing prefix register effect diverges on that register."""
    result = compare_pe(
        b"\x31\xdb\xb9\x05\x00\x00\x00\xf7\xf3",  # mov ecx,5 before div
        b"\x31\xdb\xb8\x05\x00\x00\x00\xf7\xf3",  # mov eax,5 before div
    )
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert {"eax", "ecx"}.intersection(result.diverged)


def test_pe_fault_memory_divergence() -> None:
    """A differing prefix byte store diverges on the memory output."""
    def store(value: int) -> bytes:
        return b"\x31\xdb\xc6\x05" + struct.pack("<I", STACK + 16) + bytes((value,)) + b"\xf7\xf3"

    result = compare_pe(store(0x42), store(0x43))
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "memory" in result.diverged


def test_pe_fault_prefix_code_write_still_refused() -> None:
    """A store onto executable bytes before the fault stays a refusal."""
    code = b"\x31\xdb\xc6\x05" + struct.pack("<I", ENTRY) + b"\x42\xf7\xf3"
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_flat32_terminal(pe32_bytes(code), pe_environment())
    assert error.value.kind is ST.TerminalRefusalKind.CODE_WRITE


def test_pe_quotient_overflow_fault_unguarded_by_vex() -> None:
    """edx:eax=2**32 divided by 1 is #DE — the flat32 guest guards only the
    zero divisor, so the intake decision owns the overflow condition."""
    code = b"\xba\x01\x00\x00\x00\xbb\x01\x00\x00\x00\xf7\xf3"  # edx=1;ebx=1;div ebx
    trace = ST.trace_flat32_terminal(pe32_bytes(code), pe_environment())
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    assert trace.fault is not None
    assert trace.fault.reason == "quotient_out_of_range"


def test_pe_overflow_fault_equivalent_and_corruption() -> None:
    """Equal overflow faults prove equal; overflow versus exit diverges."""
    faulting = b"\xba\x01\x00\x00\x00\xbb\x01\x00\x00\x00\xf7\xf3"
    result = compare_pe(faulting, faulting)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    result = compare_pe(faulting, exit_code())
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "terminal_outcome" in result.diverged


def test_pe_aam_zero_fault_unguarded_by_vex() -> None:
    """``aam 0`` is a #DE the flat32 guest lifts without any exit."""
    trace = ST.trace_flat32_terminal(pe32_bytes(b"\xd4\x00"), pe_environment())
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    assert trace.fault is not None
    assert trace.fault.reason == "zero_divisor"
    assert trace.fault.encoding == b"\xd4\x00"


def test_pe_int3_stays_refused() -> None:
    """``int3`` is an external/privileged boundary — outside #DE scope."""
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_flat32_terminal(pe32_bytes(b"\xcc"), pe_environment())
    assert error.value.kind in (
        ST.TerminalRefusalKind.INSTRUCTION_SCOPE,
        ST.TerminalRefusalKind.FAULT_BOUNDARY,
    )


def test_pe_zero_divisor_with_unproved_dividend() -> None:
    """A proved-zero divisor decides #DE alone — the dividend need not resolve.

    ``mov [esp],5; mov eax,[esp]`` leaves ``EDX:EAX`` reading through a store
    chain, so the 32-bit dividend is unprovable; ``idiv ebx`` still faults
    because ``ebx == 0`` is decided under the declared state.
    """
    code = (
        b"\xc7\x05" + struct.pack("<I", STACK) + b"\x05\x00\x00\x00"
        + b"\xa1" + struct.pack("<I", STACK)
        + b"\x31\xdb\xf7\xfb"
    )
    trace = ST.trace_flat32_terminal(pe32_bytes(code), pe_environment())
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    assert trace.fault is not None
    assert trace.fault.reason == "zero_divisor"
    assert trace.fault.site_address - trace.entry == 0x11


def test_pe_divisor_undeclared_read_refused() -> None:
    """A divisor load outside declared readable memory is never admitted."""
    code = b"\x31\xdb" + b"\xf7\x35" + struct.pack("<I", 0xDEAD0000)
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_flat32_terminal(pe32_bytes(code), pe_environment())
    assert error.value.kind is ST.TerminalRefusalKind.UNDECLARED_READ


def test_pe_fault_divisor_read_still_audited() -> None:
    """The divisor's initial-memory read is recorded even when it faults.

    ``div dword [0x401001]`` reads the four zero bytes of ``mov ebx,0``'s
    immediate inside the declared image — a proved zero divisor whose read
    site remains an obligation of the shared-initial-data relation.
    """
    code = b"\xbb\x00\x00\x00\x00" + b"\xf7\x35" + struct.pack("<I", ENTRY + 1)
    trace = ST.trace_flat32_terminal(pe32_bytes(code), pe_environment())
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    sites = {(site.address, site.size) for site in trace.initial_read_sites}
    assert (ENTRY + 1, 4) in sites


def test_pe_fault_unknown_guard_refused() -> None:
    """A divisor through a store chain cannot be proved — typed refusal."""
    code = b"\xc7\x05" + struct.pack("<I", STACK) + b"\x00\x00\x00\x00" + b"\xf7\x35" + struct.pack(
        "<I", STACK
    )
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_flat32_terminal(pe32_bytes(code), pe_environment())
    assert error.value.kind is ST.TerminalRefusalKind.FAULT_GUARD_UNPROVED


def test_pe_fault_dead_read_still_accounted() -> None:
    """A discarded declared read before the fault remains a read site."""
    code = b"\xa1" + struct.pack("<I", STACK) + b"\x31\xc0\x31\xdb\xf7\xf3"
    trace = ST.trace_flat32_terminal(pe32_bytes(code), pe_environment())
    assert trace.outcome is ST.TerminalOutcome.PROCESSOR_FAULT
    assert any(site.address == STACK for site in trace.initial_read_sites)


def test_pe_post_fault_writes_not_compared() -> None:
    """Different unexecuted bytes after equal faults cannot diverge."""
    result = compare_pe(
        b"\x31\xdb\xf7\xf3\xb9\x05\x00\x00\x00",  # mov ecx,5 after the fault
        b"\x31\xdb\xf7\xf3\xb8\x05\x00\x00\x00",  # mov eax,5 after the fault
    )
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT


def test_pe_fault_stale_evidence_refused() -> None:
    """A fault trace re-verified against mutated bytes refuses."""
    trace = ST.trace_flat32_terminal(pe32_bytes(b"\x31\xdb\xf7\xf3"), pe_environment())
    stale = replace(trace, source=pe32_bytes(b"\x31\xdb\xf7\xfb"))
    refusal = ST.verify_terminal_trace(stale)
    assert refusal is not None
    assert refusal.kind is ST.TerminalRefusalKind.STALE_EVIDENCE
    assert ST.verify_terminal_trace(trace) is None


def test_pe_fault_exhausted_budget_refused() -> None:
    """A zero block budget refuses before any lane outcome is trusted."""
    environment = pe_environment()
    result = ST.compare_symbolic_terminals(
        pe32_bytes(b"\x31\xdb\xf7\xf3"),
        environment,
        pe32_bytes(b"\x31\xdb\xf7\xf3"),
        environment,
        limits=ST.TerminalLimits(max_blocks=0),
    )
    assert result.status is ST.TerminalComparisonStatus.REFUSED
    assert "block_limit" in result.detail


def test_pe_nonfaulting_div_guard_still_reaches_gateway() -> None:
    """A proved non-faulting divide continues to the declared gateway."""
    code = exit_code(prefix=b"\xbb\x02\x00\x00\x00\xf7\xf3")
    result = compare_pe(code, code)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    assert result.oracle.trace is not None
    assert result.oracle.trace.outcome is ST.TerminalOutcome.DECLARED_SERVICE


# ---------------------------------------------------------------------------
# Resolution bounds
# ---------------------------------------------------------------------------


def test_fault_guard_resolution_is_dag_bounded() -> None:
    """A shared-DAG term visits each node once, bounded, never exponentially."""
    node = S.SsaExpr("const", 32, value=1)
    for _ in range(600):
        node = S.SsaExpr("add", 32, (node, node))
    gate = FaultGate(instructions={}, dividend=lambda regs, bits: None)
    with pytest.raises(ST.TerminalRefusal) as error:
        gate._resolve(node)
    assert error.value.kind is ST.TerminalRefusalKind.FAULT_GUARD_UNPROVED


def test_guard_divisor_extraction_never_evaluates_the_divisor() -> None:
    """Identifying the divisor must not traverse the divisor term itself.

    A swapped equality ``eq(0, dag)`` on a shared add-DAG would take
    exponential recursive visits if extraction evaluated the operand to
    find the zero — the term is returned untouched so the bounded resolver
    owns its evaluation instead. The same holds for the documented
    ``eq(dag, 0)`` order, and an equality with no literal zero side is
    refused rather than probed.
    """
    node = S.SsaExpr("const", 32, value=1)
    for _ in range(600):
        node = S.SsaExpr("add", 32, (node, node))
    zero = S.SsaExpr("const", 32, value=0)
    swapped = S.SsaExpr("eq", 1, (zero, node))
    documented = S.SsaExpr("eq", 1, (node, zero))
    assert _guard_divisor(swapped) is node
    assert _guard_divisor(documented) is node
    assert _guard_divisor(S.SsaExpr("eq", 1, (node, node))) is None
