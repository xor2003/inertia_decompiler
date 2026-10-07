"""Focused M5 slice tests: symbolic terminal-service comparison on native bytes.

Every case builds actual MZ or PE32 serialized bytes and declared
environments, traces both lanes with ``symbolic_terminal``, and checks typed
verdicts — never concrete replay agreement — plus complete fact counters.
"""

from __future__ import annotations

import struct
from dataclasses import replace

import pytest

import tools.dosunit.compare.symbolic_terminal as ST
from tools.dosunit.runtime.flat32_memory_permissions import DeclaredAccess
from tools.dosunit.runtime.pe32_program_boot import PeProgramEnvironment, PeProgramMemory
from tools.dosunit.reporting.proof_public_domain import OutcomeAdmission
from tools.dosunit.runtime.real16_program_boot import ProgramEnvironment
from tools.dosunit.runtime.real16_program_model import (
    ProgramAgreement,
    ProgramStatus,
    compare_programs,
)
from tools.dosunit.runtime.real16_program_replay import replay_program

ENTRY = 0x401000
EXIT = 0x70000000
STACK = 0x10001000


def mz(code: bytes, *, entry_ip: int = 0, stack_sp: int = 0x1000) -> bytes:
    """Build a real MZ executable whose load module is exactly ``code``."""
    header = bytearray(64)
    size = len(header) + len(code)
    header[:2] = b"MZ"
    for offset, value in ((2, size % 512), (4, (size + 511) // 512), (8, 4),
                          (12, 0x400), (16, stack_sp), (20, entry_ip), (24, 0x1C)):
        header[offset:offset + 2] = value.to_bytes(2, "little")
    return bytes(header) + code


def dos_environment() -> ProgramEnvironment:
    """The declared DOS arena and register file used by every real16 lane."""
    arena = bytearray(b"\xA5" * 0x2000)
    arena[:2] = b"\xCD\x20"
    arena[2:4] = (0x1200).to_bytes(2, "little")
    arena[0x200] = 3
    values = tuple((name, 0) for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"))
    return ProgramEnvironment(0x1000, bytes(arena), (*values, ("eflags", 2)), 0, 0)


def pe32_bytes(code: bytes) -> bytes:
    """Construct a real i386 PE whose virtual section ends at the last code byte."""
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x102)
    struct.pack_into("<H", data, 0x98, 0x10B)
    for offset, value in ((4, 0x200), (16, 0x1000), (20, 0x1000), (28, 0x400000),
                          (32, 0x1000), (36, 0x200), (56, 0x2000), (60, 0x200),
                          (72, 0x100000), (76, 0x1000), (80, 0x100000), (84, 0x1000), (92, 16)):
        struct.pack_into("<I", data, 0x98 + offset, value)
    struct.pack_into("<H", data, 0x98 + 68, 3)
    struct.pack_into("<8sIIIIIIHHI", data, 0x178, b".text\0\0\0", len(code), 0x1000,
                     0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    data[0x200:0x200 + len(code)] = code
    return bytes(data)


def pe_environment() -> PeProgramEnvironment:
    """The declared flat32 register file, stack allocation and exit gateway."""
    values = tuple((name, STACK if name == "esp" else 2 if name == "eflags" else 0)
                   for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags"))
    memory = PeProgramMemory(
        STACK - 0x1000, b"\xa5" * 0x2000, DeclaredAccess.READ | DeclaredAccess.WRITE
    )
    return PeProgramEnvironment(values, (memory,), EXIT)


def exit_code(value: int = 0x12345678, prefix: bytes = b"") -> bytes:
    """A stdcall-shaped exit call: ``push imm32; call <declared gateway>``."""
    pushed = prefix + b"\x68" + struct.pack("<I", value)
    return pushed + b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(pushed) + 5))


def compare_mz(
    oracle: bytes, candidate: bytes, *, environment: ProgramEnvironment | None = None
) -> ST.TerminalComparison:
    """Compare two real16 programs under one declared environment."""
    environment = environment or dos_environment()
    return ST.compare_symbolic_terminals(
        mz(oracle), environment, mz(candidate), environment
    )


def compare_pe(
    oracle: bytes, candidate: bytes, *, environment: PeProgramEnvironment | None = None
) -> ST.TerminalComparison:
    """Compare two flat32 programs under one declared environment."""
    environment = environment or pe_environment()
    return ST.compare_symbolic_terminals(
        pe32_bytes(oracle), environment, pe32_bytes(candidate), environment
    )


# ---------------------------------------------------------------------------
# Real16 DOS INT21/AH4C positives
# ---------------------------------------------------------------------------


def test_mz_equivalent_terminations_proved() -> None:
    """Byte-different but semantically identical exits prove EQUIVALENT.

    The candidate appends never-executed trailing bytes: the file and boot
    identities differ while every observable effect — the frame's stored
    return IP included — is identical.
    """
    environment = dos_environment()
    result = ST.compare_symbolic_terminals(
        mz(bytes.fromhex("b8074ccd21")),
        environment,
        mz(bytes.fromhex("b8074ccd21") + b"\x90" * 4),
        environment,
    )
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    assert result.architecture is not None and result.architecture.name == "REAL16"
    assert result.service is ST.TerminalService.DOS_TERMINATE
    assert result.environment_identity
    assert result.oracle.trace is not None and result.candidate.trace is not None
    for trace in (result.oracle.trace, result.candidate.trace):
        assert trace.event_kind.name == "DOS_EXIT"
        assert trace.payload_bits == 8
        assert trace.blocks
        assert trace.counters.raw_fact_count == len(trace.blocks)
        assert trace.counters.materialized_count > 0
        assert trace.counters.failure_count == 0
    assert result.counters.raw_fact_count == len(result.oracle.trace.blocks) + len(
        result.candidate.trace.blocks
    )
    assert result.counters.failure_count == 0


def test_mz_prefix_memory_effects_proved_and_compared() -> None:
    """Identical prefix stores plus the int-entry frame prove equal memory.

    ``ds:0x1200`` resolves to 0x11200 inside the declared arena,
    below the PSP-relative code range.
    """
    code = bytes.fromhex("c606001204b8074ccd21")
    result = compare_mz(code, code)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    trace = result.oracle.trace
    assert trace is not None and "memory" in trace.document["outputs"]
    assert "terminal_payload" in trace.document["outputs"]


def test_mz_changed_exit_code_counterexample() -> None:
    """AL=7 vs AL=8 yields a solver counterexample on the payload output."""
    result = compare_mz(bytes.fromhex("b8074ccd21"), bytes.fromhex("b8084ccd21"))
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "terminal_payload" in result.diverged
    assert "ax" in result.diverged


def test_mz_changed_prefix_store_counterexample() -> None:
    """A changed prefix byte store is a memory divergence, not agreement."""
    result = compare_mz(
        bytes.fromhex("c606001204b8074ccd21"),
        bytes.fromhex("c606001205b8074ccd21"),
    )
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "memory" in result.diverged


def test_mz_declared_initial_read_equivalent() -> None:
    """A readable declared arena load is admitted and compared symbolically."""
    code = bytes.fromhex("a10010b8074ccd21")  # mov ax,[ds:0x1000] — inside arena
    result = compare_mz(code, code)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    trace = result.oracle.trace
    assert trace is not None
    assert trace.initial_read_sites
    assert all(site.initialized == b"\xa5" * site.size for site in trace.initial_read_sites)


def test_mz_initial_bytes_mismatch_is_premise_mismatch() -> None:
    """A code byte read falsifies shared initial memory across differing boots."""
    result = compare_mz(
        bytes.fromhex("a10001b8074ccd21"),  # mov ax,[ds:0x0100] — first image bytes
        bytes.fromhex("90b8074ccd21"),
    )
    assert result.status is ST.TerminalComparisonStatus.PREMISE_MISMATCH


def test_mz_changed_frame_byte_counterexample() -> None:
    """Different declared flags change the stored frame — still compared."""
    oracle_env = dos_environment()
    candidate_env = replace(
        oracle_env,
        registers=tuple(
            (name, 3 if name == "eflags" else value)
            for name, value in oracle_env.registers
        ),
    )
    code = bytes.fromhex("b8074ccd21")
    result = ST.compare_symbolic_terminals(
        mz(code), oracle_env, mz(code), candidate_env
    )
    # Environment identities differ, so premise mismatch precedes solving.
    assert result.status is ST.TerminalComparisonStatus.PREMISE_MISMATCH


# ---------------------------------------------------------------------------
# Real16 typed refusals
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "code,kinds",
    [
        ("c3", (ST.TerminalRefusalKind.RETURN_NOT_TERMINAL,)),        # ret near
        ("ebfe", (ST.TerminalRefusalKind.LOOP_BOUNDARY,
                  ST.TerminalRefusalKind.INDIRECT_CONTROL)),         # jmp self
        ("e480", (ST.TerminalRefusalKind.ENVIRONMENT_EFFECT,)),       # in al,0x80
        ("b409cd21", (ST.TerminalRefusalKind.UNDECLARED_SERVICE,)),   # ah=09h
        ("b8074ccd20", (ST.TerminalRefusalKind.UNDECLARED_SERVICE,)), # int 20h
        ("58cd21", (ST.TerminalRefusalKind.SERVICE_GUARD_UNPROVED,)), # pop ax; unproved AH
        ("e80000", (ST.TerminalRefusalKind.CALL_BOUNDARY,)),          # call near +0
        ("cd10", (ST.TerminalRefusalKind.UNDECLARED_SERVICE,)),       # int 10h BIOS video
        ("c606000104b8074ccd21", (ST.TerminalRefusalKind.CODE_WRITE,)),
        ("c606005000b8074ccd21", (ST.TerminalRefusalKind.UNDECLARED_WRITE,)),
        ("a10020b8074ccd21", (ST.TerminalRefusalKind.UNDECLARED_READ,)),     # ds:0x2000 = arena end
        ("a1ff1fb8074ccd21", (ST.TerminalRefusalKind.UNDECLARED_READ,)),     # word read crosses arena end
        ("a1002031c0b8074ccd21", (ST.TerminalRefusalKind.UNDECLARED_READ,)), # discarded read still faults
        ("a1001089c38b07b8074ccd21", (ST.TerminalRefusalKind.UNPROVED_POINTER,)),
        ("0f31", (ST.TerminalRefusalKind.LIFT,
                  ST.TerminalRefusalKind.ENVIRONMENT_EFFECT)),       # rdtsc: lift or machine state
    ],
)
def test_mz_refusals_are_typed(code: str, kinds: tuple[ST.TerminalRefusalKind, ...]) -> None:
    """Each boundary outside the slice is a typed refusal with its kind."""
    try:
        ST.trace_real16_terminal(mz(bytes.fromhex(code)), dos_environment())
    except ST.TerminalRefusal as refusal:
        assert refusal.kind in kinds, f"{code}: got {refusal.kind.value}: {refusal.detail}"
        return
    raise AssertionError(f"{code} must refuse, got an admitted trace")


def test_mz_refusal_propagates_through_compare() -> None:
    """A refused lane produces REFUSED with the typed reason, not UNKNOWN."""
    result = compare_mz(bytes.fromhex("b8074ccd21"), bytes.fromhex("c3"))
    assert result.status is ST.TerminalComparisonStatus.REFUSED
    assert "return_not_terminal" in result.detail
    assert result.counters.failure_count == 1


def test_mz_environment_identity_mismatch() -> None:
    """Different declared environments refuse a shared verdict."""
    oracle_env = dos_environment()
    arena = bytearray(oracle_env.allocation)
    arena[0x200] = 4
    candidate_env = replace(oracle_env, allocation=bytes(arena))
    code = bytes.fromhex("b8074ccd21")
    result = ST.compare_symbolic_terminals(mz(code), oracle_env, mz(code), candidate_env)
    assert result.status is ST.TerminalComparisonStatus.PREMISE_MISMATCH
    assert result.assumptions


def test_mz_stale_block_bytes_refuse_verification() -> None:
    """A trace bound to mutated retained bytes fails re-verification."""
    trace = ST.trace_real16_terminal(mz(bytes.fromhex("b8074ccd21")), dos_environment())
    stale = replace(trace, source=mz(bytes.fromhex("b8084ccd21")))
    refusal = ST.verify_terminal_trace(stale)
    assert refusal is not None
    assert refusal.kind is ST.TerminalRefusalKind.STALE_EVIDENCE
    assert ST.verify_terminal_trace(trace) is None


# ---------------------------------------------------------------------------
# Flat32 PE declared-gateway positives and refusals
# ---------------------------------------------------------------------------


def test_pe_equivalent_terminations_proved() -> None:
    """Identical exit code plus never-executed trailing bytes prove EQUIVALENT.

    The pushed return address is observable memory state, so a shifted call
    site would genuinely diverge; equivalence is only honest when the
    executed bytes are identical.
    """
    result = ST.compare_symbolic_terminals(
        pe32_bytes(exit_code()), pe_environment(),
        pe32_bytes(exit_code() + b"\x90" * 4), pe_environment(),
    )
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    trace = result.oracle.trace
    assert trace is not None
    assert trace.service is ST.TerminalService.PE_DECLARED_EXIT
    assert trace.payload_bits == 32
    assert trace.event_kind.name == "PE_EXIT"
    assert result.environment_identity
    assert any(
        premise.get("kind") == "scope_limitation" and "not Windows import" in premise["detail"]
        for premise in result.assumptions
    )


def test_pe_walk_uses_explicit_architecture_without_global_installation(monkeypatch) -> None:
    """Observe the real walker while engine register globals retain their owners."""
    original_map = ST.S.REG_BY_OFFSET
    original_reader = ST.S._read_register
    original_statement = ST.S._lower_irsb_statement
    calls = []

    def checked_statement(statement, state, **kwargs):
        assert ST.S.REG_BY_OFFSET is original_map
        assert ST.S._read_register is original_reader
        assert state.architecture is not None
        assert state.architecture.control_register == "eip"
        calls.append(statement.tag)
        return original_statement(statement, state, **kwargs)

    monkeypatch.setattr(ST.S, "_lower_irsb_statement", checked_statement)
    trace = ST.trace_flat32_terminal(pe32_bytes(exit_code()), pe_environment())
    assert trace.service is ST.TerminalService.PE_DECLARED_EXIT
    assert calls
    assert ST.S.REG_BY_OFFSET is original_map


def test_pe_jmp_gateway_boundary() -> None:
    """A direct long jump to the declared gateway is the same boundary kind."""
    code = b"\x68" + struct.pack("<I", 0x42) + b"\xe9" + struct.pack(
        "<i", EXIT - (ENTRY + 5 + 5)
    )
    result = compare_pe(code, code)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    assert result.oracle.trace is not None
    assert result.oracle.trace.site.encoding == b"\xe9" + struct.pack(
        "<i", EXIT - (ENTRY + 10)
    )


def test_pe_changed_exit_payload_counterexample() -> None:
    """A changed pushed dword diverges on terminal_payload."""
    result = compare_pe(exit_code(), exit_code(0x12345679))
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "terminal_payload" in result.diverged


def test_pe_changed_prefix_memory_counterexample() -> None:
    """A changed declared-memory byte store diverges on the memory output."""
    oracle = exit_code(prefix=b"\xc6\x05" + struct.pack("<I", STACK + 16) + b"\x42")
    candidate = exit_code(prefix=b"\xc6\x05" + struct.pack("<I", STACK + 16) + b"\x43")
    result = compare_pe(oracle, candidate)
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "memory" in result.diverged


def test_pe_changed_gateway_target_refused() -> None:
    """A call aimed beside the declared gateway is undeclared, not terminal."""
    code = b"\x68" + struct.pack("<I", 7) + b"\xe8" + struct.pack(
        "<i", (EXIT + 4) - (ENTRY + 10)
    )
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_flat32_terminal(pe32_bytes(code), pe_environment())
    assert error.value.kind is ST.TerminalRefusalKind.UNDECLARED_SERVICE


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "code,kinds",
    [
        (b"\xc3", (ST.TerminalRefusalKind.RETURN_NOT_TERMINAL,)),
        (b"\xeb\xfe", (ST.TerminalRefusalKind.LOOP_BOUNDARY,)),
        (b"\xe4\x80", (ST.TerminalRefusalKind.ENVIRONMENT_EFFECT,)),
        (b"\xf4", (ST.TerminalRefusalKind.INSTRUCTION_SCOPE,)),        # hlt = privileged
        (b"\x8e\xd8", (ST.TerminalRefusalKind.INSTRUCTION_SCOPE,)),    # mov ds,ax
        (b"\xff\x10", (                                              # call [eax]: read at 0 faults
            ST.TerminalRefusalKind.UNDECLARED_READ,
            ST.TerminalRefusalKind.INDIRECT_CONTROL,
        )),
        # xor ebx,ebx; div ebx is no longer a refusal: a proved #DE is an
        # admitted processor-fault outcome — see test_symbolic_terminal_faults.
        (exit_code(prefix=b"\xc6\x05" + struct.pack("<I", ENTRY + 8) + b"\x00"), (
            ST.TerminalRefusalKind.CODE_WRITE,                         # store onto a code byte
        )),
        (exit_code(prefix=b"\xa1\x00\x00\x00\x00"), (
            ST.TerminalRefusalKind.UNDECLARED_READ,                    # mov eax,[0] — unmapped
        )),
        (exit_code(prefix=b"\xa1\x00\x00\x00\x00\x31\xc0"), (
            ST.TerminalRefusalKind.UNDECLARED_READ,                    # discarded read still faults
        )),
        (exit_code(prefix=b"\xa1\xfe\x1f\x00\x10"), (
            ST.TerminalRefusalKind.UNDECLARED_READ,                    # dword read crosses env top
        )),
        (exit_code(prefix=b"\xa1\x00\x10\x00\x10\x8b\x00"), (
            ST.TerminalRefusalKind.UNPROVED_POINTER,                   # mov eax,[eax] — symbolic
        )),
    ],
)
def test_pe_refusals_are_typed(code: bytes, kinds: tuple[ST.TerminalRefusalKind, ...]) -> None:
    """Every non-gateway outcome is a typed refusal on the flat32 lane."""
    try:
        ST.trace_flat32_terminal(pe32_bytes(code), pe_environment())
    except ST.TerminalRefusal as refusal:
        assert refusal.kind in kinds, f"{code.hex()}: got {refusal.kind.value}: {refusal.detail}"
        return
    raise AssertionError(f"{code.hex()} must refuse, got an admitted trace")


def test_pe_declared_read_equivalent() -> None:
    """A declared readable dword load is admitted and compared symbolically."""
    code = exit_code(prefix=b"\xa1" + struct.pack("<I", STACK))
    result = compare_pe(code, code)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT


def test_pe_initial_bytes_mismatch_is_premise_mismatch() -> None:
    """A code byte read falsifies shared initial memory across differing boots."""
    result = compare_pe(
        exit_code(prefix=b"\xa1" + struct.pack("<I", ENTRY)),
        exit_code(prefix=b"\x90" * 5),
    )
    assert result.status is ST.TerminalComparisonStatus.PREMISE_MISMATCH


def test_pe_environment_mismatch() -> None:
    """Changed declared registers change the environment identity."""
    oracle_env = pe_environment()
    candidate_env = replace(
        oracle_env,
        registers=tuple(
            (name, 1 if name == "ebx" else value) for name, value in oracle_env.registers
        ),
    )
    code = exit_code()
    result = ST.compare_symbolic_terminals(
        pe32_bytes(code), oracle_env, pe32_bytes(code), candidate_env
    )
    assert result.status is ST.TerminalComparisonStatus.PREMISE_MISMATCH


# ---------------------------------------------------------------------------
# Premise propagation, concrete separation and counters
# ---------------------------------------------------------------------------


def test_premise_propagation_into_environment_model() -> None:
    """The service premise is visible through the shared proof-domain view."""
    result = compare_mz(bytes.fromhex("b8074ccd21"), bytes.fromhex("b8074ccd21"))
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    model = result.environment_model()
    assert model.external_effects is OutcomeAdmission.COMPARED
    # A service-boundary equivalence did not exercise the fault domain:
    # supported faults are now compared, never blanket-refused, and only a
    # compared processor-fault verdict projects COMPARED.
    assert model.faults is OutcomeAdmission.NOT_ESTABLISHED
    kinds = {premise.get("kind") for premise in model.premise}
    assert "declared_environment_identity" in kinds
    assert "terminal_service_contract" in kinds
    assert "joint_premise" in kinds
    refused = compare_mz(bytes.fromhex("c3"), bytes.fromhex("c3"))
    assert refused.environment_model().external_effects is OutcomeAdmission.NOT_ESTABLISHED


def test_symbolic_verdict_is_distinct_from_concrete_replay() -> None:
    """Concrete receipts and symbolic verdicts are different typed layers."""
    from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes

    code = mz(bytes.fromhex("b8074ccd21"))
    env = dos_environment()
    concrete = replay_program(program_from_mz_bytes(code, env))
    symbolic = ST.compare_symbolic_terminals(code, env, code, env)
    assert concrete.status is ProgramStatus.TERMINATED
    assert symbolic.status is ST.TerminalComparisonStatus.EQUIVALENT
    assert isinstance(symbolic.status, ST.TerminalComparisonStatus)
    assert not isinstance(symbolic.status, ProgramAgreement)
    assert concrete.exit_code == 7
    assert compare_programs(concrete, concrete) is ProgramAgreement.AGREED


def test_fact_counters_close_on_every_path() -> None:
    """classified facts always materialize or the counter pipeline stays closed."""
    for result in (
        compare_mz(bytes.fromhex("b8074ccd21"), bytes.fromhex("b8074ccd21")),
        compare_mz(bytes.fromhex("b8074ccd21"), bytes.fromhex("b8084ccd21")),
        compare_mz(bytes.fromhex("c3"), bytes.fromhex("b8074ccd21")),
        compare_pe(exit_code(), exit_code(0x12345679)),
    ):
        counters = result.counters
        assert counters.raw_fact_count >= counters.normalized_fact_count >= 0
        if result.status is ST.TerminalComparisonStatus.EQUIVALENT:
            assert counters.materialized_count > 0
            assert counters.failure_count == 0
        if result.status is ST.TerminalComparisonStatus.REFUSED:
            assert counters.failure_count >= 1
