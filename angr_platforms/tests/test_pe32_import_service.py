"""Focused M5 slice tests: declared PE32 import-service symbolic comparison.

Every fixture builds actual PE32 serialized bytes with a genuine import
descriptor table, ILT/IAT and hint/name evidence — no metadata is faked —
and a caller-declared ``kernel32.dll!GetTickCount``-shaped no-argument
DWORD-returning service. The checks exercise the bounded symbolic terminal
path: genuine ``call/jmp dword ptr [IAT]`` routing proved from the sealed
loaded IAT, the declared response and volatile/flag policies, ordered
service events, and every refusal class.
"""

from __future__ import annotations

import dataclasses
import struct

import pytest

from tools.dosunit import symbolic_terminal as ST
from tools.dosunit.flat32_memory_permissions import DeclaredAccess
from tools.dosunit.pe32_import_service import (
    ImportResultKind,
    PeImportResult,
    PeImportService,
    ServiceFlagsPolicy,
)
from tools.dosunit.pe32_program_boot import PeProgramEnvironment, PeProgramMemory

ENTRY = 0x401000
EXIT = 0x70000000
SERVICE = 0x70000100
IAT_SLOT = 0x402030
STACK = 0x10001000


def pe32_import_bytes(code: bytes, *, iat_raw: bytes = b"\x40\x20\x00\x00") -> bytes:
    """Build a real i386 PE carrying one genuine ``kernel32.dll`` import.

    The binary declares a two-section image: ``.text`` (execute+read) and
    ``.rdata`` (read+write) holding a real import descriptor, a null
    descriptor terminator, an ILT, an IAT, the hint/name entry and the DLL
    name — exactly the metadata a loader binds. ``iat_raw`` is the IAT
    entry's on-disk dword (the hint/name RVA for an unbound image).
    """
    data = bytearray(0x600)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 2, 0, 0, 0, 0xE0, 0x102)
    struct.pack_into("<H", data, 0x98, 0x10B)
    for offset, value in (
        (4, 0x200), (16, 0x1000), (20, 0x1000), (24, 0x2000), (28, 0x400000),
        (32, 0x1000), (36, 0x200), (56, 0x3000), (60, 0x200),
        (72, 0x100000), (76, 0x1000), (80, 0x100000), (84, 0x1000), (92, 16),
    ):
        struct.pack_into("<I", data, 0x98 + offset, value)
    struct.pack_into("<H", data, 0x98 + 68, 3)
    # Data directories: index 1 import table at 0xF8+8, index 12 IAT at 0xF8+96.
    struct.pack_into("<II", data, 0xF8 + 8, 0x2000, 0x28)
    struct.pack_into("<II", data, 0xF8 + 96, 0x2030, 8)
    struct.pack_into("<8sIIIIIIHHI", data, 0x178, b".text\0\0\0", len(code), 0x1000,
                     0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    struct.pack_into("<8sIIIIIIHHI", data, 0x1A0, b".rdata\0\0", 0x200, 0x2000,
                     0x200, 0x400, 0, 0, 0, 0, 0xC0000040)
    data[0x200:0x200 + len(code)] = code
    # .rdata raw bytes at file offset 0x400: descriptor, null descriptor,
    # ILT, IAT, hint/name record and the module name.
    struct.pack_into("<IIIII", data, 0x400, 0x2028, 0, 0, 0x2050, 0x2030)
    struct.pack_into("<II", data, 0x428, 0x2040, 0)
    data[0x430:0x434] = iat_raw
    struct.pack_into("<I", data, 0x434, 0)
    struct.pack_into("<H", data, 0x440, 0)
    data[0x442:0x442 + 13] = b"GetTickCount\x00"
    data[0x450:0x450 + 13] = b"kernel32.dll\x00"
    return bytes(data)


def pe_environment(
    *,
    result: PeImportResult | None = None,
    volatile: tuple[str, ...] = ("ecx", "edx"),
    flags: ServiceFlagsPolicy = ServiceFlagsPolicy.PRESERVED,
    services: tuple[PeImportService, ...] | None = None,
) -> PeProgramEnvironment:
    """The declared flat32 environment plus the declared GetTickCount model."""
    values = tuple((name, STACK if name == "esp" else 2 if name == "eflags" else 0)
                   for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags"))
    memory = PeProgramMemory(
        STACK - 0x1000, b"\xa5" * 0x2000, DeclaredAccess.READ | DeclaredAccess.WRITE
    )
    if services is None:
        services = (
            PeImportService(
                "kernel32.dll", "GetTickCount", SERVICE,
                result or PeImportResult(ImportResultKind.SHARED_OPAQUE),
                volatile, flags,
            ),
        )
    return PeProgramEnvironment(values, (memory,), EXIT, services)


def call_service() -> bytes:
    """``call dword ptr [IAT_slot]`` — the genuine import-routed call."""
    return b"\xff\x15" + struct.pack("<I", IAT_SLOT)


def exit_call(value: int = 0x2A) -> bytes:
    """``push imm32; call <declared gateway>`` — the exit boundary."""
    head = call_service() + b"\xa3" + struct.pack("<I", STACK + 8)
    pushed = head + b"\x68" + struct.pack("<I", value)
    return pushed + b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(pushed) + 5))


def compare_pe(
    oracle: bytes, candidate: bytes, *, environment: PeProgramEnvironment | None = None
) -> ST.TerminalComparison:
    """Compare two flat32 import programs under one declared environment."""
    environment = environment or pe_environment()
    return ST.compare_symbolic_terminals(
        pe32_import_bytes(oracle), environment, pe32_import_bytes(candidate), environment
    )


def test_import_equivalent_call_and_response_use() -> None:
    """Identical import-routed programs prove EQUIVALENT with events retained."""
    result = compare_pe(exit_call(), exit_call())
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    trace = result.oracle.trace
    assert trace is not None
    assert trace.service is ST.TerminalService.PE_DECLARED_EXIT
    assert [event.service for event in trace.service_events] == ["kernel32.dll!GetTickCount"]
    assert trace.service_events[0].slot == IAT_SLOT
    assert any(premise.get("kind") == "imported_service_contract" for premise in result.assumptions)


def test_import_changed_setup_equivalent() -> None:
    """Equivalent equal-length prefixes preserve observable return-frame bytes."""
    candidate = b"\x89\xc0" + call_service() + b"\xa3" + struct.pack("<I", STACK + 8)
    candidate += b"\x68" + struct.pack("<I", 0x2A)
    candidate += b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(candidate) + 5))
    oracle = b"\x87\xc0" + candidate[2:]  # xchg eax,eax versus mov eax,eax
    result = compare_pe(oracle, candidate)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT


def test_import_shifted_return_frame_remains_observable() -> None:
    """A longer prefix shifts return addresses retained in observable stack bytes."""
    candidate = b"\x89\xc0" + call_service() + b"\xa3" + struct.pack("<I", STACK + 8)
    candidate += b"\x68" + struct.pack("<I", 0x2A)
    candidate += b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(candidate) + 5))
    result = compare_pe(exit_call(), candidate)
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "memory" in result.diverged


def test_import_altered_response_use_counterexample() -> None:
    """Differing use of the declared response is a solver counterexample."""
    oracle = exit_call()
    head = call_service() + b"\x83\xc0\x01" + b"\xa3" + struct.pack("<I", STACK + 8)
    candidate = head + b"\x68" + struct.pack("<I", 0x2A)
    candidate += b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(candidate) + 5))
    result = compare_pe(oracle, candidate)
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "memory" in result.diverged


def test_import_declared_dword_response_equivalent() -> None:
    """A concrete declared response is bound by the environment identity."""
    environment = pe_environment(result=PeImportResult(ImportResultKind.DECLARED_DWORD, 0xC0DE))
    result = compare_pe(exit_call(), exit_call(), environment=environment)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT


def test_import_dead_result_event_retained() -> None:
    """A removed call diverges on ordered events even when results are dead."""
    oracle_head = call_service() + b"\x90"
    oracle = oracle_head + b"\x68" + struct.pack("<I", 0x2A)
    oracle += b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(oracle) + 5))
    candidate = b"\x68" + struct.pack("<I", 0x2A)
    candidate += b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(candidate) + 5))
    result = compare_pe(oracle, candidate)
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "service_events" in result.diverged


def test_import_extra_call_counterexample() -> None:
    """Two ordered invocations versus one is a different observable history."""
    head = call_service() + call_service()
    oracle = head + b"\x68" + struct.pack("<I", 0x2A)
    oracle += b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(oracle) + 5))
    candidate = call_service() + b"\x68" + struct.pack("<I", 0x2A)
    candidate += b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(candidate) + 5))
    result = compare_pe(oracle, candidate)
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "service_events" in result.diverged


def test_import_jmp_thunk_routed() -> None:
    """A ``push ret; jmp dword ptr [IAT]`` thunk consumes the declared service."""
    code = b"\x68" + struct.pack("<I", ENTRY + 11) + b"\xff\x25" + struct.pack("<I", IAT_SLOT)
    code += b"\xa3" + struct.pack("<I", STACK + 8)
    code += b"\x68" + struct.pack("<I", 0x2A)
    code += b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(code) + 5))
    result = compare_pe(code, code)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    trace = result.oracle.trace
    assert trace is not None
    assert [event.service for event in trace.service_events] == ["kernel32.dll!GetTickCount"]


def test_import_missing_binding_refused() -> None:
    """An import-bearing PE under a service-free environment refuses at boot."""
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_flat32_terminal(pe32_import_bytes(exit_call()), pe_environment(services=()))
    assert error.value.kind is ST.TerminalRefusalKind.BOOT_CONTRACT


def test_import_unknown_binding_refused() -> None:
    """A declared service naming no actual import refuses at binding."""
    environment = pe_environment(
        services=(
            PeImportService(
                "kernel32.dll", "sleep", SERVICE,
                PeImportResult(ImportResultKind.SHARED_OPAQUE), (), ServiceFlagsPolicy.PRESERVED,
            ),
        )
    )
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_flat32_terminal(pe32_import_bytes(exit_call()), environment)
    assert error.value.kind is ST.TerminalRefusalKind.BOOT_CONTRACT


def test_import_mutated_iat_refused() -> None:
    """A program that overwrites its IAT slot then calls through it refuses."""
    code = b"\xc7\x05" + struct.pack("<I", IAT_SLOT) + struct.pack("<I", 0xDEADBEEF)
    code += call_service()
    code += b"\x68" + struct.pack("<I", 0x2A)
    code += b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(code) + 5))
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_flat32_terminal(pe32_import_bytes(code), pe_environment())
    assert error.value.kind is ST.TerminalRefusalKind.UNDECLARED_SERVICE


def test_import_foreign_call_site_refused() -> None:
    """A call through a non-IAT memory cell is not declared import coverage."""
    code = b"\xff\x15" + struct.pack("<I", STACK)
    code += b"\x68" + struct.pack("<I", 0x2A)
    code += b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(code) + 5))
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_flat32_terminal(pe32_import_bytes(code), pe_environment())
    assert error.value.kind is ST.TerminalRefusalKind.INDIRECT_CONTROL


def test_import_direct_service_call_refused() -> None:
    """A direct call to the declared service address is not IAT routing."""
    code = b"\xe8" + struct.pack("<i", SERVICE - (ENTRY + 5))
    code += b"\x68" + struct.pack("<I", 0x2A)
    code += b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(code) + 5))
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_flat32_terminal(pe32_import_bytes(code), pe_environment())
    assert error.value.kind is ST.TerminalRefusalKind.UNDECLARED_SERVICE


def test_import_frame_undeclared_write_refused() -> None:
    """A service call whose return frame leaves declared memory refuses.

    The writable stack region begins exactly at ``esp``; the return slot
    below it is readable only. The push has no writable coverage — the same
    memory checker that governs every other store refuses.
    """
    values = tuple((name, STACK if name == "esp" else 2 if name == "eflags" else 0)
                   for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags"))
    memory = PeProgramMemory(STACK, b"\xa5" * 0x1000, DeclaredAccess.READ | DeclaredAccess.WRITE)
    return_slot = PeProgramMemory(STACK - 4, b"\xa5" * 4, DeclaredAccess.READ)
    environment = PeProgramEnvironment(
        values, (return_slot, memory), EXIT,
        (PeImportService(
            "kernel32.dll", "GetTickCount", SERVICE,
            PeImportResult(ImportResultKind.SHARED_OPAQUE), (), ServiceFlagsPolicy.PRESERVED,
        ),),
    )
    code = exit_call()
    with pytest.raises(ST.TerminalRefusal) as error:
        ST.trace_flat32_terminal(pe32_import_bytes(code), environment)
    assert error.value.kind is ST.TerminalRefusalKind.UNDECLARED_WRITE


def test_import_volatile_clobber_compared() -> None:
    """Reading a declared-clobbered register after the call stays compared."""
    head = call_service() + b"\x89\x0d" + struct.pack("<I", STACK + 12)  # mov [stack+12], ecx
    head += b"\xa3" + struct.pack("<I", STACK + 8)
    code = head + b"\x68" + struct.pack("<I", 0x2A)
    code += b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(code) + 5))
    result = compare_pe(code, code)
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT


def test_import_volatile_preserved_differs() -> None:
    """Preserving a register the policy clobbers diverges under the declared policy."""
    head = call_service() + b"\x89\x0d" + struct.pack("<I", STACK + 12)
    head += b"\xa3" + struct.pack("<I", STACK + 8)
    oracle = head + b"\x68" + struct.pack("<I", 0x2A)
    oracle += b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(oracle) + 5))
    c_head = call_service() + b"\xb9\x01\x00\x00\x00" + b"\x89\x0d" + struct.pack("<I", STACK + 12)
    c_head += b"\xa3" + struct.pack("<I", STACK + 8)
    candidate = c_head + b"\x68" + struct.pack("<I", 0x2A)
    candidate += b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(candidate) + 5))
    environment = pe_environment(volatile=())  # declared preserved ecx
    result = compare_pe(oracle, candidate, environment=environment)
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE


def test_import_concrete_replay_refuses_service() -> None:
    """Concrete replay explicitly refuses the unexecuted declared service.

    The declared service address is a synthetic symbolic boundary — nothing
    concrete backs it — so replay must produce a typed refusal event rather
    than silently skip or execute it.
    """
    from tools.dosunit import pe32_program_boot as boot_module
    from tools.dosunit import pe32_program_replay as replay_module
    from tools.dosunit.real16_program_model import ProgramEventKind, ProgramStatus

    boot = boot_module.pe_program_from_bytes(pe32_import_bytes(exit_call()), pe_environment())
    result = replay_module.replay_pe_program(boot)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events
    assert result.events[-1].kind in (
        ProgramEventKind.CONTROL_ESCAPE,
        ProgramEventKind.UNDECLARED_ACCESS,
    )


def test_import_environment_identity_binds_declaration() -> None:
    """Different declared responses produce different environment identities."""
    left = pe_environment(result=PeImportResult(ImportResultKind.DECLARED_DWORD, 1))
    right = pe_environment(result=PeImportResult(ImportResultKind.DECLARED_DWORD, 2))
    result = ST.compare_symbolic_terminals(
        pe32_import_bytes(exit_call()), left, pe32_import_bytes(exit_call()), right
    )
    assert result.status is ST.TerminalComparisonStatus.PREMISE_MISMATCH


def two_call_code(*, store: str = "second") -> bytes:
    """Two genuine IAT calls; ``store`` selects which response is observed.

    ``call [IAT]; mov ebx, eax; call [IAT]; mov [stack+8], <reg>; push;
    call <exit>`` — ``ebx`` is nonvolatile and carries the first response
    while ``eax`` carries the second, so ``store="first"`` observes the
    first call's opaque result and ``store="second"`` the second's.
    """
    head = call_service() + b"\x89\xc3" + call_service()
    head += (b"\x89\x1d" if store == "first" else b"\xa3") + struct.pack("<I", STACK + 8)
    code = head + b"\x68" + struct.pack("<I", 0x2A)
    return code + b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(code) + 5))


def trace_pe(code: bytes) -> ST.SymbolicTerminalTrace:
    """Trace one import-routed program under the declared environment."""
    return ST.trace_flat32_terminal(pe32_import_bytes(code), pe_environment())


def refuse_stale(trace: ST.SymbolicTerminalTrace) -> None:
    """Require retained-evidence verification to refuse a forged trace."""
    refusal = ST.verify_terminal_trace(trace)
    assert refusal is not None
    assert refusal.kind is ST.TerminalRefusalKind.STALE_EVIDENCE


def test_import_two_call_responses_fresh() -> None:
    """Distinct invocations produce fresh responses — always-equal is false.

    The oracle observes the first call's result and the candidate the
    second's. If both calls shared one opaque input the solver would prove
    a spurious equality; fresh per-occurrence inputs make the shared input
    space able to distinguish them — a real counterexample.
    """
    result = compare_pe(two_call_code(store="first"), two_call_code(store="second"))
    assert result.status is ST.TerminalComparisonStatus.COUNTEREXAMPLE
    assert "memory" in result.diverged


def test_import_two_call_identical_equivalent() -> None:
    """Identical two-call programs still prove equal under aligned ordinals."""
    result = compare_pe(two_call_code(), two_call_code())
    assert result.status is ST.TerminalComparisonStatus.EQUIVALENT
    trace = result.oracle.trace
    assert trace is not None
    assert [event.service for event in trace.service_events] == [
        "kernel32.dll!GetTickCount",
        "kernel32.dll!GetTickCount",
    ]
    assert [event.sequence for event in trace.service_events] == [0, 1]
    assert trace.service_events[0].site != trace.service_events[1].site


def test_service_census_rejects_removed_event() -> None:
    """A subset receipt list cannot answer the executed-boundary census."""
    trace = trace_pe(two_call_code())
    forged = dataclasses.replace(trace, service_events=trace.service_events[:1])
    refuse_stale(forged)


def test_service_census_rejects_duplicate_event() -> None:
    """A duplicated receipt cannot answer the executed-boundary census."""
    trace = trace_pe(two_call_code())
    forged = dataclasses.replace(
        trace, service_events=(*trace.service_events, trace.service_events[-1])
    )
    refuse_stale(forged)


def test_service_census_rejects_reordered_events() -> None:
    """Reordered receipts no longer bind their census entries positionally."""
    trace = trace_pe(two_call_code())
    events = trace.service_events
    forged = dataclasses.replace(trace, service_events=(events[1], events[0]))
    refuse_stale(forged)


def test_service_census_rejects_foreign_event() -> None:
    """A receipt sited off the executed boundary does not bind the census."""
    trace = trace_pe(two_call_code())
    events = trace.service_events
    foreign = dataclasses.replace(events[0], site=events[0].site + 1)
    forged = dataclasses.replace(trace, service_events=(foreign, *events[1:]))
    refuse_stale(forged)


def test_service_census_rejects_untyped_event() -> None:
    """A malformed receipt refuses cleanly instead of accessing its fields."""
    trace = trace_pe(two_call_code())
    forged = dataclasses.replace(
        trace, service_events=(object(), *trace.service_events[1:])
    )
    refuse_stale(forged)


def test_service_census_rejects_forged_transfer_tag() -> None:
    """Retagging an IAT call as Ijk_Boring cannot hide the executed service."""
    trace = trace_pe(two_call_code())
    blocks = trace.blocks
    forged_block = dataclasses.replace(blocks[0], jumpkind="Ijk_Boring")
    forged = dataclasses.replace(trace, blocks=(forged_block, *blocks[1:]))
    refuse_stale(forged)


def test_service_census_rejects_skipped_entry_block() -> None:
    """The census must begin at the declared boot entry, not mid-chain."""
    trace = trace_pe(two_call_code())
    forged = dataclasses.replace(trace, blocks=trace.blocks[1:])
    refuse_stale(forged)


def test_service_census_rejects_invented_successor() -> None:
    """A receipt successor that native semantics do not derive is stale."""
    trace = trace_pe(two_call_code())
    blocks = trace.blocks
    assert blocks[0].next_target is not None
    forged_block = dataclasses.replace(blocks[0], next_target=blocks[0].next_target + 4)
    forged = dataclasses.replace(trace, blocks=(forged_block, *blocks[1:]))
    refuse_stale(forged)


def test_service_census_rejects_forged_counters() -> None:
    """Fact counters must re-derive from the admitted evidence census."""
    trace = trace_pe(two_call_code())
    forged = dataclasses.replace(
        trace, counters=ST.FactCounters(1, 1, 1, 1, 0)
    )
    refuse_stale(forged)
