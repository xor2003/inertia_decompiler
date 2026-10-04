"""Actual initialized PE32 process controls with independent Unicorn execution."""

import struct
from dataclasses import replace

import pytest
from test_flat32_loaded_byte_boundaries import pe32_bytes

from tools.dosunit.flat32_memory_permissions import DeclaredAccess
from tools.dosunit.flat32_replay_model import MemoryRange
from tools.dosunit.pe32_program_boot import PeProgramEnvironment, PeProgramMemory, pe_program_from_bytes
from tools.dosunit.pe32_program_replay import PeProgramObservation, replay_pe_program
from tools.dosunit.real16_program_model import (
    ProgramAgreement,
    ProgramEventKind,
    ProgramStatus,
    compare_programs,
)

ENTRY = 0x401000
EXIT = 0x70000000
STACK = 0x10001000


def environment():
    values = tuple((name, STACK if name == "esp" else 2 if name == "eflags" else 0)
                   for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags"))
    memory = PeProgramMemory(STACK - 0x1000, b"\xa5" * 0x2000, DeclaredAccess.READ | DeclaredAccess.WRITE)
    return PeProgramEnvironment(values, (memory,), EXIT)


def exit_code(value=0x12345678, prefix=b""):
    pushed = prefix + b"\x68" + struct.pack("<I", value)
    return pushed + b"\xe8" + struct.pack("<i", EXIT - (ENTRY + len(pushed) + 5))


def execute(code, *, observations=(), limit=100):
    boot = pe_program_from_bytes(pe32_bytes(code), environment())
    return replay_pe_program(boot, observations=observations, instruction_limit=limit)


def test_full_width_exit_uses_loaded_entry_and_no_synthetic_return_frame():
    result = execute(exit_code(), observations=(PeProgramObservation("initial_stack", MemoryRange(STACK, 4)),))
    assert result.status is ProgramStatus.TERMINATED
    assert result.exit_code == 0x12345678
    assert result.observations == (("initial_stack", b"\xa5" * 4),)
    assert result.events[-1].kind is ProgramEventKind.PE_EXIT
    assert compare_programs(result, result) is ProgramAgreement.AGREED
    assert result == execute(exit_code(), observations=(PeProgramObservation("initial_stack", MemoryRange(STACK, 4)),))


def test_changed_internal_registers_agree_and_exit_mutation_mismatches():
    first = execute(exit_code())
    altered = execute(exit_code(prefix=b"\xbb\x03\x00\x00\x00"))
    assert compare_programs(first, altered) is ProgramAgreement.AGREED
    assert first.boot_identity != altered.boot_identity
    assert compare_programs(first, execute(exit_code(0x12345679))) is ProgramAgreement.MISMATCHED


def test_declared_output_mutations_mismatch_without_changing_the_domain():
    observation = (PeProgramObservation("buffer", MemoryRange(STACK + 16, 1)),)
    original = execute(exit_code(prefix=b"\xc6\x05" + struct.pack("<I", STACK + 16) + b"\x42"), observations=observation)
    changed = execute(exit_code(prefix=b"\xc6\x05" + struct.pack("<I", STACK + 16) + b"\x43"), observations=observation)
    assert compare_programs(original, changed) is ProgramAgreement.MISMATCHED
    plain = execute(exit_code(prefix=b"\xc6\x05" + struct.pack("<I", STACK + 16) + b"\x42"))
    assert (plain.registers, plain.events, plain.writes) == (original.registers, original.events, original.writes)


@pytest.mark.parametrize("code", [b"\xc3", b"\xf4", b"\xcd\x21", b"\xe4\x80", b"\x64\xa1\x00\x00\x00\x00",
                                 b"\x0f\x31", b"\x0f\xa2", b"\x8e\xd8"])
def test_bare_return_unknown_services_ports_and_fs_remain_incomplete(code):
    result = execute(code)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_fault_budget_and_complete_observation_accounting():
    complete = execute(exit_code())
    faulted = execute(bytes.fromhex("31dbf7f3"))
    assert faulted.status is ProgramStatus.FAULTED
    assert compare_programs(complete, faulted) is ProgramAgreement.MISMATCHED
    assert compare_programs(faulted, faulted) is ProgramAgreement.INCOMPLETE
    budget = execute(b"\xeb\xfe", limit=5)
    assert budget.status is ProgramStatus.BUDGET_EXHAUSTED
    assert budget.instructions == 5
    assert compare_programs(complete, budget) is ProgramAgreement.INCOMPLETE
    assert compare_programs(complete, replace(complete, events=())) is ProgramAgreement.INCOMPLETE


def test_padding_and_code_mutation_never_supply_successful_execution():
    memory = PeProgramMemory(STACK - 0x1000, b"\xa5" * 0x1004, DeclaredAccess.READ | DeclaredAccess.WRITE)
    env = replace(environment(), memory=(memory,))
    code = b"\xa1" + struct.pack("<I", STACK + 4) + exit_code()
    boot = pe_program_from_bytes(pe32_bytes(code), env)
    outside = replay_pe_program(boot)
    assert outside.status is ProgramStatus.UNSUPPORTED
    assert outside.events[0].kind is ProgramEventKind.UNDECLARED_ACCESS
    changed = execute(b"\xc6\x05" + struct.pack("<I", ENTRY) + b"\x90")
    assert changed.status is ProgramStatus.UNSUPPORTED


def test_foreign_environment_and_missing_named_output_cannot_agree():
    complete = execute(exit_code(), observations=(PeProgramObservation("stack", MemoryRange(STACK, 4)),))
    assert compare_programs(complete, replace(complete, observations=())) is ProgramAgreement.INCOMPLETE
    assert compare_programs(complete, replace(complete, environment_identity="foreign")) is ProgramAgreement.INCOMPLETE


def test_parent_review_rejects_stale_boot_entry_and_loaded_bytes():
    from tools.dosunit.flat32_replay_model import ReplayImage

    boot = pe_program_from_bytes(pe32_bytes(exit_code()), environment())
    with pytest.raises(ValueError, match="identity"):
        replace(boot, entry=boot.entry + 1)
    altered = replace(boot.image, chunks=((boot.image.chunks[0][0], b"\x90" + boot.image.chunks[0][1][1:]),))
    assert isinstance(altered, ReplayImage)
    with pytest.raises(ValueError, match="identity"):
        replace(boot, image=altered)


def test_parent_review_bounds_observation_work_before_allocating_guest(monkeypatch):
    import tools.dosunit.pe32_program_replay as owner

    boot = pe_program_from_bytes(pe32_bytes(exit_code()), environment())
    monkeypatch.setattr(owner, "MAX_MAPPED_BYTES", 4, raising=False)
    outputs = (PeProgramObservation("first", MemoryRange(STACK, 4)),
               PeProgramObservation("second", MemoryRange(STACK, 4)))
    with pytest.raises(ValueError, match="budget"):
        replay_pe_program(boot, observations=outputs)


def test_native_backend_initialization_failure_is_visible(monkeypatch):
    import unicorn
    from unicorn.unicorn_py3.unicorn import UcError

    import tools.dosunit.pe32_program_replay as owner

    boot = pe_program_from_bytes(pe32_bytes(exit_code()), environment())

    def unavailable(_boot):
        raise UcError(unicorn.UC_ERR_ARCH)

    monkeypatch.setattr(owner, "_initialize", unavailable)
    result = replay_pe_program(boot)
    assert result.status is ProgramStatus.UNAVAILABLE
    assert "backend_initialization_failed" in result.detail
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_shared_receipts_do_not_truncate_pe_exit_or_widen_dos_exit():
    from tools.dosunit.real16_program_model import ProgramEvent

    pe = execute(exit_code(0x100))
    assert compare_programs(pe, pe) is ProgramAgreement.AGREED
    fake_dos = replace(pe, events=(ProgramEvent(ProgramEventKind.DOS_EXIT, EXIT, bytes((0x21, 0x4C, 0))),))
    assert compare_programs(fake_dos, fake_dos) is ProgramAgreement.INCOMPLETE
    boolean_exit = replace(pe, exit_code=True, events=(ProgramEvent(ProgramEventKind.PE_EXIT, EXIT, bytes((1, 0, 0, 0))),))
    assert compare_programs(boolean_exit, boolean_exit) is ProgramAgreement.INCOMPLETE
