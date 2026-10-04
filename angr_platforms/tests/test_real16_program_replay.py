"""Actual MZ startup/termination controls for independent program execution."""

from dataclasses import replace

import pytest

from tools.dosunit.real16_program_boot import ProgramEnvironment, program_from_mz_bytes
from tools.dosunit.real16_program_model import (
    ProgramAgreement,
    ProgramEventKind,
    ProgramObservation,
    ProgramStatus,
    compare_programs,
)
from tools.dosunit.real16_program_replay import replay_program
from tools.dosunit.real16_replay_model import LinearRange


def mz(code: bytes, *, entry_ip: int = 0, stack_sp: int = 0x1000) -> bytes:
    header = bytearray(64)
    size = len(header) + len(code)
    header[:2] = b"MZ"
    for offset, value in ((2, size % 512), (4, (size + 511) // 512), (8, 4),
                          (12, 0x400), (16, stack_sp), (20, entry_ip), (24, 0x1C)):
        header[offset:offset + 2] = value.to_bytes(2, "little")
    return bytes(header) + code


def environment() -> ProgramEnvironment:
    arena = bytearray(b"\xA5" * 0x2000)
    arena[:2] = b"\xCD\x20"
    arena[2:4] = (0x1200).to_bytes(2, "little")
    arena[0x200] = 3
    values = tuple((name, 0) for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"))
    return ProgramEnvironment(0x1000, bytes(arena), (*values, ("eflags", 2)), 0, 0)


def run(code: bytes, *, outputs: bool = False, limit: int = 100):
    boot = program_from_mz_bytes(mz(code), environment())
    observations = (ProgramObservation("buffer", LinearRange(0x10200, 1)),) if outputs else ()
    return replay_program(boot, observations=observations, instruction_limit=limit)


@pytest.mark.parametrize("code", ["0f31", "0fa2", "0fc7f0", "0fc7f8", "0f01f9", "0f01d0",
                                  "660fc7f0", "660fc7f8"])
def test_undeclared_machine_inputs_refuse_before_program_execution(code: str) -> None:
    """Process termination cannot hide preceding undeclared machine inputs."""
    result = run(bytes.fromhex(code + "b8004ccd21"))
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[0].kind is ProgramEventKind.UNSUPPORTED_INSTRUCTION
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_header_entry_and_stack_execute_without_a_caller_frame():
    boot = program_from_mz_bytes(mz(bytes.fromhex("90b8074ccd21"), entry_ip=1), environment())
    result = replay_program(boot, observations=(ProgramObservation("stack", LinearRange(0x11100, 4)),))
    assert result.status is ProgramStatus.TERMINATED
    assert result.exit_code == 7
    assert result.observations == (("stack", b"\xA5" * 4),)
    # No caller frame was invented; the executed DOS INT leaves its own frame.
    assert result.writes == ((0x110FA, bytes.fromhex("060010100200")),)
    regs = dict(result.registers)
    assert (regs["cs"], regs["ss"], regs["ds"], regs["es"], regs["sp"]) == (0x1010, 0x1010, 0x1000, 0x1000, 0x1000)
    assert result.events[0].kind is ProgramEventKind.DOS_EXIT
    assert compare_programs(result, result) is ProgramAgreement.AGREED


def test_equivalent_changed_program_keeps_initial_data_and_output():
    # DS becomes CS, the existing arena byte at offset100 is incremented, and
    # AL is returned through DOS4C. The second program changes internal BX only.
    oracle = run(bytes.fromhex("0e1fa000010401a20001b44ccd21"), outputs=True)
    candidate = run(bytes.fromhex("0e1fa000010401a20001bb004c88fccd21"), outputs=True)
    assert oracle.status is candidate.status is ProgramStatus.TERMINATED
    assert oracle.observations == candidate.observations == (("buffer", b"\x04"),)
    assert oracle.exit_code == candidate.exit_code == 4
    assert dict(oracle.registers)["bx"] != dict(candidate.registers)["bx"]
    assert compare_programs(oracle, candidate) is ProgramAgreement.AGREED
    assert oracle.boot_identity != candidate.boot_identity
    assert oracle.environment_identity == candidate.environment_identity


@pytest.mark.parametrize("candidate", ["b8084ccd21", "b8074ccd21"])
def test_exit_and_declared_output_mutations_are_rejected(candidate):
    oracle = run(bytes.fromhex("0e1fc606000104b8074ccd21"), outputs=True)
    changed = run(bytes.fromhex(candidate), outputs=True)
    assert compare_programs(oracle, changed) is ProgramAgreement.MISMATCHED


@pytest.mark.parametrize("code", ["b409cd21", "b8074ccd20", "e480b8074ccd21", "666d", "666f", "f4", "c3"])
def test_unknown_services_ports_halt_and_bare_ret_do_not_agree(code):
    result = run(bytes.fromhex(code))
    assert result.status is ProgramStatus.UNSUPPORTED
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_divide_fault_and_nontermination_keep_distinct_outcomes():
    terminated = run(bytes.fromhex("b8074ccd21"))
    faulted = run(bytes.fromhex("31dbf7f3"))
    assert faulted.status is ProgramStatus.FAULTED
    assert compare_programs(terminated, faulted) is ProgramAgreement.MISMATCHED
    assert compare_programs(faulted, faulted) is ProgramAgreement.INCOMPLETE
    exhausted = run(bytes.fromhex("ebfe"), limit=5)
    assert exhausted.status is ProgramStatus.BUDGET_EXHAUSTED
    assert exhausted.instructions == 5
    assert compare_programs(terminated, exhausted) is ProgramAgreement.INCOMPLETE


def test_padding_access_and_instruction_writes_refuse():
    # DS is PSP and offset2000 is just beyond the exact allocation.
    outside = run(bytes.fromhex("a00020b8074ccd21"))
    assert outside.status is ProgramStatus.UNSUPPORTED
    assert outside.events[0].kind is ProgramEventKind.UNDECLARED_ACCESS
    code_write = run(bytes.fromhex("0e1fc606000090b8074ccd21"))
    assert code_write.status is ProgramStatus.UNSUPPORTED
    assert code_write.events[0].kind is ProgramEventKind.CODE_WRITE


def test_fresh_program_runs_and_complete_output_denominator():
    code = bytes.fromhex("0e1fa000010401a20001b44ccd21")
    first = run(code, outputs=True)
    second = run(code, outputs=True)
    assert first == second
    assert compare_programs(first, replace(second, observations=())) is ProgramAgreement.INCOMPLETE
    assert compare_programs(first, replace(second, events=())) is ProgramAgreement.INCOMPLETE
    assert compare_programs(first, replace(second, exit_code=None)) is ProgramAgreement.INCOMPLETE
    assert compare_programs(first, replace(second, environment_identity="foreign")) is ProgramAgreement.INCOMPLETE


def test_observations_do_not_change_guest_execution():
    code = bytes.fromhex("0e1fa000010401a20001b44ccd21")
    observed, plain = run(code, outputs=True), run(code)
    assert (observed.status, observed.registers, observed.writes, observed.events) == (
        plain.status, plain.registers, plain.writes, plain.events
    )
