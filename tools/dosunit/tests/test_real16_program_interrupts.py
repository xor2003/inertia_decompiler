"""INT21 summaries must retain the architectural stack bytes visible to code."""

from dataclasses import replace

import pytest
from tools.dosunit.tests.test_real16_program_input_integration import input_environment
from tools.dosunit.tests.test_real16_program_replay import environment, mz

from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_program_interrupts import InterruptFrame, program_interrupt_frame
from tools.dosunit.runtime.real16_program_memory import ProgramMemoryLayout
from tools.dosunit.runtime.real16_program_model import ProgramObservation, ProgramStatus
from tools.dosunit.runtime.real16_program_output import OutputPolicy
from tools.dosunit.runtime.real16_program_replay import replay_program
from tools.dosunit.runtime.real16_program_version import VersionPolicy
from tools.dosunit.runtime.real16_replay_model import LinearRange, SegOffset


def test_returning_service_frame_is_visible_to_following_instructions():
    # Query at IP3 returns to IP5; read the pushed IP from SS:SP-6 before exit.
    code = bytes.fromhex("b80030cd2189e5368b46fab44ccd21")
    env = replace(environment(), version_policy=VersionPolicy(5, 0, 255, 0))
    result = replay_program(program_from_mz_bytes(mz(code), env))
    assert result.status is ProgramStatus.TERMINATED
    assert result.exit_code == 5


def test_output_service_reads_its_own_interrupt_frame_before_return():
    # DS=SS; output the return IP word from SS:0FFA (current SP-6).
    code = bytes.fromhex("161fbb0100b90200bafa0fb440cd21b8004ccd21")
    env = replace(environment(), output_policy=OutputPolicy(frozenset({1}), 8, 8))
    result = replay_program(program_from_mz_bytes(mz(code), env))
    assert result.status is ProgramStatus.TERMINATED
    assert result.events[0].data == b"\x01\x0f\x00"


def test_exit_retains_interrupt_frame_memory_for_declared_observations():
    boot = program_from_mz_bytes(mz(bytes.fromhex("b8004ccd21")), environment())
    result = replay_program(boot, observations=(
        ProgramObservation("frame", LinearRange(boot.stack.linear() - 6, 6)),
    ))
    assert result.status is ProgramStatus.TERMINATED
    assert result.observations == (("frame", bytes.fromhex("050010100200")),)


@pytest.mark.parametrize("stack_sp", [4, 8])
def test_interrupt_stack_wrap_or_code_overlap_refuses(stack_sp):
    boot = program_from_mz_bytes(mz(bytes.fromhex("b8004ccd21"), stack_sp=stack_sp), environment())
    result = replay_program(boot)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.writes == ()


def test_operand_size_prefixed_interrupt_is_not_summarized_as_six_bytes():
    result = replay_program(program_from_mz_bytes(mz(bytes.fromhex("b8004c66cd21")), environment()))
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.writes == ()


def test_file_read_cannot_overwrite_the_active_service_return_frame():
    # DS=SS; a read over the pushed return address needs handler-level control
    # semantics. Refuse before committing file bytes or its cursor.
    code = bytes.fromhex("161fbb0500b90200bafa0fb43fcd21b8004ccd21")
    result = replay_program(program_from_mz_bytes(mz(code), input_environment()))
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.events[-1].data == b"service_writes_interrupt_frame"
    assert result.input_file_positions == result.requested_input_files
    assert result.writes == ((0x110FA, bytes.fromhex("0f0010100200")),)


def test_frame_matches_captured_native_kvikdos_interrupt_entry():
    # Retained native startup witness: capture at 0110:1089 after INT21 at1087.
    # SS:SP06EA:1394, incoming FLAGS7246; actual RAM822E..8233 is below.
    frame = program_interrupt_frame(
        instruction=b"\xcd\x21", instruction_pointer=SegOffset(0x110, 0x1087),
        stack=SegOffset(0x6EA, 0x1394), flags=0x7246,
        memory=ProgramMemoryLayout(((0x822E, bytes(6)),)), code_ranges=(),
    )
    assert frame == InterruptFrame(0x822E, bytes.fromhex("891010014672"))
