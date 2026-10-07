"""Native-profile allocation changes must retain errors, metadata and refusals."""

import argparse
import json
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest
from tools.dosunit.tests.test_real16_program_replay import mz

from tools.dosunit.runtime.real16_program_boot import ProgramEnvironment, program_from_mz_bytes
from tools.dosunit.reporting.real16_program_cli import cmd_replay_program16
from tools.dosunit.runtime.real16_program_model import ProgramAgreement, ProgramEventKind, ProgramStatus, compare_programs
from tools.dosunit.runtime.real16_program_replay import replay_program
from tools.dosunit.runtime.real16_program_resize import (
    ResizeAccepted,
    ResizeRefusal,
    ResizeRefused,
    TailResizePolicy,
    parse_resize_policy,
    program_resize_call,
    resize_event_data,
    resize_policy_document,
    resize_receipt_complete,
)

MCB = bytes.fromhex("5a9201009f0000b24b56314b50523047")
POLICY = TailResizePolicy(0x100, MCB)


def environment(*, enabled: bool = True) -> ProgramEnvironment:
    """Declare every byte of the native tail block; policy is independently optional."""
    values = tuple((name, 0) for name in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"))
    return ProgramEnvironment(0x100, bytes(0x9F000), (*values, ("eflags", 2)), 0, 0,
                              resize_policy=POLICY if enabled else None)


def execute(code: str, *, enabled: bool = True):
    """Execute a real MZ load image with its own binary-derived entry/stack."""
    image = bytearray(mz(bytes.fromhex(code)))
    image[12:14] = b"\xff\xff"
    boot = program_from_mz_bytes(bytes(image), environment(enabled=enabled))
    return replay_program(boot, instruction_limit=100)


def resize_code(paragraphs: int) -> str:
    """Keep sentinel upper halves, perform resize, then terminate successfully."""
    return "66b8014a341266bb" + (0xABCD0000 | paragraphs).to_bytes(4, "little").hex() + "f9cd21b8004ccd21"


@pytest.mark.parametrize("paragraphs", [0, 1, 0x15EA, 0x9F00, 0x9F01, 0xFFFF])
def test_actual_resize_preserves_register_halves_and_metadata(paragraphs: int) -> None:
    result = execute(resize_code(paragraphs))
    assert result.status is ProgramStatus.TERMINATED
    event, exit_event = result.events
    assert event.kind is ProgramEventKind.DOS_RESIZE
    assert resize_receipt_complete(event.data)
    assert exit_event.kind is ProgramEventKind.DOS_EXIT
    regs = dict(result.registers)
    assert regs["eax"] == 0x12344C00
    assert regs["ebx"] == 0xABCD0000 | min(paragraphs, POLICY.maximum)
    assert bool(regs["eflags"] & 1) is (paragraphs > POLICY.maximum)
    assert regs["eflags"] == 2 | int(paragraphs > POLICY.maximum)
    expected = min(paragraphs, POLICY.maximum)
    assert event.data[-16:] == MCB[:3] + expected.to_bytes(2, "little") + MCB[5:]
    assert compare_programs(result, result) is ProgramAgreement.AGREED
    metadata = () if paragraphs >= POLICY.maximum else ((0xFF3, paragraphs.to_bytes(2, "little")),)
    exit_frame = bytes.fromhex("14001001") + (2 | int(paragraphs > POLICY.maximum)).to_bytes(2, "little")
    assert result.writes == (*metadata, (0x20FA, exit_frame))


def test_absent_policy_still_refuses_resize() -> None:
    result = execute(resize_code(0x15EA), enabled=False)
    assert result.status is ProgramStatus.UNSUPPORTED
    assert result.writes == ()
    assert compare_programs(result, result) is ProgramAgreement.INCOMPLETE


def test_changed_allocation_is_observable_even_with_identical_exit() -> None:
    left = execute(resize_code(0x15EA))
    right = execute(resize_code(0x15EB))
    assert left.exit_code == right.exit_code == 0
    assert compare_programs(left, right) is ProgramAgreement.MISMATCHED


def test_repeated_shrink_growth_retains_current_metadata_and_determinism() -> None:
    code = "b8014abb0100cd21b8014abb009fcd21b8004ccd21"
    first, second = execute(code), execute(code)
    assert first == second
    assert first.status is ProgramStatus.TERMINATED
    assert first.events[1].data[13:29] == MCB[:3] + b"\x01\0" + MCB[5:]
    assert first.events[1].data[-16:] == MCB


def test_physical_memory_after_shrink_is_not_an_invented_protected_arena() -> None:
    # Shrink ownership to one paragraph, then write beyond it in originally
    # supplied RAM. Real mode has no allocator-enforced memory protection.
    result = execute("b8014abb0100cd21c60600025ab8004ccd21")
    assert result.status is ProgramStatus.TERMINATED
    assert (0x1200, b"\x5a") in result.writes


def test_guest_metadata_corruption_returns_dos_error_without_overwrite() -> None:
    # ES=MCB segment; corrupt signature byte, restore ES=PSP and resize.
    result = execute("b8ff008ec026c606070000b800018ec0b8014abb0100cd21b8004ccd21")
    assert result.status is ProgramStatus.TERMINATED
    receipt = result.events[0].data
    assert receipt[8:10] == b"\x07\0"
    assert receipt[12] == 1
    assert receipt[13:29] == receipt[29:]
    assert resize_receipt_complete(receipt)


@pytest.mark.parametrize("offset,expected", [(15, ProgramStatus.TERMINATED), (-1, ProgramStatus.UNSUPPORTED)])
def test_metadata_scope_has_exact_physical_boundary(offset, expected) -> None:
    # A word crossing the adjacent declared MCB/PSP boundary is valid; the
    # byte immediately before the MCB is not supplied by the declaration.
    if offset == -1:
        code = "b8fe008ed8a00f00b8004ccd21"
    else:
        code = "b8ff008ed8a10f00b8004ccd21"
    result = execute(code)
    assert result.status is expected


def test_resize_receipt_does_not_admit_a_pe32_environment() -> None:
    result = execute(resize_code(1))
    pe_exit = replace(result.events[-1], kind=ProgramEventKind.PE_EXIT, data=bytes(4))
    forged = replace(result, events=(*result.events[:-1], pe_exit))
    assert compare_programs(forged, forged) is ProgramAgreement.INCOMPLETE


@pytest.mark.parametrize("segment,metadata,reason", [
    (0x101, MCB, ResizeRefusal.OTHER_BLOCK),
    (0x100, b"M" + MCB[1:], ResizeRefusal.CHAIN),
])
def test_incomplete_allocator_state_refuses(segment, metadata, reason) -> None:
    result = program_resize_call(POLICY, segment=segment, paragraphs=1, ax=0x4A01, metadata=metadata)
    assert result == ResizeRefused(reason)


@pytest.mark.parametrize("index", [0, 1, 7, 8, 10, 12, 29, 44])
def test_corrupted_receipt_cannot_establish_agreement(index: int) -> None:
    original = execute(resize_code(1))
    event = original.events[0]
    data = bytearray(event.data)
    data[index] ^= 0x80
    assert not resize_receipt_complete(bytes(data))
    bad = replace(original, events=(replace(event, data=bytes(data)), *original.events[1:]))
    assert compare_programs(bad, bad) is ProgramAgreement.INCOMPLETE


def test_policy_roundtrip_and_arena_binding() -> None:
    assert parse_resize_policy(resize_policy_document(POLICY)) == POLICY
    assert parse_resize_policy(None) is None
    with pytest.raises(ValueError, match="complete initial tail"):
        replace(environment(), allocation=bytes(0x2000))
    with pytest.raises(ValueError, match="requires profile"):
        parse_resize_policy({"profile": "kvikdos_single_tail"})
    with pytest.raises(ValueError, match="fixed loader PSP"):
        TailResizePolicy(0x200, MCB)
    with pytest.raises(ValueError, match="hexadecimal metadata"):
        parse_resize_policy({"profile": "kvikdos_single_tail", "segment": 256, "mcb_hex": MCB.hex(" ")})


def test_native_captured_transition_has_exact_response() -> None:
    """Retained native SORTDEMO transition, captured before resume IP1013."""
    result = program_resize_call(POLICY, segment=0x100, paragraphs=0x15EA, ax=0x4A01, metadata=MCB)
    assert result == ResizeAccepted(0x4A01, 0x15EA, False, bytes.fromhex("5a9201ea150000b24b56314b50523047"))
    assert resize_receipt_complete(resize_event_data(POLICY, 0x15EA, 0x4A01, MCB, result))


@pytest.mark.parametrize("changed", [False, True])
def test_public_resize_cli_and_schema_agree(tmp_path: Path, changed: bool) -> None:
    """The public manifest/report path must preserve allocator effects and verdicts."""
    env = environment()
    manifest = {"schema": "dosunit.real16_program_environment.v1", "environment": {
        "psp_segment": env.psp_segment, "allocation_hex": env.allocation.hex(),
        "registers": dict(env.registers), "fs": env.fs, "gs": env.gs,
        "dos_resize": resize_policy_document(POLICY),
    }}
    schemas = Path(__file__).resolve().parents[3] / "tools/dosunit/schemas"
    jsonschema.validate(manifest, json.loads((schemas / "dosunit.real16_program_environment.v1.schema.json").read_text()))
    env_file = tmp_path / "environment.json"
    env_file.write_text(json.dumps(manifest))
    paths = [tmp_path / "oracle.exe", tmp_path / "candidate.exe"]
    for path, paragraphs in zip(paths, (1, 2 if changed else 1), strict=True):
        image = bytearray(mz(bytes.fromhex(resize_code(paragraphs))))
        image[12:14] = b"\xff\xff"
        path.write_bytes(image)
    output = tmp_path / "result.json"
    assert cmd_replay_program16(argparse.Namespace(
        oracle_exe=paths[0], candidate_exe=paths[1], environment=env_file,
        instruction_limit=100, out=output,
    )) == int(changed)
    result = json.loads(output.read_text())
    jsonschema.validate(result, json.loads((schemas / "dosunit.real16_program_replay.v1.schema.json").read_text()))
    assert result["agreement"] == ("mismatched" if changed else "agreed")
    assert result["proof_status"] == "not_established_by_execution"
    assert result["contract"]["services"]["dos_resize"] == resize_policy_document(POLICY)
