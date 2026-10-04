"""Public PE32-to-PE32 different-shape loop acceptance.

Layer: tests.
Responsibility: exercise both actual comparator drivers with serialized PE32
images, full modeled register outputs, real loading/lifting/Z3 and an
equivalent rotation plus observable stride corruption. Image/startup relations
remain separately unknown when bytes differ.
"""
from __future__ import annotations

import hashlib
import struct
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest
from test_flat32_comparator_lane import _driver_lane
from test_flat32_loaded_byte_boundaries import pe32_bytes

from tools.dosunit.binary_initial_state import InitialImageReason
from tools.dosunit.flat32_memory_permissions import DeclaredAccess
from tools.dosunit.pe32_program_boot import PeProgramEnvironment, PeProgramMemory, pe_program_from_bytes
from tools.dosunit.pe32_program_replay import replay_pe_program
from tools.dosunit.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.real16_program_model import ProgramResult, ProgramStatus

ENTRY = 0x401000
ORACLE = bytes.fromhex("e3088d5b018d49ffebf6c3")
ROTATED = bytes.fromhex("eb068d5b018d49ffe302ebf6c3")
STRIDE_MUTATION = bytes.fromhex("eb068d5b028d49ffe302ebf6c3")
MATCHED_STRIDE_MUTATION = bytes.fromhex("e3088d5b028d49ffebf6c3")


def _image(directory: Path, name: str, code: bytes) -> tuple[Path, Path]:
    """Write genuine PE32 bytes and optional exact function boundary labels."""
    image = directory / f"{name}.exe"
    image.write_bytes(pe32_bytes(code))
    listing = directory / f"{name}.lst"
    listing.write_text(
        f".text:{ENTRY:08X} f proc\n"
        f".text:{ENTRY + len(code) - 1:08X} f endp\n"
    )
    return image, listing


def _compare(driver: str, directory: Path, candidate_code: bytes) -> dict[str, Any]:
    """Run one production driver using actual PE files and both boundary lists."""
    oracle, oracle_lst = _image(directory, "oracle", ORACLE)
    candidate, candidate_lst = _image(directory, "candidate", candidate_code)
    with _driver_lane(driver) as lane:
        outputs = tuple(name for name, _width in lane.adapter.REG32.values())
        args = Namespace(
            oracle_exe=oracle, oracle_lst=oracle_lst, candidate_exe=candidate,
            candidate_lst=candidate_lst, candidate_syms=None,
            cache_dir=directory / "cache", functions="f", mode="matched-cfg",
            output_regs=",".join(outputs), scan_limit=0x1000,
            timeout_ms=30000, region_max_blocks=128, normalize_globals=False,
            assume_paired_calls=False, out_dir=directory / "out",
        )
        args.out_dir.mkdir()
        with lane.adapter.installed(region=False):
            report = lane.z3cmp32.compare(args)
        assert set(outputs) <= set(report["proof_contract"]["outputs"])
    assert report["summary"]["total"] == len(report["results"]) == 1
    assert report["results"][0]["function"]["name"] == "f"
    for side, path in (("oracle", oracle), ("candidate", candidate)):
        identity = report["loaded_images"][side]
        assert identity["architecture"] == "X86" and identity["width"] == 32
        assert identity["loader"] in {"PE", "InclusivePE"}
        assert report["inputs"][side]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    relation = report["initial_image_relation"]
    assert ProofStatus(relation["status"]) is ProofStatus.UNKNOWN
    assert InitialImageReason(relation["reason"]) is InitialImageReason.RELATION_REQUIRED
    assert ProofStatus(relation["initialized_function_status"]) is ProofStatus.UNKNOWN
    assert relation["startup_and_environment_proved"] is False
    assert report["proof_scope"] == "requested_functions_over_shared_input_memory"
    return report


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_public_pe32_loop_rotation_proves(driver: str, tmp_path: Path) -> None:
    """Equivalent PE32 loops prove through each unchanged production driver."""
    report = _compare(driver, tmp_path, ROTATED)
    assert proof_status_from_legacy(report["results"][0]["status"]) is ProofStatus.PROVED, report
    assert ProofStatus(report["proof_evidence"]["status"]) is ProofStatus.PROVED


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_public_pe32_loop_stride_mutation_never_proves(driver: str, tmp_path: Path) -> None:
    """Changing the stride cannot discharge the PE32 rotation obligation."""
    report = _compare(driver, tmp_path, STRIDE_MUTATION)
    assert proof_status_from_legacy(report["results"][0]["status"]) is not ProofStatus.PROVED, report
    assert ProofStatus(report["proof_evidence"]["status"]) is not ProofStatus.PROVED


def _native(code: bytes, count: int) -> ProgramResult:
    """Execute a real initialized PE with an explicit immutable return stack."""
    stack = 0x10001000
    exit_address = 0x70000000
    allocation = bytearray(b"\xa5" * 0x2000)
    struct.pack_into("<III", allocation, 0x1000, exit_address, 0, 0)
    registers = tuple(sorted({
        "eax": 0x12345678, "ebx": 0xFFFFFFFE, "ecx": count, "edx": 0x87654321,
        "esi": 0x11111111, "edi": 0x22222222, "ebp": stack + 0x100,
        "esp": stack, "eflags": 0x202,
    }.items()))
    environment = PeProgramEnvironment(
        registers, (PeProgramMemory(stack - 0x1000, bytes(allocation),
                                    DeclaredAccess.READ | DeclaredAccess.WRITE),),
        exit_address,
    )
    boot = pe_program_from_bytes(pe32_bytes(code), environment)
    return replay_pe_program(boot, instruction_limit=6 * count + 16)


@pytest.mark.parametrize("count", [0, 1, 3, 255])
def test_pe32_rotation_independent_execution(count: int) -> None:
    """Fresh actual PE runs agree across rotation and expose stride wraparound."""
    original = _native(ORACLE, count)
    equivalent = _native(ROTATED, count)
    corrupted = _native(STRIDE_MUTATION, count)
    assert all(result.status is ProgramStatus.TERMINATED
               for result in (original, equivalent, corrupted))
    assert original.registers == equivalent.registers
    assert original.events == equivalent.events
    assert original.environment_identity == equivalent.environment_identity == corrupted.environment_identity
    assert dict(original.registers)["ebx"] == (0xFFFFFFFE + count) & 0xFFFFFFFF
    assert (original.registers != corrupted.registers) is (count != 0)
    assert original == _native(ORACLE, count)


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_public_pe32_same_shape_stride_retains_failed_obligation(driver: str, tmp_path: Path) -> None:
    """Preserve failed transition evidence and independently replay corruption."""
    report = _compare(driver, tmp_path, MATCHED_STRIDE_MUTATION)
    row = report["results"][0]
    assert proof_status_from_legacy(row["status"]) is not ProofStatus.PROVED, row
    assert proof_status_from_legacy(row["backend_status"]) is ProofStatus.COUNTEREXAMPLE, row
    assert any(proof_status_from_legacy(block["status"]) is ProofStatus.COUNTEREXAMPLE
               for block in row["block_verdicts"])
    original = _native(ORACLE, 1)
    corrupted = _native(MATCHED_STRIDE_MUTATION, 1)
    assert original.status is corrupted.status is ProgramStatus.TERMINATED
    assert original.environment_identity == corrupted.environment_identity
    assert original.registers != corrupted.registers
