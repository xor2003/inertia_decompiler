"""Layer: tests.
Responsibility: retain missing M4 binary corruption and exhaustion obligations.
"""
from __future__ import annotations

import hashlib
import json
import struct
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest
from tools.dosunit.tests.test_dosunit_tool import _edge_catalog, _mz_exe
from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes
from tools.dosunit.tests.test_relational_pe32_public import _image
from tools.dosunit.tests.test_relational_saved_public32 import EXIT_MUTATION
from tools.dosunit.tests.test_relational_saved_public32 import ORACLE as SAVED_ORACLE

from tools.dosunit.compare.flat32_invariant_retry import InvariantSearchReason
from tools.dosunit.runtime.flat32_memory_permissions import DeclaredAccess
from tools.dosunit.runtime.pe32_program_boot import PeProgramEnvironment, PeProgramMemory, pe_program_from_bytes
from tools.dosunit.runtime.pe32_program_replay import replay_pe_program
from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.compare.real16_binary_compare import compare_binary16
from tools.dosunit.runtime.real16_mz_load import image_from_mz_bytes
from tools.dosunit.runtime.real16_program_model import ProgramStatus
from tools.dosunit.runtime.real16_replay import replay
from tools.dosunit.runtime.real16_replay_model import CallerFrame, FrameKind, Real16ReplayStatus, Real16Vector, SegOffset

# No rendered-code recovery: these are exact assembled fixture bytes.
PAIRS = {
    "real16": {
        "nontermination": ("e3098d5f01678d49ffebf5c3", "e3098d5f01678d4900ebf5c3"),
        "off_by_one": ("83f90076098d5f01678d49ffebf2c3", "83f90176098d5f01678d49ffebf2c3"),
        "signedness": ("e30c8d5f01678d49ff83fb0077f2c3", "e30c8d5f01678d49ff83fb007ff2c3"),
        "wraparound": ("e3098d5f01678d49ffebf5c3", "e30b66678d5b01678d49ffebf3c3"),
    },
    "pe32": {
        "nontermination": ("e3088d5b018d49ffebf6c3", "e3088d5b018d4900ebf6c3"),
        "off_by_one": ("83f90076088d5b018d49ffebf3c3", "83f90176088d5b018d49ffebf3c3"),
        "signedness": ("e30b8d5b018d49ff83fb0077f3c3", "e30b8d5b018d49ff83fb007ff3c3"),
    },
}


def _real16_report(directory: Path, left: bytes, right: bytes) -> dict[str, Any]:
    """Use current public real16 comparison with the existing 60000ms budget."""
    paths, catalogs = [], []
    for side, code in (("oracle", left), ("candidate", right)):
        path = directory / f"{side}.exe"
        path.write_bytes(_mz_exe(bytes(0x200) + code))
        paths.append(path)
        catalogs.append(_edge_catalog("demo.exe:loop", "loop", offset=0x200, size=len(code)))
    return compare_binary16(*paths, *catalogs, solver_timeout_ms=60000)


def _pe32_report(driver: str, directory: Path, left: bytes, right: bytes) -> dict[str, Any]:
    """Exercise actual PE32 loading and either unchanged production driver."""
    oracle, oracle_lst = _image(directory, "oracle", left)
    candidate, candidate_lst = _image(directory, "candidate", right)
    with _driver_lane(driver) as lane:
        outputs = tuple(name for name, _ in lane.adapter.REG32.values())
        args = Namespace(oracle_exe=oracle, oracle_lst=oracle_lst,
                         candidate_exe=candidate, candidate_lst=candidate_lst, candidate_lst_end_kind="last-instruction",
                         candidate_syms=None, cache_dir=directory / "cache", functions="f",
                         mode="matched-cfg", output_regs=",".join(outputs), scan_limit=0x1000,
                         timeout_ms=30000, region_max_blocks=128, normalize_globals=False,
                         assume_paired_calls=False, out_dir=directory / "out")
        args.out_dir.mkdir()
        with lane.adapter.installed(region=False):
            report = lane.z3cmp32.compare(args)
        assert set(outputs) <= set(report["proof_contract"]["outputs"])
    assert report["summary"]["total"] == len(report["results"]) == 1
    for side, path in (("oracle", oracle), ("candidate", candidate)):
        assert report["inputs"][side]["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        assert report["loaded_images"][side]["loader"] in {"PE", "InclusivePE"}
    assert ProofStatus(report["initial_image_relation"]["status"]) is ProofStatus.UNKNOWN
    assert report["proof_scope"] == "requested_functions_over_shared_input_memory"
    return report


def _native16(code: bytes, count: int, bx: int) -> dict[str, int]:
    """Run a finite exact-MZ witness under independent native execution."""
    image = image_from_mz_bytes(_mz_exe(bytes(0x200) + code))
    entry = SegOffset(image.load_segment, 0x200)
    vector = Real16Vector(registers=(("cx", count), ("bx", bx), ("sp", 0x1000), ("flags", 2)),
                          segments=(("ss", 0x7000), ("ds", image.load_segment), ("es", image.load_segment)),
                          frame=CallerFrame(FrameKind.NEAR16, SegOffset(image.load_segment, 0x8000)))
    result = replay(image, entry, vector, instruction_limit=100)
    assert result.status is Real16ReplayStatus.RETURNED, result
    return dict(result.registers)


def _native32(code: bytes, count: int, bx: int) -> dict[str, int]:
    """Run a finite exact-PE32 witness with declared entry registers and stack."""
    stack, exit_address = 0x10001000, 0x70000000
    allocation = bytearray(b"\xa5" * 0x2000)
    struct.pack_into("<III", allocation, 0x1000, exit_address, 0, 0)
    registers = tuple(sorted({"eax": 0x12345678, "ebx": bx, "ecx": count,
                              "edx": 0x87654321, "esi": 0x11111111, "edi": 0x22222222,
                              "ebp": stack + 0x100, "esp": stack, "eflags": 0x202}.items()))
    environment = PeProgramEnvironment(registers, (PeProgramMemory(stack - 0x1000, bytes(allocation),
                                           DeclaredAccess.READ | DeclaredAccess.WRITE),), exit_address)
    result = replay_pe_program(pe_program_from_bytes(pe32_bytes(code), environment), instruction_limit=100)
    assert result.status is ProgramStatus.TERMINATED, result
    return dict(result.registers)


def _save(directory: Path, architecture: str, case: str, left: bytes, right: bytes,
          report: dict[str, Any], witness: dict[str, object] | None = None) -> None:
    """Retain exact bytes and full reports before assertions can fail."""
    receipt = {"architecture": architecture, "case": case, "oracle_hex": left.hex(),
               "candidate_hex": right.hex(), "report": report, "finite_witness": witness,
               "binary_hashes": {side: hashlib.sha256((directory / f"{side}.exe").read_bytes()).hexdigest()
                                 for side in ("oracle", "candidate")}}
    (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


@pytest.mark.parametrize("architecture", ["real16", "msc8", "bc5"])
@pytest.mark.parametrize("case", ["nontermination", "off_by_one", "signedness"])
def test_public_m4_missing_corruption_cells(tmp_path: Path, architecture: str, case: str) -> None:
    """Full binary obligations cannot admit stalled progress or changed exit guards."""
    track = "real16" if architecture == "real16" else "pe32"
    left, right = (bytes.fromhex(code) for code in PAIRS[track][case])
    report = _real16_report(tmp_path, left, right) if track == "real16" else _pe32_report(architecture, tmp_path, left, right)
    _save(tmp_path, architecture, case, left, right, report)
    status = ProofStatus(report["status"]) if track == "real16" else proof_status_from_legacy(report["results"][0]["status"])
    assert status in (ProofStatus.UNKNOWN, ProofStatus.COUNTEREXAMPLE), report
    if track == "pe32":
        assert ProofStatus(report["proof_evidence"]["status"]) is not ProofStatus.PROVED
    if case != "nontermination":
        count = 1 if case == "off_by_one" else 2
        bx = 0 if case == "off_by_one" else (0x7FFF if track == "real16" else 0x7FFFFFFF)
        execute = _native16 if track == "real16" else _native32
        original, corrupted = execute(left, count, bx), execute(right, count, bx)
        _save(tmp_path, architecture, case, left, right, report,
              {"input_count": count, "input_bx": bx, "oracle": original, "candidate": corrupted})
        assert original != corrupted
        output = "bx" if track == "real16" else "ebx"
        assert original[output] == bx + count
        assert corrupted[output] == bx + count - 1


def test_real16_wrapping_word_cannot_be_replaced_by_dword_increment(tmp_path: Path) -> None:
    """A 16-bit wrap differs from 32-bit carry in the retained high register half."""
    left, right = (bytes.fromhex(code) for code in PAIRS["real16"]["wraparound"])
    report = _real16_report(tmp_path, left, right)
    _save(tmp_path, "real16", "wraparound", left, right, report)
    assert ProofStatus(report["status"]) in (ProofStatus.UNKNOWN, ProofStatus.COUNTEREXAMPLE), report
    original, corrupted = _native16(left, 1, 0xFFFF), _native16(right, 1, 0xFFFF)
    _save(tmp_path, "real16", "wraparound", left, right, report,
          {"input_count": 1, "input_bx": 0xFFFF, "oracle": original, "candidate": corrupted})
    assert original["ebx"] == 0 and corrupted["ebx"] == 0x10000


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_actual_pe32_invariant_exhaustion_remains_unknown(tmp_path: Path, driver: str) -> None:
    """Actual-PE saved-slot corruption exhausts unproved invariant candidates."""
    left, right = bytes.fromhex(SAVED_ORACLE), bytes.fromhex(EXIT_MUTATION)
    report = _pe32_report(driver, tmp_path, left, right)
    _save(tmp_path, driver, "invariant_exhaustion", left, right, report)
    row = report["results"][0]
    assert proof_status_from_legacy(row["status"]) is ProofStatus.UNKNOWN, row
    assert ProofStatus(report["proof_evidence"]["status"]) is ProofStatus.UNKNOWN
    retry = row["additional_proof_attempts"]["reblocked_cfg"]
    assert proof_status_from_legacy(retry["status"]) is ProofStatus.UNKNOWN
    search = retry["invariant_search"]
    assert InvariantSearchReason(search["reason"]) is InvariantSearchReason.EXHAUSTED
    assert search["complete"] is True
    assert search["attempted_count"] > 0
    assert search["attempted_count"] == search["proposed_count"]
