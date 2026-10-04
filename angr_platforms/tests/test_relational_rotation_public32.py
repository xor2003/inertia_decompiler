"""Sealed public actual-ELF32 rotation reports for both production flat32 drivers.

Layer: tests.
Responsibility: drive the production MSC8/BC5 ``z3cmp32.compare`` public APIs
over real GNU-``as``/``ld`` ELF32 images — real CLE loading, real ``nm -S``
symbol sizes, real IDA-style ``.lst`` boundary labels — with no loader,
solver, symbol or boundary mocks.  The equivalent rotation must prove under
full REG32 outputs; the stride mutation must not prove.  The initialized-image
relation stays unproved because code bytes differ; that scope is asserted,
never weakened.
"""

from __future__ import annotations

import hashlib
import subprocess
from argparse import Namespace
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from test_flat32_comparator_lane import DriverLane, _driver_lane

from tools.dosunit.binary_initial_state import InitialImageReason
from tools.dosunit.proof_contracts import ProofStatus, proof_status_from_legacy

TEXT_BASE = 0x08048000
# All eight 32-bit GPRs: the full REG32 output contract, not a narrowed ABI.
FULL_REG32_OUTPUTS = "eax,ecx,edx,ebx,esp,ebp,esi,edi"

# jecxz +8 / lea ebx,[ebx+1] / lea ecx,[ecx-1] / jmp -10 / ret
ORACLE = "e3088d5b018d49ffebf6c3"
# Same loop entered through a rotation: jmp +6 / lea / lea / jecxz +2 / jmp -10 / ret
ROTATED = "eb068d5b018d49ffe302ebf6c3"
# Identical rotation but ebx strides by 2 — semantically different, must not prove.
STRIDE_MUTATION = "eb068d5b028d49ffe302ebf6c3"


@pytest.fixture(params=["msc8", "bc5"], ids=["msc8", "bc5"])
def lane(request: pytest.FixtureRequest) -> Iterator[DriverLane]:
    """Install each production driver through the shared lane seam."""
    with _driver_lane(str(request.param)) as installed_lane:
        yield installed_lane


def _build_elf(directory: Path, name: str, code_hex: str) -> Path:
    """Assemble exact machine bytes into a real ELF32 with a sized ``f`` symbol."""
    code = bytes.fromhex(code_hex)
    listing = ", ".join(f"0x{byte:02x}" for byte in code)
    source = directory / f"{name}.s"
    source.write_text(
        "\t.text\n"
        "\t.globl f\n"
        "\t.type f, @function\n"
        "f:\n"
        f"\t.byte {listing}\n"
        "\t.size f, . - f\n"
    )
    obj = directory / f"{name}.o"
    elf = directory / f"{name}.elf"
    subprocess.run(["as", "--32", "-o", str(obj), str(source)], check=True)
    subprocess.run(
        ["ld", "-m", "elf_i386", "-Ttext", hex(TEXT_BASE), "--entry", "f", "-o", str(elf), str(obj)],
        check=True,
    )
    return elf


def _nm_function_bounds(elf: Path, name: str = "f") -> tuple[int, int]:
    """Read the linked address and real assembler function size through nm -S."""
    output = subprocess.run(
        ["nm", "-S", "--defined-only", str(elf)], check=True, capture_output=True, text=True
    ).stdout
    for line in output.splitlines():
        parts = line.split()
        if len(parts) == 4 and parts[3] == name:
            return int(parts[0], 16), int(parts[1], 16)
        if len(parts) == 3 and parts[2] == name:
            return int(parts[0], 16), 0
    raise AssertionError(f"nm did not report {name} in {elf}")


def _write_lst(path: Path, name: str, address: int, size: int) -> Path:
    """Emit original IDA-style boundary labels; endp marks the last instruction."""
    path.write_text(
        f".text:{address:08X} {name} proc\n.text:{address + size - 1:08X} {name} endp\n"
    )
    return path


def _compare_public(lane: DriverLane, oracle_elf: Path, lst: Path, candidate_elf: Path,
                    out_dir: Path) -> dict[str, Any]:
    """Run the real sealed driver comparison; no mock anywhere in the chain."""
    out_dir.mkdir(parents=True, exist_ok=True)
    args = Namespace(
        oracle_exe=oracle_elf,
        candidate_exe=candidate_elf,
        oracle_lst=lst,
        candidate_lst=None,
        candidate_syms=None,
        cache_dir=out_dir / "cache",
        functions="f",
        mode="matched-cfg",
        output_regs=FULL_REG32_OUTPUTS,
        scan_limit=0x1000,
        timeout_ms=30000,
        region_max_blocks=128,
        normalize_globals=False,
        assume_paired_calls=False,
        out_dir=out_dir,
    )
    with lane.adapter.installed(region=False):
        return lane.z3cmp32.compare(args)


def _sealed_report(lane: DriverLane, work: Path, candidate_hex: str) -> dict[str, Any]:
    """Build both real ELF32 inputs and return the sealed public report."""
    oracle_elf = _build_elf(work, "oracle", ORACLE)
    candidate_elf = _build_elf(work, "candidate", candidate_hex)
    address, size = _nm_function_bounds(oracle_elf)
    assert size == len(bytes.fromhex(ORACLE))
    lst = _write_lst(work / "oracle.lst", "f", address, size)
    return _compare_public(lane, oracle_elf, lst, candidate_elf, work / "out")


def _single_verdict(report: dict[str, Any]) -> dict[str, Any]:
    """Return the one sealed obligation verdict for ``f``; count must be exact."""
    rows = report["results"]
    assert report["summary"]["total"] == 1
    assert len(rows) == 1
    assert rows[0]["function"]["name"] == "f"
    return rows[0]


def _assert_unproved_distinct_images(report: dict[str, Any]) -> None:
    """Code bytes differ, so the initialized-image relation must stay unproved."""
    relation = report["initial_image_relation"]
    assert ProofStatus(relation["status"]) is ProofStatus.UNKNOWN
    assert InitialImageReason(relation["reason"]) is InitialImageReason.RELATION_REQUIRED
    assert ProofStatus(relation["initialized_function_status"]) is ProofStatus.UNKNOWN
    assert relation["startup_and_environment_proved"] is False
    assert report["proof_scope"] == "requested_functions_over_shared_input_memory"
    images = report["loaded_images"]
    assert images["oracle"]["loader"] == "ELF"
    assert images["oracle"]["architecture"] == "X86" and images["oracle"]["width"] == 32
    assert images["oracle"]["sha256"] != images["candidate"]["sha256"]
    assert report["inputs"]["oracle"]["sha256"] != report["inputs"]["candidate"]["sha256"]


def test_public32_rotated_elf_proves(lane: DriverLane, tmp_path: Path) -> None:
    """The rotated equivalent proves under full REG32 outputs on a real ELF32."""
    report = _sealed_report(lane, tmp_path, ROTATED)
    row = _single_verdict(report)
    assert lane.verdict.Status(row["status"]) is lane.verdict.Status.PASSED, report
    proof = report["proof_evidence"]
    assert ProofStatus(proof["status"]) is ProofStatus.PROVED
    verdicts = proof["verdicts"]
    assert len(verdicts) == 1 and verdicts[0]["id"]["key"] == "f"
    assert ProofStatus(verdicts[0]["status"]) is ProofStatus.PROVED
    contract = proof["contract"]
    assert contract["original_hash"] == hashlib.sha256(
        (tmp_path / "oracle.elf").read_bytes()).hexdigest()
    assert contract["candidate_hash"] == hashlib.sha256(
        (tmp_path / "candidate.elf").read_bytes()).hexdigest()
    assert set(FULL_REG32_OUTPUTS.split(",")) <= set(report["proof_contract"]["outputs"])
    assert str(lane.directory) in str(report["semantic_sources"])
    _assert_unproved_distinct_images(report)


def test_public32_stride_mutation_never_proves(lane: DriverLane, tmp_path: Path) -> None:
    """The stride-2 mutation cannot discharge the same proof obligation."""
    report = _sealed_report(lane, tmp_path, STRIDE_MUTATION)
    row = _single_verdict(report)
    assert proof_status_from_legacy(row["status"]) is not ProofStatus.PROVED, report
    proof = report["proof_evidence"]
    assert ProofStatus(proof["status"]) is not ProofStatus.PROVED
    assert all(ProofStatus(verdict["status"]) is not ProofStatus.PROVED
               for verdict in proof["verdicts"])
    _assert_unproved_distinct_images(report)
