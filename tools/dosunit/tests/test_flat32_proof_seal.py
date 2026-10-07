"""Seal-failure negative controls for the flat32 proof-report boundary.

Layer: tests.
Responsibility: boundary-function controls over the real
``run_bound_comparison`` seal owner in ``flat32_proof_report``. A controlled
backend callback runs under real temporary PE32 bytes and real owned-source
hashing so that binary drift, semantic-source drift and a missing or malformed
requested-function manifest can never publish a sealed report. These are not
assembled end-to-end equivalence proofs: the backend evidence itself is a
fixed refused row and only the seal ordering is under test.
"""

from __future__ import annotations

import hashlib
import json
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest
from tools.dosunit.tests.test_flat32_comparator_lane import DRIVER_DIRS
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes

from tools.dosunit.reporting.flat32_proof_report import run_bound_comparison
from tools.dosunit.contracts.proof_contracts import ProofStatus

# mov eax,7; ret — arbitrary genuine i386 code; the seal binds bytes, not semantics.
CODE = bytes.fromhex("b807000000c3")
DRIFTED = bytes.fromhex("b808000000c3")

# Sibling names ``_semantic_sources`` reads next to the driver file.
_DRIVER_SIBLINGS = ("flat32_adapter.py", "flat32_cfg.py", "flat32_region.py", "flat32_verdict.py")

def _pe_pair(tmp_path: Path) -> tuple[Path, Path]:
    """Write two identical real PE32 images and return their paths."""
    oracle = tmp_path / "oracle.exe"
    candidate = tmp_path / "candidate.exe"
    oracle.write_bytes(pe32_bytes(CODE))
    candidate.write_bytes(pe32_bytes(CODE))
    return oracle, candidate


def _args(oracle: Path, candidate: Path, out_dir: Path) -> Namespace:
    """Build the minimal driver namespace ``run_bound_comparison`` requires."""
    out_dir.mkdir()
    return Namespace(oracle_exe=oracle, candidate_exe=candidate, mode="region",
                     output_regs="eax,esp", out_dir=out_dir)


def _backend(_args: Namespace) -> dict[str, Any]:
    """One fixed refused backend row; consistent summary counters included."""
    return {
        "requested_functions": ["f"],
        "results": [{"function": {"name": "f"}, "status": "refused", "reason": "x"}],
        "summary": {"total": 1, "passed": 0, "failed": 0, "refused": 1, "conditional": 0},
        "function_ranges": {"oracle": {}, "candidate": {}},
        "loaded_images": {},
    }


def _driver_dir(tmp_path: Path, tag: str = "driver") -> Path:
    """Create a private driver directory whose files the seal may hash/mutate."""
    directory = tmp_path / tag
    directory.mkdir()
    (directory / "z3cmp32.py").write_text("# staged driver\n")
    for name in _DRIVER_SIBLINGS:
        (directory / name).write_text(f"# staged {name}\n")
    return directory / "z3cmp32.py"


def test_no_drift_seals_and_publishes_report(tmp_path: Path) -> None:
    """Valid control: unchanged inputs produce a sealed report on disk."""
    oracle, candidate = _pe_pair(tmp_path)
    out_dir = tmp_path / "out"
    driver = DRIVER_DIRS["msc8"] / "z3cmp32.py"
    report = run_bound_comparison(_backend, _args(oracle, candidate, out_dir), driver)
    proof = report["proof_evidence"]
    assert ProofStatus(proof["status"]) is ProofStatus.UNKNOWN
    assert proof["verdicts"][0]["id"]["key"] == "f"
    assert proof["contract"]["key"]
    assert report["inputs"]["oracle"]["sha256"] == hashlib.sha256(oracle.read_bytes()).hexdigest()
    assert report["inputs"]["candidate"]["sha256"] == hashlib.sha256(candidate.read_bytes()).hexdigest()
    assert report["semantic_sources"][str(driver)] == hashlib.sha256(driver.read_bytes()).hexdigest()
    sealed = json.loads((out_dir / "compare.json").read_text())
    assert sealed["proof_evidence"]["contract"] == proof["contract"]


@pytest.mark.parametrize("side", ["oracle", "candidate"])
def test_binary_drift_cannot_be_sealed(side: str, tmp_path: Path) -> None:
    """A backend mutating either input mid-proof must fail, publishing nothing."""
    oracle, candidate = _pe_pair(tmp_path)
    out_dir = tmp_path / "out"
    target = {"oracle": oracle, "candidate": candidate}[side]

    def drifting(args: Namespace) -> dict[str, Any]:
        target.write_bytes(pe32_bytes(DRIFTED))
        return _backend(args)

    with pytest.raises(RuntimeError, match="binary changed during the proof"):
        run_bound_comparison(drifting, _args(oracle, candidate, out_dir),
                             DRIVER_DIRS["msc8"] / "z3cmp32.py")
    assert not (out_dir / "compare.json").exists()


def test_semantic_source_drift_cannot_be_sealed(tmp_path: Path) -> None:
    """Editing an owned source mid-proof must fail against a private driver dir."""
    oracle, candidate = _pe_pair(tmp_path)
    out_dir = tmp_path / "out"
    driver = _driver_dir(tmp_path)
    victim = driver.parent / "flat32_cfg.py"

    def drifting(args: Namespace) -> dict[str, Any]:
        victim.write_text(victim.read_text() + "# drifted\n")
        return _backend(args)

    with pytest.raises(RuntimeError, match="comparator sources changed during the proof"):
        run_bound_comparison(drifting, _args(oracle, candidate, out_dir), driver)
    assert not (out_dir / "compare.json").exists()


@pytest.mark.parametrize(
    "manifest",
    ["absent", "not_list", "non_string_entry", "empty_name"],
)
def test_missing_or_malformed_function_manifest_cannot_be_sealed(
    manifest: str, tmp_path: Path,
) -> None:
    """A backend dropping or corrupting requested_functions must fail."""
    oracle, candidate = _pe_pair(tmp_path)
    out_dir = tmp_path / "out"

    def backend(_args: Namespace) -> dict[str, Any]:
        raw = _backend(_args)
        if manifest == "absent":
            del raw["requested_functions"]
        elif manifest == "not_list":
            raw["requested_functions"] = "f"
        elif manifest == "non_string_entry":
            raw["requested_functions"] = ["f", 7]
        else:
            raw["requested_functions"] = ["f", ""]
        return raw

    with pytest.raises(RuntimeError, match="requested-function manifest"):
        run_bound_comparison(backend, _args(oracle, candidate, out_dir),
                             DRIVER_DIRS["msc8"] / "z3cmp32.py")
    assert not (out_dir / "compare.json").exists()


@pytest.mark.parametrize("restore", [False, True], ids=["drift", "read-and-restore"])
def test_link_map_drift_cannot_be_sealed(restore: bool, tmp_path: Path) -> None:
    """A map consumed under a different identity cannot publish proof evidence."""
    oracle, candidate = _pe_pair(tmp_path)
    out_dir = tmp_path / "out"
    args = _args(oracle, candidate, out_dir)
    link_map = tmp_path / "candidate.map"
    link_map.write_bytes(b"original map input")
    args.candidate_link_map = link_map

    def drifting(backend_args: Namespace) -> dict[str, Any]:
        link_map.write_bytes(b"different consumed map input")
        raw = _backend(backend_args)
        raw["auxiliary_inputs"] = {"candidate_link_map": {
            "path": str(link_map),
            "sha256": hashlib.sha256(link_map.read_bytes()).hexdigest(),
        }}
        if restore:
            link_map.write_bytes(b"original map input")
        return raw

    with pytest.raises(RuntimeError, match="auxiliary input"):
        run_bound_comparison(drifting, args, _driver_dir(tmp_path))
    assert not (out_dir / "compare.json").exists()


def test_link_map_identity_is_sealed_even_with_same_backend_scope(tmp_path: Path) -> None:
    """Two map inputs cannot share a contract key through identical raw scope."""
    oracle, candidate = _pe_pair(tmp_path)
    link_map = tmp_path / "candidate.map"
    driver = _driver_dir(tmp_path)
    keys: list[str] = []

    def backend(args: Namespace) -> dict[str, Any]:
        raw = _backend(args)
        raw["auxiliary_inputs"] = {"candidate_link_map": {
            "path": str(link_map),
            "sha256": hashlib.sha256(link_map.read_bytes()).hexdigest(),
        }}
        return raw

    for index, content in enumerate((b"first map", b"second map")):
        link_map.write_bytes(content)
        args = _args(oracle, candidate, tmp_path / f"out{index}")
        args.candidate_link_map = link_map
        report = run_bound_comparison(backend, args, driver)
        keys.append(report["proof_evidence"]["contract"]["key"])
    assert keys[0] != keys[1]
