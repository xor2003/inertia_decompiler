"""Public PE32 call-loop acceptance through both comparator drivers.

Layer: tests.
Responsibility: verify actual PE loading, complete callee range intake, public
proof projection, rejection of changed callee effects without assumptions, and
serialized image-bound inlined callee dependency evidence in compare.json.
"""
from __future__ import annotations

import hashlib
import json
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest
from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes

from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy

ENTRY = 0x401000
CALLER = bytes.fromhex("85c9 7408 e804000000 49 ebf4 c3")
CALLEE_ENTRY = ENTRY + len(CALLER)
SIDES = ("oracle", "candidate")


def _image(directory: Path, name: str, callee: bytes) -> tuple[Path, Path]:
    """Supply actual PE bytes plus optional exact caller/callee boundaries."""
    image, listing = directory / f"{name}.exe", directory / f"{name}.lst"
    image.write_bytes(pe32_bytes(CALLER + callee))
    boundary = ENTRY + len(CALLER)
    listing.write_text(
        f".text:{ENTRY:08X} f proc\n.text:{boundary - 1:08X} f endp\n"
        f".text:{boundary:08X} callee proc\n"
        f".text:{boundary + len(callee) - 1:08X} callee endp\n"
    )
    return image, listing


def _assert_equivalent_encoding_dependencies(
    compare: dict[str, Any],
    oracle: Path,
    candidate: Path,
    callee_sizes: dict[str, int],
) -> None:
    """Assert the serialized image-bound inlined callee identity for equivalent_encoding.

    The PROVED root row, the per-side input digests sealed into the evidence
    contract, the recorded call sites and the retained lifted-block coverage
    must jointly identify the inlined callee bytes as
    ``(side, image sha256, target/range)``.  ``function_ranges`` seals only the
    requested obligation ``f``; the callee's (entry, size) identity is the
    retained ``environment_coverage`` block at the recorded call target, not a
    per-callee hash or a theorem-dependency entry.
    """
    row = compare["results"][0]
    assert proof_status_from_legacy(row["status"]) is ProofStatus.PROVED, row
    assert row["proof_method"] == "closed_call_loop_induction"
    assert not row.get("assumptions"), row
    evidence = compare["proof_evidence"]
    assert len(evidence["verdicts"]) == 1
    verdict = evidence["verdicts"][0]
    assert verdict["id"] == {"kind": "function", "key": "f"}
    assert ProofStatus(verdict["status"]) is ProofStatus.PROVED, verdict
    assert verdict["assumptions"] == [], verdict

    digests = {
        side: hashlib.sha256(path.read_bytes()).hexdigest()
        for side, path in (("oracle", oracle), ("candidate", candidate))
    }
    assert digests["oracle"] != digests["candidate"], (
        "changed_equivalent_dependency_identity_stale: identical image digests"
    )
    contract = evidence["contract"]
    for side, key in (("oracle", "original_hash"), ("candidate", "candidate_hash")):
        assert compare["inputs"][side]["sha256"] == digests[side], (
            f"changed_equivalent_dependency_identity_stale: inputs.{side}.sha256"
        )
        assert contract[key] == digests[side], (
            f"changed_equivalent_dependency_identity_stale: contract.{key}"
        )
    assert verdict["evidence_contract_key"] == contract["key"], verdict

    oracle_bytes = oracle.read_bytes()
    caller_at = oracle_bytes.find(CALLER)
    assert caller_at >= 0
    assert candidate.read_bytes()[caller_at:caller_at + len(CALLER)] == CALLER, (
        "changed_equivalent_dependency_identity_stale: caller bytes changed"
    )

    for side in SIDES:
        assert compare["function_ranges"][side]["f"] == [ENTRY, len(CALLER)], (
            f"changed_equivalent_callee_dependency_missing: function_ranges.{side}"
        )
        sites = row["call_sites"][side]
        assert len(sites) == 1, (
            f"changed_equivalent_callee_dependency_missing: {side} call sites {sites}"
        )
        site = sites[0]
        assert site["callsite"] == hex(ENTRY + 4), site
        assert site["target"] == hex(CALLEE_ENTRY), site
        assert site["fallthrough"] == hex(ENTRY + 9), site
        assert site["depth"] == 1, site
        assert site["callee"] == "callee", site
        assert site["proved_under_entry_domain"] is False, site
        coverage = [
            part for part in row["environment_coverage"][side]
            if part["entry"]["linear"] == hex(CALLEE_ENTRY)
        ]
        assert len(coverage) == 1, (
            "changed_equivalent_callee_dependency_missing: "
            f"{side} retained coverage lacks the lifted callee block"
        )
        size = coverage[0]["source"]["machine_code_size"]
        assert size == callee_sizes[side], (
            "changed_equivalent_dependency_identity_stale: "
            f"{side} callee block size {size!r}"
        )
    assert row["return_targets_proved"] == 2


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("callee,proved", [("43c3", True), ("ffc3c3", True), ("4bc3", False)],
                         ids=["self", "equivalent_encoding", "changed_callee"])
def test_public_pe32_call_loop(driver: str, callee: str, proved: bool, tmp_path: Path) -> None:
    """PE32 proof uses checked callee effects; instruction names cannot admit edits."""
    oracle, oracle_lst = _image(tmp_path, "oracle", bytes.fromhex("43c3"))
    candidate, candidate_lst = _image(tmp_path, "candidate", bytes.fromhex(callee))
    with _driver_lane(driver) as lane:
        outputs = tuple(name for name, _ in lane.adapter.REG32.values())
        args = Namespace(
            oracle_exe=oracle, oracle_lst=oracle_lst, candidate_exe=candidate,
            candidate_lst=candidate_lst, candidate_lst_end_kind="last-instruction", candidate_syms=None,
            cache_dir=tmp_path / "cache", functions="f", mode="auto",
            output_regs=",".join(outputs), scan_limit=0x1000,
            timeout_ms=30000, region_max_blocks=128, normalize_globals=False,
            assume_paired_calls=False, out_dir=tmp_path / "out",
        )
        args.out_dir.mkdir()
        with lane.adapter.installed(region=False):
            report = lane.z3cmp32.compare(args)
    assert report["summary"]["total"] == len(report["results"]) == 1
    assert set(outputs) <= set(report["proof_contract"]["outputs"])
    for side in ("oracle", "candidate"):
        assert report["loaded_images"][side]["loader"] in {"PE", "InclusivePE"}
    row = report["results"][0]
    if proved:
        assert proof_status_from_legacy(row["status"]) is ProofStatus.PROVED, row
        assert row["proof_method"] == "closed_call_loop_induction"
        assert row["return_targets_proved"] == 2
    else:
        assert proof_status_from_legacy(row["status"]) is not ProofStatus.PROVED, row
        attempt = row["additional_proof_attempts"]["call_loop"]
        assert any(proof_status_from_legacy(block["status"]) is ProofStatus.COUNTEREXAMPLE
                   for block in attempt["block_verdicts"])
    if callee == "43c3":
        assert oracle.read_bytes() == candidate.read_bytes()
        assert ProofStatus(report["initial_image_relation"]["initialized_function_status"]) is ProofStatus.PROVED
    else:
        assert oracle.read_bytes() != candidate.read_bytes()
        assert ProofStatus(report["initial_image_relation"]["initialized_function_status"]) is ProofStatus.UNKNOWN
    assert report["proof_scope"] == "requested_functions_over_shared_input_memory"
    if callee == "ffc3c3":
        emitted = json.loads((args.out_dir / "compare.json").read_text())
        _assert_equivalent_encoding_dependencies(
            emitted, oracle, candidate,
            {"oracle": len(bytes.fromhex("43c3")), "candidate": len(bytes.fromhex(callee))},
        )
