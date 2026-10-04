"""Actual PE32 proof/cache parity and source-bound callee invalidation controls."""
import hashlib
import json
from argparse import Namespace
from pathlib import Path
from typing import Any

import pytest
from test_flat32_comparator_lane import DriverLane, _driver_lane
from test_flat32_loop_calls_public import CALLER, ENTRY, _image

from tools.dosunit.proof_contracts import ProofStatus, proof_status_from_legacy


def _run(lane: DriverLane, root: Path, oracle: Path, original_listing: Path,
         candidate: Path, candidate_listing: Path, name: str) -> tuple[dict[str, Any], Path]:
    """Run one public adapter comparison with a private persistent lift cache."""
    output = root / name
    output.mkdir()
    args = Namespace(
        oracle_exe=oracle, oracle_lst=original_listing, candidate_exe=candidate,
        candidate_lst=candidate_listing, candidate_syms=None,
        cache_dir=root / "cache", functions="f", mode="auto",
        output_regs=",".join(name for name, _ in lane.adapter.REG32.values()),
        scan_limit=0x1000, timeout_ms=30000, region_max_blocks=128,
        normalize_globals=False, assume_paired_calls=False, out_dir=output,
    )
    with lane.adapter.installed(region=args.mode in {"region", "auto"}):
        report = lane.z3cmp32.compare(args)
    assert json.loads((output / "compare.json").read_text())["proof_evidence"] == report["proof_evidence"]
    return report, output


def _proved(report: dict[str, Any]) -> None:
    """Require complete accounting and a sealed unconditional proof."""
    assert report["summary"]["total"] == len(report["results"]) == 1
    assert proof_status_from_legacy(report["results"][0]["status"]) is ProofStatus.PROVED, report
    assert report["results"][0]["proof_method"] == "closed_call_loop_induction"
    assert report["proof_evidence"]["verdicts"][0]["status"] == ProofStatus.PROVED.value
    assert report["proof_evidence"]["verdicts"][0]["assumptions"] == []


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("encoding", ["43c3", "ffc3c3"], ids=["self", "equivalent"])
def test_pe32_accepted_call_dependency_cold_warm(driver: str, encoding: str, tmp_path: Path) -> None:
    """Warm lifting must retain an actual accepted equivalent-callee proof."""
    oracle, original_listing = _image(tmp_path, "oracle", bytes.fromhex("43c3"))
    candidate, candidate_listing = _image(tmp_path, "candidate", bytes.fromhex(encoding))
    with _driver_lane(driver) as lane:
        cold, _ = _run(lane, tmp_path, oracle, original_listing, candidate, candidate_listing, "cold")
        warm, output = _run(lane, tmp_path, oracle, original_listing, candidate, candidate_listing, "warm")
        _proved(cold)
        _proved(warm)
        assert cold["proof_evidence"] == warm["proof_evidence"]
        for side in ("oracle", "candidate"):
            lowered = json.loads((output / f"{side}.ssa.json").read_text())
            assert lowered["counters"]["lifter_cache_hits"] > 0 if driver == "bc5" else lowered["counters"]["lifter_cache_hits"] == 0
        sealed = warm["proof_evidence"]["contract"]
        assert sealed["candidate_hash"] == hashlib.sha256(candidate.read_bytes()).hexdigest()
        candidate, candidate_listing = _image(tmp_path, "candidate", bytes.fromhex("4bc3"))
        changed, _ = _run(lane, tmp_path, oracle, original_listing, candidate, candidate_listing, "changed")
        assert proof_status_from_legacy(changed["results"][0]["status"]) is not ProofStatus.PROVED
        assert changed["proof_evidence"]["contract"]["key"] != sealed["key"]
        assert changed["proof_evidence"]["contract"]["candidate_hash"] != sealed["candidate_hash"]


def _chain(root: Path, name: str, leaf: bytes) -> tuple[Path, Path]:
    """Keep root and middle code unchanged while replacing a transitive leaf."""
    middle = bytes.fromhex("e801000000c3")
    image, listing = _image(root, name, middle + leaf)
    start = ENTRY + len(CALLER)
    target = start + len(middle)
    listing.write_text(
        f".text:{ENTRY:08X} f proc\n.text:{start - 1:08X} f endp\n"
        f".text:{start:08X} callee proc\n.text:{target - 1:08X} callee endp\n"
        f".text:{target:08X} leaf proc\n.text:{target + len(leaf) - 1:08X} leaf endp\n"
    )
    return image, listing


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_pe32_transitive_image_dependency_invalidation(driver: str, tmp_path: Path) -> None:
    """Whole-image identity conservatively binds even unselected nested callees."""
    oracle, original_listing = _chain(tmp_path, "oracle", bytes.fromhex("43c3"))
    candidate, candidate_listing = _chain(tmp_path, "candidate", bytes.fromhex("ffc3c3"))
    with _driver_lane(driver) as lane:
        cold, _ = _run(lane, tmp_path, oracle, original_listing, candidate, candidate_listing, "cold")
        warm, output = _run(lane, tmp_path, oracle, original_listing, candidate, candidate_listing, "warm")
        _proved(cold)
        _proved(warm)
        assert cold["proof_evidence"] == warm["proof_evidence"]
        assert warm["results"][0]["return_targets_proved"] == 4
        lowered = json.loads((output / "candidate.ssa.json").read_text())
        assert lowered["counters"]["lifter_cache_hits"] > 0 if driver == "bc5" else lowered["counters"]["lifter_cache_hits"] == 0
        previous = candidate.read_bytes()
        candidate, candidate_listing = _chain(tmp_path, "candidate", bytes.fromhex("ffcbc3"))
        current = candidate.read_bytes()
        assert len(previous) == len(current)
        assert sum(a != b for a, b in zip(previous, current, strict=True)) == 1
        changed, _ = _run(lane, tmp_path, oracle, original_listing, candidate, candidate_listing, "changed")
        assert proof_status_from_legacy(changed["results"][0]["status"]) is not ProofStatus.PROVED
        assert changed["proof_evidence"]["contract"]["key"] != warm["proof_evidence"]["contract"]["key"]
        assert changed["proof_evidence"]["contract"]["candidate_hash"] == hashlib.sha256(current).hexdigest()
