"""Real PE32 public branch-pairing regression controls for both drivers.

Layer: tests.
Responsibility: exercise genuine PE loading and sealed production driver reports
without substituting symbolic statuses, with identical complete output contracts.
"""
from __future__ import annotations

from argparse import Namespace
from pathlib import Path

import pytest
from test_flat32_comparator_lane import _driver_lane
from test_flat32_loaded_byte_boundaries import pe32_bytes

from tools.dosunit.proof_contracts import ProofStatus, proof_status_from_legacy

# Structurally ambiguous terminal arms have distinct effects; proposing the
# wrong bijection must fail solver discharge before the alternate can prove.
ORACLE = "83f800740483c301c383c302c3"
REVERSED = "83f800750483c302c383c301c3"

@pytest.mark.parametrize("driver", ["msc8", "bc5"])
@pytest.mark.parametrize("candidate,expected", [(REVERSED, ProofStatus.PROVED),
    (REVERSED.replace("7504", "7404"), ProofStatus.UNKNOWN),
    (REVERSED.replace("83c301", "83c303"), ProofStatus.UNKNOWN)],
                         ids=["equivalent", "guard-mutation", "arm-effect-mutation"])
def test_public_pe32_branch_pairing(tmp_path: Path, driver: str, candidate: str,
                                  expected: ProofStatus) -> None:
    """Both real PE images must reach the sealed driver and reject mutations."""
    images, listings = [], []
    for name, code in (("oracle", ORACLE), ("candidate", candidate)):
        image = tmp_path / f"{name}.exe"
        image.write_bytes(pe32_bytes(bytes.fromhex(code)))
        listing = tmp_path / f"{name}.lst"
        listing.write_text(f".text:00401000 f proc\n.text:{0x401000 + len(bytes.fromhex(code)) - 1:08X} f endp\n")
        images.append(image)
        listings.append(listing)
    args = Namespace(oracle_exe=images[0], candidate_exe=images[1], oracle_lst=listings[0],
                     candidate_lst=listings[1], candidate_syms=None, cache_dir=tmp_path / "cache",
                     functions="f", mode="matched-cfg", output_regs="eax,ecx,edx,ebx,esp,ebp,esi,edi",
                     scan_limit=0x1000, timeout_ms=10000, region_max_blocks=128,
                     normalize_globals=False, assume_paired_calls=False, out_dir=tmp_path / "out")
    args.out_dir.mkdir()
    with _driver_lane(driver) as lane, lane.adapter.installed(region=False):
        report = lane.z3cmp32.compare(args)
    assert report["summary"]["total"] == 1
    assert len(report["results"]) == 1
    row = report["results"][0]
    status = proof_status_from_legacy(row["status"])
    assert status is not None, row
    if expected is ProofStatus.PROVED:
        assert status is ProofStatus.PROVED, row
    else:
        assert status is not ProofStatus.PROVED, row
    for image in report["loaded_images"].values():
        assert image["loader"] == "InclusivePE"
        assert image["architecture"] == "X86" and image["width"] == 32
    assert ProofStatus(report["initial_image_relation"]["status"]) is ProofStatus.UNKNOWN
    assert report["initial_image_relation"]["startup_and_environment_proved"] is False
