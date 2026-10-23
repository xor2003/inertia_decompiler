"""Discontiguous listing declarations retain binary tail and store checks."""

from pathlib import Path

import pytest

from tools.comparator.msc8_chunks import listing_chunks, with_listing_chunks
from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane
from tools.dosunit.tests.test_flat32_enter import _project
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes
from tools.dosunit.tests.test_flat32_stack_domain_cli import _driver_args

pytestmark = pytest.mark.ssa_z3


def _listing(path: Path, start: int, last: int, owner: str = "root") -> Path:
    path.write_text(f".text:{start:08X} ; START OF FUNCTION CHUNK FOR {owner}\n"
                    f".text:{last:08X} ; END OF FUNCTION CHUNK FOR {owner}\n")
    return path


def test_chunks_remain_separate_dependency_envelopes(tmp_path: Path) -> None:
    project, entry = _project(tmp_path, bytes.fromhex("eb02ccccb801000000c3"))
    listing = _listing(tmp_path / "input.lst", entry + 4, entry + 9)
    ranges = {"root": (entry, 2)}
    result = with_listing_chunks(project, ranges, listing)
    assert result == {"root": (entry, 2), f"root@chunk:{entry + 4:x}": (entry + 4, 6)}
    assert ranges == {"root": (entry, 2)}
    assert with_listing_chunks(project, {}, listing) == {}


@pytest.mark.parametrize("text", [
    ".text:00001000 ; START OF FUNCTION CHUNK FOR root\n",
    ".text:00001000 ; END OF FUNCTION CHUNK FOR root\n",
    ".text:00001000 ; START OF FUNCTION CHUNK FOR root\n.text:00001001 ; END OF FUNCTION CHUNK FOR other\n",
])
def test_malformed_chunk_metadata_rejected(tmp_path: Path, text: str) -> None:
    path = tmp_path / "bad.lst"
    path.write_text(text)
    with pytest.raises(ValueError):
        listing_chunks(path)


def test_overlapping_chunk_rejected(tmp_path: Path) -> None:
    project, entry = _project(tmp_path, bytes.fromhex("90c3"))
    listing = _listing(tmp_path / "input.lst", entry, entry + 1)
    with pytest.raises(ValueError, match="overlapping"):
        with_listing_chunks(project, {"root": (entry, 2)}, listing)


def test_unmapped_chunk_not_admitted(tmp_path: Path) -> None:
    project, entry = _project(tmp_path, bytes.fromhex("c3"))
    listing = _listing(tmp_path / "input.lst", 0xF0000000, 0xF0000001)
    assert with_listing_chunks(project, {"root": (entry, 1)}, listing) == {"root": (entry, 1)}


@pytest.mark.parametrize("changed", [False, True])
def test_public_original_chunk_is_composed(tmp_path: Path, changed: bool) -> None:
    """A detached tail is fully checked even when candidate has no such chunk."""
    original, candidate = tmp_path / "original.exe", tmp_path / "candidate.exe"
    original.write_bytes(pe32_bytes(bytes.fromhex("eb02ccccb801000000c3")))
    candidate.write_bytes(pe32_bytes(bytes.fromhex("b8" + ("02000000" if changed else "01000000") + "c3")))
    listing = _listing(tmp_path / "oracle.lst", 0x401004, 0x401009)
    listing.write_text(".text:00401000 root proc near\n.text:00401000 root endp\n" + listing.read_text())
    candidate_listing = tmp_path / "candidate.lst"
    candidate_listing.write_text(".text:00401000 root proc near\n.text:00401005 root endp\n")
    with _driver_lane("msc8") as lane:
        args = _driver_args(lane, tmp_path, original, candidate, None)
        args.functions = "root"
        args.candidate_lst = candidate_listing
        args.candidate_lst_end_kind = "last-instruction"
        report = lane.z3cmp32.compare(args)
    result = report["results"][0]
    assert result["status"] == ("failed" if changed else "passed"), result
    assert report["summary"]["total"] == 1
