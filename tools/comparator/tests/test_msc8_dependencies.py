"""Public proofs compose independently declared per-image helper bodies."""

import hashlib
from pathlib import Path

import pytest

from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes
from tools.dosunit.tests.test_flat32_stack_domain_cli import _driver_args

pytestmark = pytest.mark.ssa_z3


def _image(directory: Path, side: str, helper: str, body: bytes) -> tuple[Path, Path]:
    image, listing = directory / f"{side}.exe", directory / f"{side}.lst"
    code = bytes.fromhex("e801000000 c3") + body
    image.write_bytes(pe32_bytes(code))
    listing.write_text(
        ".text:00401000 f proc near\n.text:00401005 f endp\n"
        f".text:00401006 {helper} proc near\n"
        f".text:{0x401000 + len(code) - 1:08X} {helper} endp\n"
    )
    return image, listing


@pytest.mark.parametrize("changed", [False, True])
def test_unpaired_helpers_remain_available_to_public_composition(tmp_path: Path, changed: bool) -> None:
    """Different helper identities need actual body proofs, not name matching."""
    original, original_listing = _image(tmp_path, "oracle", "original_helper", bytes.fromhex("b801000000c3"))
    candidate, candidate_listing = _image(tmp_path, "candidate", "rebuilt_helper",
                                         bytes.fromhex("31c0 40 " + ("40" if changed else "90") + " c3"))
    with _driver_lane("msc8") as lane:
        args = _driver_args(lane, tmp_path, original, candidate, None)
        args.oracle_lst = original_listing
        args.candidate_lst = candidate_listing
        args.candidate_lst_end_kind = "last-instruction"
        report = lane.z3cmp32.compare(args)
    row, = report["results"]
    assert row["status"] == ("failed" if changed else "passed"), row
    assert row["oracle_inlined_calls"] == row["candidate_inlined_calls"] == 1
    assert report["summary"]["total"] == 1
    assert report["original_function_coverage"]["original_functions"] == 2


def _code_map(path: Path, size: int, *, timestamp: int = 0, helper_address: int = 0x401006) -> Path:
    path.write_text(
        f" candidate\n Timestamp is {timestamp:08x}\n Preferred load address is 00400000\n"
        " Start Length Name Class\n"
        f" 0001:00000000 {size:08x}H .text CODE\n"
        " Address Publics by Value Rva+Base Lib:Object\n"
        " 0001:00000000 _f 00401000 f.obj\n entry point at 0001:00000000\n"
        f" Static symbols\n 0001:00000006 _private {helper_address:08x} f helper.obj\n"
    )
    return path


@pytest.mark.parametrize("changed", [False, True])
@pytest.mark.parametrize("scan_envelope", ["exact", "within_image", "past_image"])
def test_private_code_map_helper_is_proved_from_its_bytes(tmp_path: Path, changed: bool, scan_envelope: str) -> None:
    """A private LINK symbol admits bytes without relocation or assumed calls."""
    original, original_listing = _image(tmp_path, "oracle", "original_helper", bytes.fromhex("b801000000c3"))
    body = bytes.fromhex("31c0 40 " + ("40" if changed else "90") + " c3")
    candidate, candidate_listing = _image(tmp_path, "candidate", "private_helper", body)
    last = {"exact": 0x401005, "within_image": 0x401000 + 6 + len(body) - 1, "past_image": 0x402005}[scan_envelope]
    candidate_listing.write_text(f".text:00401000 f proc near\n.text:{last:08X} f endp\n")
    map_path = _code_map(tmp_path / "candidate.map", 6 + len(body))
    with _driver_lane("msc8") as lane:
        args = _driver_args(lane, tmp_path, original, candidate, None)
        args.oracle_lst, args.candidate_lst = original_listing, candidate_listing
        args.candidate_lst_end_kind = "last-instruction" if scan_envelope == "exact" else "last-byte"
        missing = lane.z3cmp32.compare(args)
        assert missing["results"][0]["status"] == "refused"
        args.candidate_code_map = map_path
        report = lane.z3cmp32.compare(args)
    row, = report["results"]
    assert row["status"] == ("failed" if changed else "passed"), row
    assert not row.get("assumptions"), row
    assert report["auxiliary_inputs"]["candidate_code_map"]["sha256"] == hashlib.sha256(map_path.read_bytes()).hexdigest()
    assert report["summary"]["total"] == 1


@pytest.mark.parametrize("corrupt", ["timestamp", "coordinate"])
def test_code_map_must_match_actual_image_coordinates(tmp_path: Path, corrupt: str) -> None:
    from tools.comparator.msc8_dependencies import with_code_map
    from tools.dosunit.architectures.flat32_loader import load_flat32_project
    from tools.dosunit.catalog.pe32_link_map import LinkMapError, load_candidate_link_map

    candidate, _ = _image(tmp_path, "candidate", "helper", bytes.fromhex("b801000000c3"))
    path = _code_map(tmp_path / "candidate.map", 12, timestamp=1 if corrupt == "timestamp" else 0,
                     helper_address=0x401007 if corrupt == "coordinate" else 0x401006)
    with pytest.raises(LinkMapError):
        link_map = load_candidate_link_map(path, candidate, include_statics=True)
        with_code_map(load_flat32_project(candidate), {}, link_map)


@pytest.mark.parametrize("corrupt", [None, "offset", "address", "section"])
def test_segment_end_marker_is_not_a_function(tmp_path: Path, corrupt: str | None) -> None:
    """An image-bound one-past segment label has no body, irrespective of name."""
    from tools.comparator.msc8_dependencies import with_code_map
    from tools.dosunit.architectures.flat32_loader import load_flat32_project
    from tools.dosunit.catalog.pe32_link_map import LinkMapError, load_candidate_link_map

    candidate, _ = _image(tmp_path, "candidate", "helper", bytes.fromhex("b801000000c3"))
    path = _code_map(tmp_path / "candidate.map", 12)
    offset = 13 if corrupt == "offset" else 12
    address = 0x40100D if corrupt in {"address", "offset"} else 0x40100C
    section = 2 if corrupt == "section" else 1
    text = path.read_text().replace(
        " entry point at", f" {section:04x}:{offset:08x} _arbitrary_limit {address:08x} symbols.obj\n entry point at",
    )
    path.write_text(text)
    project = load_flat32_project(candidate)
    if corrupt:
        with pytest.raises(LinkMapError):
            link_map = load_candidate_link_map(path, candidate, include_statics=True)
            with_code_map(project, {}, link_map)
    else:
        link_map = load_candidate_link_map(path, candidate, include_statics=True)
        ranges = with_code_map(project, {}, link_map)
        assert sorted(ranges.values()) == [(0x401000, 6), (0x401006, 6)]
        assert not any("_arbitrary_limit" in name for name in ranges)


def test_wrapped_noncode_alias_cannot_become_a_dependency(tmp_path: Path) -> None:
    """DATA-relative assembler aliases outside their section are not code declarations."""
    from tools.comparator.msc8_dependencies import with_code_map
    from tools.comparator.tests.test_msc8_driver import _MAP_TIMESTAMP, _link_map_text, _pe32_image
    from tools.dosunit.architectures.flat32_loader import load_flat32_project
    from tools.dosunit.catalog.pe32_link_map import load_candidate_link_map

    candidate = tmp_path / "candidate.exe"
    code = bytes.fromhex("b801000000c3") + b"\x90" * 10
    candidate.write_bytes(_pe32_image(code, timestamp=_MAP_TIMESTAMP, data_rva=0x3000))
    path = tmp_path / "candidate.map"
    path.write_text(_link_map_text(
        " 0002:ffffd000       _arbitrary_absolute 00400000 symbols.obj\n"
    ))
    link_map = load_candidate_link_map(path, candidate, include_statics=True)
    ranges = with_code_map(load_flat32_project(candidate), {}, link_map)
    assert list(ranges.values()) == [(0x401000, 0x10)]
    assert not any("_arbitrary_absolute" in name for name in ranges)


@pytest.mark.parametrize("changed", [False, True])
def test_missing_public_root_requires_native_proof(tmp_path: Path, changed: bool) -> None:
    """A recovered public removes mapping refusal without hiding changed effects."""
    original, original_listing = _image(tmp_path, "oracle", "helper", bytes.fromhex("b801000000c3"))
    candidate, candidate_listing = _image(tmp_path, "candidate", "private_helper",
                                         bytes.fromhex("b802000000c3" if changed else "b801000000c3"))
    candidate_listing.write_text("")
    with _driver_lane("msc8") as lane:
        args = _driver_args(lane, tmp_path, original, candidate, None)
        args.oracle_lst, args.candidate_lst = original_listing, candidate_listing
        args.candidate_lst_end_kind = "last-byte"
        args.candidate_code_map = _code_map(tmp_path / "candidate.map", 12)
        args.mode = "matched-cfg"
        before = lane.z3cmp32.compare(args)
        assert before["results"][0]["reason"] == "mapping_missing"
        args.match_code_symbols = True
        after = lane.z3cmp32.compare(args)
    assert after["results"][0]["status"] == ("failed" if changed else "passed"), after
    assert after["code_symbol_correspondence"][0]["status"] == "added"
    assert after["code_symbol_correspondence"][0]["function_equivalence_proved"] is False


@pytest.mark.parametrize("second_address,expected", [(0x401000, "added"), (0x401006, "ambiguous")])
def test_public_root_decoration_deduplicates_addresses_not_names(
    tmp_path: Path, second_address: int, expected: str,
) -> None:
    from tools.comparator.code_symbol_roots import match_code_symbol_roots
    from tools.comparator.msc8_catalog import Symbol
    from tools.dosunit.architectures.flat32_loader import load_flat32_project
    from tools.dosunit.catalog.pe32_link_map import load_candidate_link_map

    candidate, _ = _image(tmp_path, "candidate", "helper", bytes.fromhex("b801000000c3"))
    path = _code_map(tmp_path / "candidate.map", 12)
    path.write_text(path.read_text().replace(" entry point at",
        f" 0001:{second_address - 0x401000:08x} _f@4 {second_address:08x} another.obj\n entry point at"))
    project = load_flat32_project(candidate)
    code_map = load_candidate_link_map(path, candidate, include_statics=True)
    symbols, evidence = match_code_symbol_roots(project, {}, ["f", "private"], code_map)
    assert evidence[0]["status"] == expected
    assert ("f" in symbols) == (expected == "added")
    assert "private" not in symbols
    if expected == "added":
        assert symbols["f"].size == 6
    existing = {"f": Symbol(0x401006, 6, "T")}
    kept, evidence = match_code_symbol_roots(project, existing, ["f"], code_map)
    assert kept == existing and not evidence
