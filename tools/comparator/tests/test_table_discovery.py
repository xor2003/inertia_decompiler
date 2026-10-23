"""Native switch proposals remain separate from their required semantic proofs."""

import json
import struct
from pathlib import Path

import pytest

from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes

pytestmark = pytest.mark.ssa_z3

BASE = 0x401000


def switch_image(*, second: int = BASE + 0x30, guard: bytes = b"\x77\x3b") -> bytes:
    """An unsigned bound, native indexed JMP, two table slots and returning arms."""
    body = b"\x83\xf8\x01" + guard + b"\xff\x24\x85" + struct.pack("<I", BASE + 0x10)
    body = body.ljust(0x10, b"\x90") + struct.pack("<II", BASE + 0x20, second)
    body = body.ljust(0x20, b"\x90") + b"\xb8\x01\x00\x00\x00\xc3"
    body = body.ljust(0x30, b"\x90") + b"\xb8\x02\x00\x00\x00\xc3"
    return pe32_bytes(body.ljust(0x40, b"\x90") + b"\xc3")


def test_native_prefix_proposes_exact_extent_and_slot_correspondence() -> None:
    from tools.comparator.table_discovery import discover_entry_tables

    catalog, evidence = discover_entry_tables(switch_image(), switch_image(),
                                             {"f": (BASE, 0x41)}, {"f": (BASE, 0x41)})
    table = catalog["functions"]["f"][0]
    assert table["original_count"] == table["candidate_count"] == 2
    assert table["original_dispatch"] == hex(BASE + 5)
    assert table["original_table"] == hex(BASE + 0x10)
    assert table["assume_initial_tables"] and table["check_returning_targets"] and table["check_selected_slots"]
    assert len(table["target_pairs"]) == 2
    assert evidence["proposed_functions"] == ["f"]
    assert evidence["function_equivalence_proved"] is False


@pytest.mark.parametrize("guard", [b"\x7f\x3b", b"\x72\x3b", b"\x90\x90"])
def test_other_guards_are_not_used_to_guess_a_table_extent(guard: bytes) -> None:
    from tools.comparator.table_discovery import discover_entry_tables

    catalog, evidence = discover_entry_tables(switch_image(guard=guard), switch_image(),
                                             {"f": (BASE, 0x41)}, {"f": (BASE, 0x41)})
    assert not catalog["functions"]
    assert not evidence["proposed_functions"]


@pytest.mark.parametrize("size", [5, 6, 11])
def test_dispatch_outside_declared_function_extent_is_not_proposed(size: int) -> None:
    from tools.comparator.table_discovery import discover_entry_tables

    catalog, _ = discover_entry_tables(switch_image(), switch_image(),
                                      {"f": (BASE, size)}, {"f": (BASE, 0x41)})
    assert not catalog["functions"]


def test_inconsistent_repeated_slot_pair_is_not_proposed() -> None:
    from tools.comparator.table_discovery import discover_entry_tables

    catalog, _ = discover_entry_tables(switch_image(second=BASE + 0x20), switch_image(),
                                      {"f": (BASE, 0x41)}, {"f": (BASE, 0x41)})
    assert not catalog["functions"]


def test_unmapped_target_is_not_proposed() -> None:
    from tools.comparator.table_discovery import discover_entry_tables

    catalog, _ = discover_entry_tables(switch_image(second=0x999999), switch_image(),
                                      {"f": (BASE, 0x41)}, {"f": (BASE, 0x41)})
    assert not catalog["functions"]


@pytest.mark.parametrize("corrupt", [False, True])
@pytest.mark.parametrize("selected", [False, True])
def test_public_driver_checks_discovered_targets_before_conditional_credit(tmp_path: Path, corrupt: bool, selected: bool) -> None:
    from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane
    from tools.dosunit.tests.test_flat32_stack_domain_cli import _driver_args

    original, candidate = tmp_path / "original.exe", tmp_path / "candidate.exe"
    left = bytearray(switch_image())
    raw = bytearray(left)
    if selected:
        for index, offset in enumerate((0x20, 0x30)):
            left[0x200 + offset + 1] = index
            raw[0x200 + offset] = 0xC3
    original.write_bytes(left)
    if corrupt:
        raw[0x200 + 0x31] = 3
        if selected:
            raw[0x200 + 0x30] = 0xB8  # Corrupt a reachable return, not dead bytes.
    candidate.write_bytes(raw)
    listing = tmp_path / "oracle.lst"
    listing.write_text(".text:00401000 f proc near\n.text:00401040 f endp\n")
    with _driver_lane("msc8") as lane:
        args = _driver_args(lane, tmp_path, original, candidate, None)
        args.candidate_lst = listing
        args.candidate_lst_end_kind = "last-byte"
        args.mode = "matched-cfg"
        args.discover_target_tables = True
        report = lane.z3cmp32.compare(args)
    row, = report["results"]
    assert (row["status"] == "conditional") is not corrupt, row
    assert report["table_discovery"]["proposed_functions"] == ["f"]
    assert report["summary"]["passed"] == 0
    assert report["auxiliary_inputs"]["table_check_catalog"]["sha256"]
    assert json.loads((args.out_dir / "compare.json").read_text())["table_discovery"] == report["table_discovery"]
    if corrupt:
        assert row["partial_table_checks"][0]["target_block_checks"]["status"] == "mismatch"
    else:
        assert row["strict_function_result"]["status"] == "refused"
        assert row["assumptions"]["initial_tables"]["jointly_satisfiable"]
        if selected:
            assert row["proof_method"] == "single_switch_selected_slots"
            assert row["partial_table_checks"][0]["target_block_checks"]["status"] == "mismatch"
        else:
            check = row["partial_table_checks"][0]
            assert check["slot_target_checks"]["pending"] == "prefix unproved or strict targets already checked"
            assert "rooted_target_checks" not in check


@pytest.mark.parametrize("mode,manual", [("leaf", None), ("matched-cfg", Path("manual.json"))])
def test_discovery_conflicting_configuration_rejects_before_reading_files(mode: str, manual: Path | None) -> None:
    from argparse import Namespace

    from tools.comparator.msc8_cli import _compare_with_tables

    with pytest.raises(ValueError, match="table discovery requires"):
        _compare_with_tables(Namespace(mode=mode, table_check_catalog=manual, discover_target_tables=True))


@pytest.mark.parametrize("corrupt", [False, True])
def test_accessor_switch_proves_only_under_explicit_live_global_relation(tmp_path: Path, corrupt: bool) -> None:
    from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane
    from tools.dosunit.tests.test_flat32_stack_domain_cli import _driver_args

    images = []
    for side in range(2):
        raw = bytearray(switch_image())
        for offset in (0x20, 0x30):
            address = 0x500000 + side * 0x100000 + offset
            body = b"\xa1" + struct.pack("<I", address) + b"\xc3"
            if side and corrupt:
                body = b"\xa1" + struct.pack("<I", address) + b"\x40\xc3"
            raw[0x200 + offset:0x200 + offset + len(body)] = body
        path = tmp_path / f"{side}.exe"
        path.write_bytes(raw)
        images.append(path)
    listing = tmp_path / "oracle.lst"
    listing.write_text(".text:00401000 f proc near\n.text:00401040 f endp\n")
    with _driver_lane("msc8") as lane:
        args = _driver_args(lane, tmp_path, *images, None)
        args.candidate_lst = listing
        args.candidate_lst_end_kind = "last-byte"
        args.mode = "matched-cfg"
        args.discover_target_tables = True
        report = lane.z3cmp32.compare(args)
    row, = report["results"]
    assert (row["status"] == "conditional") is not corrupt, row
    if not corrupt:
        assert row["assumptions"]["live_global_reads"]["jointly_satisfiable"]
        assert row["strict_function_result"]["status"] == "refused"
        assert row["proof_method"] == "single_switch_read_accessors"
    assert report["summary"]["passed"] == 0


@pytest.mark.parametrize("reads, expected", [([(0x1000, 0x1004)], False),
    ([(0x1000, 0x2000), (0x2000, 0x1004)], False), ([(0x2000, 0x3000)], True)])
def test_accessor_relations_must_be_jointly_satisfiable_with_table_bytes(reads, expected) -> None:
    from tools.comparator.table_accessor_proof import joint_read_premise

    tables = {"tables": {"original": {"address": "0x1000", "targets": ["0x1", "0x2"]}}}
    result = joint_read_premise(tables, reads)
    assert result["jointly_satisfiable"] is expected


@pytest.mark.parametrize("body", ["a300005000c3", "a10000500040c3", "66a100005000c3", "a1feffffffc3"])
def test_accessor_admission_rejects_other_effects_and_wrapping_reads(body: str) -> None:
    from tools.comparator.table_accessor_proof import _accessor

    assert _accessor(pe32_bytes(bytes.fromhex(body)), BASE) is None


def test_accessor_composition_rejects_prefix_writes_and_changed_return_pop() -> None:
    from tools.comparator.table_accessor_proof import _accessor_lemmas, _memory_unchanged

    prefix = bytes.fromhex("a300005000")
    assert not _memory_unchanged(pe32_bytes(prefix + b"\xc3"),
                                 {"entry": hex(BASE), "dispatch": hex(BASE + len(prefix))})
    check = {"entries": [{"original_target": hex(BASE), "candidate_target": hex(BASE)}]}
    left = pe32_bytes(bytes.fromhex("a100005000c20400"))
    right = pe32_bytes(bytes.fromhex("a100006000c20800"))
    assert _accessor_lemmas(check, (left, right)) is None


def test_short_native_blocks_parse_each_immutable_image_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Near-section-end lifting must not repeatedly reopen PE and trigger collection."""
    import pefile

    from tools.comparator.table_checks import _pe_layout
    from tools.comparator.table_target_checks import _mapped_target_block

    images = [pe32_bytes(bytes.fromhex(code)) for code in ("90c3", "40c3")]
    constructor = pefile.PE.__init__
    calls = []

    def counted(self, *args, **kwargs):
        calls.append(kwargs.get("data"))
        constructor(self, *args, **kwargs)

    _pe_layout.cache_clear()
    monkeypatch.setattr(pefile.PE, "__init__", counted)
    for image in images:
        for offset in (0, 1):
            lowered, facts, _ = _mapped_target_block(image, BASE + offset)
            assert lowered is not None
            assert facts["instruction_bytes"] == image[0x200 + offset:0x202].hex()
    assert len(calls) == len(images)
    assert calls == images


def test_decoder_window_respects_raw_virtual_file_and_execution_boundaries() -> None:
    import pefile

    from tools.comparator.table_checks import read_pe_window

    image = pe32_bytes(bytes.fromhex("90c3"))
    assert read_pe_window(image, BASE, 128, executable=True) == bytes.fromhex("90c3")
    assert read_pe_window(image, BASE + 1, 128, executable=True) == bytes.fromhex("c3")
    assert read_pe_window(image[:0x201], BASE, 128) == bytes.fromhex("90")
    for address in (BASE - 1, BASE + 2, 0x100000000):
        with pytest.raises(ValueError):
            read_pe_window(image, address, 128)
    for size in (0, -1, True):
        with pytest.raises(ValueError):
            read_pe_window(image, BASE, size)
    pe = pefile.PE(data=image, fast_load=True)
    offset = pe.sections[0].get_file_offset()
    pe.close()
    bss = bytearray(image)
    struct.pack_into("<I", bss, offset + 8, 4)
    struct.pack_into("<I", bss, offset + 16, 2)
    assert read_pe_window(bytes(bss), BASE, 128) == bytes.fromhex("90c3")
    with pytest.raises(ValueError):
        read_pe_window(bytes(bss), BASE + 2, 128)
    data = bytearray(image)
    struct.pack_into("<I", data, offset + 36, 0x40000040)
    assert read_pe_window(bytes(data), BASE, 128) == bytes.fromhex("90c3")
    with pytest.raises(ValueError, match="not in an executable section"):
        read_pe_window(bytes(data), BASE, 128, executable=True)
