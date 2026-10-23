"""Partial checks detect corrupt tables without overstating semantic coverage."""

import json
import struct
from pathlib import Path

import pytest

from tools.comparator.table_catalog import _bind_root_entries, attach_table_catalog, prepare_table_catalog
from tools.comparator.table_check_cli import main
from tools.comparator.table_checks import TargetTable, check_target_tables, read_target_table
from tools.comparator.table_dispatch_checks import check_dispatch_pair, read_table_dispatch
from tools.comparator.table_function_proof import initial_table_premise
from tools.comparator.table_prefix_checks import check_dispatch_prefix
from tools.comparator.table_target_checks import check_returning_targets
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes


def table(*targets: int) -> TargetTable:
    return TargetTable(0x401000, targets, "fixture")


def test_relocated_targets_keep_slot_order_and_duplicates() -> None:
    result = check_target_tables(table(10, 20, 10, 0), table(200, 100, 200, 0), {10: 200, 20: 100})
    assert result["status"] == "checked"
    assert result["checked_entries"] == 4
    assert not result["function_equivalence_proved"]
    assert len(result["pending_conditions"]) == 6


@pytest.mark.parametrize("targets", [(100, 200, 200, 0), (200, 100, 100, 0), (200, 100, 200, 1), (200, 100)])
def test_shuffle_duplicate_null_and_extent_changes_are_detected(targets: tuple[int, ...]) -> None:
    result = check_target_tables(table(10, 20, 10, 0), table(*targets), {10: 200, 20: 100})
    assert result["status"] == "mismatch"


def test_missing_target_mapping_is_visible_incomplete_evidence() -> None:
    result = check_target_tables(table(10, 20), table(100, 200), {10: 100})
    assert result["status"] == "incomplete"
    assert result["checked_entries"] == 1
    assert not result["function_equivalence_proved"]


def test_code_folding_does_not_require_injective_target_map() -> None:
    assert check_target_tables(table(10, 20), table(100, 100), {10: 100, 20: 100})["status"] == "checked"


def test_empty_table_cannot_succeed_vacuously() -> None:
    with pytest.raises(ValueError):
        table()


def test_real_pe_bytes_and_truncation() -> None:
    data = pe32_bytes(struct.pack("<II", 0x401020, 0x401030))
    assert read_target_table(data, 0x401000, 2).targets == (0x401020, 0x401030)
    with pytest.raises(ValueError, match="file-backed"):
        read_target_table(data[:0x205], 0x401000, 2)
    with pytest.raises(ValueError, match="mapped section"):
        read_target_table(data, 0x400000, 1)


@pytest.mark.parametrize("count", [0, -1, 4097, True])
def test_invalid_extent_never_becomes_empty_success(count: int) -> None:
    with pytest.raises(ValueError):
        read_target_table(pe32_bytes(b"\0" * 8), 0x401000, count)


def test_cli_reports_partial_success_and_detects_mutated_slot(tmp_path: Path) -> None:
    original, candidate, mapping, output = [tmp_path / name for name in ("o.exe", "c.exe", "map.json", "out.json")]
    original.write_bytes(pe32_bytes(struct.pack("<II", 0x401020, 0x401030)))
    candidate.write_bytes(pe32_bytes(struct.pack("<II", 0x401030, 0x401020)))
    mapping.write_text(json.dumps([{"original": "0x401020", "candidate": "0x401030"},
                                   {"original": "0x401030", "candidate": "0x401020"}]))
    args = ["--original-exe", str(original), "--candidate-exe", str(candidate),
            "--original-table", "0x401000", "--candidate-table", "0x401000",
            "--original-count", "2", "--candidate-count", "2", "--target-map", str(mapping),
            "--output", str(output)]
    assert main(args) == 0
    result = json.loads(output.read_text())
    assert result["status"] == "checked" and not result["function_equivalence_proved"]
    candidate.write_bytes(original.read_bytes())
    assert main(args) == 1
    assert json.loads(output.read_text())["status"] == "mismatch"


def dispatch_image(opcode: str = "ff2485", target: int = 0x401010) -> bytes:
    """Put an indexed transfer and its declared table in one real PE section."""
    code = bytes.fromhex(opcode) + struct.pack("<I", target)
    return pe32_bytes(code.ljust(16, b"\x90") + struct.pack("<II", 0x401020, 0x401030))


def test_dispatch_binding_checks_real_instruction_and_table_bytes() -> None:
    image = dispatch_image()
    loaded = read_target_table(image, 0x401010, 2)
    result = check_dispatch_pair(image, image, loaded, loaded, 0x401000, 0x401000)
    assert result["status"] == "checked"
    assert all(result["checks"].values())
    assert result["pending_conditions"]


@pytest.mark.parametrize(("opcode", "target", "failed_check"), [
    ("ff2485", 0x401014, "candidate_table_binding"),
    ("ff2445", 0x401010, "dword_stride"),
    ("ff248d", 0x401010, "index_register_shape"),
    ("ff1485", 0x401010, "transfer_kind"),
])
def test_mutated_dispatch_is_not_hidden_by_matching_tables(opcode: str, target: int, failed_check: str) -> None:
    original, candidate = dispatch_image(), dispatch_image(opcode, target)
    left, right = read_target_table(original, 0x401010, 2), read_target_table(candidate, 0x401010, 2)
    assert check_target_tables(left, right, {0x401020: 0x401020, 0x401030: 0x401030})["status"] == "checked"
    result = check_dispatch_pair(original, candidate, left, right, 0x401000, 0x401000)
    assert result["status"] == "mismatch"
    assert result["checks"][failed_check] is False


@pytest.mark.parametrize("opcode", ["66ff24", "ff24a5", "ff2480", "ffe090"])
def test_other_encodings_remain_explicitly_incomplete(opcode: str) -> None:
    image = dispatch_image(opcode)
    assert read_table_dispatch(image, 0x401000) is None
    loaded = read_target_table(image, 0x401010, 2)
    assert check_dispatch_pair(image, image, loaded, loaded, 0x401000, 0x401000)["status"] == "incomplete"


def test_dispatch_cannot_use_table_receipt_from_other_bytes() -> None:
    image, changed = dispatch_image(), dispatch_image("ff248d")
    loaded = read_target_table(image, 0x401010, 2)
    with pytest.raises(ValueError, match="do not match"):
        check_dispatch_pair(image, changed, loaded, loaded, 0x401000, 0x401000)


def write_catalog(path: Path) -> Path:
    path.write_text(json.dumps({"schema": "comparator.target_table_catalog.v1", "functions": {"f": [{
        "original_table": "0x401010", "candidate_table": "0x401010",
        "original_count": 2, "candidate_count": 2,
        "original_dispatch": "0x401000", "candidate_dispatch": "0x401000",
        "target_pairs": [{"original": "0x401020", "candidate": "0x401020"},
                         {"original": "0x401030", "candidate": "0x401030"}],
    }]}}))
    return path


@pytest.mark.parametrize("corrupt", ["catalog", "image", "name"])
def test_catalog_inputs_are_bound_to_function_report(tmp_path: Path, corrupt: str) -> None:
    path = write_catalog(tmp_path / "tables.json")
    image = tmp_path / "image.exe"
    image.write_bytes(dispatch_image())
    if corrupt == "name":
        with pytest.raises(ValueError, match="manifest"):
            prepare_table_catalog(path, image, image, ["other"])
        return
    evidence = prepare_table_catalog(path, image, image, ["f"])
    assert evidence is not None
    report = {"inputs": {side: {"sha256": digest} for side, digest in evidence.image_sha256.items()}, "results": []}
    if corrupt == "catalog":
        path.write_text("{}")
    else:
        report["inputs"]["candidate"]["sha256"] = "changed"
    with pytest.raises(RuntimeError):
        attach_table_catalog(report, evidence)


def test_msc8_keeps_table_checks_next_to_real_function_refusal(tmp_path: Path) -> None:
    from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane
    from tools.dosunit.tests.test_flat32_stack_domain_cli import _driver_args

    image = tmp_path / "image.exe"
    image.write_bytes(dispatch_image())
    listing = tmp_path / "oracle.lst"
    listing.write_text(".text:00401000 f proc near\n.text:00401006 f endp\n")
    path = write_catalog(tmp_path / "tables.json")
    with _driver_lane("msc8") as lane:
        args = _driver_args(lane, tmp_path, image, image, None)
        args.candidate_lst = listing
        args.candidate_lst_end_kind = "last-byte"
        args.table_check_catalog = path
        report = lane.z3cmp32.compare(args)
    row, = report["results"]
    assert row["status"] == "refused"
    assert row["partial_table_checks"][0]["status"] == "checked"
    assert row["partial_table_checks"][0]["dispatch_check"]["status"] == "checked"
    assert report["partial_table_checks"]["counts"] == {"checked": 1, "mismatch": 0, "incomplete": 0}
    assert report["original_function_coverage"]["proved_percent"] == 0
    saved = json.loads((args.out_dir / "compare.json").read_text())
    assert saved["results"][0]["partial_table_checks"] == row["partial_table_checks"]


@pytest.mark.parametrize(("original", "candidate", "status"), [
    ("b802000000c20400", "8d642400b802000000c20400", "checked"),
    ("b802000000c20400", "b804000000c20400", "mismatch"),
    ("b802000000c20400", "b802000000c3", "mismatch"),
    ("c70001000000c3", "c70002000000c3", "mismatch"),
    ("fcc3", "fdc3", "mismatch"),
    ("f8c3", "f9c3", "incomplete"),
    ("eb00c3", "c3", "checked"),
    ("ebfec3", "c3", "incomplete"),
    ("7401c3c3", "c3", "checked"),
])
def test_target_behavior_observes_result_stack_memory_flags_and_control(
    original: str, candidate: str, status: str,
) -> None:
    result = check_returning_targets(pe32_bytes(bytes.fromhex(original)), pe32_bytes(bytes.fromhex(candidate)),
                                     {0x401000: 0x401000})
    assert result["status"] == status, result
    assert result["pending_conditions"]
    if status == "checked":
        outputs = result["pairs"][0]["original"]["observed_outputs"]
        assert {"eax", "esp", "ip", "memory"} <= set(outputs)


def test_empty_target_proof_does_not_succeed() -> None:
    image = pe32_bytes(b"\xc3")
    assert check_returning_targets(image, image, {})["status"] == "incomplete"


@pytest.mark.parametrize(("candidate", "expected"), [
    ("8b44240483e007", "checked"),
    ("8b44240883e007", "mismatch"),
    ("8b44240483e003", "mismatch"),
    ("8b44240483e007c70001000000", "mismatch"),
    ("eb008b44240483e007", "incomplete"),
])
def test_dispatch_prefix_checks_input_index_memory_and_control(candidate: str, expected: str) -> None:
    original = bytes.fromhex("8b44240483e007")
    rebuilt = bytes.fromhex(candidate)
    result = check_dispatch_prefix(pe32_bytes(original), pe32_bytes(rebuilt), 0x401000, 0x401000,
                                    0x401000 + len(original), 0x401000 + len(rebuilt))
    assert result["status"] == expected, result


def test_prefix_pairs_default_edges_without_assuming_their_behavior() -> None:
    # Same guard, distinct default addresses and a harmless candidate padding.
    original = bytes.fromhex("83f8077710")
    candidate = bytes.fromhex("9083f8077720")
    result = check_dispatch_prefix(pe32_bytes(original), pe32_bytes(candidate), 0x401000, 0x401000,
                                    0x401005, 0x401006)
    assert result["status"] == "checked", result
    assert result["default_target_pairs"] == [{"original": "0x401015", "candidate": "0x401026"}]
    assert "default target continuations are equivalent" in result["pending_conditions"]


@pytest.mark.parametrize(("mask", "count", "status"), [(7, 8, "checked"), (15, 8, "mismatch"), (7, 7, "mismatch")])
def test_index_bound_is_proved_for_all_inputs(mask: int, count: int, status: str) -> None:
    prefix = bytes([0x83, 0xE0, mask])
    image = pe32_bytes(prefix + bytes.fromhex("ff248520104000"))
    result = check_dispatch_prefix(image, image, 0x401000, 0x401000, 0x401003, 0x401003,
                                    original_count=count, candidate_count=count)
    assert result["status"] == status, result
    assert result["index_domain_checks"]["original"]["status"] == status
    assert ("dispatch index is within the declared table extent" in result["pending_conditions"]) == (status != "checked")


@pytest.mark.parametrize("changed", [False, True])
def test_default_behavior_is_checked_alongside_index_domain(changed: bool) -> None:
    code = bytes.fromhex("83e00783f8077707ff248520104000")
    original = pe32_bytes(code + bytes.fromhex("c20400"))
    candidate = pe32_bytes(code + bytes.fromhex("c20800" if changed else "c20400"))
    result = check_dispatch_prefix(original, candidate, 0x401000, 0x401000, 0x401008, 0x401008,
                                    original_count=8, candidate_count=8, check_defaults=True)
    assert result["status"] == ("mismatch" if changed else "checked"), result
    assert result["default_block_checks"]["status"] == ("mismatch" if changed else "checked")
    assert ("default target continuations are equivalent" in result["pending_conditions"]) == changed


@pytest.mark.parametrize(("store", "expected"), [
    ("", "checked"),
    ("c6055010400001", "checked"),
    ("c6052010400001", "mismatch"),
    ("c6053f10400001", "mismatch"),
    ("c60301", "mismatch"),
])
def test_table_preservation_observes_exact_extent_and_aliases(store: str, expected: str) -> None:
    prefix = bytes.fromhex("83e007" + store)
    image = pe32_bytes(prefix + bytes.fromhex("ff248520104000"))
    site = 0x401000 + len(prefix)
    result = check_dispatch_prefix(image, image, 0x401000, 0x401000, site, site,
                                    original_count=8, candidate_count=8)
    assert result["status"] == expected, result
    checks = result["table_preservation_checks"]
    assert checks["original"]["status"] == checks["candidate"]["status"] == expected
    assert ("table bytes survive prefix execution" in result["pending_conditions"]) == (expected != "checked")


@pytest.mark.parametrize(("candidate_entry", "expected"), [(0x2000, "checked"), (0x2001, "mismatch"), (None, "incomplete")])
def test_root_binding_uses_selected_function_coordinates(candidate_entry: int | None, expected: str) -> None:
    check = {"status": "checked", "prefix_check": {
        "original": {"entry": "0x1000"}, "candidate": {"entry": "0x2000"},
        "pending_conditions": ["declared entries are the intended root function entries"],
    }}
    ranges = {"oracle": {"f": [0x1000, 32]},
              "candidate": {} if candidate_entry is None else {"f": [candidate_entry, 32]}}
    _bind_root_entries(check, "f", ranges)
    assert check["root_entry_check"]["status"] == check["status"] == expected
    assert bool(check["prefix_check"]["pending_conditions"]) == (expected != "checked")


def test_conflicting_initial_tables_cannot_create_vacuous_proof() -> None:
    original = table(0x1000, 0x2000)
    candidate = table(0x3000, 0x4000)
    checked = check_target_tables(original, candidate, {0x1000: 0x3000, 0x2000: 0x4000})
    assert checked["status"] == "checked"
    premise = initial_table_premise(checked)
    assert premise["status"] == "incomplete"
    assert premise["reason"] == "conflicting_shared_memory_table_bytes"


def switch_image(table_offset: int, target_offset: int, changed: bool = False) -> bytes:
    code = bytearray(b"\x90" * 80)
    code[:10] = bytes.fromhex("83e001ff2485") + struct.pack("<I", 0x401000 + table_offset)
    code[target_offset:target_offset + 6] = bytes.fromhex("b803000000c3" if changed else "b802000000c3")
    code[target_offset + 8:target_offset + 14] = bytes.fromhex("b804000000c3")
    code[table_offset:table_offset + 8] = struct.pack("<II", 0x401000 + target_offset, 0x401008 + target_offset)
    return pe32_bytes(bytes(code))


@pytest.mark.parametrize(("assume", "changed", "status"), [(True, False, "conditional"),
                                                            (False, False, "refused"), (True, True, "refused")])
def test_complete_table_function_is_conditional_only_with_all_lemmas(
    tmp_path: Path, assume: bool, changed: bool, status: str,
) -> None:
    from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane
    from tools.dosunit.tests.test_flat32_stack_domain_cli import _driver_args

    original, candidate = tmp_path / "original.exe", tmp_path / "candidate.exe"
    original.write_bytes(switch_image(32, 16))
    candidate.write_bytes(switch_image(48, 64, changed))
    listing = tmp_path / "oracle.lst"
    listing.write_text(".text:00401000 f proc near\n.text:0040104f f endp\n")
    catalog = write_catalog(tmp_path / "tables.json")
    doc = json.loads(catalog.read_text())
    item = doc["functions"]["f"][0]
    item.update(original_table="0x401020", candidate_table="0x401030",
                original_entry="0x401000", candidate_entry="0x401000",
                original_dispatch="0x401003", candidate_dispatch="0x401003",
                check_returning_targets=True, assume_initial_tables=assume,
                target_pairs=[{"original": "0x401010", "candidate": "0x401040"},
                              {"original": "0x401018", "candidate": "0x401048"}])
    catalog.write_text(json.dumps(doc))
    with _driver_lane("msc8") as lane:
        args = _driver_args(lane, tmp_path, original, candidate, Flat32ProofDomain(0x7F000, 0x80000))
        args.candidate_lst = listing
        args.candidate_lst_end_kind = "last-byte"
        args.table_check_catalog = catalog
        report = lane.z3cmp32.compare(args)
    row, = report["results"]
    assert row["status"] == status, row
    assert report["original_function_coverage"]["proved_percent"] == 0
    assert report["summary"][status] == 1
    if status == "conditional":
        assert row["strict_function_result"]["status"] == "refused"
        assert row["table_function_proof"]["complete"]
        assert row["assumptions"]["initial_tables"]["jointly_satisfiable"]
        assert row["assumptions"]["entry_esp_domain"]["interval"] == {"min": "0x7f000", "max": "0x80000"}
        assert report["original_function_coverage"]["conditional_percent"] == 100
        assert "table_check_catalog" in report["auxiliary_inputs"]
        assert report["proof_evidence"]["obligations"]["conditional"] == 1


@pytest.mark.parametrize(("domain", "expected"), [
    (None, "mismatch"), (Flat32ProofDomain(0x7F000, 0x80000), "checked"),
    (Flat32ProofDomain(0x401024, 0x401024), "mismatch"),
])
def test_root_stack_premise_discharges_only_nonaliasing_pushes(domain: Flat32ProofDomain | None, expected: str) -> None:
    code = bytes.fromhex("5083e007ff248520104000")
    image = pe32_bytes(code)
    result = check_dispatch_prefix(image, image, 0x401000, 0x401000, 0x401004, 0x401004,
                                    original_count=8, candidate_count=8, entry_domain=domain)
    assert result["status"] == expected, result
    assert result["table_preservation_checks"]["original"]["status"] == expected
    if domain is not None:
        assert result["entry_domain_assumptions"] == domain.assumption_document()
    else:
        assert "entry_domain_assumptions" not in result


def test_root_interval_is_not_applied_to_default_target_entry_state() -> None:
    prefix = bytes.fromhex("83e00783f8077707ff248520104000")
    original = pe32_bytes(prefix + bytes.fromhex("89e0c3"))
    candidate = pe32_bytes(prefix + bytes.fromhex("b800f00700c3"))
    result = check_dispatch_prefix(original, candidate, 0x401000, 0x401000, 0x401008, 0x401008,
                                    original_count=8, candidate_count=8, check_defaults=True,
                                    entry_domain=Flat32ProofDomain(0x7F000, 0x7F000))
    assert result["default_block_checks"]["status"] == "mismatch", result


@pytest.mark.parametrize(("candidate", "expected"), [
    ("c700010000008b00c3", "checked"),
    ("c700010000008b4004c3", "mismatch"),
    ("c700020000008b00c3", "mismatch"),
])
def test_target_direct_chain_retains_memory_written_before_jump(candidate: str, expected: str) -> None:
    original = bytes.fromhex("c70001000000eb008b00c3")
    result = check_returning_targets(pe32_bytes(original), pe32_bytes(bytes.fromhex(candidate)),
                                     {0x401000: 0x401000})
    assert result["status"] == expected, result
    assert result["pairs"][0]["original"]["blocks_composed"] == 2


def test_target_chain_limit_is_incomplete_not_truncated_success(monkeypatch: pytest.MonkeyPatch) -> None:
    # Exercise the structural cap independently of the wall budget on a busy host.
    monkeypatch.setattr("tools.comparator.table_target_checks.time.monotonic", lambda: 0.0)
    image = pe32_bytes(bytes.fromhex("eb00") * 17 + b"\xc3")
    result = check_returning_targets(image, pe32_bytes(b"\xc3"), {0x401000: 0x401000})
    assert result["status"] == "incomplete"
    assert result["pairs"][0]["original"]["pending"] == "target chain block limit"


def test_target_chain_cannot_leave_the_pe_mapping() -> None:
    image = pe32_bytes(bytes.fromhex("e900001000"))
    result = check_returning_targets(image, pe32_bytes(b"\xc3"), {0x401000: 0x401000})
    assert result["status"] == "incomplete"


@pytest.mark.parametrize(("candidate", "expected"), [
    ("83f8007506b802000000c3b801000000c3", "checked"),
    ("83f8007506b803000000c3b801000000c3", "mismatch"),
    ("83f8007506b802000000c3b803000000c3", "mismatch"),
    ("83f80074fbb801000000c3", "incomplete"),
    ("83f8007406b801000000c3e800000000c3", "mismatch"),
])
def test_returning_target_branches_keep_both_arms(
    candidate: str, expected: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Isolate branch semantics from shared-host wall contention. Deadline
    # enforcement has its own negative control; corpus probes use the real clock.
    monkeypatch.setattr("tools.comparator.table_target_checks.time.monotonic", lambda: 0.0)
    original = pe32_bytes(bytes.fromhex("83f8007406b801000000c3b802000000c3"))
    result = check_returning_targets(original, pe32_bytes(bytes.fromhex(candidate)), {0x401000: 0x401000})
    assert result["status"] == expected, result


@pytest.mark.parametrize("value", [1, 2])
def test_returning_target_branch_memory_is_guarded(value: int, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tools.comparator.table_target_checks.time.monotonic", lambda: 0.0)
    # Both branch arms return; only the zero arm stores through EDX.
    original = pe32_bytes(bytes.fromhex("83f8007506c70201000000c3"))
    candidate = pe32_bytes(bytes.fromhex(f"83f8007506c702{value:02x}000000c3"))
    result = check_returning_targets(original, candidate, {0x401000: 0x401000})
    assert result["status"] == ("checked" if value == 1 else "mismatch"), result


def test_returning_target_composition_deadline_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    from tools.comparator.table_target_checks import _returning_block

    ticks = iter((0.0, 3.0))
    monkeypatch.setattr("tools.comparator.table_target_checks.time.monotonic", lambda: next(ticks))
    document, facts = _returning_block(pe32_bytes(b"\xc3"), 0x401000)
    assert document is None
    assert facts["pending"] == "target chain cycle or composition deadline"


def direct_call_target(helper: str, repeated: bool = False) -> bytes:
    prefix = bytes.fromhex("e80b000000e806000000c3" if repeated else "e80b000000c3")
    return pe32_bytes(prefix.ljust(16, b"\x90") + bytes.fromhex(helper))


@pytest.mark.parametrize(("candidate", "expected"), [
    ("b802000000c3", "checked"),
    ("b803000000c3", "mismatch"),
    ("b802000000c20400", "mismatch"),
    ("c7042400000000c3", "incomplete"),
    ("e8fbffffffc3", "incomplete"),
])
def test_table_target_direct_call_retains_effects_and_validates_return(
    candidate: str, expected: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("tools.comparator.table_target_checks.time.monotonic", lambda: 0.0)
    result = check_returning_targets(direct_call_target("b802000000c3"), direct_call_target(candidate),
                                     {0x401000: 0x401000})
    assert result["status"] == expected, result
    assert result["pairs"][0]["original"]["return_targets_proved"] == 1
    if candidate.startswith("c70424"):
        assert result["pairs"][0]["candidate"]["return_target_failure"]["solver_result"]["status"] == "failed"


def test_table_target_can_call_same_helper_twice(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tools.comparator.table_target_checks.time.monotonic", lambda: 0.0)
    image = direct_call_target("b802000000c3", repeated=True)
    result = check_returning_targets(image, image, {0x401000: 0x401000})
    assert result["status"] == "checked", result
    assert result["pairs"][0]["original"]["return_targets_proved"] == 2


def test_table_target_call_rejects_possible_return_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tools.comparator.table_target_checks.time.monotonic", lambda: 0.0)
    # Write to a fixed address: a free EDX could alias the return address and
    # correctly prevent return admission for reasons unrelated to this test.
    original = direct_call_target("c7050000000001000000c3")
    candidate = direct_call_target("c7050000000002000000c3")
    result = check_returning_targets(original, candidate, {0x401000: 0x401000})
    assert result["status"] == "incomplete", result
    # Even a fixed address may alias a completely unconstrained input ESP.
    assert result["pairs"][0]["original"]["return_target_failure"]["solver_result"]["status"] == "failed"


def test_table_target_call_retains_nonreturn_stack_memory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tools.comparator.table_target_checks.time.monotonic", lambda: 0.0)
    original = direct_call_target("c744240801000000c3")
    candidate = direct_call_target("c744240802000000c3")
    result = check_returning_targets(original, candidate, {0x401000: 0x401000})
    assert result["status"] == "mismatch", result
    row = result["pairs"][0]
    assert row["original"]["return_targets_proved"] == row["candidate"]["return_targets_proved"] == 1
    assert any(item["reg"] == "memory" for item in row["solver_result"]["mismatches"])
@pytest.mark.parametrize("first,last,expected", [
    (0x1000, 0x1007, True), (0x1000, 0x1006, False),
    (0x1001, 0x1007, False), (0x1007, 0x1000, False),
])
def test_table_frame_preservation_avoids_solver(
    monkeypatch: pytest.MonkeyPatch, first: int, last: int, expected: bool,
) -> None:
    """A complete declared frame covers a table; partial frames cannot certify it."""
    from tools.comparator import table_memory_checks as checks

    initial = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    other = {**initial, "name": "other"}
    memory = {"op": "memory_preserve", "width": 0, "args": [other, initial,
              {"op": "const", "width": 32, "value": hex(first)},
              {"op": "const", "width": 32, "value": hex(last)}]}
    calls = []

    def solver(*args: object, **kwargs: object) -> dict:
        calls.append(True)
        return {"status": "refused", "reason": "test_solver_unavailable"}

    monkeypatch.setattr(checks.S, "_compare_functions", solver)
    document = {"inputs": [], "assignments": [], "outputs": {"memory": memory}}
    result = checks.check_table_preservation(document, 0x1000, 2)
    assert (result["status"] == "checked") == expected
    assert bool(calls) != expected


def test_table_region_uses_serialized_address_dag_without_expanding_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fast proof consumes SSA refs and never translates disjoint store values."""
    from tools.comparator import table_memory_checks as checks

    def solver(*args: object, **kwargs: object) -> dict:
        pytest.fail("serialized disjoint addresses must prove preservation directly")

    monkeypatch.setattr(checks.S, "_compare_functions", solver)
    initial = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    document = {"inputs": [], "assignments": [
        {"id": "address", "op": "sub", "width": 32, "args": [
            {"op": "input", "name": "esp", "width": 32}, {"op": "const", "width": 32, "value": "4"}]},
        {"id": "value", "op": "input", "name": "eax", "width": 32},
        {"id": "write", "op": "storele", "width": 0, "args": [initial, {"ref": "address"}, {"ref": "value"}]},
    ], "outputs": {"memory": {"ref": "write"}}}
    result = checks.check_table_preservation(document, 0x1000, 75,
                                            entry_domain=Flat32ProofDomain(0x7F000, 0x80000))
    assert result["status"] == "checked"
    assert result["stores_checked"] == 1
    assert result["quantified_slots"] == 75



def test_repeated_pe_reads_parse_immutable_layout_once(monkeypatch: pytest.MonkeyPatch) -> None:
    from tools.comparator import table_checks

    image = pe32_bytes(bytes(range(31)))
    real_pe = table_checks.pefile.PE
    calls = []

    class CountingPE(real_pe):
        def __init__(self, *args, **kwargs):
            calls.append(1)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(table_checks.pefile, "PE", CountingPE)
    for _ in range(5):
        assert table_checks.read_pe_bytes(image, 0x401000, 4, executable=True) == bytes(range(4))
    assert len(calls) == 1


def test_cached_pe_reads_revalidate_changed_bytes_permissions_and_extent() -> None:
    import pefile

    from tools.comparator.table_checks import read_pe_bytes

    image = pe32_bytes(b"original")
    assert read_pe_bytes(image, 0x401000, 4, executable=True) == b"orig"
    changed = bytearray(image)
    changed[0x200:0x204] = b"new!"
    assert read_pe_bytes(bytes(changed), 0x401000, 4, executable=True) == b"new!"
    parsed = pefile.PE(data=image, fast_load=True)
    flags = parsed.sections[0].get_file_offset() + 36
    parsed.close()
    struct.pack_into("<I", changed, flags, 0x40000040)
    assert read_pe_bytes(bytes(changed), 0x401000, 4) == b"new!"
    with pytest.raises(ValueError, match="executable"):
        read_pe_bytes(bytes(changed), 0x401000, 4, executable=True)
    with pytest.raises(ValueError, match="file-backed"):
        read_pe_bytes(image[:0x202], 0x401000, 4)


@pytest.mark.parametrize("case,expected", [("raw", "checked"), ("bss", "checked"),
    ("mixed", "checked"), ("changed", "mismatch"), ("truncated", "incomplete"), ("outside", "incomplete")])
def test_global_initial_bytes_distinguish_bss_from_missing_data(case: str, expected: str) -> None:
    """Native section bytes support initialization evidence, never a live callback premise."""
    from tools.comparator.global_layout_checks import check_global_initial_bytes

    image = bytearray(pe32_bytes(bytes(0x200)))
    struct.pack_into("<I", image, 0x180, 0x300)
    original, candidate = bytes(image), bytes(image)
    address = 0x401000
    address = {"bss": 0x401200, "mixed": 0x4011FE, "outside": 0x4012FE}.get(case, address)
    if case == "changed":
        image[0x200] = 1
        candidate = bytes(image)
    if case == "truncated":
        address = 0x401200
        candidate = candidate[:-1]
    result = check_global_initial_bytes(original, candidate, [(address, address, 4)])
    assert result["status"] == expected
    assert not result["live_values_proved"] and not result["function_equivalence_proved"]
    if expected == "checked":
        assert result["extents"][0]["both_zero"]
        assert result["extents"][0]["original_file_bytes"] == {"raw": 4, "bss": 0, "mixed": 2}[case]
