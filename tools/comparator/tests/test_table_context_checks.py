"""Root stack premises must survive real frame changes before table calls."""

import json
import struct
from pathlib import Path

import pytest

from tools.comparator.table_catalog import attach_table_catalog, prepare_table_catalog
from tools.comparator.table_context_checks import check_rooted_targets
from tools.comparator.table_target_checks import check_returning_targets
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes


def contextual_image(store: int, value: int = 1) -> bytes:
    code = bytearray(b"\x90" * 80)
    code[:13] = bytes.fromhex("81ec00100000ff2485") + struct.pack("<I", 0x401040)
    code[16:28] = bytes.fromhex("e80b00000081c400100000c3")
    helper = b"\xc7\x05" + struct.pack("<II", store, value) + b"\xc3"
    code[32:32 + len(helper)] = helper
    code[64:68] = struct.pack("<I", 0x401010)
    return pe32_bytes(bytes(code))


@pytest.mark.parametrize(("store", "value", "expected"), [
    (0x50000, 1, "checked"),
    (0x50000, 2, "mismatch"),
    (0x7EFFC, 1, "incomplete"),
])
def test_root_domain_tracks_frame_and_rejects_real_return_alias(
    store: int, value: int, expected: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("tools.comparator.table_target_checks.time.monotonic", lambda: 0.0)
    original, candidate = contextual_image(store), contextual_image(store, value)
    result = check_rooted_targets(original, candidate, {0x401010: 0x401010},
                                  0x401000, 0x401000, 0x401006, 0x401006,
                                  entry_domain=Flat32ProofDomain(0x80000, 0x80000))
    assert result["status"] == expected, result
    assert result["entry_domain_assumptions"]
    assert not result["function_equivalence_proved"]
    assert not result["path_guards_applied"]
    if expected == "incomplete":
        assert result["pairs"][0]["original"]["pending"] == "call_return_target_mismatch"
    else:
        assert result["pairs"][0]["original"]["return_targets_proved"] == 1


def test_root_domain_cannot_bind_uncomposed_target_inputs() -> None:
    image = contextual_image(0x50000)
    with pytest.raises(ValueError, match="composed incoming states"):
        check_returning_targets(image, image, {0x401010: 0x401010},
                                 entry_domain=Flat32ProofDomain(0x80000, 0x80000))


def test_context_catalog_preserves_full_function_status(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("tools.comparator.table_target_checks.time.monotonic", lambda: 0.0)
    image = tmp_path / "image.exe"
    image.write_bytes(contextual_image(0x50000))
    catalog = tmp_path / "table.json"
    catalog.write_text(json.dumps({"schema": "comparator.target_table_catalog.v1", "functions": {"f": [{
        "original_entry": 0x401000, "candidate_entry": 0x401000,
        "original_dispatch": 0x401006, "candidate_dispatch": 0x401006,
        "original_table": 0x401040, "candidate_table": 0x401040,
        "original_count": 1, "candidate_count": 1, "check_rooted_targets": True,
        "target_pairs": [{"original": 0x401010, "candidate": 0x401010}],
    }]}}))
    evidence = prepare_table_catalog(catalog, image, image, ["f"],
                                      entry_domain=Flat32ProofDomain(0x80000, 0x80000))
    assert evidence is not None
    row = {"function": {"name": "f"}, "status": "refused"}
    report = {"inputs": {side: {"sha256": digest} for side, digest in evidence.image_sha256.items()},
              "results": [row], "function_ranges": {side: {"f": [0x401000, 0x401050]}
                                                    for side in ("oracle", "candidate")}}
    attach_table_catalog(report, evidence)
    assert row["status"] == "refused"
    check = evidence.functions["f"][0]
    rooted = check["rooted_target_checks"]
    assert rooted["status"] == "checked"
    assert rooted["entry_domain_assumptions"]
    assert "declared root entries match selected functions" not in rooted["pending_conditions"]
    assert check["prefix_check"]["index_domain_checks"]["original"]["status"] == "mismatch"


@pytest.mark.parametrize("changed, expected", [(False, "checked"), (True, "mismatch")])
def test_dispatch_guard_excludes_unreachable_register_counterexamples(changed: bool, expected: str) -> None:
    prefix = bytes.fromhex("83f807771bff248540104000").ljust(16, b"\x90")
    original = pe32_bytes(prefix + bytes.fromhex("0fb6c0c3"))
    candidate = pe32_bytes(prefix + (bytes.fromhex("b808000000c3") if changed else b"\xc3"))
    result = check_rooted_targets(original, candidate, {0x401010: 0x401010},
                                  0x401000, 0x401000, 0x401005, 0x401005)
    assert result["status"] == expected, result
    assert result["dispatch_guards_applied"]
    assert not result["function_equivalence_proved"]


def test_different_dispatch_guards_are_not_intersected() -> None:
    original = pe32_bytes(bytes.fromhex("83f807771bff248540104000").ljust(16, b"\x90") + b"\xc3")
    candidate = pe32_bytes(bytes.fromhex("83f808771bff248540104000").ljust(16, b"\x90") + b"\xc3")
    result = check_rooted_targets(original, candidate, {0x401010: 0x401010},
                                  0x401000, 0x401000, 0x401005, 0x401005)
    assert result["status"] == "mismatch", result
    assert result["dispatch_guards_applied"]


@pytest.mark.parametrize("changed, expected", [(False, "conditional"), (True, "mismatch")])
def test_relocated_targets_keep_explicit_premise_and_reject_changed_load(changed: bool, expected: str) -> None:
    from tools.comparator.table_normalized_checks import check_normalized_targets

    original = pe32_bytes(bytes.fromhex("a100005000c3"))
    candidate = pe32_bytes(bytes.fromhex("a100006000") + (bytes.fromhex("83c001") if changed else b"") + b"\xc3")
    strict = check_returning_targets(original, candidate, {0x401000: 0x401000})
    assert strict["status"] == "mismatch"
    result = check_normalized_targets(original, candidate, {0x401000: 0x401000}, {0x600000: 0x500000})
    assert result["status"] == expected, result
    assert result["assumptions"]["proved"] is False
    assert result["function_equivalence_proved"] is False


def test_normalized_attachment_preserves_strict_and_function_verdicts() -> None:
    from tools.comparator.table_normalized_checks import attach_normalized_table_checks

    original = pe32_bytes(bytes.fromhex("a100005000c3"))
    candidate = pe32_bytes(bytes.fromhex("a100006000c3"))
    strict = check_returning_targets(original, candidate, {0x401000: 0x401000})
    check = {"target_block_checks": strict}
    row = {"status": "refused", "partial_table_checks": [check]}
    report = {"results": [row], "proof_contract": {"global_normalization": {
        "relocations": {"0x600000": "0x500000"}}}}
    attach_normalized_table_checks(report, original, candidate)
    assert row["status"] == "refused"
    assert check["target_block_checks"] is strict
    assert strict["status"] == "mismatch"
    assert check["normalized_target_checks"]["status"] == "conditional"


@pytest.mark.parametrize("mapping", [{}, {1: 3, 2: 3}, {-1: 3}])
def test_invalid_target_relocation_map_rejects(mapping: dict[int, int]) -> None:
    from tools.comparator.table_normalized_checks import check_normalized_targets

    with pytest.raises(ValueError):
        check_normalized_targets(b"", b"", {}, mapping)


def test_noninjective_report_map_retains_missing_evidence_without_crash() -> None:
    from tools.comparator.table_normalized_checks import attach_normalized_table_checks

    check = {"target_block_checks": {"status": "mismatch", "pairs": []}}
    row = {"status": "refused", "partial_table_checks": [check]}
    report = {"results": [row], "proof_contract": {"global_normalization": {
        "relocations": {"0x600000": "0x500000", "0x700000": "0x500000"}}}}
    attach_normalized_table_checks(report, b"", b"")
    assert row["status"] == "refused"
    assert check["normalized_target_checks"]["reason"] == "noninjective_global_relocation_map"


@pytest.mark.parametrize("left,right,expected", [
    ("b807000000c3", "b808000000c3", "found"),
    ("b807000000c3", "b807000000c3", "not_found"),
    ("b807000000ebfe", "b808000000ebfe", "not_found"),
    ("b807000000c3", "b808000000ebfe", "not_found"),
])
def test_bounded_counterexample_requires_both_complete_returns(left: str, right: str, expected: str) -> None:
    from tools.comparator.return_counterexample import find_return_counterexample

    result = find_return_counterexample(pe32_bytes(bytes.fromhex(left)), pe32_bytes(bytes.fromhex(right)),
                                        (0x401000, len(bytes.fromhex(left))),
                                        (0x401000, len(bytes.fromhex(right))))
    assert result["status"] == expected, result
    assert result["equivalence_proved"] is False


def test_bounded_counterexample_finds_signed_byte_loop_return_difference() -> None:
    from tools.comparator.return_counterexample import find_return_counterexample

    left = bytes.fromhex("8b4c24042bc0380174108a542408381175028bc14180390075f4c3")
    right = bytes.fromhex("568b5424082bc0380274140fbe4c240c0fb6323bf175028bc242803a0075f15ec3")
    result = find_return_counterexample(pe32_bytes(left), pe32_bytes(right),
                                        (0x401000, len(left)), (0x401000, len(right)),
                                        entry_domain=Flat32ProofDomain(0x80000, 0x80000))
    assert result["status"] == "found", result
    assert result["solver_result"]["status"] == "failed"


def test_public_driver_reports_complete_root_counterexample_for_signed_loop(tmp_path: Path) -> None:
    from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane
    from tools.dosunit.tests.test_flat32_stack_domain_cli import _driver_args

    left = bytes.fromhex("8b4c24042bc0380174108a542408381175028bc14180390075f4c3")
    right = bytes.fromhex("568b5424082bc0380274140fbe4c240c0fb6323bf175028bc242803a0075f15ec3")
    original, candidate = tmp_path / "o.exe", tmp_path / "c.exe"
    original.write_bytes(pe32_bytes(left))
    candidate.write_bytes(pe32_bytes(right))
    with _driver_lane("msc8") as lane:
        args = _driver_args(lane, tmp_path, original, candidate, None)
        args.oracle_lst.write_text(f".text:00401000 f proc near\n.text:{0x401000 + len(left) - 1:08X} f endp\n")
        listing = tmp_path / "candidate.lst"
        listing.write_text(f".text:00401000 f proc near\n.text:{0x401000 + len(right) - 1:08X} f endp\n")
        args.candidate_lst = listing
        args.candidate_lst_end_kind = "last-byte"
        args.mode = "matched-cfg"
        args.find_return_counterexamples = True
        report = lane.z3cmp32.compare(args)
    row, = report["results"]
    assert row["status"] == "failed", row
    assert row["proof_method"] == "bounded_root_return_counterexample"
    assert row["strict_function_result"]["status"] == "refused"
    assert row["root_counterexample"]["status"] == "found"
    assert report["summary"]["failed"] == 1


@pytest.mark.parametrize("right", ["b9080000004975fdb807000000c3", "b808000000e800000000c3"])
def test_counterexample_clipped_or_call_paths_do_not_fake_a_return(right: str) -> None:
    from tools.comparator.return_counterexample import find_return_counterexample

    left = bytes.fromhex("b807000000c3")
    raw = bytes.fromhex(right)
    result = find_return_counterexample(pe32_bytes(left), pe32_bytes(raw),
                                        (0x401000, len(left)), (0x401000, len(raw)))
    assert result["status"] != "found", result


def test_structural_solver_failure_is_not_a_root_counterexample(monkeypatch: pytest.MonkeyPatch) -> None:
    from tools.comparator import return_counterexample as owner

    monkeypatch.setattr(owner.S, "_compare_functions", lambda *args, **kwargs:
                        {"status": "failed", "reason": "input_signature_mismatch"})
    image = pe32_bytes(bytes.fromhex("b807000000c3"))
    result = owner.find_return_counterexample(image, image, (0x401000, 6), (0x401000, 6))
    assert result["status"] == "incomplete"


@pytest.mark.parametrize("override", [{"mode": "leaf"}, {"normalize_globals": True},
    {"output_regs": "edx,esp"}, {"abi_observation_catalog": Path("abi.json")},
    {"external_call_catalog": Path("external.json")}])
def test_counterexample_mode_rejects_incompatible_observation_contract(override) -> None:
    from argparse import Namespace

    from tools.comparator.msc8_cli import _compare_with_tables

    fields = {"mode": "matched-cfg", "normalize_globals": False,
              "output_regs": "eax,edx,esp", "find_return_counterexamples": True}
    fields.update(override)
    with pytest.raises(ValueError, match="counterexamples require"):
        _compare_with_tables(Namespace(**fields))


def test_counterexample_closes_native_char_search_return_frontier() -> None:
    """Real CL strchr bodies differ after a return just beyond the branch frontier."""
    from tools.comparator.return_counterexample import find_return_counterexample

    left = bytes.fromhex("8b44240480380074138a4c2408380874064080380075f680380075022bc0c3")
    right = bytes.fromhex("8b44240480380075072bc0c38d6424000fbe4c240833d28a103bd174064080380075f280380075022bc0c3")
    result = find_return_counterexample(pe32_bytes(left), pe32_bytes(right),
                                       (0x401000, len(left)), (0x401000, len(right)),
                                       entry_domain=Flat32ProofDomain(0x80000, 0x80000))
    assert result["status"] == "found", result
    assert any(row["frontier_returns"] for row in result["work"]), result
    assert result["bounds"]["terminal_frontier_only"] is True


@pytest.mark.parametrize("tail,expected", [
    ("b808000000c3", "found"),
    ("eb00b808000000c3", "not_found"),
    ("ebfe", "not_found"),
    ("e800000000b808000000c3", "not_found"),
])
def test_counterexample_frontier_closes_only_a_real_return(tail: str, expected: str) -> None:
    """The terminal frontier cannot follow an extra edge, call or cycle."""
    from tools.comparator import return_counterexample as owner

    prefix = bytes.fromhex("eb00") * owner.MAX_DEPTH
    left = prefix + bytes.fromhex("b807000000c3")
    right = prefix + bytes.fromhex(tail)
    result = owner.find_return_counterexample(pe32_bytes(left), pe32_bytes(right),
                                              (0x401000, len(left)), (0x401000, len(right)))
    assert result["status"] == expected, result
    assert result["equivalence_proved"] is False
    assert all(row["visited_blocks"] <= owner.MAX_VISITS for row in result["work"]), result


def test_counterexample_frontier_consumes_existing_visit_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reaching a RET does not exempt its execution from the shared work cap."""
    from tools.comparator import return_counterexample as owner

    monkeypatch.setattr(owner, "MAX_VISITS", owner.MAX_DEPTH)
    prefix = bytes.fromhex("eb00") * owner.MAX_DEPTH
    left, right = prefix + bytes.fromhex("b807000000c3"), prefix + bytes.fromhex("b808000000c3")
    result = owner.find_return_counterexample(pe32_bytes(left), pe32_bytes(right),
                                              (0x401000, len(left)), (0x401000, len(right)))
    assert result["status"] != "found", result
    assert all(row["visited_blocks"] <= owner.MAX_VISITS for row in result["work"]), result
    assert all(row["frontier_returns"] == 0 for row in result["work"]), result


@pytest.mark.parametrize("mode", ["equivalent", "changed", "no_premise", "folded", "duplicate", "shuffled", "call"])
def test_selected_slot_function_can_return_index_or_constant(tmp_path: Path, mode: str) -> None:
    """Only selected slots constrain EAX; strict arbitrary-target checks still fail."""
    paths = [tmp_path / "original.exe", tmp_path / "candidate.exe"]
    for candidate, path in enumerate(paths):
        code = bytearray(bytes.fromhex("90") * 128)
        table, target = (80, 48) if candidate else (96, 16)
        code[:10] = bytes.fromhex("83e001ff2485") + struct.pack("<I", 0x401000 + table)
        for index in range(2):
            value = index + int(mode == "changed")
            if mode == "folded":
                body = bytes.fromhex("c3") if candidate else bytes.fromhex("b8") + struct.pack("<I", index) + bytes.fromhex("c3")
            else:
                body = bytes.fromhex("b8") + struct.pack("<I", value) + bytes.fromhex("c3") if candidate else bytes.fromhex("c3")
            code[target + index * 8:target + index * 8 + len(body)] = body
        targets = [0x401000 + target, 0x401008 + target]
        if (mode == "folded" and candidate) or mode == "duplicate":
            targets[1] = targets[0]
        if mode == "shuffled" and candidate:
            targets.reverse()
        if mode == "call":
            code[4] = 0x14
        code[table:table + 8] = struct.pack("<II", *targets)
        path.write_bytes(pe32_bytes(bytes(code)))
    catalog = tmp_path / "tables.json"
    catalog.write_text(json.dumps({"schema": "comparator.target_table_catalog.v1", "functions": {"f": [{
        "original_table": 0x401060, "candidate_table": 0x401050,
        "original_count": 2, "candidate_count": 2,
        "original_entry": 0x401000, "candidate_entry": 0x401000,
        "original_dispatch": 0x401003, "candidate_dispatch": 0x401003,
        "check_returning_targets": True, "check_rooted_targets": True,
        "assume_initial_tables": mode != "no_premise",
        "target_pairs": [{"original": 0x401010, "candidate": 0x401030},
                         {"original": 0x401018, "candidate": 0x401030 if mode == "folded" else 0x401038}],
    }]}}))
    evidence = prepare_table_catalog(catalog, *paths, ["f"])
    assert evidence is not None
    row = {"function": {"name": "f"}, "status": "refused", "reason": "indirect_jump"}
    report = {"inputs": {side: {"sha256": digest} for side, digest in evidence.image_sha256.items()},
              "results": [row], "function_ranges": {side: {"f": [0x401000, 0x401080]}
                                                     for side in ("oracle", "candidate")}}
    attach_table_catalog(report, evidence)
    expected = "conditional" if mode in ("equivalent", "folded") else "refused"
    assert row["status"] == expected, evidence.functions["f"]
    if expected == "conditional":
        assert row["proof_method"] == "single_switch_selected_slots"
    if mode == "duplicate":
        assert evidence.functions["f"][0]["slot_target_checks"]["status"] == "mismatch"


@pytest.mark.parametrize("mode", ["equal", "no_abi", "leak", "default", "memory", "saved", "guard", "no_premise", "wrong_entry", "missing_default", "reallocated", "wrong_index"])
def test_completed_switch_abi_preserves_dependencies(tmp_path: Path, mode: str) -> None:
    """Scratch differences may disappear only after every selected/default path returns."""
    from tools.dosunit.compare.flat32_abi_observation import Flat32AbiObservation

    paths = [tmp_path / "o.exe", tmp_path / "c.exe"]
    for candidate, path in enumerate(paths):
        code = bytearray(bytes.fromhex("90") * 128)
        code[:5] = bytes.fromhex("b9") + struct.pack("<I", 2 if candidate else 1)
        code[5:10] = bytes.fromhex("83f8") + bytes([int(candidate and mode == "guard"), 0x77, 30])
        table = 0x401060 if candidate else 0x401050
        dispatch = 12 if candidate and mode in ("reallocated", "wrong_index") else 10
        if dispatch == 12:
            move = "89ca" if mode == "wrong_index" else "89c2"
            code[5:12] = bytes.fromhex(move + "83f800771c")
        code[dispatch:dispatch + 7] = bytes.fromhex("ff24") + bytes([0x95 if dispatch == 12 else 0x85]) + struct.pack("<I", table)
        body = bytes.fromhex("89c8c3" if mode == "leak" else "b807000000c3")
        if candidate and mode == "memory":
            body = bytes.fromhex("c7050000500001000000") + body
        if candidate and mode == "saved":
            body = bytes.fromhex("bb01000000") + body
        code[20:20 + len(body)] = body
        code[40:46] = bytes.fromhex("b809000000c3" if candidate and mode == "default" else "b808000000c3")
        code[table - 0x401000:table - 0x401000 + 4] = struct.pack("<I", 0x401014)
        path.write_bytes(pe32_bytes(bytes(code)))
    catalog = tmp_path / "tables.json"
    catalog.write_text(json.dumps({"schema": "comparator.target_table_catalog.v1", "functions": {"f": [{
        "original_table": 0x401050, "candidate_table": 0x401060,
        "original_count": 1, "candidate_count": 1,
        "original_entry": 0x401000, "candidate_entry": 0x401000,
        "original_dispatch": 0x40100A, "candidate_dispatch": 0x40100C if mode in ("reallocated", "wrong_index") else 0x40100A,
        "check_returning_targets": True, "check_selected_slots": True, "assume_initial_tables": mode != "no_premise",
        "target_pairs": [{"original": 0x401014, "candidate": 0x401014}],
    }]}}))
    evidence = prepare_table_catalog(catalog, *paths, ["f"],
                                     abi_contracts={} if mode == "no_abi" else {"f": Flat32AbiObservation(32)})
    assert evidence is not None
    row = {"function": {"name": "f"}, "status": "refused"}
    report = {"inputs": {side: {"sha256": digest} for side, digest in evidence.image_sha256.items()},
              "results": [row], "function_ranges": {side: {"f": [0x401000, 0x401080]}
                                                     for side in ("oracle", "candidate")}}
    if mode == "wrong_entry":
        report["function_ranges"]["candidate"]["f"][0] += 1
    if mode == "missing_default":
        evidence.functions["f"][0]["root_path_checks"]["default_pairs"] = []
    attach_table_catalog(report, evidence)
    assert row["status"] == ("conditional" if mode in ("equal", "reallocated") else "refused"), evidence.functions
    if row["status"] == "conditional":
        assert row["proof_method"] == "single_switch_root_returns"
        assert row["assumptions"]["abi_observation"]["proved"] is False
        assert row["assumptions"]["abi_observation"]["return_bits"] == 32
        assert evidence.functions["f"][0]["prefix_check"]["status"] == "mismatch"


@pytest.mark.parametrize("case", ["finite", "changed", "unknown", "infinite", "dead_loop"])
def test_returning_targets_close_only_proved_finite_native_paths(case: str) -> None:
    """Unroll bounded concrete loops; never equate an unresolved or infinite path."""
    if case == "dead_loop":
        left = right = bytes.fromhex("31c07402ebfec3")
    else:
        left = bytes.fromhex("b90200000031c0404975fcc3")
        right = bytes.fromhex("b90200000031c040494049c3")
        if case == "changed":
            right = bytes.fromhex("b90200000031c04049404940c3")
        if case == "unknown":
            left = bytes.fromhex("31c0404975fcc3")
        if case == "infinite":
            left = bytes.fromhex("b90200000031c04085c975fbc3")
    proof = check_returning_targets(pe32_bytes(left), pe32_bytes(right), {0x401000: 0x401000})
    expected = "checked" if case in ("finite", "dead_loop") else "mismatch" if case == "changed" else "incomplete"
    assert proof["status"] == expected, proof
    if case == "unknown":
        assert sum(block["address"] == "0x401002" for block in proof["pairs"][0]["original"]["blocks"]) == 1
    if expected == "checked":
        original = proof["pairs"][0]["original"]
        assert original["constant_branch_checks"]
        assert original["blocks_composed"] <= 16


@pytest.mark.parametrize("alias, expected", [(True, "true"), (False, "unknown")])
def test_constant_branch_keeps_symbolic_memory_aliases(alias: bool, expected: str) -> None:
    """An arbitrary loaded address cannot inherit a different store value."""
    from tools.dosunit.compare.flat32_constant_branches import constant_branch

    address = {"op": "input", "name": "eax", "width": 32}
    memory = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    value = {"op": "const", "width": 8, "value": "0x1"}
    stored = {"op": "storele", "width": 0, "args": [memory, address, value]}
    loaded = {"op": "loadle", "width": 8, "args": [stored, address if alias else
              {"op": "input", "name": "edx", "width": 32}]}
    result = constant_branch({"op": "eq", "width": 1, "args": [loaded, value]})
    assert result.value == expected
    assert (result.ssa_guard is not None) == alias


def test_constant_branch_limit_retains_unknown_control() -> None:
    """Large expressions never gain a guessed branch value after clipping."""
    from tools.dosunit.compare.flat32_constant_branches import constant_branch

    term = {"op": "input", "width": 1, "name": "x"}
    for _ in range(65):
        term = {"op": "not", "width": 1, "args": [term]}
    proof = constant_branch(term)
    assert proof.value == "unknown"
    assert proof.detail == "term_work_limit"


@pytest.mark.parametrize("changed", [False, True])
def test_target_lowering_reuse_is_image_bound_and_preserves_effects(monkeypatch: pytest.MonkeyPatch, changed: bool) -> None:
    """Repeated calls reuse decoding, while changed callee bytes still change the result."""
    from collections import Counter

    from tools.comparator import table_target_checks as owner

    native = owner._target_block
    visits = Counter()

    def counted(image: bytes, address: int):
        visits[image, address] += 1
        return native(image, address)

    monkeypatch.setattr(owner, "_target_block", counted)
    calls = bytes.fromhex("e80b000000e806000000c3").ljust(16, bytes.fromhex("90"))
    original = pe32_bytes(calls + bytes.fromhex("40c3"))
    candidate = pe32_bytes(calls + bytes.fromhex("83c002c3" if changed else "40c3"))
    proof = owner.check_returning_targets(original, candidate, {0x401000: 0x401000})
    assert proof["status"] == ("mismatch" if changed else "checked"), proof
    assert visits[original, 0x401010] == 1
    assert visits[candidate, 0x401010] == 1


@pytest.mark.parametrize("cc_op", [0, 3, 6, 9, 12, 15, 18, 21])
@pytest.mark.parametrize("condition", [0, 2, 4, 14])
def test_branch_dependency_projection_preserves_symbolic_flags(cc_op: int, condition: int) -> None:
    """Compare projected guards to the unprojected backend for arbitrary dependencies."""
    import z3

    from tools.dosunit.compare import straightline_ssa as S
    from tools.dosunit.compare.flat32_constant_branches import _project_flag_dependencies
    from tools.dosunit.ssa.materialization import input_items, materialize_term

    guard = {"op": "summary_x86g_calculate_condition", "width": 32, "args": [
        {"op": "const", "width": 32, "value": hex(condition)},
        {"op": "const", "width": 32, "value": hex(cc_op)},
        *({"op": "input", "name": name, "width": 32} for name in ("dep1", "dep2", "ndep"))]}
    expressions = []
    for term in (guard, _project_flag_dependencies(guard, {})):
        assignments = []
        output = materialize_term(term, assignments=assignments, memo={})
        document = {"outputs": {"guard": output}, "assignments": assignments,
                    "inputs": input_items([output], assignments)}
        expressions.append(S._z3_term(output, document=document,
                           inputs=S._z3_inputs(document, document, z3), z3=z3))
    solver = z3.Solver()
    solver.set(timeout=1000)
    solver.add(expressions[0] != expressions[1])
    assert solver.check() == z3.unsat
