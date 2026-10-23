"""Declared return registers require paired complete-return SAT witnesses."""

from pathlib import Path

import pytest

from tools.comparator.return_counterexample import find_return_counterexample
from tools.dosunit.tests.test_flat32_loaded_byte_boundaries import pe32_bytes


@pytest.mark.parametrize("outputs,tail,expected", [
    (("eax", "edx"), "31d2c3", "found"),
    (("eax",), "31d2c3", "not_found"),
    (("eax", "edx"), "31d2ebfe", "not_found"),
    (("eax", "edx"), "c3", "not_found"),
])
def test_explicit_edx_observation_requires_complete_returns(outputs, tail, expected) -> None:
    left, right = bytes.fromhex("c3"), bytes.fromhex(tail)
    result = find_return_counterexample(
        pe32_bytes(left), pe32_bytes(right), (0x401000, len(left)), (0x401000, len(right)),
        output_registers=outputs,
    )
    assert result["status"] == expected, result
    assert result["equivalence_proved"] is False
    assert result["output_registers"] == list(outputs)
    if expected == "found":
        assert result["solver_result"]["mismatches"][0]["reg"] == "edx"


@pytest.mark.parametrize("outputs,expected", [("eax,edx,esp", "failed"), ("eax,esp", "passed")])
def test_public_driver_checks_declared_edx_after_loop_refusal(tmp_path: Path, outputs: str, expected: str) -> None:
    from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane
    from tools.dosunit.tests.test_flat32_stack_domain_cli import _driver_args

    left = bytes.fromhex("8b4c240485c974034975fdc3")
    right = bytes.fromhex("31d2") + left
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
        args.output_regs = outputs
        args.find_return_counterexamples = True
        report = lane.z3cmp32.compare(args)
    row, = report["results"]
    assert row["status"] == expected, row
    if expected == "passed":
        assert "root_counterexample" not in row
        return
    assert row["root_counterexample"]["status"] == "found"
    assert row["root_counterexample"]["solver_result"]["mismatches"][0]["reg"] == "edx"
    assert row["strict_function_result"]["status"] == "refused"


@pytest.mark.parametrize("outputs", [(), ("eax", "eax"), ("memory",), ("ax",)])
def test_counterexample_rejects_unsupported_observation(outputs) -> None:
    image = pe32_bytes(bytes.fromhex("c3"))
    with pytest.raises(ValueError, match="full-width"):
        find_return_counterexample(image, image, (0x401000, 1), (0x401000, 1), output_registers=outputs)


@pytest.mark.parametrize("tail,addresses,expected", [
    ("c3", (0x60020010,), "found"),
    ("c3", (0x60020011,), "not_found"),
    ("ebfe", (0x60020010,), "not_found"),
])
def test_memory_counterexample_requires_observed_byte_and_both_returns(tail, addresses, expected) -> None:
    left = bytes.fromhex("c6 05 10000260 11 c3")
    right = bytes.fromhex("c6 05 10000260 22 " + tail)
    result = find_return_counterexample(
        pe32_bytes(left), pe32_bytes(right), (0x401000, len(left)), (0x401000, len(right)),
        memory_addresses=addresses,
    )
    assert result["status"] == expected, result
    assert result["equivalence_proved"] is False
    assert result["memory_addresses"] == [hex(address) for address in addresses]
    if expected == "found":
        assert any(row["reg"] == "memory_byte_60020010"
                   for row in result["solver_result"]["mismatches"])


def test_memory_counterexample_requires_original_caller_return_slot() -> None:
    left = bytes.fromhex("c6 05 10000260 11 c3")
    # Changing a memory byte followed by a different return address is not a
    # paired root return witness, even if both paths execute RET.
    right = bytes.fromhex("c6 05 10000260 22 ff0424 c3")
    result = find_return_counterexample(
        pe32_bytes(left), pe32_bytes(right), (0x401000, len(left)), (0x401000, len(right)),
        memory_addresses=(0x60020010,),
    )
    assert result["status"] == "not_found", result


@pytest.mark.parametrize("addresses", [(True,), (-1,), (2**32,), (1, 1)])
def test_memory_counterexample_rejects_invalid_addresses(addresses) -> None:
    image = pe32_bytes(bytes.fromhex("c3"))
    with pytest.raises(ValueError, match="memory"):
        find_return_counterexample(image, image, (0x401000, 1), (0x401000, 1),
                                   memory_addresses=addresses)


def test_attach_memory_counterexample_retains_strict_refusal() -> None:
    from tools.comparator.return_counterexample import attach_return_counterexamples

    left, right = (bytes.fromhex("c6 05 10000260 " + value + " c3") for value in ("11", "22"))
    report = {"function_ranges": {"oracle": {"f": [0x401000, len(left)]},
                                  "candidate": {"f": [0x401000, len(right)]}},
              "results": [{"function": {"name": "f"}, "status": "refused", "reason": "test_gap"}]}
    attach_return_counterexamples(report, pe32_bytes(left), pe32_bytes(right), {"f"},
                                  memory_addresses=(0x60020010,))
    row, = report["results"]
    assert row["status"] == "failed"
    assert row["reason"] == "root_return_memory_counterexample"
    assert row["strict_function_result"]["status"] == "refused"
    assert row["root_counterexample"]["memory_addresses"] == ["0x60020010"]


@pytest.mark.parametrize("tail,expected", [
    ("c6 05 10000260 22 c3", "found"),
    ("c6 05 10000260 11 c3", "not_found"),
    ("c6 05 10000260 22 ebfe", "not_found"),
])
def test_memory_counterexample_unrolls_completed_loop(tail, expected) -> None:
    prefix = "b9 03000000 49 75fd "
    left = bytes.fromhex(prefix + "c6 05 10000260 11 c3")
    right = bytes.fromhex(prefix + tail)
    result = find_return_counterexample(
        pe32_bytes(left), pe32_bytes(right), (0x401000, len(left)), (0x401000, len(right)),
        memory_addresses=(0x60020010,),
    )
    assert result["status"] == expected, result
    assert result["equivalence_proved"] is False
    assert all(row["visited_blocks"] <= 64 for row in result["work"])


def test_counterexample_loader_stops_before_effects_after_jecxz() -> None:
    from tools.comparator.table_target_checks import _mapped_target_block

    image = pe32_bytes(bytes.fromhex("e30140c3"))
    lowered, facts, _ = _mapped_target_block(image, 0x401000)
    assert lowered is not None, facts
    assert facts["byte_count"] == 2
    assert facts["conditional_targets"] == ["0x401003"]


def test_memory_counterexample_observes_enter_frame() -> None:
    left = bytes.fromhex("c8000000 c6051000026011 c9 c3")
    right = bytes.fromhex("c8000000 c6051000026022 c9 c3")
    result = find_return_counterexample(
        pe32_bytes(left), pe32_bytes(right), (0x401000, len(left)), (0x401000, len(right)),
        memory_addresses=(0x60020010,),
    )
    assert result["status"] == "found", result


@pytest.mark.parametrize("direction,expected", [(1, 1), (0xFFFFFFFF, 1), (0, 0), (2, 0)])
def test_root_witness_guard_requires_architectural_direction(direction, expected) -> None:
    from tools.comparator.return_counterexample import _observation_document, _returned_guard
    from tools.dosunit.compare import straightline_ssa as owner

    root = {"op": "loadle", "width": 32, "args": [
        {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
        {"op": "input", "name": "esp", "width": 32}]}
    state = {"ip": root, "returned": {"op": "const", "width": 1, "value": "0x1"}}
    guard = _returned_guard(state, state)
    proof = owner._compare_functions(
        _observation_document({"observed": guard}),
        _observation_document({"observed": {"op": "const", "width": 1, "value": hex(expected)}}),
        timeout_ms=1000,
        input_constraints=[{"name": "d", "kind": "unsigned_range", "min": direction, "max": direction}],
    )
    assert proof["status"] == "passed", proof


@pytest.mark.parametrize("repeat", ["f3aa", "f3ab", "f3a4", "f3a5", "f2ae", "f3a7"])
@pytest.mark.parametrize("count,expected", [(0, "found"), (1, "not_found")])
def test_memory_counterexample_closes_supported_repeat_paths(count, expected, repeat) -> None:
    prefix = "b9 " + count.to_bytes(4, "little").hex() + " " + repeat + " "
    left = bytes.fromhex(prefix + "c6051000026011 c3")
    right = bytes.fromhex(prefix + "c6051000026022 c3")
    result = find_return_counterexample(
        pe32_bytes(left), pe32_bytes(right), (0x401000, len(left)), (0x401000, len(right)),
        memory_addresses=(0x60020010,),
    )
    assert result["status"] == ("found" if repeat == "f2ae" else expected), result
    assert result["equivalence_proved"] is False


def test_root_memory_witness_retains_input_bytes() -> None:
    left = bytes.fromhex("a000100060 a210000260 c3")
    right = bytes.fromhex("a000100060 fec0 a210000260 c3")
    result = find_return_counterexample(
        pe32_bytes(left), pe32_bytes(right), (0x401000, len(left)), (0x401000, len(right)),
        memory_addresses=(0x60020010,),
    )
    assert result["status"] == "found", result
    memory = result["solver_result"]["counterexample_memory"]["mem"]
    assert memory["status"] == "complete"
    stores = {int(row["address"], 0): row["value"] for row in memory["stores"]}
    source = stores.get(0x60001000, memory["default_byte"])
    changed = next(row for row in result["solver_result"]["mismatches"]
                   if row["reg"] == "memory_byte_60020010")
    assert int(changed["oracle_value"], 0) == source
    assert int(changed["candidate_value"], 0) == (source + 1) & 255


@pytest.mark.parametrize("repeat", ["f2ae", "f3ae", "f2af", "f3af"])
@pytest.mark.parametrize("changed", [False, True])
def test_bounded_scan_closes_single_iteration(repeat, changed) -> None:
    """A one-element native scan reaches RET; equal scans never prove equivalence."""
    prefix = "b901000000 " + repeat + " "
    left = bytes.fromhex(prefix + "b801000000 c3")
    right = bytes.fromhex(prefix + ("b802000000" if changed else "b801000000") + " c3")
    result = find_return_counterexample(
        pe32_bytes(left), pe32_bytes(right), (0x401000, len(left)), (0x401000, len(right)),
        memory_addresses=(0x60020010,),
    )
    assert result["status"] == ("found" if changed else "not_found"), result
    assert result["equivalence_proved"] is False


@pytest.mark.parametrize("repeat", ["f2ae", "f3ae", "f2af", "f3af"])
@pytest.mark.parametrize("direction", ["fc", "fd"])
@pytest.mark.parametrize("observe", ["0f94c0 0fb6c0", "89f8", "89c8"])
def test_bounded_scan_preserves_scalar_flags_index_and_counter(repeat, direction, observe) -> None:
    """One-element REP and scalar SCAS agree on flags, DF-scaled index and ECX."""
    prefix = direction + " b901000000 "
    left = bytes.fromhex(prefix + repeat + " " + observe + " c3")
    # DEC would clobber SCAS flags: use MOV ECX,0 for the scalar control.
    right = bytes.fromhex(prefix + repeat[2:] + " b900000000 " + observe + " c3")
    result = find_return_counterexample(
        pe32_bytes(left), pe32_bytes(right), (0x401000, len(left)), (0x401000, len(right)),
        memory_addresses=(0x60020010,),
    )
    assert result["status"] == "not_found", result
    assert result["work"][0]["clipped_paths"] == 0, result
    assert result["equivalence_proved"] is False


@pytest.mark.parametrize("repeat,accumulator", [("f2ae", "31c0"), ("f3ae", "b801000000")])
def test_bounded_scan_stops_on_comparison_before_exhausting_count(repeat, accumulator) -> None:
    """REPNE equality / REPE inequality stops after the first byte, with ECX=4."""
    prefix = "bf10000260 c60700 " + accumulator + " b905000000 "
    left = bytes.fromhex(prefix + repeat + " 89c8 c3")
    right = bytes.fromhex(prefix + "b804000000 c3")
    result = find_return_counterexample(
        pe32_bytes(left), pe32_bytes(right), (0x401000, len(left)), (0x401000, len(right)),
        memory_addresses=(0x60020010,),
    )
    assert result["status"] == "not_found", result
    assert result["work"][0]["clipped_paths"] == 0, result


def test_bounded_scan_does_not_turn_clipped_iterations_into_returns() -> None:
    """Four known equal bytes exceed the three-visit bound; the tail is not evidence."""
    prefix = "fc 31c0 bf10000260 c70700000000 b908000000 f3ae "
    left = bytes.fromhex(prefix + "b801000000 c3")
    right = bytes.fromhex(prefix + "b802000000 c3")
    result = find_return_counterexample(
        pe32_bytes(left), pe32_bytes(right), (0x401000, len(left)), (0x401000, len(right)),
        memory_addresses=(0x60020010,),
    )
    assert result["status"] == "not_found", result
    assert result["work"][0]["clipped_paths"] > 0, result


@pytest.mark.parametrize("observe", ["0f94c0 0fb6c0", "89f8", "89c8"])
def test_bounded_scan_two_iterations_match_two_scalar_scans(observe) -> None:
    """A first unequal byte and second equal byte advance twice and keep final flags."""
    prefix = "fc b801000000 bf10000260 c70702010000 b902000000 "
    left = bytes.fromhex(prefix + "f2ae " + observe + " c3")
    right = bytes.fromhex(prefix + "ae ae b900000000 " + observe + " c3")
    result = find_return_counterexample(
        pe32_bytes(left), pe32_bytes(right), (0x401000, len(left)), (0x401000, len(right)),
        memory_addresses=(0x60020010,),
    )
    assert result["status"] == "not_found", result
    assert result["work"][0]["clipped_paths"] == 0, result
