"""Soundness controls for closed low-bit scratch-state induction."""
import copy
import time
from typing import Any

import pytest

from tools.dosunit.compare.flat32_loop_calls import compare_flat32_loop_calls
from tools.dosunit.compare.flat32_narrow_registers import narrow_register_projection
from tools.dosunit.tests.test_flat32_comparator_lane import DriverLane, _project

pytest_plugins = ["test_flat32_comparator_lane"]
BASE = 0x100000


def _input(name: str) -> dict[str, Any]:
    """Make a full-width scratch coordinate."""
    return {"op": "input", "name": name, "width": 32}


def _literal(value: int) -> dict[str, Any]:
    """Make a control or arithmetic literal."""
    return {"op": "const", "value": hex(value), "width": 32}


def _document() -> dict[str, Any]:
    """Forward DX through a cycle before observing it at a scalar return."""
    scratch = {name: _input(name) for name in ("eax", "ecx", "edx")}
    low = {"op": "zext", "width": 32, "args": [{"op": "trunc", "width": 16, "args": [_input("edx")]}]}
    functions = []
    for token in range(3):
        terminal = token == 2
        control = _literal(1) if token == 0 else {"op": "ite", "width": 32, "args": [
            _input("ecx"), _literal(1), _literal(2)]}
        outputs = {"eax": low, "eip": _literal(0)} if terminal else {**scratch, "eip": control}
        functions.append({"source": {"cutpoint_token": token, "jumpkind": "Ijk_Ret" if terminal else "Ijk_Boring"},
                          "outputs": outputs, "assignments": []})
    return {"functions": functions}


def test_low_bits_propagate_through_cycle() -> None:
    """Repeated edges preserve all demanded DX bits and all control bits."""
    document = _document()
    result = narrow_register_projection(document, document, deadline=time.monotonic() + 10)
    assert result is not None
    evidence = result[2]
    assert evidence["live_input_bits"]["0"]["edx"] == 32
    assert evidence["live_input_bits"]["1"]["edx"] == 16
    assert evidence["retained_output_bits"][0]["edx"] == 16
    assert evidence["retained_output_bits"][1]["ecx"] == 32
    assert result[0]["functions"][2]["outputs"]["eax"]


def test_full_width_predicate_survives_projection() -> None:
    """A bound predicate retains high bits and its original assignment meaning."""
    from tools.dosunit.compare.flat32_constant_registers import _document as materialize
    from tools.dosunit.compare.flat32_dead_flags import _state

    document = _document()
    expression = {"op": "eq", "width": 1, "args": [_input("edx"), _literal(0)]}
    predicate = materialize({}, {"predicate": expression})
    document["functions"][1]["assignments"] = predicate["assignments"]
    document["functions"][1]["obligations"] = [{"predicate": predicate["outputs"]["predicate"]}]
    result = narrow_register_projection(document, document, deadline=time.monotonic() + 10)
    assert result is not None
    assert result[2]["live_input_bits"]["1"]["edx"] == 32
    for projected in result[:2]:
        function = projected["functions"][1]
        probe = {**function, "outputs": {"predicate": function["obligations"][0]["predicate"]}}
        assert _state(probe, time.monotonic() + 10)["predicate"] == expression


@pytest.mark.parametrize("consumer", ["return", "address", "control", "shift", "entry_backedge"])
def test_full_width_consumers_prevent_narrowing(consumer: str) -> None:
    """One side's full-width use keeps EDX exact through arbitrarily many laps."""
    original = _document()
    candidate = copy.deepcopy(original)
    outputs = candidate["functions"][2]["outputs"]
    if consumer == "return":
        outputs["edx"] = _input("edx")
        original["functions"][2]["outputs"]["edx"] = _input("edx")
    elif consumer == "address":
        outputs["eax"] = {"op": "loadle", "width": 32, "args": [
            {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}, _input("edx")]}
    elif consumer == "control":
        outputs["eip"] = _input("edx")
    elif consumer == "shift":
        outputs["eax"] = {"op": "lshr", "width": 32, "args": [_input("edx"), _literal(16)]}
    else:
        candidate["functions"][1]["outputs"]["eip"] = _literal(0)
    result = narrow_register_projection(original, candidate, deadline=time.monotonic() + 10)
    if consumer == "entry_backedge":
        assert result is None  # Every scratch coordinate must remain full at entry.
        return
    assert result is not None
    assert result[2]["retained_output_bits"][0]["edx"] == 32
    assert result[2]["retained_output_bits"][1]["edx"] == 32


@pytest.mark.parametrize("corruption", ["edge", "scratch", "token"])
def test_incomplete_graph_has_no_projection(corruption: str) -> None:
    """Projection needs closed paired edges and complete continuing scratch state."""
    original = _document()
    candidate = copy.deepcopy(original)
    if corruption == "edge":
        candidate["functions"][0]["outputs"]["eip"] = _literal(99)
    elif corruption == "scratch":
        del candidate["functions"][0]["outputs"]["edx"]
    else:
        candidate["functions"][0]["source"]["cutpoint_token"] = 99
    assert narrow_register_projection(original, candidate, deadline=time.monotonic() + 10) is None


@pytest.mark.parametrize("strict,changed", [(False, False), (True, False), (False, True)])
def test_native_dx_loop(lane: DriverLane, strict: bool, changed: bool) -> None:
    """Scalar return admits dead high EDX; strict EDX and changed DX still fail."""
    original = "bafeffffff 85c9 7403 49 ebf9 0fb7c2 c3"
    candidate = ("bafdff0000" if changed else "bafeff0000") + "85c9 7403 49 ebf9 0fb7c2 c3"
    outputs = lane.adapter.OUTPUT_REGS if strict else tuple(r for r in lane.adapter.OUTPUT_REGS if r != "edx")
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(candidate, BASE)),
        (BASE, len(bytes.fromhex(original))), (BASE, len(bytes.fromhex(candidate))),
        outputs, 20000,
    )
    assert result["status"] == ("refused" if strict or changed else "passed"), result
    if not strict and not changed:
        retained = result["narrow_register_projection"]["retained_output_bits"][0]["edx"]
        assert retained in {0, 16}
        if retained == 0:
            assert set(result["native_constant_invariants"]) == {"oracle", "candidate"}



@pytest.mark.parametrize("relocated", [False, True])
def test_relocated_mask_cannot_justify_dead_bits(relocated: bool) -> None:
    """A mask rewritten to cover high bits keeps those input bits observable."""
    document = _document()
    document["functions"][2]["outputs"]["eax"] = {
        "op": "and", "width": 32, "args": [_input("edx"), _literal(0xFFFF)]}
    result = narrow_register_projection(
        document, document, deadline=time.monotonic() + 10,
        candidate_normalization={0xFFFF: 0xFFFFFFFF} if relocated else None,
    )
    assert result is not None
    assert result[2]["retained_output_bits"][0]["edx"] == (32 if relocated else 16)



def test_folded_mask_does_not_hide_relocated_operands() -> None:
    """A folded 16-bit mask can gain high bits when one operand relocates."""
    document = _document()
    mask = {"op": "sub", "width": 32, "args": [_literal(0x10000), _literal(1)]}
    document["functions"][2]["outputs"]["eax"] = {
        "op": "and", "width": 32, "args": [_input("edx"), mask]}
    result = narrow_register_projection(
        document, document, deadline=time.monotonic() + 10,
        candidate_normalization={0x10000: 0x20000},
    )
    assert result is not None
    assert result[2]["retained_output_bits"][0]["edx"] == 32



def test_low_word_relocation_can_make_masked_byte_live() -> None:
    """A low-word relocation of FFFFFF00 must not hide the now-observed DL."""
    document = _document()
    masked = {"op": "and", "width": 32, "args": [_input("edx"), _literal(0xFFFFFF00)]}
    document["functions"][2]["outputs"]["eax"] = {
        "op": "zext", "width": 32, "args": [{"op": "trunc", "width": 8, "args": [masked]}]}
    result = narrow_register_projection(
        document, document, deadline=time.monotonic() + 10,
        candidate_normalization={0xFF00: 0xFFFF},
    )
    assert result is not None
    assert result[2]["retained_output_bits"][0]["edx"] == 8


@pytest.mark.parametrize("operator", ["sub", "xor"])
@pytest.mark.parametrize("same", [False, True])
def test_cancelled_operand_is_not_a_live_dependency(operator: str, same: bool) -> None:
    """Exact bitvector cancellation drops demand; distinct operands stay live."""
    document = _document()
    document["functions"][2]["outputs"]["eax"] = {
        "op": operator, "width": 32, "args": [_input("edx"), _input("edx" if same else "eax")]}
    result = narrow_register_projection(document, document, deadline=time.monotonic() + 10)
    if not same:
        assert result is None  # Every scratch coordinate remains observable.
        return
    assert result is not None
    assert result[2]["retained_output_bits"][0]["edx"] == 0


@pytest.mark.parametrize("condition,operation,expected", [
    (4, 21, {"eax": 32}), (2, 21, {"edx": 1}),
    (6, 21, {"eax": 32, "edx": 1}),
    (4, 7, {"eax": 8, "ecx": 8, "edx": 1}),
    (4, 6, {"eax": 32, "ecx": 32}), (2, 15, {}),
])
def test_exact_flag_helpers_use_only_required_dependencies(condition, operation, expected) -> None:
    """ZF after DEC ignores preserved CF; ADC and unsigned conditions retain it."""
    from tools.dosunit.compare.flat32_narrow_registers import _dependencies

    term = {"op": "summary_x86g_calculate_condition", "width": 32,
            "args": [_literal(condition), _literal(operation), _input("eax"), _input("ecx"), _input("edx")]}
    assert _dependencies(term, 32, frozenset()) == expected


@pytest.mark.parametrize("mutation", ["relocated_condition", "relocated_operation", "dynamic", "unsupported"])
def test_unfixed_flag_selectors_keep_full_dependencies(mutation: str) -> None:
    """Normalization and abstract helpers cannot inherit literal selector facts."""
    from tools.dosunit.compare.flat32_narrow_registers import _dependencies

    term = {"op": "summary_x86g_calculate_condition", "width": 32,
            "args": [_literal(4), _literal(21), _input("eax"), _input("ecx"), _input("edx")]}
    relocated = frozenset({4 if mutation == "relocated_condition" else 21}) if mutation.startswith("relocated") else frozenset()
    if mutation == "dynamic":
        term["args"][1] = _input("eax")
    elif mutation == "unsupported":
        term["args"][1] = _literal(40)
    assert _dependencies(term, 32, relocated) == {"eax": 32, "ecx": 32, "edx": 32}


def test_exact_increment_carry_ignores_result_dependency() -> None:
    """The carry-only helper observes saved CF even if INC changes its result."""
    from tools.dosunit.compare.flat32_narrow_registers import _dependencies

    term = {"op": "summary_x86g_calculate_eflags_c", "width": 32,
            "args": [_literal(18), _input("eax"), _input("ecx"), _input("edx")]}
    assert _dependencies(term, 32, frozenset()) == {"edx": 1}
