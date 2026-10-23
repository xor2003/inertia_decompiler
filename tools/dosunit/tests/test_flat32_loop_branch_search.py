"""Real-byte controls for reversed branch proposals in complete loop induction."""
from typing import Any

import pytest

from tools.dosunit.compare.flat32_loop_calls import compare_flat32_loop_calls
from tools.dosunit.tests.test_flat32_comparator_lane import DriverLane, _project

pytest_plugins = ["test_flat32_comparator_lane"]
BASE = 0x100000


@pytest.mark.parametrize("suffix,expected", [
    ("31c0c3", "passed"),
    ("c3", "refused"),
    ("8944240431c0c3", "refused"),
])
@pytest.mark.parametrize("register", ["eax", "ebx"])
def test_dead_loop_accumulator(lane: DriverLane, suffix: str, expected: str, register: str) -> None:
    """Ignore arbitrary temporary arithmetic only if no exit or store reads it."""
    original = "85c9740501d049ebf7" + suffix
    candidate = "85c974060fafc249ebf6" + suffix
    if register == "ebx":
        original = original.replace("01d0", "01d3").replace("31c0", "31db").replace("89442404", "895c2404")
        candidate = candidate.replace("0fafc2", "0fafda").replace("31c0", "31db").replace("89442404", "895c2404")
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(candidate, BASE)),
        (BASE, len(bytes.fromhex(original))), (BASE, len(bytes.fromhex(candidate))),
        lane.adapter.OUTPUT_REGS, 20000,
    )
    assert result["status"] == expected, result
    if expected == "passed" and register == "ebx":
        assert any(register in row["fields"] for row in result["dead_register_projection"]["removed_outputs"])

# AND constrains EAX to 0/1; after CMP EAX,1, ZF and CF are complements.
# JE/JB therefore exchange arms without changing the complete flag state.
ORIGINAL = "85c9741583e00183f80174058d5b01eb038d5b028d49ffebe7c3"
REVERSED = "85c9741583e00183f80172058d5b02eb038d5b018d49ffebe7c3"


@pytest.mark.parametrize("candidate,expected", [
    (REVERSED, "passed"),
    (REVERSED.replace("7205", "7405"), "refused"),
    (REVERSED.replace("8d5b01", "8d5b02"), "refused"),
    (REVERSED.replace("8d49ff", "8d4901"), "refused"),
])
def test_reversed_loop_guard(lane: DriverLane, candidate: str, expected: str) -> None:
    """A graph proposal proves only after complete state/control discharge."""
    result = compare_flat32_loop_calls(
        (_project(ORIGINAL, BASE), _project(candidate, BASE)),
        (BASE, len(bytes.fromhex(ORIGINAL))), (BASE, len(bytes.fromhex(candidate))),
        lane.adapter.OUTPUT_REGS, 20000,
    )
    assert result["status"] == expected, result
    if expected == "passed":
        assert result["graph_evidence"]["orientation"] == "permuted_binary_successors"
        assert result["graph_search"]["candidates"]
        assert result["graph_attempts"][0]["status"] == "refused"
        assert result["graph_attempts"][0]["block_verdicts"]
        assert result["graph_attempts"][-1]["status"] == "passed"


def test_reversed_loop_with_real_callee(lane: DriverLane) -> None:
    """Paired branch inversion retains actual callee and return-slot effects."""
    original = "85c9741a83e00183f80174058d5b01eb038d5b02e8060000008d49ffebe2c347c3"
    candidate = "85c9741a83e00183f80172058d5b02eb038d5b01e8060000008d49ffebe2c347c3"
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(candidate, BASE)),
        (BASE, 31), (BASE, 31), lane.adapter.OUTPUT_REGS, 20000,
        oracle_functions={BASE: 31, BASE + 31: 2},
        candidate_functions={BASE: 31, BASE + 31: 2},
        candidate_normalization={BASE + 25: BASE + 25},
    )
    assert result["status"] == "conditional", result
    assert result["graph_evidence"]["orientation"] == "permuted_binary_successors"
    assert result["return_targets_proved"] >= 2
    assert result["normalization_assumptions"]["proved"] is False


def test_later_native_refusal_replaces_structural_mismatch(lane: DriverLane) -> None:
    """Report the callback obligation reached after a successful branch pairing."""
    original = "56578b7c24108b74240c3bfe76118bff8b060bc07402ffd083c6043bfe77f15f5ec3"
    candidate = "56578b7c240c8b7424103bf776118bff8b070bc07402ffd083c7043bfe72f15f5ec3"
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(candidate, BASE)),
        (BASE, len(bytes.fromhex(original))), (BASE, len(bytes.fromhex(candidate))),
        lane.adapter.OUTPUT_REGS, 20000,
    )
    assert result["status"] == "refused", result
    assert result["reason"] == "call_indirect_target_unconstrained", result
    assert result["graph_attempts"][0]["reason"] == "cfg_not_bijective", result
    assert result["graph_evidence"]["orientation"] == "permuted_binary_successors", result


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("changed", [False, True])
def test_merged_loop_return_tails(lane: DriverLane, reverse: bool, changed: bool) -> None:
    """Every split return must prove against the shared compiler return tail."""
    split = "85c9 7407 85d2 7404 49 ebf5 c3 " + ("40c3" if changed else "c3")
    merged = "85c9 7407 85d2 7403 49 ebf5 c3"
    original, candidate = (merged, split) if reverse else (split, merged)
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(candidate, BASE)),
        (BASE, len(bytes.fromhex(original))), (BASE, len(bytes.fromhex(candidate))),
        lane.adapter.OUTPUT_REGS, 20000,
    )
    assert result["status"] == ("refused" if changed else "passed"), result
    assert result["graph_evidence"]["terminal_merges"], result
    if changed:
        assert any(row["status"] == "failed" for row in result["block_verdicts"]), result


@pytest.mark.parametrize("live_carry", [False, True])
def test_dead_loop_flags_preserve_live_memory_carry(lane: DriverLane, live_carry: bool) -> None:
    """INC/ADD flags may differ only when no successor observes the carry."""
    carry = "8354240400" if live_carry else ""
    original = "40 7401 90 " + carry + "31c0 c3"
    candidate = "83c001 7401 90 " + carry + "31c0 c3"
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(candidate, BASE)),
        (BASE, len(bytes.fromhex(original))), (BASE, len(bytes.fromhex(candidate))),
        lane.adapter.OUTPUT_REGS, 20000,
    )
    assert result["status"] == ("refused" if live_carry else "passed"), result
    if not live_carry:
        assert result["dead_flag_projection"]["removed_outputs"], result


def _flag_dependency_document() -> dict[str, Any]:
    """A loop forwards lazy state before a later return observes CC_OP."""
    flags = {name: {"op": "input", "name": name, "width": 32}
             for name in ("cc_op", "cc_dep1", "cc_dep2", "cc_ndep")}
    one = {"op": "const", "width": 32, "value": "0x1"}
    two = {"op": "const", "width": 32, "value": "0x2"}
    guard = {"op": "input", "name": "ecx", "width": 32}
    functions = []
    for token, control in enumerate((one, {"op": "ite", "width": 32, "args": [guard, one, two]}, two)):
        terminal = token == 2
        outputs = {"eax": flags["cc_op"], "eip": control} if terminal else {**flags, "eip": control}
        functions.append({"source": {"cutpoint_token": token, "jumpkind": "Ijk_Ret" if terminal else "Ijk_Boring"},
                          "outputs": outputs, "assignments": []})
    return {"functions": functions}


def test_flag_demand_propagates_through_cycle() -> None:
    """A later observation keeps a flag live through arbitrarily many laps."""
    import time

    from tools.dosunit.compare.flat32_dead_flags import dead_flag_projection
    document = _flag_dependency_document()
    result = dead_flag_projection(document, document, deadline=time.monotonic() + 10)
    assert result is not None
    for projected in result[:2]:
        assert "cc_op" in projected["functions"][0]["outputs"]
        assert "cc_op" in projected["functions"][1]["outputs"]
        assert "cc_dep1" not in projected["functions"][0]["outputs"]
        assert projected["functions"][2]["outputs"] == document["functions"][2]["outputs"]
    assert result[2]["live_inputs"] == {"0": ["cc_op"], "1": ["cc_op"], "2": ["cc_op"]}


@pytest.mark.parametrize("field", ["cc_dep1", "ebx"])
@pytest.mark.parametrize("obligation", [False, True])
def test_predicate_only_dependency_is_live(field: str, obligation: bool) -> None:
    """An assignment-bound exception predicate retains otherwise dead inputs."""
    import time

    from tools.dosunit.compare.flat32_constant_registers import _document
    from tools.dosunit.compare.flat32_dead_flags import dead_flag_projection, dead_register_projection

    document = _flag_dependency_document()
    initial = {"op": "input", "name": field, "width": 32}
    zero = {"op": "const", "width": 32, "value": "0x0"}
    for function in document["functions"][:-1]:
        function["outputs"][field] = initial
        function["outputs"]["ecx"] = {"op": "input", "name": "ecx", "width": 32}
    if obligation:
        predicate = _document({}, {"predicate": {"op": "eq", "width": 1, "args": [initial, zero]}})
        function = document["functions"][1]
        function["assignments"] = predicate["assignments"]
        function["obligations"] = [{"predicate": predicate["outputs"]["predicate"]}]
    projection = dead_flag_projection if field == "cc_dep1" else dead_register_projection
    result = projection(document, document, deadline=time.monotonic() + 10)
    assert result is not None
    for projected in result[:2]:
        for function in projected["functions"][:-1]:
            assert (field in function["outputs"]) is obligation
        if obligation:
            assert projected["functions"][1]["obligations"] == document["functions"][1]["obligations"]


@pytest.mark.parametrize("corruption", ["missing_edge", "missing_state"])
def test_dead_flag_projection_requires_closed_complete_state(corruption: str) -> None:
    """An unknown successor or missing lazy-state output cannot justify projection."""
    import time

    from tools.dosunit.compare.flat32_dead_flags import dead_flag_projection
    document = _flag_dependency_document()
    if corruption == "missing_edge":
        document["functions"][0]["outputs"]["eip"] = {"op": "const", "width": 32, "value": "0x99"}
    else:
        del document["functions"][0]["outputs"]["cc_dep2"]
    assert dead_flag_projection(document, document, deadline=time.monotonic() + 10) is None



@pytest.mark.parametrize("prefix,expected", [
    ("90", "passed"), ("8bff", "passed"),
    ("40", "refused"), ("c744240401000000", "refused"),
])
@pytest.mark.parametrize("reverse", [False, True])
def test_shared_loop_body_with_entry_prefix(lane: DriverLane, prefix: str, expected: str, reverse: bool) -> None:
    """Both aliases must prove full effects; changed registers/memory cannot hide."""
    compact = "85c9 7405 49 85c9 75fb c3"
    padded = "85c9 74" + f"{5 + len(bytes.fromhex(prefix)):02x}" + prefix + "4985c975fbc3"
    original, candidate = (padded, compact) if reverse else (compact, padded)
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(candidate, BASE)),
        (BASE, len(bytes.fromhex(original))), (BASE, len(bytes.fromhex(candidate))),
        lane.adapter.OUTPUT_REGS, 20000,
    )
    assert result["status"] == expected, result
    assert result["graph_evidence"]["state_merges"], result
    assert len(result["block_verdicts"]) == 4
    if expected == "passed":
        assert result["graph_attempts"][0]["status"] == "refused"


def test_shared_loop_body_keeps_exit_guard(lane: DriverLane) -> None:
    """Reversing the entry guard changes termination and must remain unproved."""
    original = "85c974054985c975fbc3"
    candidate = "85c97506904985c975fbc3"
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(candidate, BASE)),
        (BASE, len(bytes.fromhex(original))), (BASE, len(bytes.fromhex(candidate))),
        lane.adapter.OUTPUT_REGS, 20000,
    )
    assert result["status"] == "refused", result


@pytest.mark.parametrize("selector", ["literal", "relocated", "dynamic"])
def test_flag_helper_dependencies_respect_selector_domain(selector: str) -> None:
    """DEC ZF drops saved CF, but changed or unknown selectors retain it."""
    import time

    from tools.dosunit.compare.flat32_dead_flags import dead_flag_projection

    document = _flag_dependency_document()
    inputs = {name: {"op": "input", "name": name, "width": 32}
              for name in ("cc_op", "cc_dep1", "cc_dep2", "cc_ndep")}
    operation = inputs["cc_op"] if selector == "dynamic" else {"op": "const", "value": "0x15", "width": 32}
    document["functions"][2]["outputs"]["eax"] = {
        "op": "summary_x86g_calculate_condition", "width": 32,
        "args": [{"op": "const", "value": "0x4", "width": 32}, operation,
                 inputs["cc_dep1"], inputs["cc_dep2"], inputs["cc_ndep"]],
    }
    result = dead_flag_projection(
        document, document, deadline=time.monotonic() + 10,
        candidate_normalization={21: 7} if selector == "relocated" else None,
    )
    if selector == "dynamic":
        assert result is None
    else:
        assert result is not None
        assert ("cc_ndep" in result[0]["functions"][0]["outputs"]) == (selector == "relocated")
        assert "cc_dep1" in result[0]["functions"][0]["outputs"]
        assert result[0]["functions"][2]["outputs"] == document["functions"][2]["outputs"]
