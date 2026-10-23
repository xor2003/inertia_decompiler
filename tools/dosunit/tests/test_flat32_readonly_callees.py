"""Real native nested-loop proofs and adversarial return-frame controls."""
import pytest

from tools.dosunit.compare.flat32_loop_calls import compare_flat32_loop_calls
from tools.dosunit.tests.test_flat32_comparator_lane import BASE, DriverLane, _project

pytest_plugins = ["test_flat32_comparator_lane"]


@pytest.mark.parametrize("callee,expected", [
    ("85c9740349ebf9c3", "passed"),
    ("85c97404ffc9ebf8c3", "passed"),
    ("85c9740341ebf9c3", "refused"),
    ("85c9740349ebf9c704242a000000c3", "refused"),
    ("85c9740349ebf983c404c3", "refused"),
    ("85c9740349ebf9c20400", "refused"),
])
def test_nested_count_loop(lane: DriverLane, callee: str, expected: str) -> None:
    """Use unbounded native induction; retain changed iteration/return behavior."""
    caller = "e801000000c3"
    original = "85c9740349ebf9c3"
    result = compare_flat32_loop_calls(
        (_project(caller + original, BASE), _project(caller + callee, BASE)),
        (BASE, 6), (BASE, 6), lane.adapter.OUTPUT_REGS, 20000,
        oracle_functions={BASE: 6, BASE + 6: len(bytes.fromhex(original))},
        candidate_functions={BASE: 6, BASE + 6: len(bytes.fromhex(callee))},
    )
    assert result["status"] == expected, result
    if expected == "passed":
        evidence = result["callee_frame_expansion"]
        assert len(evidence["oracle"]) == len(evidence["candidate"]) == 1
        assert all(proof["proof"]["status"] == "passed"
                   for side in evidence.values() for record in side for proof in record["proofs"])
        assert "assumptions" not in result


@pytest.mark.parametrize("caller,callee", [
    ("e806000000e801000000c3", "85c9740349ebf9c3"),
    ("ff742408ff742408e80400000083c408c3", "8b4c240433c0380174108a542408381175028bc14180390075f4c3"),
])
def test_distinct_contexts_and_native_byte_scan(lane: DriverLane, caller: str, callee: str) -> None:
    """Keep each return continuation separate and admit a data-dependent scan."""
    size = len(bytes.fromhex(caller))
    code = caller + callee
    functions = {BASE: size, BASE + size: len(bytes.fromhex(callee))}
    result = compare_flat32_loop_calls(
        (_project(code, BASE), _project(code, BASE)), (BASE, size), (BASE, size),
        lane.adapter.OUTPUT_REGS, 20000,
        oracle_functions=functions, candidate_functions=functions,
    )
    assert result["status"] == "passed", result
    records = result["callee_frame_expansion"]["oracle"]
    expected = 2 if size == 11 else 1
    assert len(records) == expected
    coordinates = [address for record in records for address in record["cloned_blocks"].values()]
    assert len(coordinates) == len(set(coordinates))


@pytest.mark.parametrize("corrupt", [False, True])
def test_saved_register_frame(lane: DriverLane, corrupt: bool) -> None:
    """PUSH/POP frame slots are allowed; overlapping return-slot writes are not."""
    caller = "e801000000c3"
    original = "5385c9740349ebf95bc3"
    candidate = original if not corrupt else "5385c9740349ebf9c74424042a0000005bc3"
    result = compare_flat32_loop_calls(
        (_project(caller + original, BASE), _project(caller + candidate, BASE)),
        (BASE, 6), (BASE, 6), lane.adapter.OUTPUT_REGS, 20000,
        oracle_functions={BASE: 6, BASE + 6: len(bytes.fromhex(original))},
        candidate_functions={BASE: 6, BASE + 6: len(bytes.fromhex(candidate))},
    )
    assert result["status"] == ("refused" if corrupt else "passed"), result
    if not corrupt:
        proofs = result["callee_frame_expansion"]["oracle"][0]["proofs"]
        assert any(row.get("entry_stack_displacement") == "0xfffffffc" for row in proofs)


@pytest.mark.parametrize("changed", [False, True])
def test_disjoint_store_is_still_observed(lane: DriverLane, changed: bool) -> None:
    """Proving return-slot preservation never hides other callee memory writes."""
    caller = "e801000000c3"
    original = "85c9740bc74424042a00000049ebf1c3"
    candidate = original.replace("2a000000", "2b000000") if changed else original
    functions = {BASE: 6, BASE + 6: len(bytes.fromhex(original))}
    result = compare_flat32_loop_calls(
        (_project(caller + original, BASE), _project(caller + candidate, BASE)),
        (BASE, 6), (BASE, 6), lane.adapter.OUTPUT_REGS, 20000,
        oracle_functions=functions, candidate_functions=functions,
    )
    assert result["status"] == ("refused" if changed else "passed"), result
    assert all(result["callee_frame_expansion"][side] for side in ("oracle", "candidate"))


@pytest.mark.parametrize("corrupt", [False, True])
def test_nested_wrapper_frames(lane: DriverLane, corrupt: bool) -> None:
    """Induct through two wrappers, retaining a leaf write into the outer return slot."""
    wrappers = "e801000000c3" * 3
    leaf = "85c97404ffc9ebf8" + ("c74424082a000000" if corrupt else "") + "c3"
    original = wrappers + "85c9740349ebf9c3"
    candidate = wrappers + leaf
    functions = {BASE: 6, BASE + 6: 6, BASE + 12: 6, BASE + 18: 8}
    result = compare_flat32_loop_calls(
        (_project(original, BASE), _project(candidate, BASE)),
        (BASE, 6), (BASE, 6), lane.adapter.OUTPUT_REGS, 20000,
        oracle_functions=functions,
        candidate_functions={**functions, BASE + 18: len(bytes.fromhex(leaf))},
    )
    assert result["status"] == ("refused" if corrupt else "passed"), result
    if not corrupt:
        record = result["callee_frame_expansion"]["oracle"][0]
        assert record["nested_callees"][0]["nested_callees"]


@pytest.mark.parametrize("recursive", [False, True])
def test_nested_frame_expansion_keeps_budget_and_recursion(lane: DriverLane, recursive: bool) -> None:
    """Incomplete child certificates never erase CALLs or publish partial bodies."""
    from tools.dosunit.compare.flat32_call_contracts import (
        CallCompositionLimits,
        _ComposeSession,
        _register_widths,
    )
    from tools.dosunit.compare.flat32_call_lowering import _lift_function
    from tools.dosunit.compare.flat32_callee_frames import expand_frame_safe_callees

    code = "e8fbffffffc3" if recursive else "e801000000c3" * 3 + "85c9740349ebf9c3"
    functions = {BASE: 6} if recursive else {BASE: 6, BASE + 6: 6, BASE + 12: 6, BASE + 18: 8}
    with lane.adapter.installed(region=True):
        session = _ComposeSession(
            project=_project(code, BASE), functions=functions, labels={},
            limits=CallCompositionLimits(max_inlined_calls=1), reg_widths=_register_widths(),
        )
        root = _lift_function(session, BASE)
        expanded, records = expand_frame_safe_callees(session, root)
    assert expanded == root
    assert records == []
    assert session.inlined_calls == 1


@pytest.mark.parametrize("unsafe_first", [False, True])
@pytest.mark.parametrize("unsafe_code", ["f7f1c3", "ffe090"])
def test_exception_callee_keeps_certified_sibling(
    lane: DriverLane, unsafe_first: bool, unsafe_code: str,
) -> None:
    """An incomplete DIV or indirect-JMP body keeps its CALL and certified sibling."""
    from tools.dosunit.compare.flat32_call_contracts import CallCompositionLimits, _ComposeSession, _register_widths
    from tools.dosunit.compare.flat32_call_lowering import _lift_function
    from tools.dosunit.compare.flat32_callee_frames import expand_frame_safe_callees

    calls = "e806000000e804000000c3" if unsafe_first else "e809000000e801000000c3"
    code = calls + unsafe_code + "85c9740349ebf9c3"
    with lane.adapter.installed(region=True):
        session = _ComposeSession(
            project=_project(code, BASE), functions={BASE: 11, BASE + 11: 3, BASE + 14: 8}, labels={},
            limits=CallCompositionLimits(), reg_widths=_register_widths(),
        )
        root = _lift_function(session, BASE)
        expanded, records = expand_frame_safe_callees(session, root)
    unsafe = BASE if unsafe_first else BASE + 5
    safe = BASE + 5 if unsafe_first else BASE
    assert expanded[unsafe] == root[unsafe]
    assert expanded[unsafe].jumpkind == "Ijk_Call"
    assert expanded[safe].jumpkind == "Ijk_Boring"
    assert len(records) == 1
    assert records[0]["callee"] == hex(BASE + 14)


def test_incomplete_parent_spends_no_certificate_budget(lane: DriverLane) -> None:
    """A wrapper with a cyclic child and an indirect jump cannot close as a frame."""
    from tools.dosunit.compare.flat32_call_contracts import CallCompositionLimits, _ComposeSession, _register_widths
    from tools.dosunit.compare.flat32_call_lowering import _lift_function
    from tools.dosunit.compare.flat32_callee_frames import expand_frame_safe_callees

    code = "e801000000c3" + "e806000000e809000000c3" + "85c9740349ebf9c3" + "ffe090"
    with lane.adapter.installed(region=True):
        session = _ComposeSession(
            project=_project(code, BASE),
            functions={BASE: 6, BASE + 6: 11, BASE + 17: 8, BASE + 25: 3}, labels={},
            limits=CallCompositionLimits(), reg_widths=_register_widths(),
        )
        root = _lift_function(session, BASE)
        expanded, records = expand_frame_safe_callees(session, root)
    assert expanded == root
    assert records == []
    assert session.compositions == 0
