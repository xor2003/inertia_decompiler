"""Native nested-call controls for root-bound composition and shared budgets."""

from pathlib import Path
from typing import Any

import pytest

import tools.dosunit.compare.flat32_call_execution as execution
from tools.dosunit.compare.flat32_call_composition import (
    CallCompositionLimits,
    compare_functions_with_calls,
    summarize_with_calls,
)
from tools.dosunit.compare.flat32_call_contracts import CallCompositionRefusal
from tools.dosunit.tests.test_flat32_comparator_lane import BASE, DriverLane, _project
from tools.dosunit.tests.test_flat32_comparator_lane import lane as lane
from tools.dosunit.tests.test_flat32_stack_domain_cli import TEXT_BASE, _driver_args, _install_fixture, pe32_bytes

FUNCTIONS = {BASE: 13, BASE + 13: 6, BASE + 19: 7}


@pytest.mark.parametrize("changed", [False, True])
@pytest.mark.parametrize("transfer", ["e801000000c3", "e90100000090"])
def test_summary_schedule_proves_deep_internal_chain(
    lane: DriverLane, changed: bool, transfer: str,
) -> None:
    """Completed leaf-first summaries cross depth1 without enlarging work caps."""
    prefix = transfer * 7
    original = prefix + "b82a000000c3"
    candidate = prefix + ("b82b000000c3" if changed else "b82a000000c3")
    functions = {BASE + index * 6: 6 for index in range(8)}
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(original, BASE), _project(candidate, BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions=functions, candidate_functions=functions,
            outputs=lane.adapter.GPRS, timeout_ms=10000,
            limits=CallCompositionLimits(max_inline_depth=1),
        )
    assert result["status"] == ("failed" if changed else "passed"), result


def test_summary_schedule_preserves_nested_cycle_location(lane: DriverLane) -> None:
    """A generic cyclic leaf must reach induction retry, not become a depth cap."""
    code = "e801000000c3" * 3 + "85c9740349ebf9c3"
    functions = {BASE: 6, BASE + 6: 6, BASE + 12: 6, BASE + 18: 8}
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(code, BASE), _project(code, BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions=functions, candidate_functions=functions,
            outputs=lane.adapter.GPRS, timeout_ms=10000,
            limits=CallCompositionLimits(max_inline_depth=1),
        )
    assert result["status"] == "refused", result
    assert result["reason"] == "loop_requires_inductive_proof", result
    assert result["refusal_location"]["function_entry"] == hex(BASE + 18), result


def test_summary_cycle_restores_caller_mode(lane: DriverLane) -> None:
    """Failed generic scheduling preserves the caller domain and publishes no body."""
    from tools.dosunit.compare.flat32_call_contracts import (
        InductiveLoopRequired,
        _ComposeSession,
        _register_widths,
    )
    from tools.dosunit.compare.flat32_summary_schedule import prepare_internal_summary

    code = "85c9740349ebf9c3"
    with lane.adapter.installed(region=True):
        session = _ComposeSession(
            project=_project(code, BASE), functions={BASE: 8}, labels={},
            limits=CallCompositionLimits(max_inline_depth=1), reg_widths=_register_widths(),
            root_bound_inputs=True,
        )
        domain = session.entry_domain
        with pytest.raises(InductiveLoopRequired):
            prepare_internal_summary(session, BASE, frozenset(), execution._compose_function)
    assert session.root_bound_inputs is True
    assert session.entry_domain is domain
    assert BASE not in session.summaries


def test_summary_schedule_rebinds_root_context(lane: DriverLane) -> None:
    """One cached body receives distinct caller EAX and ESP at two call sites."""
    from tools.dosunit.compare import straightline_ssa as scalar
    from tools.dosunit.compare.flat32_call_contracts import _ComposeSession, _register_widths
    from tools.dosunit.compare.flat32_constant_registers import _document

    # Two root calls to the same four-wrapper chain, each with a fresh EAX.
    root = "b801000000e80b000000b807000000e801000000c3"
    code = root + "e801000000c3" * 4 + "83c001c3"
    functions = {BASE: 21, **{BASE + 21 + index * 6: 6 for index in range(4)}, BASE + 45: 4}
    with lane.adapter.installed(region=True):
        session = _ComposeSession(
            project=_project(code, BASE), functions=functions, labels={},
            limits=CallCompositionLimits(max_inline_depth=1), reg_widths=_register_widths(),
            root_bound_inputs=True,
        )
        state = execution._compose_root(session, BASE)
        proof = scalar._compare_functions(
            _document({}, {"eax": state["eax"]}),
            _document({}, {"eax": {"op": "const", "width": 32, "value": "0x8"}}), timeout_ms=1000,
        )
    assert proof["status"] == "passed", proof
    assert session.root_bound_inputs is True
    assert session.summaries


def test_summary_schedule_rebinds_checking_predicates(lane: DriverLane) -> None:
    """A generic FWAIT obligation is rebound before and after root FNINIT."""
    from tools.dosunit.compare import straightline_ssa as scalar
    from tools.dosunit.compare.flat32_call_contracts import _ComposeSession, _register_widths
    from tools.dosunit.compare.flat32_constant_registers import _document

    root = "e808000000dbe3e801000000c3"
    code = root + "e801000000c3" * 4 + "9bc3"
    functions = {BASE: 13, **{BASE + 13 + index * 6: 6 for index in range(4)}, BASE + 37: 2}
    with lane.adapter.installed(region=True):
        session = _ComposeSession(
            project=_project(code, BASE), functions=functions, labels={},
            limits=CallCompositionLimits(max_inline_depth=1), reg_widths=_register_widths(),
            root_bound_inputs=True,
        )
        execution._compose_root(session, BASE)
        assert len(session.x87_obligations) == 2
        proofs = [scalar._compare_functions(
            _document({}, {"eax": obligation["predicate"]}),
            _document({}, {"eax": {"op": "const", "width": 1, "value": "0x1"}}), timeout_ms=1000,
        ) for obligation in session.x87_obligations]
    assert [proof["status"] for proof in proofs] == ["failed", "passed"]


def _code(offset: int = 0x100, value: int = 42) -> str:
    """Root derives EAX from ESP; two calls reach a dword store through EAX."""
    return (
        "89e0 05" + (offset & 0xFFFFFFFF).to_bytes(4, "little").hex()
        + " e801000000 c3 e801000000 c3 c700"
        + value.to_bytes(4, "little").hex() + " c3"
    )


def _result(lane: DriverLane, oracle: str, candidate: str) -> dict[str, Any]:
    """Compare all retained register, memory and return effects using real Z3."""
    with lane.adapter.installed(region=True):
        return compare_functions_with_calls(
            _project(oracle, BASE), _project(candidate, BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions=FUNCTIONS, candidate_functions=FUNCTIONS,
            outputs=lane.adapter.GPRS, timeout_ms=10000,
        )


def test_nested_store_uses_proved_root_pointer_without_assumption(lane: DriverLane) -> None:
    """Caller-computed disjointness survives a nested call boundary."""
    result = _result(lane, _code(), _code())
    assert result["status"] == "passed", result
    assert "assumptions" not in result
    assert result["return_targets_proved"] == 4


def test_nested_store_mutation_remains_observable(lane: DriverLane) -> None:
    """Root-bound inlining must not hide the nested callee's memory write."""
    result = _result(lane, _code(), _code(value=43))
    assert result["status"] == "failed", result


@pytest.mark.parametrize("offset", (-4, -8))
def test_nested_store_cannot_overwrite_either_return_slot(lane: DriverLane, offset: int) -> None:
    """Inner and outer return-address corruption still prevents continuation."""
    result = _result(lane, _code(offset), _code(offset))
    assert result["status"] == "refused", result
    assert result["reason"].startswith("call_return_target")


@pytest.mark.parametrize("budget", (3, 4))
def test_retry_shares_inline_budget_and_reuses_lifted_blocks(lane: DriverLane, budget: int) -> None:
    """Both attempts are charged; retry reuses the same five lifted blocks."""
    with lane.adapter.installed(region=True):
        if budget == 3:
            with pytest.raises(CallCompositionRefusal, match="call_inline_budget"):
                summarize_with_calls(
                    _project(_code(), BASE), entry=BASE, functions=FUNCTIONS,
                    outputs=lane.adapter.GPRS, limits=CallCompositionLimits(max_inlined_calls=budget),
                )
        else:
            summary = summarize_with_calls(
                _project(_code(), BASE), entry=BASE, functions=FUNCTIONS,
                outputs=lane.adapter.GPRS, limits=CallCompositionLimits(max_inlined_calls=budget),
            )
            assert summary["root_bound_retry"] is True
            assert summary["blocks_lifted"] == 5  # root/continuation, wrapper/continuation, leaf
            assert summary["inlined_calls"] == 4
            assert summary["return_targets_proved"] == len(summary["call_sites"]) == 2


def test_second_call_does_not_reuse_first_contextual_summary(lane: DriverLane) -> None:
    """The same callee at a later callsite must consume that site's pointer."""
    root = bytearray()
    root_size = 25
    for offset in (0x100, -8):
        root.extend(bytes.fromhex("89e0 05") + (offset & 0xFFFFFFFF).to_bytes(4, "little"))
        displacement = root_size - (len(root) + 5)
        root.extend(b"\xe8" + displacement.to_bytes(4, "little", signed=True))
    root.extend(bytes.fromhex("c3 e801000000 c3 c7002a000000 c3"))
    functions = {BASE: root_size, BASE + root_size: 6, BASE + root_size + 6: 7}
    code = root.hex()
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(code, BASE), _project(code, BASE), oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions=functions, candidate_functions=functions,
            outputs=lane.adapter.GPRS, timeout_ms=10000,
        )
    assert result["status"] == "refused"
    assert result["reason"].startswith("call_return_target")


def test_root_return_failure_does_not_repeat_identical_work(lane: DriverLane, monkeypatch: pytest.MonkeyPatch) -> None:
    """Root return checks already include caller state and cannot benefit from retry."""
    from tools.dosunit.tests.test_flat32_stack_domain import STORE_CODE, STORE_FUNCTIONS

    original = execution._compose_function
    root_calls = []

    def counted(session, entry, active, depth, **kwargs):
        if depth == 0:
            root_calls.append(entry)
        return original(session, entry, active, depth, **kwargs)

    monkeypatch.setattr(execution, "_compose_function", counted)
    with lane.adapter.installed(region=True), pytest.raises(CallCompositionRefusal, match="call_return_target"):
        summarize_with_calls(
            _project(STORE_CODE, BASE), entry=BASE, functions=STORE_FUNCTIONS,
            outputs=lane.adapter.GPRS,
        )
    assert root_calls == [BASE]


@pytest.mark.parametrize("offset,value,expected", ((0x100, 42, "passed"), (0x100, 43, "failed"), (-8, 42, "refused")))
def test_public_pe32_contextual_call_result(
    lane: DriverLane, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    offset: int, value: int, expected: str,
) -> None:
    """Both public adapters retain success, store mismatch and bad-return refusal."""
    boundaries = {
        "f": (TEXT_BASE, TEXT_BASE + 12),
        "callee": (TEXT_BASE + 13, TEXT_BASE + 18),
        "leaf": (TEXT_BASE + 19, TEXT_BASE + 25),
    }
    oracle, candidate = _install_fixture(lane, monkeypatch, tmp_path, _code(offset), boundaries)
    candidate.write_bytes(pe32_bytes(bytes.fromhex(_code(offset, value))))
    symbols = {name: lane.catalog.Symbol(start, end - start + 1, "T") for name, (start, end) in boundaries.items()}
    monkeypatch.setattr(lane.z3cmp32, "nm_symbols", lambda _path: symbols)
    args = _driver_args(lane, tmp_path, oracle, candidate, None)
    with lane.adapter.installed(region=True):
        report = lane.z3cmp32.compare(args)
    assert len(report["results"]) == 1
    row = report["results"][0]
    assert row["status"] == expected, row
    if expected == "passed":
        assert not row.get("assumptions")


@pytest.mark.parametrize("original,candidate,expected", [
    ("31c0eb03ffd1c385c075f9c3", "31c0c3", "passed"),
    ("31c0eb02ebfe85c075fac3", "31c0c3", "passed"),
    ("31c0eb03ffd1c385c075f9c3", "b801000000c3", "failed"),
    ("31c0eb03ffd1c385c075f9c3", "31c042c3", "failed"),
    ("c70600000000eb00833e007501c3ffd1c3", "c70600000000eb00c3", "passed"),
    ("c70600000000c70701000000eb00833e007501c3ffd1c3", "c70600000000c70701000000eb00c3", "refused"),
    ("89d0eb03ffd1c385c075f9c3", "31c0c3", "refused"),
    ("31c0eb03ffd1c385c074f9c3", "31c0c3", "refused"),
])
def test_composed_constant_branch_keeps_only_proved_reachable_arm(
    lane: DriverLane, original: str, candidate: str, expected: str,
) -> None:
    """A cross-block constant can exclude a dead callback or loop, never a live one."""
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(original, BASE), _project(candidate, BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))},
            outputs=lane.adapter.GPRS, timeout_ms=10000,
        )
    assert result["status"] == expected, result
    if expected in {"passed", "failed"}:
        proofs = result["constant_branch_proofs"]["oracle"]
        assert proofs
        assert proofs[0]["proof"]["value"] in {"true", "false"}
        assert proofs[0]["proof"]["ssa_guard"]
        assert "assumptions" not in result


@pytest.mark.parametrize("known,changed,expected", [
    (True, False, "passed"), (True, True, "failed"),
    (False, False, "refused"),
])
def test_nested_callback_uses_actual_root_state(
    lane: DriverLane, known: bool, changed: bool, expected: str,
) -> None:
    """An actual caller target resolves a nested callback without a premise."""
    prefix = "b9" + (BASE + 14).to_bytes(4, "little").hex() if known else "9090909090"
    original = prefix + "e801000000c3ffd1c3b82a000000c3"
    candidate = prefix + "e801000000c3ffd1c3b8" + ("2b" if changed else "2a") + "000000c3"
    functions = {BASE: 11, BASE + 11: 3, BASE + 14: 6}
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(original, BASE), _project(candidate, BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions=functions, candidate_functions=functions,
            outputs=lane.adapter.GPRS, timeout_ms=10000,
        )
    assert result["status"] == expected, result
    if expected != "refused":
        assert not result.get("assumptions")


@pytest.mark.parametrize("changed", [False, True])
@pytest.mark.parametrize("memory", [False, True])
def test_constant_count_loop_matches_complete_unrolling(lane: DriverLane, changed: bool, memory: bool) -> None:
    """Every reachable iteration executes, including overlapping word stores."""
    body = "668b1666891783c60283c70249" if memory else "4049"
    jump = (256 - (len(bytes.fromhex(body)) + 2)).to_bytes(1, "little").hex()
    original = "b906000000" + body + "75" + jump + "c3"
    candidate = "b906000000" + body * (5 if changed else 6) + "b900000000c3"
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(original, BASE), _project(candidate, BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions={BASE: len(bytes.fromhex(original))},
            candidate_functions={BASE: len(bytes.fromhex(candidate))},
            outputs=lane.adapter.GPRS, timeout_ms=10000,
        )
    assert result["status"] == ("failed" if changed else "passed"), result
    assert any(p.get("revisited_target") for p in result["constant_branch_proofs"]["oracle"])


@pytest.mark.parametrize("code", ["b90100000085c975fcc3", "404975fcc3"])
def test_loop_unrolling_never_truncates_live_iterations(lane: DriverLane, code: str) -> None:
    """An infinite or symbolic loop cannot pass by reaching the work cap."""
    from tools.dosunit.compare.flat32_call_contracts import CallCompositionLimits

    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(code, BASE), _project("c3", BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions={BASE: len(bytes.fromhex(code))}, candidate_functions={BASE: 1},
            outputs=lane.adapter.GPRS, timeout_ms=10000,
            limits=CallCompositionLimits(max_compositions=12),
        )
    assert result["status"] == "refused", result
    assert result["reason"] in {"loop_requires_inductive_proof", "region_composition_limit"}


@pytest.mark.parametrize("dead_effect", ["ffd0", "ebfe"])
def test_repeated_guard_excludes_unreachable_call_or_loop(lane: DriverLane, dead_effect: str) -> None:
    code = "85c0740685c07502" + dead_effect + "c3"
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(code, BASE), _project("c3", BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions={BASE: 11}, candidate_functions={BASE: 1},
            outputs=("eax",), timeout_ms=10000,
        )
    assert result["status"] == "passed", result
    proofs = result["constant_branch_proofs"]["oracle"]
    assert any(p["proof"].get("method") == "exact_ssa_path_implication" for p in proofs)


def test_guard_change_keeps_reachable_unknown_call(lane: DriverLane) -> None:
    code = "85c0740685c07402ffd0c3"
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(code, BASE), _project("c3", BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions={BASE: 11}, candidate_functions={BASE: 1},
            outputs=("eax",), timeout_ms=10000,
        )
    assert result["status"] == "refused", result
    assert result["reason"] == "call_indirect_target_unconstrained"


@pytest.mark.parametrize("candidate", ["40c3", "c70601000000c3"])
def test_path_pruning_preserves_return_and_memory_differences(lane: DriverLane, candidate: str) -> None:
    code = "85c0740685c07502ffd0c3"
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(code, BASE), _project(candidate, BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions={BASE: 11}, candidate_functions={BASE: len(bytes.fromhex(candidate))},
            outputs=("eax",), timeout_ms=10000,
        )
    assert result["status"] == "failed", result


def test_register_write_invalidates_repeated_guard(lane: DriverLane) -> None:
    # EAX=ffffffff is nonzero at entry but INC makes the second test zero.
    code = "85c074074085c07502ffd0c3"
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(code, BASE), _project("c3", BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions={BASE: 12}, candidate_functions={BASE: 1},
            outputs=("eax",), timeout_ms=10000,
        )
    assert result["status"] == "refused", result
    assert result["reason"] == "call_indirect_target_unconstrained"


@pytest.mark.parametrize("narrow", [False, True])
@pytest.mark.parametrize("high,divisor,expected", [(0, 10, "passed"), (0, 0, "refused"), (10, 10, "refused")])
def test_native_division_requires_zero_and_overflow_proofs(
    lane: DriverLane, high: int, divisor: int, expected: str, narrow: bool,
) -> None:
    """A nonzero divisor alone does not exclude x86 quotient overflow."""
    code = "ba" + high.to_bytes(4, "little").hex() + "b9" + divisor.to_bytes(4, "little").hex() + "f7f1c3"
    if narrow:
        code = "66ba" + high.to_bytes(2, "little").hex() + "66b9" + divisor.to_bytes(2, "little").hex() + "66f7f1c3"
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(code, BASE), _project(code, BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions={BASE: len(bytes.fromhex(code))}, candidate_functions={BASE: len(bytes.fromhex(code))},
            outputs=lane.adapter.GPRS, timeout_ms=10000,
        )
    assert result["status"] == expected, result
    if expected == "passed":
        assert result["unreachable_exception_proofs"]["oracle"][0]["proof"]["status"] == "passed"


@pytest.mark.parametrize("memory", [False, True])
def test_proved_division_preserves_quotient_difference(lane: DriverLane, memory: bool) -> None:
    """Discharging fault conditions does not equate different quotient results."""
    a = "31d2b90a000000f7f1c3"
    b = "31d2b90b000000f7f1c3"
    if memory:
        a, b = "c70601000000" + a, "c70602000000" + a
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(a, BASE), _project(b, BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions={BASE: len(bytes.fromhex(a))}, candidate_functions={BASE: len(bytes.fromhex(b))},
            outputs=lane.adapter.GPRS, timeout_ms=10000,
        )
    assert result["status"] == "failed", result


@pytest.mark.parametrize("zero_second", [False, True])
def test_safe_divisions_keep_preceding_divisor(lane: DriverLane, zero_second: bool) -> None:
    """Pruning a proved fault must not lose a constant before the next DIV."""
    code = "b90a00000031d2f7f1" + ("31c9" if zero_second else "") + "31d2f7f1c3"
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(code, BASE), _project(code, BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions={BASE: len(bytes.fromhex(code))}, candidate_functions={BASE: len(bytes.fromhex(code))},
            outputs=lane.adapter.GPRS, timeout_ms=10000,
        )
    assert result["status"] == ("refused" if zero_second else "passed"), result


@pytest.mark.parametrize("changed", [False, True])
@pytest.mark.parametrize("entries", [3, 44])
def test_finite_search_reenters_header_inside_initial_block(
    lane: DriverLane, changed: bool, entries: int,
) -> None:
    """An early symbolic exit must not hide the first proved finite backedge."""
    bound = (0x200000 + 2 * entries).to_bytes(4, "little").hex()
    prefix = "31c9ba000020000fb6323bf0740c83c2024181fa" + bound + "72ed"
    original = prefix + "b800000000c3"
    candidate = prefix + ("b801000000c3" if changed else "b800000000c3")
    functions = {BASE: len(bytes.fromhex(original))}
    with lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            _project(original, BASE), _project(candidate, BASE),
            oracle_entry=BASE, candidate_entry=BASE,
            oracle_functions=functions, candidate_functions=functions,
            outputs=lane.adapter.GPRS, timeout_ms=10000,
        )
    assert result["status"] == ("failed" if changed else "passed"), result


@pytest.mark.parametrize("operation,left,right,expected", [
    ("add", 0xFFFFFFFF, 1, 0), ("sub", 0, 1, 0xFFFFFFFF),
    ("add", 0x7FFFFFFF, 1, 0x80000000),
])
def test_branch_literal_folding_retains_modular_overflow(
    operation: str, left: int, right: int, expected: int,
) -> None:
    """Counter simplification uses native-width arithmetic, not unbounded integers."""
    from tools.dosunit.compare.flat32_constant_branches import _fold_literal_arithmetic

    term = {"op": operation, "width": 32, "args": [
        {"op": "const", "width": 32, "value": hex(left)},
        {"op": "const", "width": 32, "value": hex(right)}]}
    assert _fold_literal_arithmetic(term, {}) == {"op": "const", "width": 32, "value": hex(expected)}


def test_root_bound_leaf_summary_avoids_repeated_block_work(lane: DriverLane) -> None:
    """Two calls with different EAX reuse one generic body under a fixed work cap."""
    from tools.dosunit.compare import straightline_ssa as scalar
    from tools.dosunit.compare.flat32_call_contracts import _ComposeSession, _register_widths
    from tools.dosunit.compare.flat32_constant_registers import _document

    root = "b801000000e80b000000b807000000e801000000c3"
    # Six distinct blocks, each adding one, joined by direct jumps.
    leaf = "83c001eb00" * 5 + "83c001c3"
    code = root + leaf
    with lane.adapter.installed(region=True):
        session = _ComposeSession(
            project=_project(code, BASE), functions={BASE:21, BASE+21:len(bytes.fromhex(leaf))}, labels={},
            limits=CallCompositionLimits(max_compositions=10), reg_widths=_register_widths(),
            root_bound_inputs=True,
        )
        state = execution._compose_root(session,BASE)
        result = scalar._compare_functions(
            _document({}, {"eax":state["eax"]}),
            _document({}, {"eax":{"op":"const","width":32,"value":"0xd"}}), timeout_ms=1000)
    assert result["status"] == "passed",result
    assert session.return_targets_proved == 2
    assert session.compositions <= 10


def test_generic_leaf_failure_falls_back_to_actual_counter(lane: DriverLane) -> None:
    """An arbitrary loop bound cannot be cached; the concrete caller still proves it."""
    from tools.dosunit.compare import straightline_ssa as scalar
    from tools.dosunit.compare.flat32_call_contracts import _ComposeSession, _register_widths
    from tools.dosunit.compare.flat32_constant_registers import _document

    code = "b902000000e801000000c34975fdc3"
    with lane.adapter.installed(region=True):
        session = _ComposeSession(
            project=_project(code,BASE), functions={BASE:11,BASE+11:4}, labels={},
            limits=CallCompositionLimits(), reg_widths=_register_widths(),root_bound_inputs=True)
        state = execution._compose_root(session,BASE)
        result = scalar._compare_functions(
            _document({}, {"ecx":state["ecx"]}),
            _document({}, {"ecx":{"op":"const","width":32,"value":"0x0"}}), timeout_ms=1000)
    assert result["status"] == "passed",result
    assert BASE+11 not in session.summaries
    assert BASE+11 in session.leaf_summary_attempts
    assert session.root_bound_inputs is True
