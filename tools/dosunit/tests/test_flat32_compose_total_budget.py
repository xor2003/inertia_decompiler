"""Regression evidence for the shared flat32 call-composition deadline.

Real i386 bytes are lifted through pyvex/angr and compared with real Z3.
The oracle fixture is the reviewed caller/near-callee pair (and, for the
nested-tail boundary, the call -> jmp thunk -> callee chain) already used
by the composition and tail controls.

Every deadline scenario is driven by a deterministic ``_Clock`` patched in
as ``time.monotonic`` plus a work mock on ``_lift_function`` that advances
the fake clock by a scripted amount per lifted function — no test depends
on wall time and no test sleeps.  New checks must refuse with
``compose_budget_exceeded`` exactly when the fake deadline has passed and
must never let a solver call or a published verdict overrun it.

"""

import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import angr
import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "artifacts" / "msc8-z3cmp32"))
sys.path.insert(0, str(ROOT))

from flat32_adapter import GPRS, installed

import tools.dosunit.compare.flat32_call_composition as _composition
import tools.dosunit.compare.flat32_call_execution as _execution
import tools.dosunit.compare.straightline_ssa as _S
from tools.dosunit.compare.flat32_call_composition import (
    CallCompositionLimits,
    CallCompositionRefusal,
    CallProofSide,
    compare_functions_with_calls,
    summarize_with_calls,
)
from tools.dosunit.compare.flat32_call_contracts import (
    _ComposeSession,
    _normalize_function_map,
    _register_widths,
)
from tools.dosunit.compare.flat32_call_execution import _compose_function

BASE = 0x100000
OUTPUTS = GPRS

# caller: mov eax,[esp+4]; call BASE+0x0d; add eax,2; ret   (0x0d bytes)
# callee at BASE+0x0d: add eax,5; ret                       (4 bytes)
CALLER = "8b442404 e804000000 83c002 c3"
CALLEE = "83c005 c3"
CODE = f"{CALLER} {CALLEE}"
FUNCTIONS = {BASE: 0x0D, BASE + 0x0D: 4}

# caller -> near call -> jmp thunk -> separately declared callee.
# caller: mov eax,[esp+4]; call BASE+0x0d; add eax,2; ret   (0x0d bytes)
# thunk  at BASE+0x0d: jmp BASE+0x16                        (5 bytes)
# pad    at BASE+0x12..0x15, callee at BASE+0x16: add eax,5; ret  (4 bytes)
TAIL_CODE = "8b442404 e804000000 83c002 c3 e904000000 90909090 83c005 c3"
TAIL_FUNCTIONS = {BASE: 0x0D, BASE + 0x0D: 5, BASE + 0x16: 4}


class _Clock:
    """Deterministic monotonic source; reads never advance it.

    Patched over ``time.monotonic`` so every module — the staged deadline
    checks, the shared ``straightline_ssa`` owner and the sibling
    ``flat32_region_attempts.comparison_deadline`` — observes the same
    scripted time.  Tests move it explicitly (directly or through the
    lift work mock), so nothing in this file measures real elapsed time.
    """

    def __init__(self, now: float = 1000.0) -> None:
        """Start the fake clock at an arbitrary monotonic epoch."""
        self.now = now

    def monotonic(self) -> float:
        """Return the scripted time without advancing it."""
        return self.now

    def advance(self, seconds: float) -> None:
        """Move the scripted time forward by a fixed amount."""
        self.now += seconds


def _project(code: str, base: int = BASE) -> angr.Project:
    """Load real i386 bytes as a flat shellcode project."""
    return angr.load_shellcode(bytes.fromhex(code.replace(" ", "")), arch="x86", load_address=base)


def _compare(
    oracle_code: str = CODE,
    candidate_code: str = CODE,
    *,
    oracle_functions: dict[int, int] | None = None,
    candidate_functions: dict[int, int] | None = None,
    timeout_ms: int = 5000,
    limits: CallCompositionLimits | None = None,
    total_deadline: float | None = None,
    outputs: tuple[str, ...] = OUTPUTS,
) -> dict[str, Any]:
    """Compare two composed call regions under the installed flat32 seams.

    ``total_deadline`` is forwarded only when set so the same scenario can
    run against a tree whose ``compare_functions_with_calls`` predates the
    parameter: the baseline then publishes its verdict, which is exactly
    the over-budget publication the new checks are red-tested against.
    """
    extra = {} if total_deadline is None else {"total_deadline": total_deadline}
    with installed(region=True):
        return compare_functions_with_calls(
            _project(oracle_code),
            _project(candidate_code),
            oracle_entry=BASE,
            candidate_entry=BASE,
            oracle_functions=oracle_functions or FUNCTIONS,
            candidate_functions=candidate_functions or FUNCTIONS,
            outputs=outputs,
            timeout_ms=timeout_ms,
            limits=limits,
            **extra,
        )


def _advancing_lift(
    clock: _Clock, steps: list[float]
) -> tuple[Callable[[_ComposeSession, int], dict[int, Any]], list[int]]:
    """Wrap ``_lift_function`` so each function lifted consumes scripted time.

    Returns ``(wrapper, calls)``; ``calls`` records the lifted entries in
    order so tests can also prove which side ran before a refusal.
    """
    real_lift = _execution._lift_function
    calls: list[int] = []

    def lifting(session: _ComposeSession, entry: int) -> dict[int, Any]:
        if len(calls) < len(steps):
            clock.advance(steps[len(calls)])
        calls.append(entry)
        return real_lift(session, entry)

    return lifting, calls


def _solver_spy() -> tuple[Callable[..., dict[str, Any]], list[int]]:
    """Record ``timeout_ms`` of every ``S._compare_functions`` call."""
    real_solver = _S._compare_functions
    timeouts: list[int] = []

    def spy(*args: Any, **kwargs: Any) -> dict[str, Any]:
        timeouts.append(int(kwargs.get("timeout_ms", -1)))
        return real_solver(*args, **kwargs)

    return spy, timeouts


def test_default_compare_still_passes() -> None:
    """Green control: the deadline path does not disturb a normal compare."""
    result = _compare(timeout_ms=10000)
    assert result["status"] == "passed"
    assert result["oracle_inlined_calls"] == 1
    assert result["candidate_inlined_calls"] == 1
    assert result["return_targets_proved"] == 2


def test_expired_total_deadline_refuses_before_first_side(monkeypatch: pytest.MonkeyPatch) -> None:
    """An already-expired shared deadline refuses before any lifting runs."""
    clock = _Clock()
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    lifting, calls = _advancing_lift(clock, [])
    monkeypatch.setattr(_execution, "_lift_function", lifting)
    result = _compare(timeout_ms=5000, total_deadline=clock.now - 1.0)
    assert result["status"] == "refused"
    assert result["reason"] == "compose_budget_exceeded"
    assert calls == []


def test_shared_deadline_expires_after_oracle_side(monkeypatch: pytest.MonkeyPatch) -> None:
    """Budget spent by the oracle side is charged before the candidate starts."""
    clock = _Clock()
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    real_side = _composition._summarize_side
    seen: list[CallProofSide] = []

    def expire_after_first(
        side: CallProofSide, project: angr.Project, **kwargs: Any
    ) -> dict[str, Any]:
        summary = real_side(side, project, **kwargs)
        if not seen:
            clock.advance(6.0)  # the whole 5000ms budget is gone between sides
        seen.append(side)
        return summary

    monkeypatch.setattr(_composition, "_summarize_side", expire_after_first)
    result = _compare(timeout_ms=5000)
    assert result["status"] == "refused"
    assert result["reason"] == "compose_budget_exceeded"
    assert len(seen) == 1


def test_no_solver_call_after_deadline_pre_final(monkeypatch: pytest.MonkeyPatch) -> None:
    """Expiry between the second side and the final solve skips the solver."""
    clock = _Clock()
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    real_side = _composition._summarize_side
    seen: list[CallProofSide] = []

    def expire_after_second(
        side: CallProofSide, project: angr.Project, **kwargs: Any
    ) -> dict[str, Any]:
        summary = real_side(side, project, **kwargs)
        seen.append(side)
        if len(seen) == 2:
            clock.advance(6.0)
        return summary

    monkeypatch.setattr(_composition, "_summarize_side", expire_after_second)
    solver_times: list[float] = []
    real_solver = _S._compare_functions

    def timed_spy(*args: Any, **kwargs: Any) -> dict[str, Any]:
        solver_times.append(clock.now)
        return real_solver(*args, **kwargs)

    monkeypatch.setattr(_S, "_compare_functions", timed_spy)
    result = _compare(timeout_ms=5000)
    assert result["status"] == "refused"
    assert result["reason"] == "compose_budget_exceeded"
    assert len(seen) == 2
    # Two in-composition RET proofs ran while time remained; nothing ran after.
    assert solver_times and all(at < 1005.0 for at in solver_times)


def test_solver_timeouts_draw_from_shared_remaining(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each RET proof and the final solve get only what the deadline leaves.

    Scripted lift costs: oracle caller 2.0s, oracle callee 2.5s, then both
    candidate lifts 0.125s each (exact binary fractions keep the remaining
    millisecond math deterministic).  With a 5.0s total budget the first
    return proof sees 500ms remaining (not its full 1000ms cap), the
    second 250ms, and the final solver call is clamped to the same 250ms
    remainder — never the fresh ``timeout_ms``.
    """
    clock = _Clock()
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    lifting, calls = _advancing_lift(clock, [2.0, 2.5, 0.125, 0.125])
    monkeypatch.setattr(_execution, "_lift_function", lifting)
    spy, timeouts = _solver_spy()
    monkeypatch.setattr(_S, "_compare_functions", spy)
    result = _compare(timeout_ms=5000)
    assert result["status"] == "passed"
    assert len(calls) == 4
    assert timeouts == [500, 250, 250]


def test_deadline_refuses_mid_composition(monkeypatch: pytest.MonkeyPatch) -> None:
    """Budget exhaustion while inlining a callee aborts the whole compare."""
    clock = _Clock()
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    lifting, calls = _advancing_lift(clock, [6.0])
    monkeypatch.setattr(_execution, "_lift_function", lifting)
    result = _compare(timeout_ms=5000)
    assert result["status"] == "refused"
    assert result["reason"] == "compose_budget_exceeded"
    assert len(calls) >= 1


def test_tail_chain_composition_stays_within_shared_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Nested call->tail->callee closure draws from the same deadline.

    This is the shape that overran the previous per-proof-only budget: the
    callee is reached through an admitted tail transfer inside an inlined
    call.  With 4.5s of scripted lift work against a 5s budget the first
    return proof is clamped to the remaining 500ms and the compare still
    proves green inside the bound.
    """
    clock = _Clock()
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    lifting, calls = _advancing_lift(clock, [1.5, 1.5, 1.5, 0.0625, 0.0625, 0.0625])
    monkeypatch.setattr(_execution, "_lift_function", lifting)
    spy, timeouts = _solver_spy()
    monkeypatch.setattr(_S, "_compare_functions", spy)
    result = _compare(
        TAIL_CODE,
        TAIL_CODE,
        oracle_functions=TAIL_FUNCTIONS,
        candidate_functions=TAIL_FUNCTIONS,
        timeout_ms=5000,
    )
    assert result["status"] == "passed"
    assert len(calls) == 6
    assert timeouts == [500, 312, 312]
    assert result["oracle_tail_transfers"] == 1
    assert result["return_targets_proved"] == 2


def test_cached_summary_still_enforces_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """A cached callee summary cannot publish after the deadline expired."""
    clock = _Clock()
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    with installed(region=True):
        session = _ComposeSession(
            project=_project(CODE),
            functions=_normalize_function_map(FUNCTIONS),
            labels={},
            limits=CallCompositionLimits(),
            reg_widths=_register_widths(),
        )
        first = _compose_function(session, BASE, frozenset({BASE}), 0)
        assert isinstance(first["eip"], dict)
        assert BASE + 0x0D in session.summaries
        # Expire the shared budget after the summary was cached; even the
        # O(1) cached return must refuse rather than publish post-deadline.
        session.compose_stats = {"deadline": clock.now - 1.0}
        with pytest.raises(CallCompositionRefusal, match="compose_budget_exceeded"):
            _compose_function(session, BASE, frozenset({BASE}), 0)


def test_summarize_total_deadline_named_arg(monkeypatch: pytest.MonkeyPatch) -> None:
    """The optional deadline bounds standalone composition identically."""
    clock = _Clock()
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    with installed(region=True), pytest.raises(
        CallCompositionRefusal, match="compose_budget_exceeded"
    ):
        summarize_with_calls(
            _project(CODE),
            entry=BASE,
            functions=FUNCTIONS,
            outputs=OUTPUTS,
            total_deadline=clock.now - 1.0,
        )
    with installed(region=True):
        document = summarize_with_calls(
            _project(CODE), entry=BASE, functions=FUNCTIONS, outputs=OUTPUTS
        )
    assert document["inlined_calls"] == 1
    assert document["blocks_composed"] >= 2


def test_non_finite_deadline_refuses() -> None:
    """NaN can never silently disable the shared deadline.

    ``NaN`` comparisons never hold, so a non-finite bound reaching
    ``compose_stats`` would turn the deadline check into a permanent no-op.
    Both the summary API (``total_deadline``, ``max_total_seconds``) and the
    compare API refuse with a typed ``invalid_total_deadline`` instead.
    """
    with installed(region=True), pytest.raises(
        CallCompositionRefusal, match="invalid_total_deadline"
    ):
        summarize_with_calls(
            _project(CODE),
            entry=BASE,
            functions=FUNCTIONS,
            outputs=OUTPUTS,
            total_deadline=float("nan"),
        )
    with installed(region=True), pytest.raises(
        CallCompositionRefusal, match="invalid_total_deadline"
    ):
        summarize_with_calls(
            _project(CODE),
            entry=BASE,
            functions=FUNCTIONS,
            outputs=OUTPUTS,
            limits=CallCompositionLimits(max_total_seconds=float("nan")),
        )
    result = _compare(timeout_ms=5000, total_deadline=float("nan"))
    assert result["status"] == "refused"
    assert result["reason"] == "invalid_total_deadline"


def test_max_total_seconds_limits_field() -> None:
    """The appended limits field is positional-safe and enforced when set."""
    legacy = CallCompositionLimits(64, 4, 32, 1, 12000, 4096, 2048, 1000, 64, 128)
    assert legacy.max_tail_transfers == 32
    assert legacy.max_total_seconds is None
    with installed(region=True), pytest.raises(
        CallCompositionRefusal, match="compose_budget_exceeded"
    ):
        summarize_with_calls(
            _project(CODE),
            entry=BASE,
            functions=FUNCTIONS,
            outputs=OUTPUTS,
            limits=CallCompositionLimits(max_total_seconds=-1.0),
        )


def test_last_materialization_cannot_publish_after_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """A late last output must invalidate standalone summary publication."""
    clock = _Clock()
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    original_inputs = _S._term_input_items

    def late_inputs(*args: Any, **kwargs: Any) -> Any:
        result = original_inputs(*args, **kwargs)
        clock.advance(10.0)
        return result

    monkeypatch.setattr(_S, "_term_input_items", late_inputs)
    with installed(region=True), pytest.raises(CallCompositionRefusal, match="compose_budget_exceeded"):
        summarize_with_calls(
            _project("c3"), entry=BASE, functions={BASE: 1}, outputs=OUTPUTS,
            total_deadline=clock.now + 5.0,
        )


def test_zero_return_solver_cap_never_disables_total_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Z3 zero means unlimited, so a zero per-return cap must still be bounded."""
    clock = _Clock()
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    spy, timeouts = _solver_spy()
    monkeypatch.setattr(_S, "_compare_functions", spy)
    result = _compare(timeout_ms=5000, limits=CallCompositionLimits(ret_check_timeout_ms=0))
    assert timeouts and all(timeout > 0 for timeout in timeouts)
    assert result["status"] == "passed"
    assert timeouts == [5000, 5000, 5000]


def test_late_final_solver_never_publishes_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """A solver completing past its budget cannot publish a successful verdict."""
    clock = _Clock()
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    original_solver = _S._compare_functions
    calls = 0

    def late_final(*args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal calls
        result = original_solver(*args, **kwargs)
        calls += 1
        if calls == 3:
            clock.advance(10.0)
        return result

    monkeypatch.setattr(_S, "_compare_functions", late_final)
    result = _compare(timeout_ms=5000)
    assert calls == 3
    assert result["status"] == "refused"
    assert result["reason"] == "compose_budget_exceeded"


def test_zero_compare_budget_refuses_before_work(monkeypatch: pytest.MonkeyPatch) -> None:
    """A zero total budget cannot become an unlimited final solver timeout."""
    clock = _Clock(now=0.0)
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    lifting, calls = _advancing_lift(clock, [])
    monkeypatch.setattr(_execution, "_lift_function", lifting)
    result = _compare(timeout_ms=0)
    assert result["status"] == "refused"
    assert result["reason"] == "compose_budget_exceeded"
    assert calls == []


def test_summary_refuses_at_exact_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """The shared budget owner must agree with the comparison's expiry boundary."""
    clock = _Clock(now=0.0)
    monkeypatch.setattr(time, "monotonic", clock.monotonic)
    with installed(region=True), pytest.raises(CallCompositionRefusal, match="compose_budget_exceeded"):
        summarize_with_calls(
            _project("c3"), entry=BASE, functions={BASE: 1}, outputs=OUTPUTS,
            total_deadline=clock.now,
        )
