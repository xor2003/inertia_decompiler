"""Durable mocked contracts for real16 retry-budget stage diagnostics.

Layer: tests.
Responsibility: pin the additive ``retry_budget`` admission records emitted
by ``tools.dosunit.real16_call_retry`` and ``tools.dosunit.real16_macro_retry``
to the exact production scheduling contract — identical monotonic-read count,
identical timeout arguments, identical verdict rows (status/reason/method/
counters/assumptions). All stage engines are mocked: no binary is loaded,
no solver runs, and no wall-clock deadline is actually consumed.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

import pytest

from tools.dosunit import real16_call_retry, real16_macro_retry
from tools.dosunit.macro_step_contracts import (
    MacroProofReason,
    MacroSearchStatus,
    MacroStepProof,
    MacroStepReason,
)
from tools.dosunit.proof_contracts import (
    Architecture,
    ContractIdentity,
    FactCounters,
    Obligation,
    ObligationEvidence,
    ObligationId,
    ProofStatus,
)
from tools.dosunit.proof_scope import ProofScope
from tools.dosunit.real16_call_contracts import Real16CallLimits
from tools.dosunit.real16_call_retry import FunctionRetryEvidence
from tools.dosunit.real16_loop_calls import LoopCallProof, LoopCallReason
from tools.dosunit.real16_region_proof import RegionProof, RegionProofReason

FUNCTION_ID = "demo.exe:f"
CANDIDATE_ID = "demo.exe:cf"
OBLIGATION = Obligation(ObligationId("function", FUNCTION_ID))
CONTRACT = ContractIdentity(Architecture.REAL16, *("retry-budget",) * 5)
COUNTERS = FactCounters(1, 1, 1, 1, 1)
TIMEOUT = 100

_StageLog = list[tuple[str, tuple[object, ...], dict[str, object]]]


class _Clock:
    """Scripted ``time.monotonic`` replacement counting every read."""

    def __init__(self) -> None:
        """Start the scripted clock at zero seconds."""
        self.now = 0.0
        self.calls = 0

    def monotonic(self) -> float:
        """Return the scripted time and count the read."""
        self.calls += 1
        return self.now


def _docs(*, calls: bool = True, mapped: bool = True) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return (oracle, candidate) SSA document fixtures."""
    jumpkind = "Ijk_Call" if calls else "Ijk_Boring"
    oracle = {"functions": [{"function": {"id": FUNCTION_ID}, "source": {"jumpkind": jumpkind}}]}
    part = {"function": {"id": CANDIDATE_ID, "name": FUNCTION_ID}}
    return oracle, {"functions": [part] if mapped else []}


def _remaining(now: float) -> int:
    """Recompute the gate remainder: deadline is ``TIMEOUT/1000`` from t0=0."""
    return int(((TIMEOUT / 1000) - now) * 1000)


def _macro_proof(status: ProofStatus, reason: MacroProofReason | MacroStepReason) -> MacroStepProof:
    """Build one cutpoint-scoped macro verdict fixture."""
    return MacroStepProof(status, reason, None, (), COUNTERS, (), MacroSearchStatus.EXHAUSTED,
                          MacroStepReason.MACRO_UNSUPPORTED_BOUNDARY, ProofScope.CUTPOINT_SIMULATION)


def _stage_fake(
    log: _StageLog, clock: _Clock, jumps: dict[str, float], name: str, value: object,
) -> Callable[..., object]:
    """Return a stage stub logging calls and optionally advancing the clock."""

    def stage(*args: object, **kwargs: object) -> object:
        log.append((name, args, kwargs))
        if name in jumps:
            clock.now = jumps[name]
        return copy.deepcopy(value)

    return stage


def _call_run(
    monkeypatch: pytest.MonkeyPatch, *, has_calls: bool = True, mapped: bool = True,
    call_result: dict[str, Any] | None = None, loop: LoopCallProof | None = None,
    region: RegionProof | None = None, jumps: dict[str, float] | None = None,
) -> tuple[FunctionRetryEvidence | None, _Clock, _StageLog]:
    """Invoke production ``retry_whole_function`` with mocked stages."""
    clock, log, steps = _Clock(), [], dict(jumps or {})
    monkeypatch.setattr(real16_call_retry, "time", clock)
    for attr, name, value in (
        ("compare_real16_with_calls", "with_calls", call_result or {"status": "passed"}),
        ("compare_real16_loop_calls", "loop", loop),
        ("compare_real16_regions", "regions", region),
    ):
        monkeypatch.setattr(real16_call_retry, attr,
                            _stage_fake(log, clock, steps, name, value))
    oracle, candidate = _docs(calls=has_calls, mapped=mapped)
    result = real16_call_retry.retry_whole_function(
        OBLIGATION, {"id": FUNCTION_ID}, CONTRACT, oracle, candidate, None,
        timeout_ms=TIMEOUT, limits=Real16CallLimits(),
    )
    return result, clock, log


def _macro_run(
    monkeypatch: pytest.MonkeyPatch, *, timeout_ms: int = TIMEOUT, retry: str = "unknown",
    mapped: bool = True, macro_proof: MacroStepProof | None = None,
    jumps: dict[str, float] | None = None, backend: dict[str, Any] | None = None,
) -> tuple[FunctionRetryEvidence | None, _Clock, _StageLog]:
    """Invoke production ``retry_whole_function_with_macro``, mocked chain."""
    clock, log, steps = _Clock(), [], dict(jumps or {})
    monkeypatch.setattr(real16_macro_retry, "time", clock)
    inner = None
    if retry != "none":
        row = ObligationEvidence(
            OBLIGATION.id, CONTRACT,
            ProofStatus.PROVED if retry == "proved" else ProofStatus.UNKNOWN,
            reason="inner_refusal", method="inner_method", counters=COUNTERS,
        )
        inner = FunctionRetryEvidence(row, backend if backend is not None else {"status": "refused"})

    def fake_retry(*args: object, **kwargs: object) -> FunctionRetryEvidence | None:
        log.append(("retry", args, kwargs))
        if "retry" in steps:
            clock.now = steps["retry"]
        return inner

    def fake_resolve(*args: object, **kwargs: object) -> str:
        log.append(("resolve", args, kwargs))
        clock.now = steps["resolve"]
        return CANDIDATE_ID

    def fake_macro(*args: object, **kwargs: object) -> MacroStepProof | None:
        log.append(("macro", args, kwargs))
        return macro_proof

    monkeypatch.setattr(real16_macro_retry, "retry_whole_function", fake_retry)
    if "resolve" in steps:
        monkeypatch.setattr(real16_macro_retry, "_sole_candidate_id", fake_resolve)
    monkeypatch.setattr(real16_macro_retry, "compare_real16_macro", fake_macro)
    oracle, candidate = _docs(mapped=mapped)
    result = real16_macro_retry.retry_whole_function_with_macro(
        OBLIGATION, {"id": FUNCTION_ID}, CONTRACT, oracle, candidate, None,
        timeout_ms=timeout_ms, limits=Real16CallLimits(),
    )
    return result, clock, log


def _check(doc: dict[str, Any], *, attempted: bool, required: bool, remaining_ms: int) -> None:
    """Assert one decision record and its internal consistency."""
    assert doc == {
        "attempted": attempted, "required": required,
        "budget_open": remaining_ms > 0, "remaining_ms": remaining_ms,
    }
    assert doc["attempted"] == (required and remaining_ms > 0)


def _names(log: _StageLog) -> list[str]:
    """Return the recorded stage-invocation order."""
    return [entry[0] for entry in log]


def _kwargs(log: _StageLog, name: str) -> dict[str, object]:
    """Return the keyword arguments of one stage invocation."""
    return next(entry[2] for entry in log if entry[0] == name)


def test_call_free_loop_not_required_region_attempted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A call-free function records a non-budget loop skip, then runs regions."""
    region = RegionProof(ProofStatus.UNKNOWN, RegionProofReason.ADMISSION, (), COUNTERS)
    result, clock, log = _call_run(monkeypatch, has_calls=False, region=region)
    assert result is not None and clock.calls == 3 and _names(log) == ["regions"]
    budget = result.backend["retry_budget"]
    _check(budget["loop_induction"], attempted=False, required=False, remaining_ms=_remaining(0.0))
    _check(budget["paired_regions"], attempted=True, required=True, remaining_ms=_remaining(0.0))
    assert _kwargs(log, "regions")["timeout_ms"] == _remaining(0.0)


def test_deadline_closed_records_exhausted_loop_and_region(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Budget spent inside call composition: both gated stages show exhausted."""
    result, clock, log = _call_run(
        monkeypatch, call_result={"status": "refused"}, jumps={"with_calls": 0.15},
    )
    assert result is not None and clock.calls == 3 and _names(log) == ["with_calls"]
    for doc in result.backend["retry_budget"].values():
        _check(doc, attempted=False, required=True, remaining_ms=_remaining(0.15))


def test_loop_attempted_then_region_budget_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Loop runs with its real remaining budget; the region gate then closes."""
    loop = LoopCallProof(ProofStatus.UNKNOWN, LoopCallReason.TRANSITION, (), (), COUNTERS)
    result, clock, log = _call_run(
        monkeypatch, call_result={"status": "refused"}, loop=loop, jumps={"loop": 0.15},
    )
    assert result is not None and clock.calls == 3
    assert _names(log) == ["with_calls", "loop"]
    assert _kwargs(log, "loop")["timeout_ms"] == _remaining(0.0)
    budget = result.backend["retry_budget"]
    _check(budget["loop_induction"], attempted=True, required=True, remaining_ms=_remaining(0.0))
    _check(budget["paired_regions"], attempted=False, required=True, remaining_ms=_remaining(0.15))


def test_composition_proved_marks_both_stages_not_required(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A proved composition closes both gates non-budget; row keeps its method."""
    result, clock, log = _call_run(monkeypatch)
    assert result is not None and clock.calls == 3 and _names(log) == ["with_calls"]
    assert result.evidence.status is ProofStatus.PROVED
    assert result.evidence.method == "ssa_z3_complete_call_inlining"
    for doc in result.backend["retry_budget"].values():
        _check(doc, attempted=False, required=False, remaining_ms=_remaining(0.0))


def test_unmapped_candidate_returns_none_before_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Candidate resolution precedes the deadline: no clock reads, no record."""
    result, clock, log = _call_run(monkeypatch, mapped=False)
    assert result is None and clock.calls == 0 and log == []


def test_nonpositive_timeout_refused_without_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """Zero budget refuses before any deadline read or retry-chain call."""
    result, clock, log = _macro_run(monkeypatch, timeout_ms=0)
    assert result is not None and clock.calls == 0 and log == []
    assert result.evidence.reason == "compose_budget_exceeded"
    assert "retry_budget" not in result.backend


@pytest.mark.parametrize("retry", ["none", "proved"])
def test_macro_gate_not_evaluated_passthrough(
    monkeypatch: pytest.MonkeyPatch, retry: str,
) -> None:
    """No record when the gate is never evaluated (None chain or proved row)."""
    result, clock, _log = _macro_run(monkeypatch, retry=retry)
    assert clock.calls == 1
    if retry == "none":
        assert result is None
    else:
        assert result is not None and "retry_budget" not in result.backend


def test_macro_first_gate_exhausted(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exhaustion before the macro gate names the budget, retaining prior evidence."""
    result, clock, log = _macro_run(monkeypatch, jumps={"retry": 0.15})
    assert result is not None and clock.calls == 2 and _names(log) == ["retry"]
    assert "macro_steps" not in result.backend
    _check(result.backend["retry_budget"]["macro_steps"],
           attempted=False, required=True, remaining_ms=_remaining(0.15))
    assert result.evidence.reason == "compose_budget_exceeded"
    assert result.evidence.method == "inner_method"
    assert result.evidence.counters == COUNTERS


@pytest.mark.parametrize("jumps,expected", [(None, 0.0), ({"retry": 0.15}, 0.15)])
def test_macro_unmapped_candidate_never_exhausted(
    monkeypatch: pytest.MonkeyPatch, jumps: dict[str, float] | None, expected: float,
) -> None:
    """An unresolved candidate records a non-budget skip, never exhaustion."""
    result, clock, log = _macro_run(monkeypatch, mapped=False, jumps=jumps)
    assert result is not None and clock.calls == 2 and _names(log) == ["retry"]
    assert result.evidence.reason == "inner_refusal"
    _check(result.backend["retry_budget"]["macro_steps"],
           attempted=False, required=False, remaining_ms=_remaining(expected))


def test_macro_exhausted_after_candidate_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Resolution spent the deadline: composed refusal plus decision record."""
    result, clock, log = _macro_run(monkeypatch, jumps={"retry": 0.05, "resolve": 0.2})
    assert result is not None and clock.calls == 3
    assert _names(log) == ["retry", "resolve"]
    assert result.evidence.reason == "compose_budget_exceeded"
    assert result.evidence.counters == FactCounters(1, 1, 1, 1, 1)
    assert result.backend["macro_steps"] == {
        "status": "unknown", "reason": "compose_budget_exceeded", "attempted": False,
    }
    _check(result.backend["retry_budget"]["macro_steps"],
           attempted=False, required=True, remaining_ms=_remaining(0.2))


def test_macro_performed_unknown_preserves_row_and_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An attempted macro refusal keeps its reason/counters and real budget."""
    proof = _macro_proof(ProofStatus.UNKNOWN, MacroStepReason.MACRO_UNSUPPORTED_BOUNDARY)
    result, clock, log = _macro_run(monkeypatch, macro_proof=proof)
    assert result is not None and clock.calls == 3
    assert _kwargs(log, "macro")["timeout_ms"] == _remaining(0.0)
    assert result.evidence.reason == MacroStepReason.MACRO_UNSUPPORTED_BOUNDARY.value
    assert result.evidence.method == "inner_method"
    assert result.evidence.counters == COUNTERS
    _check(result.backend["retry_budget"]["macro_steps"],
           attempted=True, required=True, remaining_ms=_remaining(0.0))


def test_macro_performed_proved_promotes_row(monkeypatch: pytest.MonkeyPatch) -> None:
    """A scoped-proved macro promotes status/method and records the attempt."""
    proof = _macro_proof(ProofStatus.PROVED, MacroProofReason.PROVED)
    result, clock, _log = _macro_run(monkeypatch, macro_proof=proof)
    assert result is not None and clock.calls == 3
    assert result.evidence.status is ProofStatus.PROVED
    assert result.evidence.method == real16_macro_retry.MACRO_STEP_METHOD
    assert result.evidence.assumptions == ()
    assert result.evidence.counters == COUNTERS
    _check(result.backend["retry_budget"]["macro_steps"],
           attempted=True, required=True, remaining_ms=_remaining(0.0))


def test_merged_backend_never_mutates_prior_retry_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The merged backend copy leaves the inner chain's budget dict intact."""
    prior = {"loop_induction": {"attempted": True, "required": True,
                              "budget_open": True, "remaining_ms": 42}}
    inner: dict[str, Any] = {"status": "refused", "retry_budget": dict(prior)}
    proof = _macro_proof(ProofStatus.UNKNOWN, MacroStepReason.MACRO_UNSUPPORTED_BOUNDARY)
    result, _clock, _log = _macro_run(monkeypatch, macro_proof=proof, backend=inner)
    assert result is not None
    assert inner["retry_budget"] == prior
    merged = result.backend["retry_budget"]
    assert merged["loop_induction"] == prior["loop_induction"]
    assert merged["macro_steps"]["attempted"] is True
