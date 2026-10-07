"""Exercise real ctypes wrapping without timing-dependent sleeps or host load."""

import contextlib
import ctypes
from typing import Any

import pytest
from tools.dosunit.tests.test_real16_control_boundary import _CALLBACKS

import tools.dosunit.compare.real16_control_boundary as boundary
import tools.dosunit.compare.real16_control_targets as targets
import tools.dosunit.compare.straightline_ssa as ssa


def _wrapped_alarm(alarm: ssa._BlockLiftTimeout) -> None:
    """ctypes wraps exceptions raised while converting native-call arguments."""
    class ExpiringArgument:
        @classmethod
        def from_param(cls, value: object) -> int:
            alarm._handle_timeout(0, None)
            raise AssertionError("alarm must interrupt conversion")

    # ctypes accepts from_param adapters although its stub lists ctypes only.
    absolute: Any = ctypes.CDLL(None)["abs"]
    absolute.argtypes = [ExpiringArgument]
    absolute.restype = ctypes.c_int
    absolute(1)


def test_ctypes_wrapped_alarm_keeps_timeout_and_cause() -> None:
    alarm = ssa._control_proof_alarm(0)
    with pytest.raises(TimeoutError) as failure, alarm:
        _wrapped_alarm(alarm)
    assert isinstance(failure.value.__cause__, ctypes.ArgumentError)


def test_wrapped_alarm_becomes_typed_control_refusal() -> None:
    alarm = ssa._control_proof_alarm(0)

    def prove(*args: Any) -> Any:
        _wrapped_alarm(alarm)
        raise AssertionError("expired proof must never produce evidence")

    ledger = boundary.ControlProofLedger()
    result = boundary._run_attempt(
        {}, [], callbacks=_CALLBACKS, ledger=ledger, deadline=None,
        alarm_ms=lambda _: alarm, role="test.ctypes_timeout", prove=prove,
    )
    assert result.failure is targets.ControlDomainFailure.BUDGET_EXHAUSTED
    assert result.value is None
    assert ledger.classified_fact_count == 0
    assert ledger.accounting_failure() is boundary.ControlEvidenceFailure.PROOF_REFUSED


def test_unrelated_ctypes_argument_error_is_loud() -> None:
    failure = ctypes.ArgumentError("invalid native argument")
    with pytest.raises(ctypes.ArgumentError) as raised, ssa._control_proof_alarm(0):
        raise failure
    assert raised.value is failure


def test_swallowed_alarm_cannot_finish_as_success() -> None:
    alarm = ssa._control_proof_alarm(0)
    with pytest.raises(TimeoutError), alarm, contextlib.suppress(TimeoutError):
        alarm._handle_timeout(0, None)
