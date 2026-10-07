"""Expired macro-step deadlines must stop before invoking a solver."""

import contextlib
import time
from typing import NoReturn

import pytest
from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane

import tools.dosunit.compare.flat32_macro_terms as proof
from tools.dosunit.compare.flat32_macro_proof import compare_macro_cfg
from tools.dosunit.compare.macro_step_contracts import MacroStepReason
from tools.dosunit.contracts.proof_contracts import ProofStatus


class _Adapter:
    """Only the installation boundary needed by the endpoint proof."""

    def installed(self) -> contextlib.nullcontext[None]:
        """Provide a no-op third-party installation boundary."""
        return contextlib.nullcontext()


def test_expired_endpoint_does_not_start_solver(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even an immediately successful solver cannot promote expired work."""
    calls = []

    def solver(*args: object, **kwargs: object) -> ProofStatus:
        """Record an invocation that expired work must never initiate."""
        calls.append((args, kwargs))
        return ProofStatus.PROVED

    monkeypatch.setattr(proof, "prove_terms_equal", solver)
    with pytest.raises(proof._Flat32Refusal) as refused:
        proof.endpoint_discharge32(
            {"eip": {"op": "const", "width": 32, "value": "0x0"}},
            0, {"op": "const", "width": 1, "value": "0x1"},
            _Adapter(), time.monotonic() - 1,
        )
    assert refused.value.reason is MacroStepReason.MACRO_DEADLINE
    assert calls == []


def test_expired_public_entry_does_not_discover_cfg(monkeypatch: pytest.MonkeyPatch) -> None:
    """The outer budget must stop work before discovery starts."""
    with _driver_lane("msc8") as lane:
        calls = []

        def discover(*args: object, **kwargs: object) -> NoReturn:
            """Fail immediately if expired work enters CFG discovery."""
            calls.append((args, kwargs))
            raise AssertionError("CFG discovery started after deadline")

        monkeypatch.setattr(lane.cfg, "discover", discover)
        result = compare_macro_cfg(
            (object(), object()), (0x12345000, 1), (0x23456000, 1),
            lane.adapter.OUTPUT_REGS, 1000, total_deadline=time.monotonic() - 1,
        )
        assert result["status"] is lane.verdict.Status.REFUSED
        assert result["reason"] == MacroStepReason.MACRO_DEADLINE.value
        assert calls == []
