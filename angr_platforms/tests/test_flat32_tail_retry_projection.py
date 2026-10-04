"""Tail-transfer dependencies publish and gate like composed direct calls.

Layer: tests.
Responsibility: pin the flat32 retry projection contract for tail-only
compositions. Positive ``*_tail_transfers`` evidence is the same dependency
class as inlined calls: it admits a checked composition verdict, keeps a
conditional verdict conditional (never promoted), and routes every composed
conditional through the binary environment gate. Verdicts without composed
dependencies — zero or missing counters — keep their prior ungated and
unadmitted behavior.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any, cast

import pytest

import tools.dosunit.flat32_proof_retry as retry_owner
from tools.dosunit.binary_environment import EnvironmentScan
from tools.dosunit.flat32_proof_retry import (
    ProofContext,
    checked_environment_verdict,
    retry_function_proof,
)

if TYPE_CHECKING:
    import angr

TAIL_SITE = {"site": 1, "block": 0x1000, "target": 0x2000, "depth": 0, "callee": "g"}


class _AdapterStub:
    """Minimal adapter seam; the retried composition only needs ``installed``."""

    @contextmanager
    def installed(self, region: bool = False) -> Iterator[None]:
        del region
        yield


def _context() -> ProofContext:
    """Return a retry context whose projects are never dereferenced under mocks."""
    project = cast("angr.Project", object())
    return (project, project, {"f": (0x1000, 8)}, {"f": (0x1000, 8)})


def _tail_only(status: str, **extra: Any) -> dict[str, Any]:
    """Build a composition verdict whose only dependencies are tail transfers."""
    document = {
        "status": status,
        "oracle_inlined_calls": 0,
        "candidate_inlined_calls": 0,
        "oracle_tail_transfers": 1,
        "candidate_tail_transfers": 0,
        "tail_sites": {"oracle": [dict(TAIL_SITE)], "candidate": []},
    }
    document.update(extra)
    return document


def _stub_boundaries(monkeypatch: pytest.MonkeyPatch, calls: dict[str, Any]) -> None:
    """Pin the composition result and make every other retry method refuse."""
    monkeypatch.setitem(sys.modules, "flat32_adapter", _AdapterStub())
    monkeypatch.setattr(
        "tools.dosunit.flat32_call_composition.compare_functions_with_calls",
        lambda *_args, **_kwargs: calls,
    )
    monkeypatch.setattr(
        "tools.dosunit.flat32_cfg_regions.compare_reblocked_cfg",
        lambda *_args, **_kwargs: {"status": "refused", "reason": "stub"},
    )
    monkeypatch.setattr(
        "tools.dosunit.flat32_macro_proof.compare_macro_cfg",
        lambda *_args, **_kwargs: {"status": "refused", "reason": "stub"},
    )


def _stub_scan(monkeypatch: pytest.MonkeyPatch, scan: EnvironmentScan) -> None:
    """Pin the binary environment admission check at the module boundary."""
    monkeypatch.setattr(
        "tools.dosunit.binary_environment.scan_lowered_parts",
        lambda *_args, **_kwargs: scan,
    )


def test_tail_only_proof_publishes_through_checked_composition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tail transfers without inlined calls still count as dependency evidence."""
    _stub_boundaries(monkeypatch, _tail_only("passed"))
    original = {"status": "refused", "reason": "call_or_exception_boundary"}
    result = retry_function_proof("f", original, _context(), ("eax",), 1000)
    assert result["status"] == "passed"
    assert result["proof_method"] == "checked_direct_call_composition"


def test_retry_preserves_original_total_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Adapter setup cannot restart the deadline before direct-call composition."""
    _stub_boundaries(monkeypatch, _tail_only("passed"))
    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    original_import = retry_owner.import_module

    def setup(name: str) -> object:
        adapter = original_import(name)
        now[0] += 0.25
        return adapter

    monkeypatch.setattr("tools.dosunit.flat32_proof_retry.import_module", setup)
    received: dict[str, Any] = {}

    def compare(*_args: Any, **kwargs: Any) -> dict[str, Any]:
        received.update(kwargs)
        return _tail_only("passed")

    monkeypatch.setattr("tools.dosunit.flat32_call_composition.compare_functions_with_calls", compare)
    result = retry_function_proof("f", {"status": "refused"}, _context(), ("eax",), 1000)
    assert result["status"] == "passed"
    assert received["total_deadline"] == 1001.0


def test_tail_only_conditional_publishes_without_promotion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A premise-dependent tail composition stays conditional with assumptions."""
    assumptions = {"kind": "caller_supplied_entry_esp_domain", "proved": False}
    _stub_boundaries(
        monkeypatch,
        _tail_only("conditional", reason="unproved_entry_esp_domain",
                   assumptions=assumptions),
    )
    original = {"status": "refused", "reason": "call_or_exception_boundary"}
    result = retry_function_proof("f", original, _context(), ("eax",), 1000)
    assert result["status"] == "conditional"
    assert result["proof_method"] == "checked_direct_call_composition"
    assert result["assumptions"] is assumptions


def test_tail_only_conditional_without_assumptions_is_not_admitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No silent promotion: an assumption-free conditional cannot replace a refusal."""
    _stub_boundaries(monkeypatch, _tail_only("conditional"))
    original = {"status": "refused", "reason": "call_or_exception_boundary"}
    result = retry_function_proof("f", original, _context(), ("eax",), 1000)
    assert result["status"] == "refused"
    assert "proof_method" not in result
    assert result["additional_proof_attempts"]["calls"]["oracle_tail_transfers"] == 1


@pytest.mark.parametrize("status", ["refused", "unmapped-verdict"])
def test_tail_counts_with_non_proof_status_are_not_admitted(
    monkeypatch: pytest.MonkeyPatch, status: str,
) -> None:
    """Tail counters never admit a refused or unmapped composition status."""
    _stub_boundaries(monkeypatch, _tail_only(status, reason="stub"))
    original = {"status": "refused", "reason": "call_or_exception_boundary"}
    result = retry_function_proof("f", original, _context(), ("eax",), 1000)
    assert result["status"] == "refused"
    assert "proof_method" not in result


@pytest.mark.parametrize("calls", [
    {"status": "passed"},
    {"status": "passed", "oracle_tail_transfers": 0, "oracle_inlined_calls": 0},
    {"status": "conditional", "assumptions": {"kind": "caller_supplied_entry_esp_domain"}},
])
def test_composition_without_dependency_is_not_admitted(
    monkeypatch: pytest.MonkeyPatch, calls: dict[str, Any],
) -> None:
    """Zero or missing dependency counters can never publish a composition."""
    _stub_boundaries(monkeypatch, calls)
    original = {"status": "refused", "reason": "call_or_exception_boundary"}
    result = retry_function_proof("f", original, _context(), ("eax",), 1000)
    assert result["status"] == "refused"
    assert "proof_method" not in result


def test_call_only_composition_still_publishes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pre-existing call-dependent admission path is unchanged."""
    _stub_boundaries(
        monkeypatch,
        {"status": "passed", "oracle_inlined_calls": 1, "candidate_inlined_calls": 1},
    )
    original = {"status": "refused", "reason": "call_or_exception_boundary"}
    result = retry_function_proof("f", original, _context(), ("eax",), 1000)
    assert result["status"] == "passed"
    assert result["proof_method"] == "checked_direct_call_composition"


@pytest.mark.parametrize("verdict", [
    _tail_only("conditional", assumptions={"kind": "caller_supplied_entry_esp_domain"}),
    _tail_only("conditional"),  # tail-dependent conditionals gate even bare
    {**_tail_only("passed"), "candidate_tail_transfers": 2},
])
def test_tail_dependent_verdicts_refuse_on_incomplete_environment(
    monkeypatch: pytest.MonkeyPatch, verdict: dict[str, Any],
) -> None:
    """Call-free tail dependency evidence cannot bypass the environment gate."""
    _stub_scan(monkeypatch, EnvironmentScan(complete=False, requires_contract=False, blocks_scanned=0))
    refused = checked_environment_verdict(verdict, _context(), [], [])
    assert refused == {"status": "refused", "reason": "environment_effect_coverage_incomplete"}


@pytest.mark.parametrize("verdict", [
    _tail_only("conditional", assumptions={"kind": "caller_supplied_entry_esp_domain"}),
    _tail_only("passed"),
])
def test_tail_dependent_verdicts_refuse_when_contract_required(
    monkeypatch: pytest.MonkeyPatch, verdict: dict[str, Any],
) -> None:
    """External environment effects refuse tail-dependent verdicts identically."""
    _stub_scan(monkeypatch, EnvironmentScan(complete=True, requires_contract=True, blocks_scanned=1))
    refused = checked_environment_verdict(verdict, _context(), [], [])
    assert refused == {"status": "refused", "reason": "external_environment_contract_required"}


def test_tail_dependent_conditional_passes_complete_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Complete contract-free member coverage admits a tail-only conditional."""
    verdict = _tail_only(
        "conditional", assumptions={"kind": "caller_supplied_entry_esp_domain"},
    )
    _stub_scan(monkeypatch, EnvironmentScan(complete=True, requires_contract=False, blocks_scanned=1))
    assert checked_environment_verdict(verdict, _context(), [], []) is verdict


def test_call_dependent_conditional_remains_gated(monkeypatch: pytest.MonkeyPatch) -> None:
    """The pre-existing call-only environment gate behavior is unchanged."""
    verdict = {
        "status": "conditional", "oracle_inlined_calls": 1,
        "assumptions": {"kind": "caller_supplied_entry_esp_domain"},
    }
    _stub_scan(monkeypatch, EnvironmentScan(complete=False, requires_contract=False, blocks_scanned=0))
    refused = checked_environment_verdict(verdict, _context(), [], [])
    assert refused == {"status": "refused", "reason": "environment_effect_coverage_incomplete"}


def test_conditional_without_dependency_remains_ungated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Region conditionals without composed dependency evidence are untouched."""
    _stub_scan(monkeypatch, EnvironmentScan(complete=False, requires_contract=True, blocks_scanned=0))
    verdict = {
        "status": "conditional", "reason": "relocation_assumptions",
        "assumptions": {"constant_relocation_count": 1},
    }
    assert checked_environment_verdict(verdict, _context(), [], []) is verdict
    zeroed = {**verdict, "oracle_inlined_calls": 0, "candidate_tail_transfers": 0}
    assert checked_environment_verdict(zeroed, _context(), [], []) is zeroed


@pytest.mark.parametrize("counter", ["oracle_tail_transfers", "oracle_inlined_calls"])
@pytest.mark.parametrize("value", [-1, True, "1", 1.0])
def test_invalid_dependency_counter_cannot_publish_proof(
    monkeypatch: pytest.MonkeyPatch, counter: str, value: object,
) -> None:
    """Malformed dependency counts cannot authorize composition publication."""
    _stub_boundaries(monkeypatch, {"status": "passed", counter: value})
    original = {"status": "refused", "reason": "call_or_exception_boundary"}
    result = retry_function_proof("f", original, _context(), ("eax",), 1000)
    assert result["status"] == "refused"
    assert result["reason"] == original["reason"]
