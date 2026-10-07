"""Automatic discovery never extends deadlines or recurses on explicit candidates."""
from __future__ import annotations

import time
from typing import Any, Never

from tools.dosunit.compare.flat32_invariant_retry import InvariantSearchReason, retry_entry_invariants
from tools.dosunit.compare.flat32_region_attempts import comparison_deadline
from tools.dosunit.contracts.memory_state_invariants import MemoryInvariant
from tools.dosunit.contracts.memory_state_relations import MemoryPermutation
from tools.dosunit.contracts.proof_contracts import ProofStatus, legacy_status_for, proof_status_from_legacy
from tools.dosunit.contracts.register_state_relations import MachineState


def _entry() -> MachineState:
    """Provide one exact entry store over live scalar components."""
    address = {"op": "input", "name": "address", "width": 32}
    value = {"op": "input", "name": "value", "width": 8}
    return {"address": address, "value": value,
            "memory": {"op": "storele", "width": 0, "args": [
                {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}, address, value]}}


def _initial(status: ProofStatus = ProofStatus.UNKNOWN) -> dict[str, Any]:
    """Model the legacy driver boundary with its required status vocabulary."""
    return {"status": legacy_status_for(status), "relation_attempts": [{"status": ProofStatus.UNKNOWN, "tag": "baseline"}]}


def _unexpected(_invariant: MemoryInvariant, _remaining: int) -> Never:
    """Fail if a stopped search attempts another candidate."""
    raise AssertionError("discovery must not invoke the proof callback")


def test_explicit_candidate_stops_nested_discovery() -> None:
    """A recursive comparison with a candidate does not synthesize another level."""
    initial = _initial()
    result = retry_entry_invariants(initial, _entry(), MemoryPermutation(),
        explicit=MemoryInvariant(), deadline=time.monotonic() + 1, compare=_unexpected)
    assert result is initial


def test_proved_initial_result_stops_discovery() -> None:
    """Existing full proof remains authoritative without a redundant search."""
    initial = _initial(ProofStatus.PROVED)
    result = retry_entry_invariants(initial, _entry(), MemoryPermutation(),
        explicit=None, deadline=time.monotonic() + 1, compare=_unexpected)
    assert result is initial


def test_expired_deadline_is_visible_and_never_proves() -> None:
    """Missing time retains baseline evidence and an incomplete typed search."""
    result = retry_entry_invariants(_initial(), _entry(), MemoryPermutation(),
        explicit=None, deadline=time.monotonic() - 1, compare=_unexpected)
    assert proof_status_from_legacy(result["status"]) is ProofStatus.UNKNOWN
    assert result["invariant_search"]["reason"] is InvariantSearchReason.DEADLINE
    assert result["invariant_search"]["attempted_count"] == 0
    assert result["invariant_search"]["complete"] is False
    assert result["relation_attempts"][0]["tag"] == "baseline"


def test_all_failed_attempts_remain_visible() -> None:
    """Candidate exhaustion keeps each unproved attempt and complete effort counts."""
    calls: list[tuple[MemoryInvariant, int]] = []
    def refused(invariant: MemoryInvariant, remaining: int) -> dict[str, Any]:
        """Return an explicit controlled refusal at the legacy adapter boundary."""
        calls.append((invariant, remaining))
        return {"status": legacy_status_for(ProofStatus.UNKNOWN), "relation_attempts": [{"status": ProofStatus.UNKNOWN, "tag": "retry"}]}
    result = retry_entry_invariants(_initial(), _entry(), MemoryPermutation(),
        explicit=None, deadline=time.monotonic() + 1, compare=refused)
    assert proof_status_from_legacy(result["status"]) is ProofStatus.UNKNOWN
    assert result["invariant_search"]["reason"] is InvariantSearchReason.EXHAUSTED
    assert result["invariant_search"]["complete"] is True
    assert len(calls) == result["invariant_search"]["attempted_count"]
    assert len(result["relation_attempts"]) == len(calls) + 1
    assert all(0 < remaining <= 1000 for _, remaining in calls)


def test_nested_deadline_never_exceeds_outer_deadline() -> None:
    """A nested comparison cannot restart its total budget."""
    outer = time.monotonic() + 1
    assert comparison_deadline(10000, outer) <= outer
    expired = time.monotonic() - 1
    assert comparison_deadline(10000, expired) == expired
