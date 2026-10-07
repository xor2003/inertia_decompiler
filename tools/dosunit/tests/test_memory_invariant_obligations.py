"""Projection assumptions require independent entry and preservation proofs."""
from __future__ import annotations

from tools.dosunit.compare.memory_invariant_obligations import MemoryInvariantObligation, prove_fixed_point
from tools.dosunit.contracts.memory_state_invariants import MemoryByteFact, MemoryInvariant
from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy


def _state():
    return {"a": {"op": "input", "name": "a", "width": 32},
            "v": {"op": "input", "name": "v", "width": 8},
            "paired_control": {"op": "const", "width": 32, "value": "0x1"},
            "memory": {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}}


def _invariant():
    state = _state()
    return MemoryInvariant((MemoryByteFact(state["a"], state["v"]),))


def _proof(state, obligation, reenters_entry=False):
    return prove_fixed_point(_invariant(), state, obligation, timeout_ms=5000,
                             control_field="paired_control", reenters_entry=reenters_entry)


def test_arbitrary_entry_cannot_assume_a_saved_byte():
    proof = _proof(_state(), MemoryInvariantObligation.INITIATION)
    assert proof.status is ProofStatus.UNKNOWN
    assert proof_status_from_legacy(proof.diagnostics["status"]) is ProofStatus.COUNTEREXAMPLE


def test_established_byte_proves_init_and_preservation():
    projected = _invariant().apply(_state())
    for obligation in MemoryInvariantObligation:
        assert _proof(projected, obligation).status is ProofStatus.PROVED


def test_scalar_update_without_matching_memory_update_refuses():
    projected = _invariant().apply(_state())
    projected["v"] = {"op": "add", "width": 8,
                      "args": [projected["v"], {"op": "const", "width": 8, "value": "0x1"}]}
    assert _proof(projected, MemoryInvariantObligation.PRESERVATION).status is ProofStatus.UNKNOWN


def test_entry_backedge_restores_unprojected_domain():
    state = _state()
    state["paired_control"] = {"op": "const", "width": 32, "value": "0x0"}
    assert _proof(state, MemoryInvariantObligation.PRESERVATION, True).status is ProofStatus.PROVED


def test_interior_edge_cannot_use_entry_exception():
    assert _proof(_state(), MemoryInvariantObligation.PRESERVATION, True).status is ProofStatus.UNKNOWN
