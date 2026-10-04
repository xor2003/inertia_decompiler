"""Entry-derived invariant proposals require actual full-memory proofs."""
from __future__ import annotations

import pytest

from tools.dosunit import straightline_ssa as S
from tools.dosunit.memory_invariant_proposals import propose_entry_invariants
from tools.dosunit.memory_state_invariants import MemoryInvariant
from tools.dosunit.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.real16_call_contracts import materialize_function


def _input(name, width):
    return {"op": "input", "name": name, "width": width}


def _entry(endian, width):
    address = {"op": "sub", "width": 32, "args": [_input("esp", 32), {"op": "const", "width": 32, "value": "0x10"}]}
    return {"esp": address, "ebp": _input("esp", 32), "value": _input("value", width),
            "memory": {"op": endian, "width": 0, "args": [
                {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}, address, _input("value", width)]}}


def _status(entry, invariant: MemoryInvariant):
    result = S._compare_functions(materialize_function("entry", entry), materialize_function("projected", invariant.apply(entry)), timeout_ms=5000)
    return proof_status_from_legacy(result["status"])


@pytest.mark.parametrize("endian", ["storele", "storebe"])
@pytest.mark.parametrize("width", [8, 16, 32, 64])
def test_saved_scalar_entry_fixed_point(endian, width):
    entry = _entry(endian, width)
    proposed = propose_entry_invariants(entry)
    invariants = [proposal.invariant for proposal in proposed if proposal.invariant is not None]
    assert invariants
    assert all(_status(entry, invariant) is ProofStatus.PROVED for invariant in invariants)
    assert any(len(invariant.facts) == width // 8 for invariant in invariants)


def test_memory_dependent_saved_value_is_not_proposed():
    entry = _entry("storele", 16)
    memory = entry["memory"]["args"][0]
    entry["memory"]["args"][2] = {"op": "loadle", "width": 16, "args": [memory, _input("esp", 32)]}
    assert not any(proposal.invariant is not None for proposal in propose_entry_invariants(entry))


def test_missing_inverse_is_not_guessed():
    entry = _entry("storele", 16)
    del entry["value"]
    assert not any(proposal.invariant is not None for proposal in propose_entry_invariants(entry))


def test_split_register_bytes_form_one_candidate():
    """Byte-lowered register stores remain a complete finite invariant proposal."""
    entry = _entry("storele", 16)
    base = entry["memory"]["args"][1]
    memory = entry["memory"]["args"][0]
    for index in range(2):
        address = {"op": "add", "width": 32, "args": [base, {"op": "const", "width": 32, "value": hex(index)}]}
        value = _input("value", 16)
        if index:
            value = {"op": "lshr", "width": 16, "args": [value, {"op": "const", "width": 8, "value": "0x8"}]}
        memory = {"op": "storele", "width": 0, "args": [memory, address, {"op": "trunc", "width": 8, "args": [value]}]}
    entry["counter"] = _input("counter", 8)
    entry["memory"] = {"op": "storele", "width": 0, "args": [memory,
        {"op": "add", "width": 32, "args": [base, {"op": "const", "width": 32, "value": "0x2"}]},
        entry["counter"]]}
    invariants = [proposal.invariant for proposal in propose_entry_invariants(entry) if proposal.invariant is not None]
    assert any(len(invariant.facts) == 2 for invariant in invariants)
    assert all(_status(entry, invariant) is ProofStatus.PROVED for invariant in invariants)
