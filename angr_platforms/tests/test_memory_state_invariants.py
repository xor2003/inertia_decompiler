"""Finite memory invariant projections preserve all other machine components."""
from __future__ import annotations

from typing import Any

import pytest

from tools.dosunit import straightline_ssa as S
from tools.dosunit.memory_state_invariants import (
    MemoryByteFact,
    MemoryInvariant,
    MemoryInvariantReason,
    MemoryInvariantRefusal,
)
from tools.dosunit.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.real16_call_contracts import materialize_function


def _input(name: str, width: int) -> dict[str, Any]:
    return {'op': 'input', 'name': name, 'width': width}


def _state() -> dict[str, dict[str, Any]]:
    return {'a': _input('a', 32), 'b': _input('b', 32), 'v': _input('v', 8),
            'dx': _input('dx', 16), 'ss': _input('ss', 16), 'bp': _input('bp', 16),
            'memory': {'op': 'mem_input', 'name': 'mem', 'addr_width': 32, 'value_width': 8}}


def _compare(left: dict[str, dict[str, Any]], right: dict[str, dict[str, Any]]) -> ProofStatus:
    result = S._compare_functions(materialize_function('oracle', left), materialize_function('candidate', right), timeout_ms=10000)
    return proof_status_from_legacy(result['status']) or ProofStatus.UNKNOWN


def test_overlapping_facts_are_idempotent() -> None:
    """Idempotence holds even when two unknown byte addresses coincide."""
    relation = MemoryInvariant((MemoryByteFact(_input('a', 32), _input('v', 8)),
                                MemoryByteFact(_input('b', 32), {'op': 'const', 'width': 8, 'value': '0x5a'})))
    once = relation.apply(_state())
    assert _compare(once, relation.apply(once)) is ProofStatus.PROVED
    assert {k: v for k, v in once.items() if k != 'memory'} == {k: v for k, v in _state().items() if k != 'memory'}


def test_conflicting_same_address_last_write_is_fixed_point() -> None:
    """The invariant is the projection image, with exact ordered-store semantics."""
    relation = MemoryInvariant((MemoryByteFact(_input('a', 32), _input('v', 8)),
                                MemoryByteFact(_input('a', 32), {'op': 'const', 'width': 8, 'value': '0x5a'})))
    projected = relation.apply(_state())
    assert _compare(projected, relation.apply(projected)) is ProofStatus.PROVED


def test_changed_projection_is_not_equivalence() -> None:
    """Applying a proposed invariant does not prove its initial-state obligation."""
    relation = MemoryInvariant((MemoryByteFact(_input('a', 32), _input('v', 8)),))
    assert _compare(_state(), relation.apply(_state())) is not ProofStatus.PROVED


def test_array_merge_is_supported() -> None:
    """A complete memory-valued conditional may be projected without dropping either arm."""
    state = _state()
    original = state['memory']
    state['memory'] = {'op': 'ite', 'width': 0, 'args': [
        {'op': 'eq', 'width': 1, 'args': [_input('a', 32), _input('b', 32)]},
        original, {'op': 'storele', 'width': 0, 'args': [original, _input('a', 32), _input('v', 8)]}]}
    relation = MemoryInvariant((MemoryByteFact(_input('b', 32), _input('v', 8)),))
    once = relation.apply(state)
    assert _compare(once, relation.apply(once)) is ProofStatus.PROVED


@pytest.mark.parametrize('missing,width,reason', [(True, 8, MemoryInvariantReason.MISSING),
                                                 (False, 16, MemoryInvariantReason.WIDTH)])
def test_invalid_register_binding_refuses(missing: bool, width: int, reason: MemoryInvariantReason) -> None:
    """Missing and differently sized values never become guessed byte facts."""
    state = _state()
    if missing:
        del state['v']
    else:
        state['v'] = _input('v', width)
    relation = MemoryInvariant((MemoryByteFact(_input('a', 32), _input('v', 8)),))
    with pytest.raises(MemoryInvariantRefusal) as caught:
        relation.apply(state)
    assert caught.value.reason is reason


def test_memory_dependent_fact_template_refuses() -> None:
    """A fact template cannot read the memory being projected."""
    with pytest.raises(MemoryInvariantRefusal):
        MemoryByteFact(_input('a', 32), {'op': 'loadle', 'width': 8, 'args': [_state()['memory'], _input('a', 32)]})


def test_segmented_address_idempotence() -> None:
    """Exact SS:BP execution-address terms retain their original scalar semantics."""
    address = {'op': 'add', 'width': 32, 'args': [
        {'op': 'shl', 'width': 32, 'args': [{'op': 'zext', 'width': 32, 'args': [_input('ss', 16)]},
                                          {'op': 'const', 'width': 8, 'value': '0x4'}]},
        {'op': 'zext', 'width': 32, 'args': [_input('bp', 16)]}]}
    relation = MemoryInvariant((MemoryByteFact(address, {'op': 'trunc', 'width': 8, 'args': [_input('dx', 16)]}),))
    once = relation.apply(_state())
    assert _compare(once, relation.apply(once)) is ProofStatus.PROVED


def test_cyclic_template_refuses() -> None:
    """A cyclic proposal fails before recursive substitution or materialization."""
    cyclic = {'op': 'add', 'width': 32, 'args': []}
    cyclic['args'].append(cyclic)
    with pytest.raises(MemoryInvariantRefusal) as caught:
        MemoryByteFact(cyclic, _input('v', 8))
    assert caught.value.reason is MemoryInvariantReason.MALFORMED


def test_conflicting_input_widths_refuse() -> None:
    """The same symbolic input cannot denote two different bitvector sorts."""
    address = {'op': 'add', 'width': 32, 'args': [_input('a', 32), _input('a', 16)]}
    with pytest.raises(MemoryInvariantRefusal) as caught:
        MemoryByteFact(address, _input('v', 8))
    assert caught.value.reason is MemoryInvariantReason.WIDTH


def test_scalar_memory_root_refuses() -> None:
    """An ordinary bitvector conditional never becomes an admitted byte array."""
    state = _state()
    state['memory'] = {'op': 'ite', 'width': 32, 'args': [
        {'op': 'const', 'width': 1, 'value': '0x1'}, _input('a', 32), _input('b', 32)]}
    with pytest.raises(MemoryInvariantRefusal):
        MemoryInvariant().apply(state)


def test_empty_projection_preserves_all_components() -> None:
    """An empty proposed invariant retains full state and reports identity."""
    invariant = MemoryInvariant()
    assert invariant.is_identity
    assert invariant.apply(_state()) == _state()
