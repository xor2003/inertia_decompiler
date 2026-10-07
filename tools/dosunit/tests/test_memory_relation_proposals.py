"""Binary-SSA byte correspondence remains an untrusted full-array proposal."""

from typing import Any

import pytest

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.compare.memory_relation_proposals import MemoryProposalReason, propose_memory_permutation
from tools.dosunit.contracts.proof_contracts import ProofStatus, proof_status_from_legacy
from tools.dosunit.compare.real16_call_contracts import materialize_function


def _constant(value: int, width: int = 32) -> dict[str, Any]:
    return {'op': 'const', 'width': width, 'value': hex(value)}


def _input_term(name: str, width: int = 32) -> dict[str, Any]:
    return {'op': 'input', 'name': name, 'width': width}


def _entry(order: tuple[int, ...]) -> dict[str, dict[str, Any]]:
    original_sp = _input_term('sp')
    state = {f'v{i}': _input_term(f'v{i}', 8) for i in range(3)}
    state['sp'] = {'op': 'sub', 'width': 32, 'args': [original_sp, _constant(12)]}
    memory = {'op': 'mem_input', 'name': 'mem', 'addr_width': 32, 'value_width': 8}
    for offset, index in enumerate(order):
        address = {'op': 'add', 'width': 32, 'args': [original_sp, _constant(offset)]}
        memory = {'op': 'storele', 'width': 0, 'args': [memory, address, state[f'v{index}']]}
    state['memory'] = memory
    return state


@pytest.mark.parametrize('order', [(1, 0, 2), (1, 2, 0), (2, 0, 1)])
def test_changed_entry_bytes_propose_correct_rebased_cycle(order: tuple[int, ...]) -> None:
    """Every proposed cycle satisfies entry full-memory equality in cutpoint coordinates."""
    left, right = _entry((0, 1, 2)), _entry(order)
    proposed = propose_memory_permutation(left, right)
    assert proposed.reason is MemoryProposalReason.PROPOSED
    assert proposed.relation is not None
    state = dict(left)
    state['memory'] = proposed.relation.apply(left['memory'], left)
    compared = S._compare_functions(materialize_function('oracle', state),
                                     materialize_function('candidate', right), timeout_ms=15000)
    assert proof_status_from_legacy(compared['status']) is ProofStatus.PROVED, compared


def test_changed_value_has_no_bijective_proposal() -> None:
    """A value mutation is not a byte permutation."""
    left, right = _entry((0, 1, 2)), _entry((1, 2, 0))
    right['memory']['args'][2] = _constant(0x53, 8)
    proposed = propose_memory_permutation(left, right)
    assert proposed.relation is None
    assert proposed.reason is MemoryProposalReason.AMBIGUOUS


def test_missing_post_entry_anchor_refuses() -> None:
    """Destroying the stack anchor cannot yield a guessed relation."""
    left, right = _entry((0, 1, 2)), _entry((1, 2, 0))
    left['sp'] = _constant(0)
    proposed = propose_memory_permutation(left, right)
    assert proposed.relation is None
    assert proposed.reason is MemoryProposalReason.ANCHOR


@pytest.mark.parametrize('width', [16, 32])
@pytest.mark.parametrize('operation', ['storele', 'storebe'])
def test_wide_store_permutation_preserves_complete_array(width: int, operation: str) -> None:
    """Both endian store contracts synthesize exact finite byte correspondences."""
    def build(order: tuple[int, ...]) -> dict[str, dict[str, Any]]:
        state = {f'v{i}': _input_term(f'v{i}', width) for i in range(3)}
        state['sp'] = _input_term('sp')
        memory: dict[str, Any] = {'op': 'mem_input', 'name': 'mem', 'addr_width': 32, 'value_width': 8}
        for offset, index in enumerate(order):
            address = {'op': 'add', 'width': 32, 'args': [state['sp'], _constant(offset * (width // 8))]}
            memory = {'op': operation, 'width': 0, 'args': [memory, address, state[f'v{index}']]}
        state['memory'] = memory
        return state
    left, right = build((0, 1, 2)), build((1, 2, 0))
    proposed = propose_memory_permutation(left, right)
    assert proposed.relation is not None
    transformed = dict(left)
    transformed['memory'] = proposed.relation.apply(left['memory'], left)
    compared = S._compare_functions(materialize_function('oracle', transformed),
                                     materialize_function('candidate', right), timeout_ms=10000)
    assert proof_status_from_legacy(compared['status']) is ProofStatus.PROVED, compared
