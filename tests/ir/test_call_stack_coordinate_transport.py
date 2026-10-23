"""Call-stack evidence remains current and complete across IR projections."""
from copy import deepcopy
from dataclasses import replace

import pytest

from inertia.ir.core import IRAddress, IRBlock, MemSpace
from inertia.ir.native_copy_memo import seed_native_copy_memo_8616
from inertia.ir.real16_invocation_domain import _native_call_effect_equal_8616
from inertia.ir.source_graph_binding import canonical_source_graph_8616
from inertia.semantics import callee_stack_effects as body_owner
from tests.semantics.test_call_stack_coordinates import _image, _prove, _world
from tests.semantics.test_callee_stack_effects import _effect

pytestmark = pytest.mark.decompiler


def _block(effect):
    """Attach the offered effect to the exact original source CALL."""
    coordinates = effect.stack_coordinates
    source = coordinates.source
    instruction = replace(source.instruction, call_stack_effect=effect)
    return IRBlock(source.block.addr, (instruction,))


def _snapshot(effect, *, reference=None):
    """Capture the owned data and current certificate readiness together."""
    block = _block(effect if reference is None else reference)
    block = replace(block, instrs=(replace(block.instrs[0], call_stack_effect=effect),))
    return canonical_source_graph_8616(block.addr, (block,))


def test_seeded_copy_preserves_authority_and_detaches_coordinate_data():
    """A copy retains original project scope without cloning the project."""
    _code, _project, result, coordinates = _effect('c3')
    effect = result.facts[0].effect
    original = _block(effect)
    (copied,) = deepcopy((original,), seed_native_copy_memo_8616((original,)))
    offered = copied.instrs[0].call_stack_effect
    clone = offered.stack_coordinates
    assert clone is not coordinates
    assert clone.source is coordinates.source
    assert clone.callee_sp_proof is coordinates.callee_sp_proof
    assert clone.argument_top is not coordinates.argument_top
    assert offered.current_net_stack_delta == effect.current_net_stack_delta == 0
    assert _native_call_effect_equal_8616(effect, offered, 0)
    assert _snapshot(effect) == _snapshot(offered)
    object.__setattr__(clone, 'net_sp_delta', 2)
    assert coordinates.net_sp_delta == 0 and offered.current_net_stack_delta is None


@pytest.mark.parametrize('mutation', ['net', 'census', 'source', 'argument', 'effect_net'])
def test_corruption_changes_source_binding_and_cannot_preserve_sp_storage(mutation):
    """Neither a copied integer nor stale evidence can authorize reuse."""
    _code, _project, result, coordinates = _effect('c3')
    address = IRAddress(MemSpace.SS, ('sp',), 8, 2)
    effect = replace(result.facts[0].effect, complete=True, preserved_ranges=(address,))
    assert effect.preserves(address)
    if mutation == 'net':
        changed = replace(coordinates, net_sp_delta=2)
    elif mutation == 'census':
        changed = replace(coordinates, classified_fact_count=0)
    elif mutation == 'source':
        changed = replace(coordinates, source=None)
    elif mutation == 'argument':
        changed = replace(coordinates, argument_top=replace(coordinates.argument_top, extent_bytes=4))
    else:
        changed = coordinates
    offered = replace(effect, stack_coordinates=changed)
    if mutation == 'effect_net':
        offered = replace(offered, net_stack_delta=2)
    assert offered.current_net_stack_delta is None
    assert not offered.preserves(address)
    assert _snapshot(effect) != _snapshot(offered, reference=effect)
    assert not _native_call_effect_equal_8616(effect, offered, 0)


def test_source_mutation_invalidates_original_and_copy():
    """Sharing an immutable certificate never freezes its source validity."""
    _code, project, result, _coordinates = _effect('c3')
    effect = result.facts[0].effect
    block = _block(effect)
    before = _snapshot(effect)
    (copied,) = deepcopy((block,), seed_native_copy_memo_8616((block,)))
    offered = copied.instrs[0].call_stack_effect
    project.loader.memory.store(0x1010, b'\xcb')
    assert effect.current_net_stack_delta is None
    assert offered.current_net_stack_delta is None
    assert _snapshot(offered) != before


def test_readiness_recheck_never_discovers_a_new_body(monkeypatch):
    """Predicate reads consume retained body authority, including refusals."""
    _code, project, result, coordinates = _effect('c3')

    def forbidden(*args, **kwargs):
        raise AssertionError('A readiness predicate attempted new body analysis')

    monkeypatch.setattr(body_owner, 'prove_direct_callee_stack_effect_8616', forbidden)
    from inertia.semantics import call_stack_coordinates as producer
    monkeypatch.setattr(producer, 'prove_direct_callee_stack_effect_8616', forbidden)
    assert coordinates.has_proven_sp_delta
    assert result.facts[0].effect.current_net_stack_delta == 0
    unproven = replace(coordinates, callee_sp_proof=None, net_sp_delta=None)
    assert not unproven.has_proven_sp_delta
    project.loader.memory.store(0x1010, b'\xcb')
    assert not coordinates.has_proven_sp_delta


def test_different_projects_do_not_share_coordinate_scope():
    """Equal scalar effects do not equate different analysis authorities."""
    _code, _project, first, _coordinates = _effect('c3')
    _code, _project, second, _coordinates = _effect('c3')
    assert not _native_call_effect_equal_8616(first.facts[0].effect, second.facts[0].effect, 0)


def test_nonadjacent_argument_push_never_proves_empty_region():
    """A normal intervening instruction must not turn an argument into zero."""
    code = _image('6a0190e80a00c3', '5589e58b46045dc20200')
    project, _function, artifact, summary = _world(code, 0x1003)
    coordinates = _prove(project, artifact, summary)
    assert coordinates.argument_top is None or coordinates.argument_top.extent_bytes == 2
    assert coordinates.has_proven_sp_delta and coordinates.net_sp_delta == 2
