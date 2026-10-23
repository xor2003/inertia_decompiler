"""Native guarded returns require full reachability, not only a backward cone."""
import time
from dataclasses import replace

import pytest

from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from inertia.ir import entry_domain_call_preservation as entry
from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.scoped_return_reachability import prove_scoped_reachable_return_view_8616
from tests.ir.test_forward_declared_call_scope import _forward_world

pytestmark = pytest.mark.decompiler


def _scope(world):
    project, _boot, artifact, boundary, resolver, _admission = world
    index = build_boundary_direct_callsite_index_8616(boundary, direct_target_resolver=resolver)
    callsite = index.for_target(0x1050)[0]
    pairs = [(block, row) for block in artifact.blocks for row in block.instrs
             if row.op == 'CALL' and row.addr == callsite.callsite_addr]
    assert len(pairs) == 1
    block, instruction = pairs[0]
    _binding, _route, scope = entry._deferred_declared_raw_callee_scope_8616(
        project, artifact, boundary, block, instruction, callsite, 0x1050, (),
    )
    assert scope is not None
    return scope


@pytest.fixture
def guarded_view():
    world = _forward_world(guarded=True)
    project = world[0]
    with direct_evidence_deadline_scope_8616(project, time.monotonic() + 20), native_import_request_8616():
        scope = _scope(world)
        chain = scope.chain
        view = prove_scoped_reachable_return_view_8616(
            project, chain.callee_artifact, chain.callee_boundary, invocation_scope=scope,
        )
        assert view is not None
        yield project, scope, view


def test_dead_service_is_retained_in_raw_census(guarded_view):
    _project, scope, view = guarded_view
    projection = view.cfg_projection_for(scope)
    assert projection is not None
    raw = view.source_artifact
    service_blocks = {block.addr for block in raw.blocks if any(row.op == 'CALL' for row in block.instrs)}
    assert service_blocks and service_blocks <= projection.unreachable_block_addrs
    assert {block.addr for block in projection.blocks} == {block.addr for block in raw.blocks}
    assert not service_blocks.intersection(projection.successors)
    assert all(not projection.predecessors[addr] for addr in service_blocks)
    assert not view.complete


@pytest.mark.parametrize('mutation', ['ledger', 'edge', 'path', 'native', 'scope'])
def test_changed_reachability_authority_refuses(guarded_view, mutation):
    project, scope, view = guarded_view
    domain = view.reachability_domain
    assert domain is not None and domain.infeasible_edges
    if mutation == 'ledger':
        view = replace(view, materialized_count=view.materialized_count + 1)
    elif mutation == 'edge':
        view = replace(view, reachability_domain=replace(domain, infeasible_edges=()))
    elif mutation == 'path':
        view = replace(view, reachability_domain=replace(domain, path_block_addrs=(0x1050,)))
    elif mutation == 'native':
        # TEST AX,AX -> TEST DX,DX; DX is not a declared or derived constant.
        project.loader.memory.store(0x1051, bytes.fromhex('85d2'))
    else:
        scope = replace(scope, entry_segment=scope.entry_segment + 1)
    assert view.cfg_projection_for(scope) is None


@pytest.mark.parametrize('known_argument', [True, False])
def test_backward_return_cone_does_not_hide_reachable_or_unknown_service(known_argument):
    world = _forward_world(0, guarded=True, known_argument=known_argument)
    project = world[0]
    with direct_evidence_deadline_scope_8616(project, time.monotonic() + 20), native_import_request_8616():
        scope = _scope(world)
        chain = scope.chain
        view = prove_scoped_reachable_return_view_8616(
            project, chain.callee_artifact, chain.callee_boundary, invocation_scope=scope,
        )
        assert view is None
