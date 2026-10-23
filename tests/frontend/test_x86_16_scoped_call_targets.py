"""Conditional CALL targets require exact callsite CS proof and native AIL binding.

The raw/CFG projection remains untouched. Only scoped semantic IR and private
Clinic AIL may gain the admitted constant; no calling convention is inferred.
"""
from dataclasses import replace
from types import SimpleNamespace

import networkx as nx
import pytest
from angr import ailment
from angr.codenode import BlockNode

from inertia.frontend.x86_16.clinic_entry_jump_transport import begin_clinic_entry_jump_conversion_8616
from inertia.frontend.x86_16.clinic_scoped_control import transport_clinic_scoped_control_8616
from inertia.ir.entry_projection_mode import EntryProjectionMode8616
from inertia.ir.near_call_entry_pipeline import NativeNearCallPipeline8616
from inertia.ir.vex_import import prove_scoped_x86_16_ir_function_view_8616, raw_x86_16_import_bundle_for_artifact_8616
from tests.frontend.test_x86_16_clinic_terminal_control import _clinic_stub, _convert
from tests.ir.test_near_call_scoped_view import _native_pending_view_surface

pytestmark = pytest.mark.decompiler


def _conversion():
    surface, scope = _native_pending_view_surface()
    bundle = raw_x86_16_import_bundle_for_artifact_8616(surface.project, surface.boundary, surface.artifact)
    assert bundle is not None
    view = prove_scoped_x86_16_ir_function_view_8616(surface.project, bundle, surface.boundary, near_call_scope=scope)
    assert view.failure is None
    # Source authority is not consulted by Clinic transport; use exact scope inputs.
    entry = NativeNearCallPipeline8616(None, bundle, scope, view, scope.context.callsite_index.for_target(surface.artifact.function_addr)[0])
    clinic = _clinic_stub(surface.project)
    blocks = [surface.project.factory.block(b.addr, size=b.size) for b in surface.boundary.blocks]
    nodes = {b.addr: BlockNode(b.addr, b.size) for b in blocks}
    graph = nx.DiGraph()
    graph.add_nodes_from(nodes.values())
    graph.add_edges_from((nodes[a], nodes[b]) for a, b in surface.boundary.successor_edges)
    clinic.function = SimpleNamespace(addr=surface.artifact.function_addr, graph=graph)
    clinic._func_graph = graph
    clinic._blocks_by_addr_and_size = {}
    begin_clinic_entry_jump_conversion_8616(clinic)
    for block in blocks:
        clinic._blocks_by_addr_and_size[(block.addr, block.size)] = _convert(clinic, block)
    return surface, scope, entry, clinic


def test_scoped_call_targets_reach_semantics_and_ail():
    from inertia.semantics.scoped_call_projection import scoped_call_blocks_8616

    surface, scope, entry, clinic = _conversion()
    projection = entry.view.cfg_projection_for(scope, mode=EntryProjectionMode8616.CALL_TARGETS)
    assert projection is not None
    assert len(projection.call_targets) == 1
    assert projection.call_target_stats.to_dict() == {
        "raw_fact_count": 1, "normalized_fact_count": 1, "classified_fact_count": 1,
        "materialized_count": 1, "failure_count": 0,
    }
    semantic = scoped_call_blocks_8616(projection)
    instruction = next(i for b in semantic for i in b.instrs if i.op == 'CALL')
    assert instruction.args[0].const == 0x1008
    assert surface.call.args[0].const is None
    assert next(i for b in projection.blocks for i in b.instrs if i.op == 'CALL').args == surface.call.args
    before_functions = tuple(surface.project.kb.functions)
    transport_clinic_scoped_control_8616(clinic, entry)
    assert tuple(surface.project.kb.functions) == before_functions
    block = next(b for (addr, _), b in clinic._blocks_by_addr_and_size.items() if addr == surface.block.addr)
    terminal = block.statements[-1]
    assert isinstance(terminal, ailment.Stmt.SideEffectStatement)
    assert isinstance(terminal.expr, ailment.Expr.Call)
    assert isinstance(terminal.expr.target, ailment.Expr.Const)
    assert terminal.expr.target.value == 0x1008


@pytest.mark.parametrize('damage', ['copied_scope', 'context', 'bytes', 'coordinates', 'ail'])
def test_scoped_call_transport_refuses_stale_authority_atomically(damage):
    from inertia.pipeline.errors import PipelineHardError

    surface, scope, entry, clinic = _conversion()
    original_blocks = clinic._blocks_by_addr_and_size
    original_graph = clinic._func_graph
    assert entry.view.cfg_projection_for(None) is None
    if damage == 'copied_scope':
        entry = replace(entry, scope=replace(scope))
    elif damage == 'context':
        object.__setattr__(scope.context, 'selector_high', -1)
    elif damage == 'bytes':
        surface.project.loader.memory.store(surface.call.addr, b'\x90')
    elif damage == 'coordinates':
        object.__setattr__(scope.preservations[0].theorem, 'target_addr', 0x1009)
    else:
        call_block = next(b for (addr, _), b in original_blocks.items() if addr == surface.block.addr)
        call_block.statements.clear()
    with pytest.raises(PipelineHardError):
        transport_clinic_scoped_control_8616(clinic, entry)
    assert clinic._blocks_by_addr_and_size is original_blocks
    assert clinic._func_graph is original_graph


def test_unproved_call_census_preserves_control_projection(monkeypatch):
    from inertia.ir import entry_jump_domain as owner
    from inertia.semantics.scoped_call_projection import scoped_call_blocks_8616

    surface, scope, entry, clinic = _conversion()
    monkeypatch.setattr(owner, '_admit_application_calls_8616',
                        lambda *args: owner.ScopedCallTargetStatus8616.UNPROVED)
    projection = entry.view.cfg_projection_for(scope, mode=EntryProjectionMode8616.CALL_TARGETS)
    assert projection is not None and projection.applied
    assert projection.call_target_status is owner.ScopedCallTargetStatus8616.UNPROVED
    assert projection.call_targets == ()
    assert projection.call_target_stats.raw_fact_count == 1
    assert projection.call_target_stats.materialized_count == 0
    assert projection.call_target_stats.failure_count == 1
    assert scoped_call_blocks_8616(projection) == projection.blocks
    transport_clinic_scoped_control_8616(clinic, entry)
    call_block = next(b for (addr, _), b in clinic._blocks_by_addr_and_size.items() if addr == surface.block.addr)
    assert not isinstance(call_block.statements[-1].expr.target, ailment.Expr.Const)


def test_call_admission_uses_one_bounded_application_solve(monkeypatch):
    from inertia.ir import entry_jump_domain as owner

    _, scope, entry, _ = _conversion()
    original = owner.solve_segment_state_8616
    solves = []

    def count(*args, **kwargs):
        solves.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(owner, 'solve_segment_state_8616', count)
    projection = entry.view.cfg_projection_for(scope, mode=EntryProjectionMode8616.CALL_TARGETS)
    assert projection is not None and projection.call_targets
    assert len(solves) == 1


def test_control_only_projection_does_not_solve_call_obligations(monkeypatch):
    """Ordinary CFG/segment consumers never request outgoing CALL admission."""
    from inertia.ir import entry_jump_domain as owner

    _, scope, entry, _ = _conversion()

    def unexpected(*args, **kwargs):
        pytest.fail('control-only projection requested an extra segment solve')

    monkeypatch.setattr(owner, 'solve_segment_state_8616', unexpected)
    projection = entry.view.cfg_projection_for(scope)
    assert projection is not None and projection.applied
    assert projection.call_targets == ()
