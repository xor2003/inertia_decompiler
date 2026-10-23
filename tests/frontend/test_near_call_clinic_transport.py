"""Native conditional entry reaches private AIL and its matching CFG."""

from dataclasses import replace
from types import SimpleNamespace

import networkx as nx
import pytest
from angr import ailment
from angr.codenode import BlockNode

from inertia.frontend.x86_16.clinic_entry_jump_transport import begin_clinic_entry_jump_conversion_8616
from inertia.frontend.x86_16.clinic_scoped_control import (
    prepare_clinic_scoped_partition_8616,
    transport_clinic_scoped_control_8616,
)
from inertia.ir.near_call_entry_pipeline import prepare_near_call_entry_pipeline_8616
from inertia.pipeline.errors import PipelineHardError
from tests.frontend.test_x86_16_clinic_terminal_control import _clinic_stub, _convert
from tests.ir.test_near_call_entry_pipeline import _installed

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("damage", [None, "incoming_bytes", "scope"])
def test_native_near_call_entry_binds_private_clinic_control(damage):
    """Only the exact current incoming CALL scope can change private control."""
    surface, _ = _installed()
    entry = prepare_near_call_entry_pipeline_8616(surface.project, surface.boundary).entry
    assert entry is not None
    boundary = entry.view.boundary
    graph = nx.DiGraph()
    nodes = {block.addr: BlockNode(block.addr, block.size) for block in boundary.blocks}
    graph.add_nodes_from(nodes.values())
    graph.add_edges_from((nodes[a], nodes[b]) for a, b in boundary.successor_edges)
    original_edges = set(graph.edges)
    clinic = _clinic_stub(surface.project)
    clinic.function = SimpleNamespace(addr=boundary.addr, graph=graph)
    clinic._func_graph = graph
    clinic._blocks_by_addr_and_size = {}
    prepare_clinic_scoped_partition_8616(clinic, entry)
    begin_clinic_entry_jump_conversion_8616(clinic)
    for native in boundary.blocks:
        block = surface.project.factory.block(native.addr, size=native.size)
        clinic._blocks_by_addr_and_size[(block.addr, block.size)] = _convert(clinic, block)
    if damage is not None:
        before_graph = clinic._func_graph
        before_blocks = clinic._blocks_by_addr_and_size
        if damage == "incoming_bytes":
            surface.project.loader.memory.store(entry.scope.context.callsite_addr + 1, b"\x00")
        else:
            entry = replace(entry, scope=replace(entry.scope))
        with pytest.raises(PipelineHardError):
            transport_clinic_scoped_control_8616(clinic, entry)
        assert clinic._func_graph is before_graph
        assert clinic._blocks_by_addr_and_size is before_blocks
        return
    transport_clinic_scoped_control_8616(clinic, entry)
    projected = entry.view.cfg_projection_for(entry.scope)
    assert projected is not None and projected.applied
    assert {(a.addr, b.addr) for a, b in clinic._func_graph.edges} == {
        (a, b) for a, successors in projected.successors.items() for b in successors
    }
    for admission in projected.applied:
        block = next(block for (address, _), block in clinic._blocks_by_addr_and_size.items()
                     if address == admission.block_addr)
        assert isinstance(block.statements[-1].target, ailment.Expr.Const)
        assert block.statements[-1].target.value == admission.target
    assert graph is not clinic._func_graph
    assert set(graph.edges) == original_edges
