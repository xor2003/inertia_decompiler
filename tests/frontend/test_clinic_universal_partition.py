"""Layer: Frontend tests.
Responsibility: carry authenticated native interior-target partitions into pre-SSA Clinic.
"""
import io
from types import SimpleNamespace

import angr
import networkx as nx
import pytest
from angr import ailment
from angr.codenode import BlockNode

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.clinic_entry_jump_transport import (
    begin_clinic_entry_jump_conversion_8616,
    transport_clinic_entry_jumps_8616,
)
from tests.frontend.test_x86_16_clinic_terminal_control import _clinic_stub, _convert

pytestmark = pytest.mark.decompiler


def _world() -> tuple[SimpleNamespace, nx.DiGraph, bytes]:
    """Two return-producing paths share a JMP inside an initially merged block."""
    body=bytes.fromhex('558bec8b56043b56067d0433c0eb0c3b56087e02ebf5b80100ebf25dc3')
    project=angr.Project(io.BytesIO(body), main_opts={
        'backend':'blob','arch':Arch86_16(),'base_addr':0x1019,'entry_point':0x1019},auto_load_libs=False)
    sizes={0x1019:11,0x1024:4,0x1028:5,0x102d:2,0x102f:5,0x1034:2}
    nodes={a:BlockNode(a,n) for a,n in sizes.items()}
    graph=nx.DiGraph()
    graph.add_nodes_from(nodes.values())
    graph.add_edges_from((nodes[a],nodes[b]) for a,b in (
        (0x1019,0x1024),(0x1019,0x1028),(0x1024,0x1034),
        (0x1028,0x102d),(0x1028,0x102f),(0x102d,0x1024)))
    function=SimpleNamespace(addr=0x1019,graph=graph,blocks=tuple(project.factory.block(a,size=n) for a,n in sizes.items()),
                             block_addrs_set=set(sizes))
    clinic=_clinic_stub(project)
    clinic.function=function
    clinic._func_graph=graph
    clinic._blocks_by_addr_and_size={}
    return clinic,graph,body


@pytest.mark.parametrize('damage',[None,'native','graph'])
def test_shared_return_partition_and_effects(damage: str | None) -> None:
    """Fresh proof splits native control; later changes cannot bind its terminal."""
    clinic,original,body=_world()
    begin_clinic_entry_jump_conversion_8616(clinic)
    assert len(original.nodes)==6
    assert {node.addr for node in clinic._func_graph.nodes} == {0x1019,0x1024,0x1026,0x1028,0x102d,0x102f,0x1034}
    for node in clinic._func_graph.nodes:
        block=clinic.project.factory.block(node.addr,size=node.size)
        clinic._blocks_by_addr_and_size[(node.addr,node.size)]=_convert(clinic,block)
    before={key:tuple(block.statements) for key,block in clinic._blocks_by_addr_and_size.items()}
    if damage=='native':
        clinic.project.loader.memory.store(0x1033,b'\x00')
    elif damage=='graph':
        clinic._func_graph.remove_edge(next(n for n in clinic._func_graph if n.addr==0x1024),
                                      next(n for n in clinic._func_graph if n.addr==0x1026))
    report=transport_clinic_entry_jumps_8616(clinic,next_atom=clinic._ail_manager.next_atom)
    if damage:
        assert report.stats.materialized_count==0 and report.stats.failure_count>0
        return
    assert report.stats.materialized_count==1 and report.stats.failure_count==0
    terminal=clinic._blocks_by_addr_and_size[(0x102f,5)].statements[-1]
    assert isinstance(terminal.target,ailment.Expr.Const) and terminal.target.value==0x1026
    assert (0x102f,0x1026) in {(a.addr,b.addr) for a,b in clinic._func_graph.edges}
    assert bytes(clinic.project.loader.memory.load(0x1019,len(body)))==body
    for key,statements in before.items():
        current=clinic._blocks_by_addr_and_size[key].statements
        assert len(current)==len(statements)
        assert all(a.likes(b) for a,b in zip(statements[:-1],current[:-1],strict=True))


def test_exact_native_nodes_missing_proven_edge() -> None:
    """Matching extents cannot suppress repair of a proved interior JMP edge."""
    first, _, _ = _world()
    begin_clinic_entry_jump_conversion_8616(first)
    graph = first._func_graph.copy()
    nodes = {n.addr: n for n in graph}
    graph.remove_edge(nodes[0x102f], nodes[0x1026])
    function = SimpleNamespace(addr=first.function.addr, graph=graph,
        blocks=tuple(first.project.factory.block(n.addr, size=n.size) for n in graph),
        block_addrs_set=set(nodes))
    clinic = _clinic_stub(first.project)
    clinic.function = function
    clinic._func_graph = graph
    clinic._blocks_by_addr_and_size = {}
    begin_clinic_entry_jump_conversion_8616(clinic)
    assert (0x102f, 0x1026) in {(a.addr, b.addr) for a, b in clinic._func_graph.edges}
    assert not graph.has_edge(nodes[0x102f], nodes[0x1026])
