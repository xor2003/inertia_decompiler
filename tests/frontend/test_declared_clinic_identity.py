"""Declared control transport retains every native converted CALL exactly."""
from dataclasses import replace
from types import SimpleNamespace

import networkx as nx
import pytest
from angr import ailment
from angr.codenode import BlockNode

from inertia.frontend.x86_16.clinic_conversion_source import snapshot_clinic_ail_8616
from inertia.frontend.x86_16.clinic_entry_jump_transport import begin_clinic_entry_jump_conversion_8616
from inertia.frontend.x86_16.clinic_scoped_control import transport_clinic_scoped_control_8616
from inertia.ir.declared_entry_pipeline import DeclaredEntryPipeline8616
from inertia.ir.entry_jump_domain import prove_entry_jump_domains_8616
from inertia.ir.real16_invocation_domain import (
    DeclaredFunctionEntryLink8616,
    prove_real16_declared_function_entry_domain_8616,
)
from inertia.ir.scoped_function_ir_view import prove_scoped_function_ir_view_8616
from inertia.ir.vex_import import raw_x86_16_import_bundle_for_artifact_8616
from inertia.pipeline.errors import PipelineHardError
from tests.frontend.test_x86_16_clinic_terminal_control import _clinic_stub, _convert
from tests.ir.test_declared_function_entry_domain import _recompute
from tests.ir.test_declared_function_entry_intake import _install
from tests.ir.test_forward_declared_call_scope import _forward_world


def _conversion() -> tuple[SimpleNamespace, DeclaredEntryPipeline8616]:
    """Convert an actual source-bound declared graph with two native CALLs."""
    project,boot,artifact,boundary,_resolver,admission=_forward_world()
    link=DeclaredFunctionEntryLink8616(admission,artifact,boundary)
    scope=prove_real16_declared_function_entry_domain_8616(project,link,artifact.function_addr,boot=boot,boot_recompute=_recompute)
    assert scope.complete
    bundle=raw_x86_16_import_bundle_for_artifact_8616(project,boundary,artifact)
    assert bundle is not None
    proof=prove_entry_jump_domains_8616(artifact,bundle.terminal_evidence,project=project)
    view=prove_scoped_function_ir_view_8616(artifact,boundary,proof,invocation_scope=scope)
    assert view.failure is None
    entry=DeclaredEntryPipeline8616(_install(project,boot,link),admission,bundle,scope,view)
    blocks=[project.factory.block(b.addr,size=b.size) for b in boundary.blocks]
    nodes={b.addr:BlockNode(b.addr,b.size) for b in blocks}
    graph=nx.DiGraph()
    graph.add_nodes_from(nodes.values())
    graph.add_edges_from((nodes[a],nodes[b]) for a,b in boundary.successor_edges)
    clinic=_clinic_stub(project)
    clinic.function=SimpleNamespace(addr=artifact.function_addr,graph=graph)
    clinic._func_graph=graph
    clinic._blocks_by_addr_and_size={}
    begin_clinic_entry_jump_conversion_8616(clinic)
    for block in blocks:
        clinic._blocks_by_addr_and_size[(block.addr,block.size)]=_convert(clinic,block)
    return clinic,entry


def test_declared_control_preserves_native_ail_calls() -> None:
    """Control-only transport never rewrites a raw CALL expression or argument."""
    clinic,entry=_conversion()
    original=dict(clinic._blocks_by_addr_and_size)
    calls=[s.expr for b in original.values() for s in b.statements
           if isinstance(s,ailment.Stmt.SideEffectStatement) and isinstance(s.expr,ailment.Expr.Call)]
    assert len(calls)==2
    targets=tuple(call.target for call in calls)
    snapshots={key:snapshot_clinic_ail_8616(block,clinic.project.arch.ip_offset)
               for key,block in original.items()}
    graph=clinic.function.graph
    edges=set(graph.edges)
    transport_clinic_scoped_control_8616(clinic,entry)
    assert all(clinic._blocks_by_addr_and_size[key] is block for key,block in original.items())
    # Rust AIL getters return fresh carriers even before transport. The
    # canonical snapshot binds typed effects, statement indices and origins.
    assert all(snapshot.matches(clinic._blocks_by_addr_and_size[key])
               for key,snapshot in snapshots.items())
    assert all(call.target.likes(target) and call.target.idx == target.idx
               for call,target in zip(calls,targets,strict=True))
    assert set(clinic._func_graph.edges)==edges and clinic.function.graph is graph


@pytest.mark.parametrize("damage",["scope","bytes","ail"])
def test_declared_control_refuses_foreign_or_mutated_source(damage: str) -> None:
    """Existing source seals reject corruption atomically on the declared route."""
    clinic,entry=_conversion()
    graph=clinic._func_graph
    blocks=clinic._blocks_by_addr_and_size
    if damage=="scope":
        entry=replace(entry,scope=replace(entry.scope,project=object()))
    elif damage=="bytes":
        clinic.project.loader.memory.store(0x1043,b"\x90")
    else:
        next(iter(blocks.values())).statements.clear()
    with pytest.raises(PipelineHardError):
        transport_clinic_scoped_control_8616(clinic,entry)
    assert clinic._func_graph is graph and clinic._blocks_by_addr_and_size is blocks
