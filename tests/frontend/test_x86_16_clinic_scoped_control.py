"""Scoped native AIL targets and CFG successors must be consumed together."""
from dataclasses import replace
from types import SimpleNamespace

import networkx as nx
import pytest
from angr import ailment
from angr.codenode import BlockNode

from inertia.frontend.x86_16.clinic_entry_jump_transport import begin_clinic_entry_jump_conversion_8616
from inertia.frontend.x86_16.clinic_scoped_control import transport_clinic_scoped_control_8616
from inertia.ir.declared_entry_pipeline import DeclaredEntryPipeline8616
from inertia.ir.scoped_function_ir_view import prove_scoped_function_ir_view_8616
from inertia.ir.vex_import import raw_x86_16_import_bundle_for_artifact_8616
from inertia.pipeline.errors import PipelineHardError
from tests.frontend.test_x86_16_clinic_terminal_control import _clinic_stub, _convert
from tests.ir.test_declared_entry_scoped_view import native_scope as native_scope
from tests.ir.test_declared_function_entry_intake import _install

pytestmark = pytest.mark.decompiler


def _conversion(native_scope):
    project, link, scope, proof = native_scope
    view = prove_scoped_function_ir_view_8616(link.artifact, link.boundary, proof, invocation_scope=scope)
    assert view.failure is None
    bundle = raw_x86_16_import_bundle_for_artifact_8616(project, link.boundary, link.artifact)
    assert bundle is not None
    source = _install(project, scope.boot, link)
    entry = DeclaredEntryPipeline8616(source, link.admission, bundle, scope, view)
    graph = nx.DiGraph()
    blocks = [project.factory.block(block.addr, size=block.size) for block in link.boundary.blocks]
    nodes = {block.addr: BlockNode(block.addr, block.size) for block in blocks}
    graph.add_nodes_from(nodes.values())
    projection = view.cfg_projection_for(scope)
    assert projection is not None and projection.applied
    omitted = {(row.block_addr, row.target) for row in projection.applied}
    graph.add_edges_from((nodes[a], nodes[b]) for a, b in link.boundary.successor_edges
                         if (a, b) not in omitted)
    assert omitted - {(a.addr, b.addr) for a, b in graph.edges}
    clinic = _clinic_stub(project)
    clinic.function = SimpleNamespace(addr=link.artifact.function_addr, graph=graph)
    clinic._func_graph = graph
    clinic._blocks_by_addr_and_size = {}
    begin_clinic_entry_jump_conversion_8616(clinic)
    for block in blocks:
        clinic._blocks_by_addr_and_size[(block.addr, block.size)] = _convert(clinic, block)
    return clinic, entry, graph


def test_scoped_native_jump_updates_private_cfg_and_ail_atomically(native_scope):
    clinic, entry, graph = _conversion(native_scope)
    before = set(graph.edges)
    transport_clinic_scoped_control_8616(clinic, entry)
    projection = entry.view.cfg_projection_for(entry.scope)
    assert projection is not None
    expected = {(a, b) for a, targets in projection.successors.items() for b in targets}
    assert {(a.addr, b.addr) for a, b in clinic._func_graph.edges} == expected
    assert set(graph.edges) == before
    assert clinic._func_graph is not graph
    for admission in projection.applied:
        block = next(b for (addr, _), b in clinic._blocks_by_addr_and_size.items() if addr == admission.block_addr)
        assert isinstance(block.statements[-1].target, ailment.Expr.Const)
        assert block.statements[-1].target.value == admission.target


@pytest.mark.parametrize('damage', ['bytes', 'scope', 'target', 'ail'])
def test_stale_scoped_conversion_publishes_neither_operand_nor_graph(native_scope, damage):
    clinic, entry, graph = _conversion(native_scope)
    original_blocks = clinic._blocks_by_addr_and_size
    if damage == 'bytes':
        clinic.project.loader.memory.store(0x1031, b'\x90')
    elif damage == 'scope':
        entry = replace(entry, scope=replace(entry.scope, project=object()))
    elif damage == 'target':
        clinic._func_graph.remove_node(next(n for n in graph.nodes if n.addr == 0x1020))
    else:
        block = next(iter(original_blocks.values()))
        block.statements.clear()
    with pytest.raises(PipelineHardError):
        transport_clinic_scoped_control_8616(clinic, entry)
    assert clinic._func_graph is graph
    assert clinic._blocks_by_addr_and_size is original_blocks


@pytest.mark.parametrize('damage', [None, 'source_graph', 'receipt'])
def test_native_interior_jump_partition_is_redecoded_before_ail_conversion(damage):
    """A backward native edge splits the preceding XOR/JMP shared-return arm."""
    import hashlib
    import io

    import angr

    from inertia.frontend.x86_16.arch_86_16 import Arch86_16
    from inertia.frontend.x86_16.clinic_scoped_control import prepare_clinic_scoped_partition_8616
    from inertia.frontend.x86_16.declared_function_entry import admit_declared_function_entry_8616
    from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
    from inertia.ir.declared_entry_pipeline import prepare_declared_entry_pipeline_8616
    from inertia.ir.real16_invocation_domain import DeclaredFunctionEntryLink8616, real16_native_census_import_8616
    from tests.ir.test_declared_function_entry_domain import _world
    from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
    from tools.dosunit.runtime.real16_replay_model import LinearRange

    _, original, old_link = _world()
    body = bytes.fromhex('83f800740431c0eb17b80200') + b'\x90'*4 + bytes.fromhex('ebf5') + b'\x90'*14 + b'\xc3'
    source = bytearray(original.source)
    source[0x40:0x40+len(body)] = body
    boot = program_from_mz_bytes(bytes(source), original.environment,
        code_ranges=(LinearRange(0x1000,2),LinearRange(0x1020,len(body)),LinearRange(0x1070,1)))
    module = boot.image.chunks[0][1]
    project = angr.Project(io.BytesIO(module),main_opts={'backend':'blob','arch':Arch86_16(),
        'base_addr':0x1000,'entry_point':0x1000},auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project,0x1020,0x1020+len(body))
    assert boundary is not None
    artifact = real16_native_census_import_8616(project,boundary)
    assert artifact is not None
    spec = replace(old_link.admission.spec,source_sha256=hashlib.sha256(boot.source).hexdigest(),
        relocated_sha256=hashlib.sha256(module).hexdigest(),native_sha256=hashlib.sha256(body).hexdigest(),
        range_end=0x1020+len(body))
    admission = admit_declared_function_entry_8616(spec,source=boot.source,loaded_module=module,
        environment_sha256=spec.environment_sha256)
    link = DeclaredFunctionEntryLink8616(admission,artifact,boundary)
    _install(project,boot,link)
    graph = nx.DiGraph()
    nodes = {block.addr:BlockNode(block.addr,block.size) for block in boundary.blocks if block.addr != 0x1027}
    nodes[0x1025] = BlockNode(0x1025,4)
    graph.add_nodes_from(nodes.values())
    for a,b in boundary.successor_edges:
        if a == 0x1027 or b == 0x1027:
            continue
        graph.add_edge(nodes[a],nodes[b])
    graph.add_edge(nodes[0x1025],nodes[0x1040])
    clinic = _clinic_stub(project)
    clinic.function = SimpleNamespace(addr=0x1020,graph=graph)
    clinic._func_graph = graph
    clinic._blocks_by_addr_and_size = {}
    entry = prepare_declared_entry_pipeline_8616(project,clinic,0x1020)
    assert entry is not None
    prepare_clinic_scoped_partition_8616(clinic,entry)
    assert (0x1027,2) in {(n.addr,n.size) for n in clinic._func_graph.nodes}
    assert (0x1025,2) in {(n.addr,n.size) for n in clinic._func_graph.nodes}
    assert (0x1025,4) in {(n.addr,n.size) for n in graph.nodes}
    begin_clinic_entry_jump_conversion_8616(clinic)
    for node in clinic._func_graph.nodes:
        native = project.factory.block(node.addr,size=node.size)
        clinic._blocks_by_addr_and_size[(node.addr,node.size)] = _convert(clinic,native)
    if damage == 'source_graph':
        graph.add_edge(nodes[0x1025], nodes[0x1020])
    elif damage == 'receipt':
        clinic._inertia_clinic_scoped_partition_8616 = replace(
            clinic._inertia_clinic_scoped_partition_8616, entry=replace(entry, source=object()))
    if damage is not None:
        original_blocks = clinic._blocks_by_addr_and_size
        original_graph = clinic._func_graph
        with pytest.raises(PipelineHardError):
            transport_clinic_scoped_control_8616(clinic,entry)
        assert clinic._blocks_by_addr_and_size is original_blocks
        assert clinic._func_graph is original_graph
        return
    transport_clinic_scoped_control_8616(clinic,entry)
    assert (0x1027,0x1040) in {(a.addr,b.addr) for a,b in clinic._func_graph.edges}
    assert clinic.function.graph is graph
    assert isinstance(clinic._blocks_by_addr_and_size[(0x1027,2)].statements[-1].target,ailment.Expr.Const)


def test_installed_clinic_wrapper_prepares_partition_before_native_conversion(native_scope, monkeypatch):
    """The installed producer consumes native partition authority before lifting."""
    from angr.analyses.decompiler.clinic import Clinic

    from inertia.frontend.x86_16 import clinic_scoped_control, compat
    from inertia.ir import declared_entry_pipeline

    clinic, entry, _ = _conversion(native_scope)
    events = []
    clinic._blocks_by_addr_and_size = {}
    def prepare(project, consumer, address):
        assert project is clinic.project and consumer is clinic
        assert address == entry.bundle.artifact.function_addr
        events.append('entry')
        return entry
    original_partition = clinic_scoped_control.prepare_clinic_scoped_partition_8616
    def partition(consumer, retained):
        assert retained is entry
        events.append('partition')
        original_partition(consumer, retained)
    original_begin = compat.begin_clinic_entry_jump_conversion_8616
    def begin(consumer):
        events.append('capture')
        original_begin(consumer)
    def convert(consumer):
        events.append('convert')
        assert consumer._inertia_declared_entry_pipeline_8616 is entry
        for node in consumer._func_graph.nodes:
            block = consumer.project.factory.block(node.addr,size=node.size)
            consumer._blocks_by_addr_and_size[(node.addr,node.size)] = _convert(consumer,block)
    original_transport = clinic_scoped_control.transport_clinic_scoped_control_8616
    def transport(consumer, retained):
        assert retained is entry
        events.append('transport')
        original_transport(consumer,retained)
    monkeypatch.setattr(declared_entry_pipeline,'prepare_declared_entry_pipeline_8616',prepare)
    monkeypatch.setattr(clinic_scoped_control,'prepare_clinic_scoped_partition_8616',partition)
    monkeypatch.setattr(clinic_scoped_control,'transport_clinic_scoped_control_8616',transport)
    monkeypatch.setattr(compat,'begin_clinic_entry_jump_conversion_8616',begin)
    monkeypatch.setattr(Clinic,'_convert_all',convert)
    compat._install_clinic_entry_jump_conversion_8616()
    Clinic._convert_all(clinic)
    assert events == ['entry','partition','capture','convert','transport']
