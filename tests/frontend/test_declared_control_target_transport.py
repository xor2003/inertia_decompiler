"""Declared CS must reach exact native CALL and JMP target materialization."""

import hashlib
import io
from dataclasses import replace
from types import SimpleNamespace

import angr
import networkx as nx
import pytest
from angr import ailment
from angr.codenode import BlockNode

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.clinic_entry_jump_transport import begin_clinic_entry_jump_conversion_8616
from inertia.frontend.x86_16.clinic_scoped_control import (
    prepare_clinic_scoped_partition_8616,
    transport_clinic_scoped_control_8616,
)
from inertia.frontend.x86_16.declared_function_entry import DeclaredEntryMemory8616, admit_declared_function_entry_8616
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir.declared_entry_pipeline import DeclaredEntryPipeline8616, prepare_declared_entry_pipeline_8616
from inertia.ir.real16_declared_interrupt8616 import declared_environment_digest_8616
from inertia.ir.real16_invocation_domain import DeclaredFunctionEntryLink8616, real16_native_census_import_8616
from inertia.pipeline.errors import PipelineHardError
from tests.frontend.test_x86_16_clinic_terminal_control import _clinic_stub, _convert
from tests.ir.test_declared_function_entry_domain import _world
from tests.ir.test_declared_function_entry_intake import _install
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

pytestmark = pytest.mark.decompiler


def _native_conversion(kind: str, *, declared: bool = True, helper: bytes = b"\xc3") -> tuple[SimpleNamespace, DeclaredEntryPipeline8616 | None]:
    _, original, old_link = _world()
    base = 418 << 4
    start, body = (
        (0x1DCE, bytes.fromhex("e811ffc3")) if kind == "call" else (0x1DDB, b"\x90" * 24 + bytes.fromhex("ebe6"))
    )
    image = bytearray(0x500)
    image[:2] = bytes.fromhex("0f0b")
    image[0x1CE2 - base:0x1CE2 - base + len(helper)] = helper
    image[start - base : start - base + len(body)] = body
    image[0x470] = 0xC3
    header = bytearray(original.source[:32])
    header[2:4] = (0x120).to_bytes(2, "little")
    header[4:6] = (3).to_bytes(2, "little")
    header[12:14] = (0x200).to_bytes(2, "little")
    environment = replace(original.environment, psp_segment=418 - 16, allocation=bytes(0x2000))
    boot = program_from_mz_bytes(
        bytes(header + image),
        environment,
        code_ranges=(
            LinearRange(base, 2),
            LinearRange(start, len(body)),
            LinearRange(0x1CE2, len(helper)),
            LinearRange(base + 0x470, 1),
        ),
    )
    module = boot.image.chunks[0][1]
    project = angr.Project(
        io.BytesIO(module),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": base, "entry_point": base},
        auto_load_libs=False,
    )
    boundary = exact_function_range_boundary_8616(project, start, start + len(body))
    assert boundary is not None
    artifact = real16_native_census_import_8616(project, boundary)
    assert artifact is not None
    spec = replace(
        old_link.admission.spec,
        source_sha256=hashlib.sha256(boot.source).hexdigest(),
        relocated_sha256=hashlib.sha256(module).hexdigest(),
        native_sha256=hashlib.sha256(body).hexdigest(),
        load_segment=418,
        entry_segment=418,
        entry_offset=start - base,
        range_start=start,
        range_end=start + len(body),
        environment_sha256=declared_environment_digest_8616(environment),
        registers=(("ss", 0x220), ("sp", 0x80)),
        memory=(DeclaredEntryMemory8616(0x2280, bytes.fromhex("7004")),),
        return_boundary=replace(old_link.admission.spec.return_boundary, segment=418, offset=0x470),
    )
    admission = admit_declared_function_entry_8616(
        spec, source=boot.source, loaded_module=module, environment_sha256=spec.environment_sha256
    )
    link = DeclaredFunctionEntryLink8616(admission, artifact, boundary)
    if declared:
        _install(project, boot, link)
    graph = nx.DiGraph()
    nodes = {block.addr: BlockNode(block.addr, block.size) for block in boundary.blocks}
    graph.add_nodes_from(nodes.values())
    graph.add_edges_from((nodes[a], nodes[b]) for a, b in boundary.successor_edges)
    clinic = _clinic_stub(project)
    clinic.function = SimpleNamespace(addr=start, graph=graph)
    clinic._func_graph = graph
    clinic._blocks_by_addr_and_size = {}
    entry = prepare_declared_entry_pipeline_8616(project, clinic, start)
    if declared:
        assert isinstance(entry, DeclaredEntryPipeline8616), entry
        prepare_clinic_scoped_partition_8616(clinic, entry)
    else:
        assert entry is None
    begin_clinic_entry_jump_conversion_8616(clinic)
    for node in clinic._func_graph.nodes:
        block = project.factory.block(node.addr, size=node.size)
        clinic._blocks_by_addr_and_size[(node.addr, node.size)] = _convert(clinic, block)
    return clinic, entry


@pytest.mark.parametrize("kind", ["call", "jump"])
@pytest.mark.parametrize("damage", [None, "missing", "changed"])
def test_declared_cs_reaches_native_control_target(kind: str, damage: str | None) -> None:
    clinic, entry = _native_conversion(kind, declared=damage != "missing")
    if damage == "changed":
        assert entry is not None
        entry = replace(entry, scope=replace(entry.scope, entry_segment=419))
        with pytest.raises(PipelineHardError, match="scoped Clinic partition receipt is foreign"):
            transport_clinic_scoped_control_8616(clinic, entry)
        return
    if entry is not None:
        transport_clinic_scoped_control_8616(clinic, entry)
    head, target = (0x1DCE, 0x1CE2) if kind == "call" else (0x1DF3, 0x1DDB)
    terminals = [
        block.statements[-1]
        for block in clinic._blocks_by_addr_and_size.values()
        if block.statements and block.statements[-1].tags.get("ins_addr") == head
    ]
    assert len(terminals) == 1
    terminal = terminals[0]
    operand = terminal.expr.target if isinstance(terminal, ailment.Stmt.SideEffectStatement) else terminal.target
    if damage == "missing":
        assert not isinstance(operand, ailment.Expr.Const)
        return
    assert entry is not None
    assert isinstance(operand, ailment.Expr.Const), (kind, operand, entry.scope.entry_call_preservations)
    assert operand.value == target


def test_unknown_callee_keeps_declared_call_target_unproved() -> None:
    """An unmodeled interrupt cannot acquire target/effect authority from CALL presence."""
    clinic, entry = _native_conversion("call", helper=bytes.fromhex("cd21c3"))
    assert entry is not None
    assert not entry.scope.entry_call_preservations
    transport_clinic_scoped_control_8616(clinic, entry)
    block = next(block for (address, _), block in clinic._blocks_by_addr_and_size.items() if address == 0x1dce)
    call = block.statements[-1]
    assert isinstance(call, ailment.Stmt.SideEffectStatement)
    assert not isinstance(call.expr.target, ailment.Expr.Const)
