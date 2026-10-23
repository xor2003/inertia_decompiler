"""Reject changes to the complete context behind an entry-domain transport."""

from types import SimpleNamespace

import networkx
import pytest
import pyvex
from angr import ailment

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.clinic_entry_jump_transport import (
    _context_is_current_8616,
    begin_clinic_entry_jump_conversion_8616,
    capture_clinic_converted_block_8616,
)
from inertia.frontend.x86_16.clinic_terminal_control import (
    ClinicTerminalControlStats8616,
    ClinicTerminalTransport8616,
)


@pytest.fixture
def context():
    """Capture an exact native/AIL pair without running a proof engine."""
    arch = Arch86_16()
    vex = pyvex.IRSB.empty_block(arch, addr=0x1000)
    vex.tyenv.add("Ity_I32")
    vex.next = pyvex.expr.RdTmp(0)
    vex.statements = [pyvex.stmt.IMark(0x1000, 2, 0)]
    node = SimpleNamespace(addr=0x1000, size=2)
    # NetworkX needs hashable nodes; a named native coordinate is sufficient.
    class Node:
        addr = node.addr
        size = node.size
    graph = networkx.DiGraph()
    graph.add_node(Node())
    memory = bytearray(b"\x90\xc3")
    project = SimpleNamespace(loader=SimpleNamespace(memory=SimpleNamespace(
        load=lambda addr, size: bytes(memory[addr-0x1000:addr-0x1000+size]),
    )))
    native = SimpleNamespace(addr=0x1000, size=2, bytes=bytes(memory), vex=vex)
    assignment = ailment.Stmt.Assignment(
        0, ailment.Expr.Register(0, arch.registers["cs"][0], 16),
        ailment.Expr.Const(1, 0x1234, 16), ins_addr=0x1000,
    )
    converted = ailment.Block(0x1000, 2, statements=[assignment])
    clinic = SimpleNamespace(
        project=project, function=SimpleNamespace(graph=graph), _func_graph=graph,
        _blocks_by_addr_and_size={(0x1000, 2): converted},
    )
    begin_clinic_entry_jump_conversion_8616(clinic)
    transport = ClinicTerminalTransport8616(
        False, None, None, "", ClinicTerminalControlStats8616(0, 0, 0, 0, 0), None,
    )
    capture_clinic_converted_block_8616(clinic, native, converted, transport=transport)
    captures = clinic._inertia_entry_jump_captures_8616
    assert _context_is_current_8616(clinic, captures)
    return clinic, captures, native, converted, memory


@pytest.mark.parametrize("mutation", ["bytes", "vex", "width", "edges", "partition", "ail", "foreign", "replacement"])
def test_changed_context_refuses(context, mutation):
    """Earlier effects and graph changes invalidate every terminal admission."""
    clinic, captures, native, converted, memory = context
    if mutation == "bytes":
        memory[0] ^= 1
    elif mutation == "vex":
        native.vex.statements.append(pyvex.stmt.Put(pyvex.expr.Const(pyvex.const.U16(7)), 28))
    elif mutation == "width":
        native.vex.tyenv.types[0] = "Ity_I16"
    elif mutation == "edges":
        node = next(iter(clinic._func_graph.nodes()))
        clinic._func_graph.add_edge(node, node)
    elif mutation == "partition":
        next(iter(clinic._func_graph.nodes())).size = 1
    elif mutation == "ail":
        converted.statements[0].src = ailment.Expr.Const(2, 0x5678, 16)
    elif mutation == "foreign":
        clinic.function = SimpleNamespace(graph=clinic.function.graph)
    else:
        clinic._blocks_by_addr_and_size[(0x1000, 2)] = converted.copy()
    assert not _context_is_current_8616(clinic, captures)


def test_unchanged_context_remains_current(context):
    """Freshness validation is a read-only check on native and converted IR."""
    clinic, captures, *_ = context
    assert _context_is_current_8616(clinic, captures)
    assert _context_is_current_8616(clinic, captures)
