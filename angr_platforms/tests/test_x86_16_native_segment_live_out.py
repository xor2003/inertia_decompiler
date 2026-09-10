"""Check native SSA segment-output uses without costly whole decompilations."""

import networkx as nx
import pytest
from angr.ailment import Block
from angr.ailment.expression import Const, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, ConditionalJump, Return
from angr.analyses.s_reaching_definitions.s_reaching_definitions import SReachingDefinitions
from angr_platforms.X86_16.ir.native_segment_live_out import preserve_native_segment_live_outs_8616
from test_x86_16_cod_samples import _project_from_bytes


@pytest.mark.parametrize("register", ["es", "ds", "ss", "cs", "fs", "gs"])
def test_only_reaching_segment_definition_has_boundary_use(register: str) -> None:
    project = _project_from_bytes(b"\xc3")
    function = project.kb.functions.function(addr=0x1000, create=True)
    offset, _ = project.arch.registers[register]
    first = VirtualVariable(0, 0, 16, VirtualVariableCategory.REGISTER, oident=offset)
    last = VirtualVariable(1, 1, 16, VirtualVariableCategory.REGISTER, oident=offset)
    block = Block(0x1000, 1, statements=[
        Assignment(0, first, Const(2, 1, 16), ins_addr=0x1000),
        Assignment(1, last, Const(3, 2, 16), ins_addr=0x1000),
        Return(2, [], ins_addr=0x1000),
    ])
    graph = nx.DiGraph()
    graph.add_node(block)
    analysis = SReachingDefinitions(project, function, func_graph=graph)
    report = preserve_native_segment_live_outs_8616(analysis)
    assert not analysis.model.all_vvar_uses[0]
    assert len(analysis.model.all_vvar_uses[1]) == 1
    assert report.raw_fact_count == report.classified_fact_count == report.materialized_count == 1
    assert report.failure_count == 0


def test_block_analysis_does_not_invent_function_boundary_uses() -> None:
    project = _project_from_bytes(b"\xc3")
    offset, _ = project.arch.registers["es"]
    value = VirtualVariable(0, 0, 16, VirtualVariableCategory.REGISTER, oident=offset)
    block = Block(0x1000, 1, statements=[Assignment(0, value, Const(1, 0, 16))])
    analysis = SReachingDefinitions(project, block)
    assert preserve_native_segment_live_outs_8616(analysis).materialized_count == 0
    assert not analysis.model.all_vvar_uses[0]


def test_each_branch_return_preserves_its_own_segment_definition() -> None:
    project = _project_from_bytes(b"\xc3")
    function = project.kb.functions.function(addr=0x1000, create=True)
    offset, _ = project.arch.registers["es"]
    entry = Block(0x1000, 1, statements=[
        ConditionalJump(0, Const(0, 1, 1), Const(1, 0x1010, 32), Const(2, 0x1020, 32), ins_addr=0x1000),
    ])
    graph = nx.DiGraph()
    for varid, address in [(1, 0x1010), (2, 0x1020)]:
        value = VirtualVariable(varid, varid, 16, VirtualVariableCategory.REGISTER, oident=offset)
        terminal = Block(address, 1, statements=[
            Assignment(0, value, Const(3, varid, 16), ins_addr=address),
            Return(1, [], ins_addr=address),
        ])
        graph.add_edge(entry, terminal)
    analysis = SReachingDefinitions(project, function, func_graph=graph)
    report = preserve_native_segment_live_outs_8616(analysis)
    expected_outputs = 2
    assert report.materialized_count == expected_outputs
    for varid, address in [(1, 0x1010), (2, 0x1020)]:
        uses = analysis.model.all_vvar_uses[varid]
        assert len(uses) == 1
        assert next(iter(uses))[1].block_addr == address
