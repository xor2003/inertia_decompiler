"""Check native SSA segment-output uses without costly whole decompilations."""

import networkx as nx
import pytest
from angr.ailment import Block
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import Const, Load, UnaryOp, VirtualVariable, VirtualVariableCategory
from angr.ailment.statement import Assignment, ConditionalJump, Jump, Return, Store
from angr.analyses.s_reaching_definitions.s_reaching_definitions import SReachingDefinitions

from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.ir.native_segment_live_out import (
    _StackLoadAnchorViewer8616,
    preserve_native_segment_live_outs_8616,
)
from inertia.ir.native_stack_anchor import NATIVE_ENTRY_SP_ANCHOR_TAG8616
from tests.cli.test_x86_16_cod_samples import _project_from_bytes


@pytest.fixture(scope="module", autouse=True)
def _initialize_native_frontend() -> None:
    """Register the calling convention and native adapters for isolated runs."""
    apply_x86_16_bootstrap()


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


@pytest.mark.parametrize("symbolic_target", [False, True])
def test_unmodeled_tail_preserves_reaching_architectural_definitions(
    symbolic_target: bool,
) -> None:
    """An exit without callee effects cannot prove a register definition dead."""
    project = _project_from_bytes(b"\xc3")
    function = project.kb.functions.function(addr=0x1000, create=True)
    assignments = []
    for varid, register in enumerate(("ax", "bx", "cs", "dflag", "flags", "sp", "bp")):
        offset, size = project.arch.registers[register]
        destination = VirtualVariable(
            varid, varid, size * 8, VirtualVariableCategory.REGISTER, oident=offset,
        )
        assignments.append(Assignment(varid, destination, Const(10 + varid, 2, size * 8), ins_addr=0x1000))
    target = (
        VirtualVariable(20, 20, 32, VirtualVariableCategory.REGISTER, oident=project.arch.ip_offset)
        if symbolic_target else Const(20, 0x2000, 32)
    )
    block = Block(0x1000, 1, statements=[*assignments, Jump(7, target, ins_addr=0x1000)])
    graph = nx.DiGraph()
    graph.add_node(block)
    analysis = SReachingDefinitions(project, function, func_graph=graph)
    report = preserve_native_segment_live_outs_8616(analysis)

    for varid in range(7):
        uses = analysis.model.all_vvar_uses[varid]
        assert len(uses) == 1, f"register definition {varid} lost its unknown-exit use"
        assert next(iter(uses))[1].stmt_idx == 7
    assert report.materialized_count == 7
    assert report.raw_fact_count == report.normalized_fact_count == report.classified_fact_count == 7
    assert report.failure_count == 0


def test_unknown_exit_keeps_only_the_reaching_definition() -> None:
    """Overwritten writes stay optimizable: retention follows the reaching view."""
    project = _project_from_bytes(b"\xc3")
    function = project.kb.functions.function(addr=0x1000, create=True)
    offset, _ = project.arch.registers["ax"]
    overwritten = VirtualVariable(0, 0, 16, VirtualVariableCategory.REGISTER, oident=offset)
    reaching = VirtualVariable(1, 1, 16, VirtualVariableCategory.REGISTER, oident=offset)
    block = Block(0x1000, 1, statements=[
        Assignment(0, overwritten, Const(1, 1, 16), ins_addr=0x1000),
        Assignment(1, reaching, Const(2, 2, 16), ins_addr=0x1000),
        Jump(2, Const(3, 0x2000, 32), ins_addr=0x1000),
    ])
    graph = nx.DiGraph()
    graph.add_node(block)
    analysis = SReachingDefinitions(project, function, func_graph=graph)
    report = preserve_native_segment_live_outs_8616(analysis)

    assert not analysis.model.all_vvar_uses[0]
    assert len(analysis.model.all_vvar_uses[1]) == 1
    assert report.materialized_count == 1
    assert report.unknown_exit_output_count == 1


def test_unknown_exit_keeps_the_chain_feeding_the_reaching_value() -> None:
    """A definition read by the reaching assignment remains observable too."""
    project = _project_from_bytes(b"\xc3")
    function = project.kb.functions.function(addr=0x1000, create=True)
    ax_offset, _ = project.arch.registers["ax"]
    bx_offset, _ = project.arch.registers["bx"]
    bx_vvar = VirtualVariable(0, 0, 16, VirtualVariableCategory.REGISTER, oident=bx_offset)
    ax_vvar = VirtualVariable(1, 1, 16, VirtualVariableCategory.REGISTER, oident=ax_offset)
    block = Block(0x1000, 1, statements=[
        Assignment(0, bx_vvar, Const(1, 1, 16), ins_addr=0x1000),
        Assignment(1, ax_vvar, bx_vvar, ins_addr=0x1000),
        Jump(2, Const(2, 0x2000, 32), ins_addr=0x1000),
    ])
    graph = nx.DiGraph()
    graph.add_node(block)
    analysis = SReachingDefinitions(project, function, func_graph=graph)
    preserve_native_segment_live_outs_8616(analysis)

    for varid in (0, 1):
        uses = analysis.model.all_vvar_uses[varid]
        assert any(expr is None and loc.stmt_idx == 2 for expr, loc in uses)


def test_ail_simplifier_keeps_reaching_writes_and_inputs_at_unknown_tail() -> None:
    """Real simplifier run: reaching AX write and its BX input survive the exit."""
    # mov bx, 1; mov ax, bx; jmp rel16 (selector-dependent, unmodeled target)
    project = _project_from_bytes(bytes.fromhex("bb010089d8e95bfe"))
    cfg = project.analyses.CFGFast(normalize=True)
    clinic = project.analyses.Clinic(cfg.functions[0x1000])
    blocks = list(clinic.graph.nodes())

    for register in ("ax", "bx"):
        offset, _ = project.arch.registers[register]
        writes = [
            statement
            for block in blocks
            for statement in block.statements
            if isinstance(statement, Assignment)
            and isinstance(statement.dst, VirtualVariable)
            and statement.dst.category == VirtualVariableCategory.REGISTER
            and statement.dst.oident == offset
        ]
        assert len(writes) == 1, f"{register} write lost through the unknown tail"
    assert isinstance(blocks[0].statements[-1], Jump)


def test_ail_simplifier_still_removes_overwritten_writes_at_unknown_tail() -> None:
    """Real simplifier run: only the reaching AX write survives, not history."""
    # mov ax, 1; mov ax, 2; jmp rel16 (selector-dependent, unmodeled target)
    project = _project_from_bytes(bytes.fromhex("b80100b80200e95bfe"))
    cfg = project.analyses.CFGFast(normalize=True)
    clinic = project.analyses.Clinic(cfg.functions[0x1000])
    ax_offset, _ = project.arch.registers["ax"]
    ax_writes = [
        statement
        for block in clinic.graph.nodes()
        for statement in block.statements
        if isinstance(statement, Assignment)
        and isinstance(statement.dst, VirtualVariable)
        and statement.dst.category == VirtualVariableCategory.REGISTER
        and statement.dst.oident == ax_offset
    ]
    assert len(ax_writes) == 1
    assert isinstance(ax_writes[0].src, Const)
    assert ax_writes[0].src.value_int == 2


def test_internal_jump_does_not_invent_gp_live_out() -> None:
    """A modeled internal edge remains subject to ordinary dead-use analysis."""
    project = _project_from_bytes(b"\xc3")
    function = project.kb.functions.function(addr=0x1000, create=True)
    offset, _ = project.arch.registers["ax"]
    value = VirtualVariable(0, 0, 16, VirtualVariableCategory.REGISTER, oident=offset)
    entry = Block(0x1000, 1, statements=[
        Assignment(0, value, Const(1, 2, 16), ins_addr=0x1000),
        Jump(1, Const(2, 0x1010, 32), ins_addr=0x1000),
    ])
    terminal = Block(0x1010, 1, statements=[Return(0, [], ins_addr=0x1010)])
    graph = nx.DiGraph()
    graph.add_edge(entry, terminal)
    analysis = SReachingDefinitions(project, function, func_graph=graph)
    report = preserve_native_segment_live_outs_8616(analysis)

    assert not analysis.model.all_vvar_uses[0]
    assert report.materialized_count == 0


@pytest.mark.parametrize("target_idx,retained", [(0, True), (1, False)])
def test_jump_successor_requires_the_same_block_coordinate(target_idx: int, retained: bool) -> None:
    """A same-address clone does not discharge a different target block."""
    project = _project_from_bytes(b"\xc3")
    function = project.kb.functions.function(addr=0x1000, create=True)
    offset, _ = project.arch.registers["ax"]
    value = VirtualVariable(0, 0, 16, VirtualVariableCategory.REGISTER, oident=offset)
    entry = Block(0x1000, 1, statements=[
        Assignment(0, value, Const(1, 2, 16), ins_addr=0x1000),
        Jump(1, Const(2, 0x1010, 32), target_idx=target_idx, ins_addr=0x1000),
    ])
    successor = Block(0x1010, 1, idx=1, statements=[Return(0, [], ins_addr=0x1010)])
    graph = nx.DiGraph()
    graph.add_edge(entry, successor)
    analysis = SReachingDefinitions(project, function, func_graph=graph)
    report = preserve_native_segment_live_outs_8616(analysis)

    assert bool(analysis.model.all_vvar_uses[0]) is retained
    assert report.unknown_exit_output_count == int(retained)


def test_empty_sink_cannot_prove_incoming_register_definitions_dead() -> None:
    """Retain state at the last real instruction before a missing successor."""
    project = _project_from_bytes(b"\xc3")
    function = project.kb.functions.function(addr=0x1000, create=True)
    offset, _ = project.arch.registers["ax"]
    value = VirtualVariable(0, 0, 16, VirtualVariableCategory.REGISTER, oident=offset)
    entry = Block(0x1000, 1, statements=[
        Assignment(0, value, Const(1, 2, 16), ins_addr=0x1000),
        Jump(1, Const(2, 0x1010, 32), ins_addr=0x1000),
    ])
    sink = Block(0x1010, 0, statements=[])
    graph = nx.DiGraph()
    graph.add_edge(entry, sink)
    analysis = SReachingDefinitions(project, function, func_graph=graph)
    report = preserve_native_segment_live_outs_8616(analysis)

    assert len(analysis.model.all_vvar_uses[0]) == 1
    location = next(iter(analysis.model.all_vvar_uses[0]))[1]
    assert location.block_addr == 0x1000
    assert location.stmt_idx == 1
    assert report.unknown_exit_output_count == 1


def test_native_ssa_keeps_callee_saved_restores_after_stack_conversion() -> None:
    """Native save-area cleanup must not erase still-present segmented restores."""
    project = _project_from_bytes(bytes.fromhex(
        "55 8b ec 57 56 06 8b 4e 08 8b 46 0a c4 7e 04 "
        "f2 ab 07 2b c0 5e 5f 8b e5 5d c3"
    ))
    cfg = project.analyses.CFGFast(normalize=True)
    decompiled = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    writes = {
        (statement.tags.get("ins_addr"), statement.dst.oident)
        for block in decompiled.clinic.graph
        for statement in block.statements
        if isinstance(statement, Assignment)
        and isinstance(statement.dst, VirtualVariable)
        and statement.dst.category == VirtualVariableCategory.REGISTER
    }
    for instruction, register in ((0x1014, "si"), (0x1015, "di")):
        assert (instruction, project.arch.registers[register][0]) in writes

    class Anchors(AILBlockViewer):
        def _handle_UnaryOp(self, expr_idx, expr, stmt_idx, stmt, block):
            anchor = expr.tags.get(NATIVE_ENTRY_SP_ANCHOR_TAG8616)
            if anchor is not None:
                offsets.add(anchor)
            return super()._handle_UnaryOp(expr_idx, expr, stmt_idx, stmt, block)

    offsets = set()
    push_es_addr = 0x1005
    for block in decompiled.clinic.graph:
        for statement in block.statements:
            if isinstance(statement, Store) and statement.tags.get("ins_addr") == push_es_addr:
                Anchors().walk_expression(statement.addr)
    assert offsets == {-8, -7}, "PUSH ES must use updated SP, not the preceding SI slot"


@pytest.mark.parametrize("anchor,loaded,expected", [
    (-4, True, True),
    (None, True, False),
    (4, True, False),
    (0, True, False),
    (-4, False, False),
])
def test_native_stack_output_requires_proven_load_address(anchor, loaded, expected) -> None:
    """A local-looking offset or an address value alone is not load evidence."""
    value = VirtualVariable(0, 0, 16, VirtualVariableCategory.STACK, oident=-4)
    reference = UnaryOp(1, "Reference", value, bits=16)
    if anchor is not None:
        reference.tags[NATIVE_ENTRY_SP_ANCHOR_TAG8616] = anchor
    source = Load(2, reference, 2, "Iend_LE") if loaded else reference
    viewer = _StackLoadAnchorViewer8616()
    viewer.walk_expression(source)
    assert viewer.has_stack_load is expected


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


def test_unknown_tail_output_survives_cli_ast_cleanup() -> None:
    """Architectural SSA boundary uses must survive the normal AST DCE pass."""
    from angr.analyses.decompiler.structured_codegen.c import CAssignment, CVariable
    from angr.sim_variable import SimRegisterVariable

    from inertia.cli import cli_core  # noqa: F401 - canonical CLI compatibility registration
    from inertia.cli.cli_c_ast_rewrites import _iter_c_nodes_deep, _prune_dead_local_assignments

    project = _project_from_bytes(bytes.fromhex("b80200e95bfe"))
    cfg = project.analyses.CFGFast(normalize=True)
    # Match normal CLI resilience while retaining the expected control refusal.
    decompiled = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg, fail_fast=False)
    assert decompiled.errors
    codegen = decompiled.codegen
    ax_offset, _ = project.arch.registers["ax"]

    def output_assignments() -> list[CAssignment]:
        return [
            node for node in _iter_c_nodes_deep(codegen.cfunc.statements)
            if isinstance(node, CAssignment) and isinstance(node.lhs, CVariable)
            and isinstance(node.lhs.variable, SimRegisterVariable)
            and node.lhs.variable.reg == ax_offset
        ]

    before = output_assignments()
    assert len(before) == 1
    from inertia.postprocess.decompiler_postprocess_stage import _dead_code_elimination_after_flag_prune_8616
    _dead_code_elimination_after_flag_prune_8616(codegen)
    assert output_assignments() == before
    _prune_dead_local_assignments(codegen)
    assert output_assignments() == before
