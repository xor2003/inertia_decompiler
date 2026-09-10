"""Binary callee cleanup becomes a narrow scalar effect, never guessed DCE."""

import io

import angr
import networkx as nx
import pytest
from angr import ailment
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.call_cleanup_compat import materialize_callee_cleanup_8616


def _fixture(encoded="c2 08 00"):
    project = angr.Project(
        io.BytesIO(bytes.fromhex(encoded)), auto_load_libs=False,
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x2000, "entry_point": 0x2000},
    )
    manager = ailment.Manager(arch=project.arch)
    target = ailment.Expr.Const(manager.next_atom(), 0x2000, 16)
    argument = ailment.Expr.Register(manager.next_atom(), project.arch.sp_offset, 16)
    call = ailment.Stmt.SideEffectStatement(
        manager.next_atom(), ailment.Expr.Call(manager.next_atom(), target, args=(argument,), bits=16),
        ins_addr=0x1000,
    )
    block = ailment.Block(0x1000, 3, statements=[call])
    successor = ailment.Block(0x1003, 1, statements=[])
    graph = nx.DiGraph([(block, successor)])
    return project, manager, graph, block, successor, call


def test_binary_cleanup_is_after_call_narrow_and_idempotent():
    project, manager, graph, block, successor, call = _fixture()
    result = materialize_callee_cleanup_8616(project, graph, manager, (0x1000,), sp_offset=project.arch.sp_offset)
    assert result.raw_fact_count == result.normalized_fact_count == 1
    assert result.classified_fact_count == result.materialized_count == 1
    assert result.failure_count == 0
    assert block.statements[0] is call
    assert len(call.expr.args) == 1 and call.expr.args[0].bits == 16
    update = block.statements[1]
    assert update.dst.reg_offset == project.arch.sp_offset and update.dst.bits == 16
    assert update.src.op == "Add" and update.src.bits == 16
    assert update.src.operands[0].reg_offset == project.arch.sp_offset
    assert update.src.operands[1].value == 8
    assert len({update.idx, update.dst.idx, update.src.idx, *(op.idx for op in update.src.operands)}) == 5
    assert update.tags["ins_addr"] == 0x1000
    assert update.tags["inertia_callee_cleanup"] == result.facts[0]
    assert "vex_stmt_idx" not in update.tags
    assert successor.statements == [] and list(graph.edges) == [(block, successor)]
    repeated = materialize_callee_cleanup_8616(project, graph, manager, (0x1000,), sp_offset=project.arch.sp_offset)
    assert repeated.materialized_count == 0 and len(block.statements) == 2


@pytest.mark.parametrize("encoded", ["c3", "66 c2 08 00", "ca 08 00", "ff e0", "85 c0 74 03 c2 08 00 c2 04 00"])
def test_unproven_or_unsupported_return_keeps_call(encoded):
    project, manager, graph, block, _successor, call = _fixture(encoded)
    result = materialize_callee_cleanup_8616(project, graph, manager, (0x1000,), sp_offset=project.arch.sp_offset)
    assert result.materialized_count == 0 and result.failure_count == 1
    assert block.statements == [call]


@pytest.mark.parametrize("case", ["unconsumed_frame", "no_return_edge", "duplicate_call", "existing_effect", "indirect"])
def test_ambiguous_call_projection_refuses(case):
    project, manager, graph, block, successor, call = _fixture()
    accepted = () if case == "unconsumed_frame" else (0x1000,)
    if case == "no_return_edge":
        graph.remove_edge(block, successor)
    elif case == "duplicate_call":
        duplicate = ailment.Block(0x900, 1, statements=[call])
        graph.add_edge(duplicate, successor)
    elif case == "existing_effect":
        block.statements.append(ailment.Stmt.Assignment(
            manager.next_atom(), ailment.Expr.Register(manager.next_atom(), project.arch.sp_offset, 16),
            ailment.Expr.Const(manager.next_atom(), 0, 16), ins_addr=0x1000,
        ))
    elif case == "indirect":
        call.expr = ailment.Expr.Call(
            manager.next_atom(), ailment.Expr.Register(manager.next_atom(), 0, 16), args=(), bits=16,
        )
    before = tuple(block.statements)
    result = materialize_callee_cleanup_8616(project, graph, manager, accepted, sp_offset=project.arch.sp_offset)
    assert result.materialized_count == 0
    assert tuple(block.statements) == before


def test_shared_successor_has_no_cleanup_for_other_predecessor():
    project, manager, graph, block, successor, _call = _fixture()
    other = ailment.Block(0x900, 1, statements=[])
    graph.add_edge(other, successor)
    result = materialize_callee_cleanup_8616(project, graph, manager, (0x1000,), sp_offset=project.arch.sp_offset)
    assert result.materialized_count == 1 and len(block.statements) == 2
    assert not other.statements and not successor.statements
    assert set(graph.predecessors(successor)) == {block, other}
