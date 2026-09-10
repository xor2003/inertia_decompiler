"""Constant reassociation preserves bit vectors and native atom identities."""

from types import SimpleNamespace
from typing import cast

import claripy
import networkx as nx
import pytest
from angr import ailment
from angr.ailment.expression import BinaryOp, Const, Expression, Register
from angr.ailment.manager import Manager
from angr.analyses.decompiler.clinic import Clinic
from angr_platforms.X86_16.ail_displacement_compat import apply_register_displacement_compatibility_8616
from angr_platforms.X86_16.ir.ail_register_displacement import normalize_register_displacements_8616


def _evaluate(expression: Expression, symbol: claripy.ast.BV) -> claripy.ast.BV:
    if isinstance(expression, Register):
        return symbol
    if isinstance(expression, Const):
        return claripy.BVV(expression.value, expression.bits)
    assert isinstance(expression, BinaryOp)
    left, right = (_evaluate(operand, symbol) for operand in expression.operands)
    return left + right if expression.op == "Add" else left - right


@pytest.mark.parametrize("bits", [8, 16, 32])
@pytest.mark.parametrize("inner,outer", [("Add", "Add"), ("Add", "Sub"), ("Sub", "Add"), ("Sub", "Sub")])
@pytest.mark.parametrize("constants", [(2, 2), (2, 4), (-2, 0xffff)])
def test_register_displacements_preserve_all_bitvector_inputs(bits: int, inner: str, outer: str, constants: tuple[int, int]) -> None:
    manager = Manager()
    base = Register(manager.next_atom(), 16, bits)
    first = Const(manager.next_atom(), constants[0], bits)
    second = Const(manager.next_atom(), constants[1], bits)
    nested = BinaryOp(manager.next_atom(), inner, (base, first), False, bits=bits)
    expression = BinaryOp(manager.next_atom(), outer, (nested, second), False, bits=bits, ins_addr=0x1010)
    destination = Register(manager.next_atom(), 24, bits)
    block = ailment.Block(0x1000, 1, statements=[ailment.Stmt.Assignment(0, destination, expression)])
    successor = ailment.Block(0x1001, 1, statements=[])
    graph = nx.DiGraph([(block, successor)])
    report = normalize_register_displacements_8616(graph, manager)
    assert report.materialized_count == 1
    assert report.failure_count == 0
    result = block.statements[0].src
    symbol = claripy.BVS("register", bits)
    assert not claripy.Solver().satisfiable(extra_constraints=[_evaluate(expression, symbol) != _evaluate(result, symbol)])
    assert list(graph.edges) == [(block, successor)]
    assert block.statements[0].dst.idx == destination.idx
    assert block.statements[0].dst.likes(destination)
    assert report.facts[0].source_indices == (expression.idx, nested.idx)
    if isinstance(result, BinaryOp):
        assert result.operands[0].idx == base.idx
        assert result.operands[0].likes(base)
        assert result.idx not in {base.idx, expression.idx, nested.idx, first.idx, second.idx}
        assert result.operands[1].idx != result.idx
        assert result.tags["ins_addr"] == 0x1010
    else:
        assert result.idx == base.idx
        assert result.likes(base)
    assert normalize_register_displacements_8616(graph, manager).materialized_count == 0


@pytest.mark.parametrize("kind", ["floating", "mixed_width", "call", "stack_address", "conversion", "nonconstant", "unknown_operation"])
def test_unproven_displacement_chain_is_retained(kind: str) -> None:
    manager = Manager()
    base = Register(manager.next_atom(), 16, 16)
    if kind == "call":
        base = ailment.Expr.Call(manager.next_atom(), Const(manager.next_atom(), 0x2000, 16), args=(), bits=16)
    elif kind == "stack_address":
        base = ailment.Expr.StackBaseOffset(manager.next_atom(), 16, -2)
    elif kind == "conversion":
        base = ailment.Expr.Convert(manager.next_atom(), 32, 16, False, Register(manager.next_atom(), 16, 32))
    operand = Register(manager.next_atom(), 0, 16) if kind == "nonconstant" else Const(manager.next_atom(), 2, 16)
    nested = BinaryOp(manager.next_atom(), "Mul" if kind == "unknown_operation" else "Sub", (base, operand), False, bits=16)
    expression = BinaryOp(manager.next_atom(), "Add", (nested, Const(manager.next_atom(), 4, 32 if kind == "mixed_width" else 16)), False, bits=16, floating_point=kind == "floating")
    statement = ailment.Stmt.Assignment(0, Register(manager.next_atom(), 24, 16), expression)
    block = ailment.Block(0x1000, 1, statements=[statement])
    graph = nx.DiGraph()
    graph.add_node(block)
    report = normalize_register_displacements_8616(graph, manager)
    assert report.materialized_count == 0
    assert block.statements[0] is statement


@pytest.mark.parametrize("architecture", ["86_16", "AMD64"])
def test_native_boundary_runs_both_phases_and_invalidates_changed_rda(monkeypatch: pytest.MonkeyPatch, architecture: str) -> None:
    manager = Manager()

    def assignment() -> ailment.Stmt.Assignment:
        base = Register(manager.next_atom(), 16, 16)
        minus = BinaryOp(manager.next_atom(), "Sub", (base, Const(manager.next_atom(), 2, 16)), False, bits=16)
        expression = BinaryOp(manager.next_atom(), "Add", (minus, Const(manager.next_atom(), 2, 16)), False, bits=16)
        return ailment.Stmt.Assignment(0, Register(manager.next_atom(), 24, 16), expression)

    block = ailment.Block(0x1000, 1, statements=[assignment()])
    graph = nx.DiGraph()
    graph.add_node(block)
    receiver = SimpleNamespace(
        project=SimpleNamespace(arch=SimpleNamespace(name=architecture)),
        _ail_graph=graph, _ail_manager=manager, reaching_definitions="old",
    )
    calls = []

    def original(clinic: Clinic) -> None:
        calls.append(clinic)
        assert isinstance(block.statements[0].src, Register if architecture == "86_16" else BinaryOp)
        block.statements = [assignment()]
        receiver.reaching_definitions = "native"

    monkeypatch.setattr(Clinic, "_stage_post_ssa_level1_simplifications", original)
    apply_register_displacement_compatibility_8616()
    installed = Clinic._stage_post_ssa_level1_simplifications
    apply_register_displacement_compatibility_8616()
    assert Clinic._stage_post_ssa_level1_simplifications is installed
    installed(cast(Clinic, receiver))
    assert calls == [receiver]
    if architecture == "86_16":
        assert isinstance(block.statements[0].src, Register)
        assert receiver.reaching_definitions is None
        assert [report.materialized_count for report in receiver._inertia_register_displacement_reports_8616] == [1, 1]
    else:
        assert isinstance(block.statements[0].src, BinaryOp)
        assert receiver.reaching_definitions == "native"
