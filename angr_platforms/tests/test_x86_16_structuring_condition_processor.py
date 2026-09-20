from __future__ import annotations

from types import SimpleNamespace

import archinfo
import claripy
import pytest
from angr import ailment
from angr.ailment.manager import Manager
from angr.analyses.decompiler.condition_processor import ConditionProcessor
from angr_platforms.X86_16.decompiler_structuring_stage import (
    _guard_condition_processor_multibit_bool_predicates_8616,
)


def test_condition_processor_multibit_must_bool_becomes_nonzero_bool_predicate():
    project = SimpleNamespace()
    arch = archinfo.ArchX86()
    reg = ailment.Expr.Register(None, 0, 16)

    with _guard_condition_processor_multibit_bool_predicates_8616(project):
        processor = ConditionProcessor(arch, Manager(arch=arch))
        predicate = processor.claripy_ast_from_ail_condition(reg, must_bool=True, ins_addr=0x4010)

    assert isinstance(predicate, claripy.ast.Bool)
    assert getattr(project, "_inertia_condition_predicate_multibit_bool_normalized", 0) == 1
    assert getattr(project, "_inertia_condition_predicate_multibit_bool_refused", 0) == 0


def test_equal_predicates_keep_distinct_branch_origins():
    arch = archinfo.ArchX86()
    processor = ConditionProcessor(arch, Manager(arch=arch))
    operands = (ailment.Expr.Tmp(None, 1, 16), ailment.Expr.Const(None, 40, 16))
    predicates = [
        ailment.Expr.BinaryOp(None, "CmpGT", operands, True, bits=1,
                              ins_addr=address, vex_block_addr=address - 3)
        for address in (0x4013, 0x4023)
    ]
    with _guard_condition_processor_multibit_bool_predicates_8616(SimpleNamespace()):
        symbolic = [processor.claripy_ast_from_ail_condition(value, must_bool=True,
                     ins_addr=value.tags["ins_addr"]) for value in predicates]
    recovered = [processor.convert_claripy_bool_ast(value) for value in symbolic]
    assert [value.tags["ins_addr"] for value in recovered] == [0x4013, 0x4023]
    solver = claripy.Solver()
    assert not solver.satisfiable(extra_constraints=[symbolic[0] != symbolic[1]])


@pytest.mark.parametrize("tags", [{}, {"ins_addr": 0x4013}, {"vex_block_addr": 0x4010}])
def test_incomplete_branch_origin_is_not_invented(tags):
    from angr_platforms.X86_16.structuring.symbolic_condition_origin import (
        preserve_symbolic_condition_origin_8616,
    )

    predicate = claripy.BoolS("unknown_origin")
    processor = SimpleNamespace(_ast2annotations={})
    assert preserve_symbolic_condition_origin_8616(processor, SimpleNamespace(tags=tags), predicate) is predicate
    assert not processor._ast2annotations


def test_ite_predicates_preserve_distinct_callsite_results():
    arch = archinfo.ArchX86()
    processor = ConditionProcessor(arch, Manager(arch=arch))
    const = ailment.Expr.Const
    predicates = []
    for address in (0x4010, 0x4020):
        call = ailment.Expr.Call(None, const(None, 0x2000, 32), args=(), bits=16, ins_addr=address)
        condition = ailment.Expr.BinaryOp(None, "CmpEQ", (call, const(None, 1, 16)), False, bits=1)
        predicates.append(ailment.Expr.ITE(None, condition, const(None, 0, 16), const(None, 1, 16)))
    with _guard_condition_processor_multibit_bool_predicates_8616(SimpleNamespace()):
        symbolic = [processor.claripy_ast_from_ail_condition(value, must_bool=True) for value in predicates]
    assert all(isinstance(value, claripy.ast.Bool) for value in symbolic)
    assert claripy.Solver().satisfiable(extra_constraints=[symbolic[0] != symbolic[1]])


@pytest.mark.parametrize("must_bool", [False, True])
def test_opaque_ite_roundtrip_preserves_source_and_reuses_identity(must_bool):
    arch = archinfo.ArchX86()
    processor = ConditionProcessor(arch, Manager(arch=arch))
    const = ailment.Expr.Const
    expression = ailment.Expr.ITE(None, const(None, 1, 16),
                                 const(None, 0x8000, 16), const(None, 0x100, 16))
    with _guard_condition_processor_multibit_bool_predicates_8616(SimpleNamespace()):
        value = processor.claripy_ast_from_ail_condition(expression, must_bool=must_bool)
        repeated = processor.claripy_ast_from_ail_condition(expression, must_bool=must_bool)
    assert repeated is value
    if not must_bool:
        assert value.size() == 16
    assert processor.convert_claripy_bool_ast(value) is expression
