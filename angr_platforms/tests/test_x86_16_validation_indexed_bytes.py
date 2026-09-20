"""Exact byte stores define only covered bytes of an addressed stack scalar."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CIfElse,
    CIndexedVariable,
    CStatements,
    CUnaryOp,
)
from angr.sim_type import SimTypeChar, SimTypePointer
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from angr_platforms.X86_16.validation_dataflow import validate_structured_def_use_8616
from angr_platforms.X86_16.validation_indexed_bytes import indexed_scalar_byte_view_8616
from test_x86_16_validation_dataflow import _codegen, _const, _local


def _byte(local, index, codegen):
    pointer = SimTypePointer(SimTypeChar(False)).with_arch(codegen.project.arch)
    return CIndexedVariable(
        CSemanticCast8616(None, pointer, CUnaryOp("Reference", local, codegen=codegen), codegen=codegen),
        _const(index, codegen), codegen=codegen,
    )


@pytest.mark.parametrize("indices,passed", [((0, 1), True), ((1, 0), True),
    ((0,), False), ((1,), False), ((0, 0), False), ((0, 2), False), ((-1, 1), False)])
def test_indexed_byte_stores_require_complete_coverage(indices, passed):
    codegen = _codegen()
    local = _local(-4, codegen)
    stores = [CAssignment(_byte(local, index, codegen), _const(7, codegen), codegen=codegen) for index in indices]
    report = validate_structured_def_use_8616(CStatements([*stores, local], codegen=codegen))
    assert report.passed is passed
    assert report.raw_fact_count == 1
    assert report.materialized_count == int(passed)


def test_indexed_byte_definition_remains_conditional():
    codegen = _codegen()
    local = _local(-4, codegen)
    low = CAssignment(_byte(local, 0, codegen), _const(7, codegen), codegen=codegen)
    high = CAssignment(_byte(local, 1, codegen), _const(0, codegen), codegen=codegen)
    branch = CIfElse([(_const(1, codegen), CStatements([high], codegen=codegen))], codegen=codegen)
    report = validate_structured_def_use_8616(CStatements([low, branch, local], codegen=codegen))
    assert not report.passed


@pytest.mark.parametrize("read_index,passed", [(0, True), (1, False)])
def test_indexed_byte_read_uses_exact_covered_range(read_index, passed):
    codegen = _codegen()
    local = _local(-4, codegen)
    store = CAssignment(_byte(local, 0, codegen), _const(7, codegen), codegen=codegen)
    report = validate_structured_def_use_8616(
        CStatements([store, _byte(local, read_index, codegen)], codegen=codegen),
    )
    assert report.passed is passed
    assert report.raw_fact_count == 1


@pytest.mark.parametrize("index", [-1, True, 1.0])
def test_byte_view_refuses_non_exact_indices(index):
    codegen = _codegen()
    assert indexed_scalar_byte_view_8616(_byte(_local(-4, codegen), index, codegen)) is None


def test_byte_view_refuses_dynamic_index_and_indirect_pointer():
    codegen = _codegen()
    local = _local(-4, codegen)
    view = _byte(local, 0, codegen)
    view.index = local
    assert indexed_scalar_byte_view_8616(view) is None
    view.index = _const(0, codegen)
    view.variable.expr = local
    assert indexed_scalar_byte_view_8616(view) is None


def test_byte_store_does_not_define_another_stack_range():
    codegen = _codegen()
    local = _local(-4, codegen)
    stores = [CAssignment(_byte(local, index, codegen), _const(7, codegen), codegen=codegen) for index in (0, 1)]
    report = validate_structured_def_use_8616(CStatements([*stores, _local(-2, codegen)], codegen=codegen))
    assert not report.passed
