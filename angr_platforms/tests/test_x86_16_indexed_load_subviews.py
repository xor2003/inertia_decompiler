from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CVariable
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.indexed_load_subviews import (
    project_indexed_load_subview_8616,
    project_word_load_index_8616,
)
from angr_platforms.X86_16.lowering.real_mode_linear import RealModeLinearGlobalAddress8616
from angr_platforms.X86_16.lowering.segmented_global_loads import (
    IndexedSegmentedGlobalEvidence8616,
    IndexedSegmentedGlobalLoadSiteEvidence8616,
    _indexed_global_load_from_site_evidence_8616,
)
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from test_x86_16_segmented_global_loads import _const, _deref, _dirty, _DummyCodegen, _stack

_BYTE_MASK = 0xFF
_BYTE_BITS = 8
_WORD_BYTES = 2


class _Codegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self._node_index = 0

    def next_node_idx(self) -> int:
        self._node_index += 1
        return self._node_index

    def next_ident(self, name: str) -> str:
        return name


@pytest.mark.parametrize("source_type", [None, SimTypeBottom(), SimTypePointer(SimTypeShort()), SimTypeChar(False)])
def test_word_index_refuses_unknown_noninteger_or_narrow_type(source_type) -> None:
    """Physical word storage alone cannot prove its emitted C value width."""
    codegen = _DummyCodegen()
    index = _stack(-4, codegen, name="index")
    index.variable_type = source_type
    assert project_word_load_index_8616(index, _WORD_BYTES) is None


@pytest.mark.parametrize("signed", [False, True])
@pytest.mark.parametrize("storage_width", [1, 2, 4])
def test_raw_load_site_consumes_index_width_and_unsigned_view(signed: bool, storage_width: int) -> None:
    """A word-index fact cannot silently consume a byte or dword declaration."""
    codegen = _DummyCodegen()
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))
    index = _stack(-4, codegen, name="index")
    index.variable.size = storage_width
    index.variable_type = SimTypeShort(signed)
    codegen.cfunc = SimpleNamespace(addr=0x1050, variables_in_use={index.variable: index})
    pointer = CBinaryOp("Add", _dirty(11, codegen), _const(0, codegen), codegen=codegen,
                        tags={"ins_addr": 0x1057})
    site = IndexedSegmentedGlobalLoadSiteEvidence8616(0x42, 1, -4, 1, 0x1057)
    result = _indexed_global_load_from_site_evidence_8616(
        project, codegen, _deref(pointer, codegen),
        {(0x42, 1): IndexedSegmentedGlobalEvidence8616(0x42, "g_work", 0, 1)},
        {site.ins_addr: site}, copies=None,
    )
    if storage_width != site.index_stack_width:
        assert result is None
        return
    assert result is not None
    projected_index = result.variable.index
    if signed:
        assert isinstance(projected_index, CSemanticCast8616)
        assert projected_index.dst_type.signed is False
        assert projected_index.expr is index
    else:
        assert projected_index is index


def _value(codegen: _Codegen, *, width: int) -> CVariable:
    variable_type = SimTypeChar(False) if width == 1 else SimTypeShort(False)
    return CVariable(
        SimMemoryVariable(0x222, width, name="words"),
        variable_type=variable_type,
        codegen=codegen,
    )


def test_indexed_load_subview_projects_high_byte_from_binary_word_site() -> None:
    codegen = _Codegen()
    full_value = _value(codegen, width=2)
    access_node = _value(codegen, width=1)
    access = RealModeLinearGlobalAddress8616("ds", 0x223, (), width=1)

    projection = project_indexed_load_subview_8616(
        codegen,
        access_node,
        full_value,
        access,
        site_base_offset=0x222,
        site_width=2,
    )

    assert projection is not None
    assert projection.byte_offset == 1
    assert projection.access_width == 1
    assert isinstance(projection.expression, CBinaryOp)
    assert projection.expression.op == "And"
    assert projection.expression.rhs.value == _BYTE_MASK
    assert isinstance(projection.expression.lhs, CBinaryOp)
    assert projection.expression.lhs.op == "Shr"
    assert projection.expression.lhs.lhs is full_value
    assert projection.expression.lhs.rhs.value == _BYTE_BITS


def test_indexed_load_subview_keeps_exact_full_width_value() -> None:
    codegen = _Codegen()
    full_value = _value(codegen, width=2)

    projection = project_indexed_load_subview_8616(
        codegen,
        full_value,
        full_value,
        None,
        site_base_offset=0x222,
        site_width=2,
    )

    assert projection is not None
    assert projection.expression is full_value
    assert projection.byte_offset == 0
    assert projection.access_width == _WORD_BYTES


def test_indexed_load_subview_accepts_untyped_single_byte_site() -> None:
    """A one-byte binary site has no ambiguous narrower lane to project."""
    codegen = _Codegen()
    full_value = _value(codegen, width=1)

    projection = project_indexed_load_subview_8616(
        codegen,
        object(),
        full_value,
        None,
        site_base_offset=0x222,
        site_width=1,
    )

    assert projection is not None
    assert projection.expression is full_value
    assert projection.byte_offset == 0
    assert projection.access_width == 1


def test_indexed_load_subview_refuses_wrong_segment_or_out_of_range_lane() -> None:
    codegen = _Codegen()
    full_value = _value(codegen, width=2)
    access_node = _value(codegen, width=1)

    for access in (
        RealModeLinearGlobalAddress8616("es", 0x222, (), width=1),
        RealModeLinearGlobalAddress8616("ds", 0x224, (), width=1),
    ):
        assert (
            project_indexed_load_subview_8616(
                codegen,
                access_node,
                full_value,
                access,
                site_base_offset=0x222,
                site_width=2,
            )
            is None
        )
