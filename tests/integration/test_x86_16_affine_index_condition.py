from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CFunctionCall
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.postprocess.decompiler_postprocess_typed_conditions import _build_c_expr_for_operand
from inertia.ir.core import (
    IRBinaryValue,
    IRValue,
    MemSpace,
)


class _Codegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self._index = 0

    def next_idx(self, _name: str) -> int:
        self._index += 1
        return self._index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _shellsort_indexed_byte() -> IRValue:
    row = IRValue(MemSpace.SS, name="bp", offset=-4, size=2)
    gap = IRValue(MemSpace.SS, name="bp", offset=-2, size=2)
    return IRValue(
        MemSpace.DS,
        offset=0xB4A,
        size=1,
        index=IRBinaryValue("add", row, gap, size=2),
        index_shift=1,
        memory_access_size=1,
        memory_access_insn=0x1050,
    )


def test_affine_index_materializes_both_stack_slots_before_scale() -> None:
    codegen = _Codegen()
    expression = _build_c_expr_for_operand(codegen.project, _shellsort_indexed_byte(), codegen)

    assert isinstance(expression, CFunctionCall)
    assert expression.callee_target == "SEG_U8"
    indexed_offset = expression.args[1]
    assert isinstance(indexed_offset, CBinaryOp)
    assert indexed_offset.op == "Add"
    assert indexed_offset.lhs.value == 0xB4A
    scaled_index = indexed_offset.rhs
    assert isinstance(scaled_index, CBinaryOp)
    assert scaled_index.op == "Shl"
    affine_index = scaled_index.lhs
    assert isinstance(affine_index, CBinaryOp)
    assert affine_index.op == "Add"
    assert affine_index.lhs.variable.name == "local_4"
    assert affine_index.rhs.variable.name == "local_2"
    assert scaled_index.rhs.value == 1
