from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CUnaryOp
from angr.sim_type import SimTypeInt
from inertia.postprocess.decompiler_postprocess_stage import _repair_missing_cnode_codegen_metadata_8616
from inertia.postprocess.decompiler_postprocess_utils import _c_constant_value_8616

from inertia.postprocess.optimization.const_prop import _constant_propagation_8616


class _FakeCodegen:
    const_formats = {}  # noqa: RUF012

    def __init__(self):
        self._next_idx = 0
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _const(value: int, codegen):
    return CConstant(int(value), SimTypeInt(signed=False), codegen=codegen)


def test_constant_propagation_preserves_codegen_on_folded_binary_constants():
    codegen = _FakeCodegen()
    expr = CBinaryOp("Add", _const(1, codegen), _const(2, codegen), codegen=codegen)

    assert _constant_propagation_8616([expr], codegen=codegen) is True

    assert _c_constant_value_8616(expr.lhs) == 3
    assert _c_constant_value_8616(expr.rhs) == 0
    assert expr.lhs.codegen is codegen
    assert expr.rhs.codegen is codegen


def test_constant_propagation_preserves_codegen_on_folded_unary_constants():
    codegen = _FakeCodegen()
    expr = CUnaryOp("Not", _const(0, codegen), codegen=codegen)

    assert _constant_propagation_8616([expr], codegen=codegen) is True

    assert _c_constant_value_8616(expr.operand) == 1
    assert expr.operand.codegen is codegen


def test_codegen_metadata_repair_restores_missing_child_codegen():
    codegen = _FakeCodegen()
    expr = CBinaryOp("CmpNE", _const(1, codegen), _const(2, codegen), codegen=codegen)
    expr.lhs.codegen = None

    assert _repair_missing_cnode_codegen_metadata_8616(expr, codegen) == 1

    assert expr.lhs.codegen is codegen
    assert codegen._inertia_codegen_metadata_repaired == 1
