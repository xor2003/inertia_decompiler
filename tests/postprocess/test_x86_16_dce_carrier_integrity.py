"""Regression tests for conservative X86-16 DCE carrier liveness."""

from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort

from inertia.postprocess.optimization.dce import (
    _dead_code_elimination_8616,
)


class _FakeCodegen(SimpleNamespace):
    def __init__(self) -> None:
        super().__init__()
        self._next = 0
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        self._next += 1
        return self._next

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _dirty(codegen: _FakeCodegen, varid: int) -> structured_c.CDirtyExpression:
    return structured_c.CDirtyExpression(
        SimpleNamespace(varid=varid, idx=varid, name=f"tmp_{varid}", bits=16),
        codegen=codegen,
    )


def test_storage_free_dirty_dce_keeps_producer_read_by_retained_consumer() -> None:
    codegen = _FakeCodegen()
    producer = _dirty(codegen, 66)
    consumer = _dirty(codegen, 85)
    producer_assignment = structured_c.CAssignment(
        producer,
        structured_c.CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    consumer_assignment = structured_c.CAssignment(
        consumer,
        structured_c.CBinaryOp(
            "Add",
            producer,
            structured_c.CFunctionCall("effectful_helper", None, (), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    statements = structured_c.CStatements(
        [producer_assignment, consumer_assignment],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=statements)
    codegen._inertia_dce_allow_storage_free_dirty_8616 = True
    codegen._inertia_dce_allow_dirty_value_reads_8616 = True

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert list(statements.statements) == [producer_assignment, consumer_assignment]
