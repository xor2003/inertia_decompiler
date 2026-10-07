from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from inertia.postprocess.optimization.dce import (
    _dead_code_elimination_8616,
)


class _FakeCodegen(SimpleNamespace):
    def __init__(self) -> None:
        super().__init__()
        self._next = 0
        self.cfunc = SimpleNamespace()
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=archinfo.ArchX86())

    def next_idx(self, _kind: str) -> int:
        self._next += 1
        return self._next

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _variable(codegen: _FakeCodegen, name: str, offset: int) -> structured_c.CVariable:
    return structured_c.CVariable(
        SimRegisterVariable(offset, 2, name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _constant(codegen: _FakeCodegen, value: int) -> structured_c.CConstant:
    return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)


def test_dce_removes_pure_empty_if_else_and_its_dead_condition_chain() -> None:
    codegen = _FakeCodegen()
    condition = _variable(codegen, "flag_condition", 0)
    arm_value = _variable(codegen, "flag_arm_value", 2)
    seed = structured_c.CAssignment(
        condition,
        structured_c.CBinaryOp(
            "And",
            _constant(codegen, 7),
            _constant(codegen, 1),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    branch = structured_c.CIfElse(
        [
            (
                condition,
                structured_c.CStatements(
                    [structured_c.CAssignment(arm_value, _constant(codegen, 1), codegen=codegen)],
                    codegen=codegen,
                ),
            )
        ],
        else_node=structured_c.CStatements(
            [structured_c.CAssignment(arm_value, _constant(codegen, 1), codegen=codegen)],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([seed, branch], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert tuple(codegen.cfunc.statements.statements) == ()
    stats = codegen._inertia_dce_noop_conditional_prune_stats_8616
    assert stats.raw_fact_count == stats.normalized_fact_count == 1
    assert stats.classified_fact_count == stats.materialized_count == 1
    assert stats.failure_count == stats.refused_count == 0
    assert stats.closed


def test_dce_refuses_empty_if_else_with_effectful_condition() -> None:
    codegen = _FakeCodegen()
    condition = structured_c.CFunctionCall("unknown_condition", None, [], codegen=codegen)
    branch = structured_c.CIfElse(
        [(condition, structured_c.CStatements([], codegen=codegen))],
        else_node=structured_c.CStatements([], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([branch], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert tuple(codegen.cfunc.statements.statements) == (branch,)
    stats = codegen._inertia_dce_noop_conditional_prune_stats_8616
    assert stats.raw_fact_count == stats.normalized_fact_count == 1
    assert stats.classified_fact_count == stats.materialized_count == 0
    assert stats.failure_count == 0
    assert stats.refused_count == 1
    assert stats.closed
