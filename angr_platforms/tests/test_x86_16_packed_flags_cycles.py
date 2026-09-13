"""Closed packed-FLAGS cycles must not become artificial runtime inputs."""

from copy import copy
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.structuring.condition_materialization import (
    prune_dead_flag_assignments_after_structuring_8616,
)
from test_x86_16_packed_flags_state import _Codegen


@pytest.mark.parametrize("consumer", ("none", "return", "guard"))
@pytest.mark.parametrize("evidence", (None, False, True))
@pytest.mark.parametrize("has_comparison", (False, True))
def test_loop_flag_cycle_is_removed_only_without_an_external_consumer(consumer, evidence, has_comparison):
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    flags = c.CVariable(
        SimRegisterVariable(36, 2, ident="ir_flags", region=0x100),
        variable_type=SimTypeShort(False), codegen=codegen,
    )
    constant = c.CConstant(0xFFFE, SimTypeShort(False), codegen=codegen)
    rhs = c.CBinaryOp("And", copy(flags), constant, codegen=codegen)
    if has_comparison:
        predicate = c.CBinaryOp("CmpEQ", copy(flags), constant, codegen=codegen)
        rhs = c.CBinaryOp("Or", rhs, predicate, codegen=codegen)
    update = c.CAssignment(flags, rhs, codegen=codegen)
    body = c.CStatements([update], codegen=codegen)
    guard = c.CVariable(
        SimRegisterVariable(codegen.project.arch.registers["ax"][0], 2, ident="loop_guard", region=0x100),
        variable_type=SimTypeShort(False), codegen=codegen,
    )
    loop = c.CWhileLoop(copy(flags) if consumer == "guard" else guard, body, codegen=codegen)
    result = c.CReturn(copy(flags) if consumer == "return" else constant, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x100, statements=c.CStatements([loop, result], codegen=codegen))
    if evidence is not None:
        codegen._inertia_structuring_condition_materialization_result_8616 = SimpleNamespace(
            condition_evidence_complete=evidence,
        )

    prune_dead_flag_assignments_after_structuring_8616(codegen.project, codegen)

    retained = consumer != "none" or evidence is not True
    assert body.statements == ([update] if retained else [])
    stats = codegen._inertia_packed_flags_cycle_stats_8616
    assert stats.materialized_count == int(not retained)
    assert stats.failure_count == int(evidence is not True)
