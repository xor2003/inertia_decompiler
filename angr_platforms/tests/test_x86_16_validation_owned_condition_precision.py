"""Contextual predicates consume the same exact precision proof as final validation."""

from copy import copy
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.tail_validation import _clear_tail_validation_expr_fingerprint_cache_8616
from angr_platforms.X86_16.tail_validation_condition_context import (
    _owned_materialized_condition_fingerprint_8616,
)
from angr_platforms.X86_16.tail_validation_fingerprint import _expr_fingerprint
from angr_platforms.X86_16.validation_condition_precision import (
    ConditionPrecisionEvidence8616,
    condition_precision_token_8616,
)


def _surface():
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(
        project=project, next_idx=lambda _name: 1, next_node_idx=lambda: 1,
        next_ident=lambda name: name, cstyle_null_cmp=False,
    )
    value = CVariable(SimRegisterVariable(0, 2, name="ax"), codegen=codegen)
    condition = CBinaryOp(
        "CmpEQ", value, CConstant(27, SimTypeShort(False), codegen=codegen),
        codegen=codegen, tags={"typed_condition": True, "ins_addr": 0x1010},
    )
    actual = _expr_fingerprint(condition, project)
    evidence = ConditionPrecisionEvidence8616(
        "CmpNE(reg:ax,const:27)", condition_precision_token_8616(actual), 0x1010,
    )
    codegen._inertia_condition_precision_evidence_8616 = (evidence,)
    project._inertia_tail_validation_active_codegen = codegen
    return project, codegen, condition, actual, evidence


@pytest.mark.parametrize("clone", (False, True))
def test_context_uses_exact_register_condition_precision(clone):
    project, _codegen, condition, actual, _evidence = _surface()
    if clone:
        condition = copy(condition)
    assert _owned_materialized_condition_fingerprint_8616(condition, project) == actual


@pytest.mark.parametrize("corruption", ("constant", "operator", "jcc", "missing", "conflict"))
def test_context_refuses_stale_or_conflicting_register_condition_precision(corruption):
    project, codegen, condition, _actual, evidence = _surface()
    if corruption == "constant":
        condition.rhs = CConstant(28, SimTypeShort(False), codegen=codegen)
    elif corruption == "operator":
        condition.op = "CmpNE"
    elif corruption == "jcc":
        condition.tags = {**condition.tags, "ins_addr": 0x1020}
    elif corruption == "missing":
        codegen._inertia_condition_precision_evidence_8616 = ()
    else:
        codegen._inertia_condition_precision_evidence_8616 = (
            evidence, ConditionPrecisionEvidence8616("before", "CmpEQ(reg:ax,const:28)", 0x1010),
        )
    _clear_tail_validation_expr_fingerprint_cache_8616(project)
    assert _owned_materialized_condition_fingerprint_8616(condition, project) is None
