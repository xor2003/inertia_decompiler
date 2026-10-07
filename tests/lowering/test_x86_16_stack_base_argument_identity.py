"""Regress exact stack-base projections into typed BP arguments."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CFakeVariable,
    CIndexedVariable,
    CReturn,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeBottom, SimTypePointer, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.stack_argument_identity import (
    unify_positive_bp_argument_identity_8616,
)


def _codegen() -> SimpleNamespace:
    arch = Arch86_16()
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=arch),
        next_idx=lambda _name: 1,
        next_ident=lambda name: name,
        next_node_idx=lambda: 1,
    )
    word_type = SimTypeShort(True).with_arch(arch)
    arguments = [
        CVariable(
            SimStackVariable(offset, 2, base="bp", name=name, region=0x1000),
            variable_type=word_type,
            codegen=codegen,
        )
        for offset, name in ((4, "x"), (6, "y"))
    ]
    stack_base = CFakeVariable(
        "stack_base",
        SimTypePointer(SimTypeBottom()).with_arch(arch),
        codegen=codegen,
    )
    indexed = CIndexedVariable(
        stack_base,
        CConstant(4, word_type, codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=arguments,
        statements=CStatements([CReturn(indexed, codegen=codegen)], codegen=codegen),
        variables_in_use={argument.variable: argument for argument in arguments},
        unified_local_vars={},
    )
    return codegen


def test_stack_base_index_at_exact_argument_offset_uses_typed_argument() -> None:
    codegen = _codegen()

    assert unify_positive_bp_argument_identity_8616(codegen) is True

    returned = codegen.cfunc.statements.statements[0].retval
    assert isinstance(returned, CVariable)
    assert returned.variable is codegen.cfunc.arg_list[0].variable
    stats = codegen._inertia_arg_stack_identity_stats_8616
    assert stats.classified_fact_count == stats.materialized_count == 1
    assert stats.failure_count == 0


def test_stack_base_index_without_exact_argument_remains_unresolved() -> None:
    codegen = _codegen()
    codegen.cfunc.statements.statements[0].retval.index.value = 8

    assert unify_positive_bp_argument_identity_8616(codegen) is False

    returned = codegen.cfunc.statements.statements[0].retval
    assert isinstance(returned, CIndexedVariable)
    stats = codegen._inertia_arg_stack_identity_stats_8616
    assert stats.raw_fact_count == stats.normalized_fact_count == 1
    assert stats.classified_fact_count == stats.materialized_count == 0
