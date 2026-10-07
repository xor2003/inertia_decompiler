"""Tests for typed caller-cleanup carrier pruning."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CStatements,
    CVariable,
)
from angr.sim_variable import SimStackVariable
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.lowering.call_cleanup_carriers import (
    prune_consumed_call_cleanup_carriers_8616,
)
from archinfo import ArchX86
from capstone.x86_const import (
    X86_INS_ADD,
    X86_OP_IMM,
    X86_OP_REG,
    X86_REG_SP,
)


def _summary() -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x10BE5,
        target_addr=0x1075B,
        return_addr=0x10BE8,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=False,
        push_arg_instruction_addrs=(0x10BDF, 0x10BE2),
        stack_cleanup_instruction_addr=0x10BE8,
    )


def _surface(*, cleanup_amount: int = 4) -> tuple[object, object, CStatements, CAssignment]:
    instruction = SimpleNamespace(
        address=0x10BE8,
        id=X86_INS_ADD,
        operands=(
            SimpleNamespace(type=X86_OP_REG, reg=X86_REG_SP),
            SimpleNamespace(type=X86_OP_IMM, imm=cleanup_amount),
        ),
    )
    block = SimpleNamespace(
        capstone=SimpleNamespace(insns=(instruction,)),
    )
    project = SimpleNamespace(
        arch=ArchX86(),
        factory=SimpleNamespace(
            block=lambda _address, **_kwargs: block,
        ),
    )
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=project,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    local = CVariable(
        SimStackVariable(-8, 2, base="bp", name="saved_di"),
        codegen=codegen,
    )
    assignment = CAssignment(
        local,
        local,
        codegen=codegen,
        tags={"ins_addr": 0x10BE8},
    )
    root = CStatements([assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_consumed_call_cleanup_carrier_ins_addrs_8616 = frozenset(
        {0x10BE8}
    )
    codegen._inertia_callsite_summary_inventory_8616 = {0x10BE5: _summary()}
    return project, codegen, root, assignment


def test_prunes_pure_stack_assignment_for_exact_consumed_cleanup() -> None:
    project, codegen, root, _assignment = _surface()

    assert prune_consumed_call_cleanup_carriers_8616(project, codegen)
    assert root.statements == []
    stats = codegen._inertia_call_cleanup_carrier_prune_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_refuses_cleanup_carrier_when_instruction_amount_disagrees() -> None:
    project, codegen, root, assignment = _surface(cleanup_amount=2)

    assert not prune_consumed_call_cleanup_carriers_8616(project, codegen)
    assert root.statements == [assignment]
    stats = codegen._inertia_call_cleanup_carrier_prune_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 0
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1


def test_prunes_when_cleanup_provenance_is_on_nested_expression() -> None:
    project, codegen, root, assignment = _surface()
    assignment.tags = {}
    assignment.rhs.tags = {"ins_addr": 0x10BE8}

    assert prune_consumed_call_cleanup_carriers_8616(project, codegen)
    assert root.statements == []


def test_refuses_nested_cleanup_mixed_with_unrelated_provenance() -> None:
    project, codegen, root, assignment = _surface()
    assignment.tags = {}
    assignment.lhs.tags = {"ins_addr": 0x10BE8}
    assignment.rhs = CVariable(
        SimStackVariable(-6, 2, base="bp", name="foreign"),
        codegen=codegen,
        tags={"ins_addr": 0x1234},
    )

    assert not prune_consumed_call_cleanup_carriers_8616(project, codegen)
    assert root.statements == [assignment]
