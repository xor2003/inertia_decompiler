"""Tests for Structuring-owned stored call-return early exits."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.semantics.callsite_summary import (
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
)
from inertia.ir.condition_ir import ConditionIR, ConditionRegisterBindingIR
from inertia.ir.core import IRValue, MemSpace
import inertia.structuring.stored_call_return_early_exit as stored_early_exit
import inertia.structuring.stored_call_return_operands as stored_operands
from archinfo import ArchX86

from inertia.structuring.stored_call_return_early_exit import (
    StoredCallReturnEarlyExitStatus8616,
    materialize_stored_call_return_early_exit_8616,
)

JCC_ADDR = 0x1021
BLOCK_ADDR = 0x1019
SUCCESS_TARGET = 0x1025
ERROR_TARGET = 0x1023


def _summary() -> CallsiteSummary8616:
    """Build exact call-return-to-stack evidence."""
    return CallsiteSummary8616(
        callsite_addr=0x1016,
        target_addr=0x2000,
        return_addr=BLOCK_ADDR,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register="ax",
        return_used=True,
        return_store_destination=("bp", -2),
        return_store_width=2,
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
    )


def _typed_condition() -> ConditionIR:
    """Build the taken-on-zero condition after exact stack-store projection."""
    stored_return = IRValue(MemSpace.SS, name="bp", offset=-2, size=2)
    return ConditionIR(
        op="zero",
        lhs=stored_return,
        width_bits=16,
        src_insn=JCC_ADDR,
        block_addr=BLOCK_ADDR,
        taken_target=SUCCESS_TARGET,
        fallthrough_target=ERROR_TARGET,
        register_bindings=(
            ConditionRegisterBindingIR(register_name="ax", value=stored_return),
        ),
    )


def _surface() -> tuple[SimpleNamespace, SimpleNamespace, CIfElse, CAssignment]:
    """Build an error early-exit with a side-effectful continuation."""
    project = SimpleNamespace(arch=ArchX86())
    codegen = SimpleNamespace(next_idx=lambda _name: 1, cstyle_null_cmp=False, project=project, next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    err = CVariable(
        SimStackVariable(-2, 2, base="bp", name="err"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    condition = CBinaryOp(
        "CmpNE",
        err,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": JCC_ADDR, "vex_block_addr": BLOCK_ADDR},
    )
    true_return = CReturn(None, codegen=codegen)
    side_effect = CAssignment(
        CVariable(SimStackVariable(-4, 2, base="bp"), codegen=codegen),
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    branch = CIfElse(
        [(condition, CStatements([true_return], codegen=codegen))],
        else_node=CStatements(
            [CStatements([side_effect], codegen=codegen), CStatements([CReturn(None, codegen=codegen)], codegen=codegen)],
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=CStatements([branch], codegen=codegen))
    codegen._inertia_typed_conditions = (_typed_condition(),)
    summary = _summary()
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}
    return project, codegen, branch, side_effect


def test_materializes_both_returns_and_preserves_success_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    project, codegen, branch, side_effect = _surface()
    targets: list[int] = []

    def recover(_project: object, actual_codegen: object, target: int) -> CVariable | CConstant | None:
        targets.append(target)
        assert actual_codegen is codegen
        if target == ERROR_TARGET:
            return None
        assert target == SUCCESS_TARGET
        return CConstant(0, SimTypeShort(False), codegen=codegen)

    monkeypatch.setattr(
        "inertia.structuring.stored_call_return_early_exit.recover_branch_target_return_expression_8616",
        recover,
    )
    monkeypatch.setattr(
        "inertia.structuring.stored_call_return_early_exit.branch_target_preserves_return_registers_8616",
        lambda *_args: True,
    )

    result = materialize_stored_call_return_early_exit_8616(project, codegen)

    assert result.status is StoredCallReturnEarlyExitStatus8616.MATERIALIZED
    assert result.changed is True
    assert result.evidence.raw_fact_count == result.evidence.materialized_count == 1
    assert result.evidence.failure_count == 0
    assert targets == [ERROR_TARGET, SUCCESS_TARGET]
    assert branch.else_node is None
    statements = tuple(codegen.cfunc.statements.statements)
    assert statements[0] is branch
    assert side_effect in tuple(statements[1].statements)
    true_return = branch.condition_and_nodes[0][1].statements[0]
    assert isinstance(true_return.retval, CVariable)
    final_return = statements[2].statements[0]
    assert isinstance(final_return.retval, CConstant)
    assert final_return.retval.value == 0

    repeated = materialize_stored_call_return_early_exit_8616(project, codegen)

    assert repeated.status is StoredCallReturnEarlyExitStatus8616.ALREADY_MATERIALIZED
    assert repeated.changed is False
    assert tuple(codegen.cfunc.statements.statements) == statements


def test_stored_operand_uses_machine_bp_projection_over_stale_register_ast(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, codegen, _branch, _side_effect = _surface()
    candidate = stored_early_exit._matching_candidate_8616(
        project,
        codegen,
        codegen.cfunc.statements,
    )
    assert candidate is not None
    _candidate_branch, condition, evidence = candidate
    expected = condition.lhs
    condition.lhs = CVariable(SimRegisterVariable(8, 2), codegen=codegen)

    monkeypatch.setattr(
        stored_operands,
        "stack_cvar_for_machine_bp_range_8616",
        lambda actual_codegen, offset, size: (
            expected
            if actual_codegen is codegen and (offset, size) == (-2, 2)
            else None
        ),
    )

    assert stored_operands.stored_return_operand_8616(
        condition,
        evidence,
        project,
        codegen,
    ) is expected


def test_materializes_cfg_proven_returns_missing_from_flattened_branch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, codegen, branch, side_effect = _surface()
    err = branch.condition_and_nodes[0][0].lhs
    branch.condition_and_nodes[0][1].statements = []
    branch.else_node = None
    codegen.cfunc.statements.statements = [
        branch,
        CStatements([side_effect], codegen=codegen),
    ]

    def recover(_project: object, actual_codegen: object, target: int) -> CVariable | CConstant | None:
        assert actual_codegen is codegen
        if target == ERROR_TARGET:
            return None
        assert target == SUCCESS_TARGET
        return CConstant(0, SimTypeShort(False), codegen=codegen)

    monkeypatch.setattr(
        "inertia.structuring.stored_call_return_early_exit.recover_branch_target_return_expression_8616",
        recover,
    )
    monkeypatch.setattr(
        "inertia.structuring.stored_call_return_early_exit.branch_target_preserves_return_registers_8616",
        lambda *_args: True,
    )

    result = materialize_stored_call_return_early_exit_8616(project, codegen)

    assert result.status is StoredCallReturnEarlyExitStatus8616.MATERIALIZED
    assert result.evidence.failure_count == 0
    true_return = branch.condition_and_nodes[0][1].statements[0]
    assert isinstance(true_return, CReturn)
    assert true_return.retval is err
    statements = tuple(codegen.cfunc.statements.statements)
    assert side_effect in tuple(statements[1].statements)
    assert isinstance(statements[2], CReturn)
    assert isinstance(statements[2].retval, CConstant)
    assert statements[2].retval.value == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda _project, codegen, _branch: setattr(
            codegen,
            "_inertia_typed_conditions",
            (replace(_typed_condition(), taken_target=None),),
        ),
        lambda _project, codegen, _branch: setattr(
            codegen,
            "_inertia_typed_conditions",
            (replace(_typed_condition(), fallthrough_target=None),),
        ),
        lambda _project, codegen, _branch: setattr(
            codegen,
            "_inertia_typed_conditions",
            (replace(_typed_condition(), register_bindings=()),),
        ),
        lambda _project, codegen, _branch: setattr(
            codegen,
            "_inertia_callsite_summary_inventory_8616",
            {0x1016: replace(_summary(), return_store_destination=None)},
        ),
        lambda _project, _codegen, branch: setattr(branch.condition_and_nodes[0][0], "op", "CmpEQ"),
        lambda _project, _codegen, branch: setattr(
            branch.condition_and_nodes[0][1].statements[0],
            "retval",
            CConstant(9, SimTypeShort(False), codegen=branch.codegen),
        ),
    ],
)
def test_refuses_incomplete_or_conflicting_evidence(
    monkeypatch: pytest.MonkeyPatch,
    mutate: object,
) -> None:
    project, codegen, branch, _side_effect = _surface()
    mutate(project, codegen, branch)
    err = branch.condition_and_nodes[0][0].lhs

    def recover(_project: object, _codegen: object, target: int) -> CVariable | CConstant:
        if target == ERROR_TARGET:
            return err
        return CConstant(0, SimTypeShort(False), codegen=codegen)

    monkeypatch.setattr(
        "inertia.structuring.stored_call_return_early_exit.recover_branch_target_return_expression_8616",
        recover,
    )
    monkeypatch.setattr(
        "inertia.structuring.stored_call_return_early_exit.branch_target_preserves_return_registers_8616",
        lambda *_args: True,
    )

    result = materialize_stored_call_return_early_exit_8616(project, codegen)

    assert result.status in {
        StoredCallReturnEarlyExitStatus8616.NOT_APPLICABLE,
        StoredCallReturnEarlyExitStatus8616.REFUSED,
    }
    assert branch.else_node is not None
    assert branch.condition_and_nodes[0][1].statements[0].retval is None or branch.condition_and_nodes[0][1].statements[0].retval.value == 9
