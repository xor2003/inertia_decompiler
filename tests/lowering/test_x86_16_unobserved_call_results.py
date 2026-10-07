from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeInt, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.caller_return_use_contracts import CallsiteReturnUseKind8616
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.frontend.x86_16.interrupt_contract import interrupt_core_addr_8616
import inertia.lowering.unobserved_call_results as unobserved_module
from inertia.lowering.callsite_prototype_declarations import (
    CallsiteCResultContract8616,
    CallsiteCResultKind8616,
)
from inertia.lowering.unobserved_call_results import (
    lower_unobserved_call_result_assignments_8616,
)

from inertia.lowering.analysis_helpers import InterruptCall
from inertia.semantics.software_interrupt_inputs import (
    SoftwareInterruptInputArtifact8616,
    SoftwareInterruptInputFact8616,
)


def _call_result_codegen(
    *,
    return_used: bool,
    return_use_kind: CallsiteReturnUseKind8616 | None,
    return_register: str | None = "ax",
):
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        cstyle_null_cmp=False,
        next_idx=lambda _name: 0,
        next_ident=lambda name: name,
        next_node_idx=lambda: 0,
    )
    call = CFunctionCall(
        "callee",
        SimpleNamespace(addr=0x12000, prototype=None, prototype_libname=None),
        [],
        tags={"ins_addr": 0x10100},
        codegen=codegen,
    )
    carrier = CVariable(
        SimRegisterVariable(0, 4, name="eax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = CAssignment(carrier, call, codegen=codegen)
    root = CStatements([assignment], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x10100,
            target_addr=0x12000,
            return_addr=0x10103,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register=return_register,
            return_used=return_used,
            return_use_kind=return_use_kind,
        )
    }
    return codegen, root, call, assignment


def test_lowers_typed_clobbered_ax_result_to_standalone_call() -> None:
    codegen, root, call, assignment = _call_result_codegen(
        return_used=False,
        return_use_kind=CallsiteReturnUseKind8616.CLOBBERED,
    )

    assert lower_unobserved_call_result_assignments_8616(codegen) is True

    [statement] = root.statements
    assert isinstance(statement, CExpressionStatement)
    assert statement.expr is call
    assert statement is not assignment
    stats = codegen._inertia_unobserved_call_result_lowering_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert stats.closed is True


def test_refuses_call_result_without_clobbered_return_evidence() -> None:
    codegen, root, _call, assignment = _call_result_codegen(
        return_used=True,
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
    )

    assert lower_unobserved_call_result_assignments_8616(codegen) is False
    assert root.statements == [assignment]
    stats = codegen._inertia_unobserved_call_result_lowering_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0


def test_lowers_typed_unused_ax_assignment_at_void_exit() -> None:
    codegen, root, call, _assignment = _call_result_codegen(
        return_used=False,
        return_use_kind=None,
        return_register=None,
    )

    assert lower_unobserved_call_result_assignments_8616(codegen) is True
    [statement] = root.statements
    assert isinstance(statement, CExpressionStatement)
    assert statement.expr is call


def test_lowers_typed_clobbered_wide_projection_to_standalone_call() -> None:
    """A generated high-word projection cannot retain a clobbered call result."""
    codegen, root, call, assignment = _call_result_codegen(
        return_used=False,
        return_use_kind=CallsiteReturnUseKind8616.CLOBBERED,
    )
    assignment.rhs = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CUnaryOp("Reference", call, codegen=codegen),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    assert lower_unobserved_call_result_assignments_8616(codegen) is True
    [statement] = root.statements
    assert isinstance(statement, CExpressionStatement)
    assert statement.expr is call


@pytest.mark.parametrize("recognized_view", (True, False))
def test_lowers_typed_void_masked_subregister_projection(monkeypatch, recognized_view) -> None:
    """A void call cannot remain as the value operand of an angr byte merge."""
    codegen, root, call, assignment = _call_result_codegen(
        return_used=False,
        return_use_kind=CallsiteReturnUseKind8616.CLOBBERED,
    )
    call.callee_func.prototype = SimTypeFunction(
        [],
        SimTypeBottom(label="void"),
    ).with_arch(codegen.project.arch)
    assignment.lhs = CVariable(
        SimMemoryVariable(
            0x10008,
            4,
            name="inertia_eax",
            category="inertia_gp_register_state",
        ),
        variable_type=SimTypeInt(False),
        codegen=codegen,
    )
    preserved_carrier = CVariable(
        SimMemoryVariable(
            0x10008,
            4,
            name="inertia_eax",
            category="inertia_gp_register_state",
        ),
        variable_type=SimTypeInt(False),
        codegen=codegen,
    )
    assignment.rhs = CBinaryOp(
        "Or",
        CBinaryOp(
            "And",
            preserved_carrier,
            CConstant(0xFFFFFF00, SimTypeInt(False), codegen=codegen),
            codegen=codegen,
        ),
        CBinaryOp(
            "And",
            call,
            CConstant(0xFF, SimTypeInt(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    if not recognized_view:
        monkeypatch.setattr(unobserved_module, "physical_register_view_8616", lambda _node: None)
        monkeypatch.setattr(unobserved_module, "runtime_gp_expression_view_8616", lambda _node: None)
        assert lower_unobserved_call_result_assignments_8616(codegen) is False
        assert root.statements == [assignment]
    else:
        assert lower_unobserved_call_result_assignments_8616(codegen) is True
        [statement] = root.statements
        assert isinstance(statement, CExpressionStatement)
        assert statement.expr is call


def test_splits_clobbered_insert_base_call_from_retained_inserted_value() -> None:
    """A later subregister write retains its value without retaining the call result."""
    codegen, root, call, assignment = _call_result_codegen(
        return_used=False,
        return_use_kind=CallsiteReturnUseKind8616.CLOBBERED,
    )
    call.callee_func.prototype = SimTypeFunction(
        [],
        SimTypeInt(False),
    ).with_arch(codegen.project.arch)
    segment_value = CVariable(
        SimRegisterVariable(24, 2, name="ds"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment.rhs = CFunctionCall(
        "_INSERT",
        None,
        [
            call,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            segment_value,
        ],
        codegen=codegen,
    )

    assert lower_unobserved_call_result_assignments_8616(codegen) is True

    call_statement, residual_assignment = root.statements
    assert isinstance(call_statement, CExpressionStatement)
    assert call_statement.expr is call
    assert isinstance(residual_assignment, CAssignment)
    assert residual_assignment.lhs is assignment.lhs
    assert all(
        not isinstance(node, CFunctionCall)
        for node in (
            residual_assignment.rhs,
            *unobserved_module._iter_c_nodes_deep_8616(residual_assignment.rhs),
        )
    )
    stats = codegen._inertia_unobserved_call_result_lowering_stats_8616
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_refuses_insert_projection_with_a_second_effectful_call() -> None:
    """A projection split cannot reorder or discard another call operand."""
    codegen, root, call, assignment = _call_result_codegen(
        return_used=False,
        return_use_kind=CallsiteReturnUseKind8616.CLOBBERED,
    )
    second_call = CFunctionCall("other_effect", None, [], codegen=codegen)
    assignment.rhs = CFunctionCall(
        "_INSERT",
        None,
        [
            call,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            second_call,
        ],
        codegen=codegen,
    )

    assert lower_unobserved_call_result_assignments_8616(codegen) is False
    assert root.statements == [assignment]
    stats = codegen._inertia_unobserved_call_result_lowering_stats_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0


def test_keeps_used_wide_call_projection() -> None:
    """A caller-observed projected result remains intact."""
    codegen, root, call, assignment = _call_result_codegen(
        return_used=True,
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
    )
    assignment.rhs = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CUnaryOp("Reference", call, codegen=codegen),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    assert lower_unobserved_call_result_assignments_8616(codegen) is False
    assert root.statements == [assignment]


def test_lowers_typed_void_projection_without_summary_identity() -> None:
    """A cloned call may consume its explicit void contract after summary replay."""
    codegen, root, call, assignment = _call_result_codegen(
        return_used=True,
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
    )
    call.callee_func.prototype = SimTypeFunction(
        [],
        SimTypeBottom(label="void"),
    ).with_arch(codegen.project.arch)
    assignment.rhs = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CUnaryOp("Reference", call, codegen=codegen),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {}

    assert lower_unobserved_call_result_assignments_8616(codegen) is True
    [statement] = root.statements
    assert isinstance(statement, CExpressionStatement)
    assert statement.expr is call


def test_lowers_declaration_typed_void_projection_without_summary_identity() -> None:
    """Final declaration metadata survives cloned-call summary identity loss."""
    codegen, root, call, assignment = _call_result_codegen(
        return_used=True,
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
    )
    assignment.rhs = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CUnaryOp("Reference", call, codegen=codegen),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {}
    codegen._inertia_callsite_c_result_contracts_8616 = {
        0x10100: CallsiteCResultContract8616(
            CallsiteCResultKind8616.VOID,
            "void",
        )
    }

    assert lower_unobserved_call_result_assignments_8616(codegen) is True
    [statement] = root.statements
    assert isinstance(statement, CExpressionStatement)
    assert statement.expr is call


def test_lowers_rebased_declaration_typed_void_projection() -> None:
    """An active slice address resolves the final contract at its original address."""
    codegen, root, call, assignment = _call_result_codegen(
        return_used=True,
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
    )
    call.tags["ins_addr"] = 0x100
    codegen.project._inertia_original_linear_delta = 0x10000
    assignment.rhs = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CUnaryOp("Reference", call, codegen=codegen),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {}
    codegen._inertia_callsite_c_result_contracts_8616 = {
        0x10100: CallsiteCResultContract8616(
            CallsiteCResultKind8616.VOID,
            "void",
        )
    }

    assert lower_unobserved_call_result_assignments_8616(codegen) is True
    [statement] = root.statements
    assert isinstance(statement, CExpressionStatement)
    assert statement.expr is call


def test_lowers_semantics_typed_void_interrupt_projection() -> None:
    """An exact interrupt ABI fact with no result register preserves only the call."""
    codegen, root, call, assignment = _call_result_codegen(
        return_used=True,
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
    )
    assignment.rhs = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CUnaryOp("Reference", call, codegen=codegen),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {}
    codegen._inertia_software_interrupt_input_artifact_8616 = (
        SoftwareInterruptInputArtifact8616(
            facts=(
                SoftwareInterruptInputFact8616(
                    callsite_addr=0x10100,
                    target_addr=0x12000,
                    vector=0x21,
                    selector_value=0x09,
                    argument_registers=("dx",),
                    argument_values=(),
                    result_register=None,
                ),
            ),
        )
    )

    assert lower_unobserved_call_result_assignments_8616(codegen) is True
    [statement] = root.statements
    assert isinstance(statement, CExpressionStatement)
    assert statement.expr is call


def test_lowers_exact_binary_inventory_typed_void_interrupt_projection(
    monkeypatch,
) -> None:
    """Exact binary callsite evidence types a raw interrupt-core call as void."""
    codegen, root, call, assignment = _call_result_codegen(
        return_used=True,
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
    )
    call.callee_func = None
    call.callee_target = CConstant(
        interrupt_core_addr_8616(0x21),
        SimTypeShort(False),
        codegen=codegen,
    )
    assignment.rhs = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CUnaryOp("Reference", call, codegen=codegen),
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    function = SimpleNamespace(get_call_target=lambda _addr: interrupt_core_addr_8616(0x21))
    codegen.cfunc.addr = 0x10000
    codegen.project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda **_kwargs: function)
    )
    codegen._inertia_callsite_summaries = {}
    monkeypatch.setattr(
        unobserved_module,
        "collect_interrupt_service_calls",
        lambda _function: [InterruptCall(insn_addr=0x10100, vector=0x21, ah=0x09)],
    )

    assert lower_unobserved_call_result_assignments_8616(codegen) is True
    [statement] = root.statements
    assert isinstance(statement, CExpressionStatement)
    assert statement.expr is call
