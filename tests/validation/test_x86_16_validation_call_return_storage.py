"""Tests for typed stored call-return validation projection."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CIfElse,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.semantics.callsite_summary import (
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
    bind_structured_callsite_identity_8616,
)
from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
from archinfo import ArchX86

from inertia.validation.tail_validation import _collect_observed_locations
from inertia.validation.tail_validation_condition_context import (
    _owned_materialized_condition_fingerprint_8616,
    build_x86_16_contextual_condition_fingerprints,
)
from inertia.validation.validation_call_return_storage import (
    StoredCallReturnConditionKind8616,
    direct_call_return_condition_projection_8616,
    stored_call_return_condition_projection_8616,
)

JCC_ADDR = 0x1021
RETURN_ADDR = 0x101C
CALLSITE_ADDR = 0x1016


def _summary() -> CallsiteSummary8616:
    """Build exact call-return-to-stack evidence."""
    return CallsiteSummary8616(
        callsite_addr=CALLSITE_ADDR,
        target_addr=0x2000,
        return_addr=RETURN_ADDR,
        kind="near",
        arg_count=4,
        arg_widths=(2, 2, 2, 2),
        stack_cleanup=8,
        return_register="ax",
        return_used=True,
        return_store_destination=("bp", -2),
        return_store_width=2,
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
    )


def _condition(*, op: str = "ne", constant: int = 0, register_name: str = "ax") -> ConditionIR:
    """Build one exact typed branch fact."""
    arch = ArchX86()
    offset, size = arch.registers[register_name]
    return ConditionIR(
        op=op,
        lhs=IRValue(MemSpace.REG, name=register_name, offset=offset, size=size),
        rhs=IRValue(MemSpace.CONST, name="const", const=constant, size=size),
        width_bits=size * 8,
        src_insn=JCC_ADDR,
        block_addr=RETURN_ADDR,
    )


def _surface(
    *,
    conditions: tuple[ConditionIR, ...] | None = None,
    summaries: tuple[CallsiteSummary8616, ...] | None = None,
) -> tuple[SimpleNamespace, SimpleNamespace]:
    """Build the owned project/codegen evidence surfaces."""
    project = SimpleNamespace(arch=ArchX86())
    actual_conditions = (_condition(),) if conditions is None else conditions
    actual_summaries = (_summary(),) if summaries is None else summaries
    codegen = SimpleNamespace(
        project=project,
        next_idx=lambda _name: 1,
        cstyle_null_cmp=False,
        _inertia_typed_conditions=actual_conditions,
        _inertia_callsite_summary_inventory_8616={item.callsite_addr: item for item in actual_summaries},
        _inertia_callsite_summaries={},
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    project._inertia_tail_validation_active_codegen = codegen
    return project, codegen


def _direct_summary() -> CallsiteSummary8616:
    """Build exact direct call-return condition evidence."""
    return replace(
        _summary(),
        return_store_destination=None,
        return_store_width=None,
        return_use_kind=CallsiteReturnUseKind8616.CONDITION,
    )


def _callee() -> SimpleNamespace:
    """Build a typed angr callee surface for structured call expressions."""
    return SimpleNamespace(
        addr=0x2000,
        name="sub_2000",
        prototype=SimTypeFunction([], SimTypeShort(False)),
        prototype_libname=None,
    )


def test_projects_exact_stored_call_return_condition() -> None:
    project, codegen = _surface()

    projection = stored_call_return_condition_projection_8616(
        project,
        codegen,
        jcc_addr=JCC_ADDR,
        block_addr=RETURN_ADDR,
    )

    assert projection is not None
    assert projection.kind is StoredCallReturnConditionKind8616.NONZERO
    assert projection.stack_location == "stack_slot:SS:BP-0x2:size2"
    assert projection.fingerprint == "CmpNE(stack_slot:SS:BP-0x2:size2,const:0)"


def test_structured_condition_orientation_overrides_machine_taken_polarity() -> None:
    project, codegen = _surface(conditions=(_condition(op="zero"),))
    ax_offset, ax_size = project.arch.registers["ax"]
    structured = CBinaryOp(
        "CmpNE",
        CVariable(SimRegisterVariable(ax_offset, ax_size), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    projection = stored_call_return_condition_projection_8616(
        project,
        codegen,
        jcc_addr=JCC_ADDR,
        block_addr=RETURN_ADDR,
        structured_condition=structured,
    )

    assert projection is not None
    assert projection.kind is StoredCallReturnConditionKind8616.ZERO
    assert projection.fingerprint == "CmpNE(stack_slot:SS:BP-0x2:size2,const:0)"


def test_direct_call_return_projection_is_stable_across_materialization() -> None:
    summary = _direct_summary()
    project, codegen = _surface(summaries=(summary,))
    ax_offset, ax_size = project.arch.registers["ax"]
    raw_condition = CBinaryOp(
        "CmpNE",
        CVariable(SimRegisterVariable(ax_offset, ax_size), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": JCC_ADDR, "vex_block_addr": RETURN_ADDR},
    )
    callee = _callee()
    call = CFunctionCall(
        callee.name,
        callee,
        [CConstant(104, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    bind_structured_callsite_identity_8616(call, summary)
    codegen._inertia_callsite_summaries[id(call)] = summary
    materialized_condition = CBinaryOp(
        "CmpNE",
        call,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={
            "ins_addr": JCC_ADDR,
            "vex_block_addr": RETURN_ADDR,
            "inertia_structuring_condition_cfg_materialized_8616": True,
        },
    )

    raw = direct_call_return_condition_projection_8616(
        project,
        codegen,
        jcc_addr=JCC_ADDR,
        block_addr=RETURN_ADDR,
        structured_condition=raw_condition,
    )
    materialized = direct_call_return_condition_projection_8616(
        project,
        codegen,
        jcc_addr=JCC_ADDR,
        block_addr=RETURN_ADDR,
        structured_condition=materialized_condition,
    )

    assert raw is not None
    assert materialized is not None
    assert raw.fingerprint == materialized.fingerprint
    assert raw.fingerprint == "CmpNE(callsite:0x1016:addr:0x2000,const:0)"


def test_direct_call_return_context_uses_exact_callsite_not_arguments() -> None:
    summary = _direct_summary()
    project, codegen = _surface(summaries=(summary,))
    callee = _callee()
    call = CFunctionCall(
        callee.name,
        callee,
        [CConstant(118, SimTypeShort(False), codegen=codegen)],
        codegen=codegen,
    )
    bind_structured_callsite_identity_8616(call, summary)
    codegen._inertia_callsite_summaries[id(call)] = summary
    condition = CBinaryOp(
        "CmpNE",
        call,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={
            "ins_addr": JCC_ADDR,
            "vex_block_addr": RETURN_ADDR,
            "inertia_structuring_condition_cfg_materialized_8616": True,
        },
    )
    root = CStatements(
        [CIfElse([(condition, CStatements([], codegen=codegen))], codegen=codegen)],
        codegen=codegen,
    )

    contextual = build_x86_16_contextual_condition_fingerprints(root, project)

    assert contextual[id(condition)] == "CmpNE(callsite:0x1016:addr:0x2000,const:0)"


def test_direct_call_return_projection_refuses_wrong_structured_callsite() -> None:
    summary = _direct_summary()
    project, codegen = _surface(summaries=(summary,))
    call = CFunctionCall(_callee().name, _callee(), [], codegen=codegen)
    wrong = replace(summary, callsite_addr=summary.callsite_addr + 2)
    bind_structured_callsite_identity_8616(call, wrong)
    codegen._inertia_callsite_summaries[id(call)] = wrong
    condition = CBinaryOp(
        "CmpNE",
        call,
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    assert (
        direct_call_return_condition_projection_8616(
            project,
            codegen,
            jcc_addr=JCC_ADDR,
            block_addr=RETURN_ADDR,
            structured_condition=condition,
        )
        is None
    )


@pytest.mark.parametrize(
    ("conditions", "summaries"),
    [
        ((_condition(constant=1),), (_summary(),)),
        ((_condition(register_name="bx"),), (_summary(),)),
        ((_condition(), _condition()), (_summary(),)),
        ((_condition(),), (_summary(), replace(_summary(), callsite_addr=0x1010))),
        ((_condition(),), (replace(_summary(), return_used=None),)),
        ((_condition(),), (replace(_summary(), return_store_destination=None),)),
    ],
)
def test_refuses_inexact_or_ambiguous_evidence(
    conditions: tuple[ConditionIR, ...],
    summaries: tuple[CallsiteSummary8616, ...],
) -> None:
    project, codegen = _surface(conditions=conditions, summaries=summaries)

    assert (
        stored_call_return_condition_projection_8616(
            project,
            codegen,
            jcc_addr=JCC_ADDR,
            block_addr=RETURN_ADDR,
        )
        is None
    )


def test_context_and_observed_locations_use_the_same_typed_projection() -> None:
    project, codegen = _surface()
    ax_offset, ax_size = project.arch.registers["ax"]
    raw_condition = CBinaryOp(
        "CmpNE",
        CVariable(SimRegisterVariable(ax_offset, ax_size), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": JCC_ADDR, "vex_block_addr": RETURN_ADDR},
    )
    root = CStatements(
        [CIfElse([(raw_condition, CStatements([], codegen=codegen))], codegen=codegen)],
        codegen=codegen,
    )

    contextual = build_x86_16_contextual_condition_fingerprints(root, project)
    observed = _collect_observed_locations(root, project, "live_out", contextual)

    assert contextual[id(raw_condition)] == "CmpNE(stack_slot:SS:BP-0x2:size2,const:0)"
    assert "stack_slot:SS:BP-0x2:size2" in observed


def test_materialized_condition_refuses_register_hidden_by_copy_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    project, codegen = _surface()
    ax_offset, ax_size = project.arch.registers["ax"]
    raw_condition = CBinaryOp(
        "CmpNE",
        CVariable(SimRegisterVariable(ax_offset, ax_size), codegen=codegen),
        CConstant(0, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
        tags={"typed_condition": True},
    )
    monkeypatch.setattr(
        "inertia.validation.tail_validation_condition_context._expr_fingerprint",
        lambda _node, _project: "CmpNE(ds_global:0x7014,const:0)",
    )

    assert _owned_materialized_condition_fingerprint_8616(raw_condition, project) is None
