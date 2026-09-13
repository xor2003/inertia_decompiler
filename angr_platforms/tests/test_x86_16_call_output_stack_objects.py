from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CIfElse,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CVariableField,
)
from angr.sim_type import SimStruct, SimTypeArray, SimTypeBottom, SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import (
    CallsiteReturnShape8616,
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
)
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.ir.core import IRValue, MemSpace
from angr_platforms.X86_16.lowering.call_output_stack_object_replay import (
    reapply_call_output_stack_object_types_8616,
)
from angr_platforms.X86_16.lowering.call_output_stack_objects import (
    lower_call_output_stack_fields_in_condition_8616,
    lower_wide_call_return_condition_chain_8616,
    prune_materialized_call_output_stack_carriers_8616,
    prune_materialized_wide_condition_call_carrier_8616,
    recover_call_output_stack_object_facts_8616,
    select_wide_call_return_condition_chain_8616,
)
from angr_platforms.X86_16.lowering.condition_stack_operands import (
    materialize_typed_condition_stack_operand_8616,
)
from angr_platforms.X86_16.lowering.semantic_cast import CSemanticCast8616
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)


class _Types:
    def __init__(self):
        self.values = {}

    def __setitem__(self, name, value):
        self.values[name] = value


class _VariableManager:
    def __init__(self):
        self.types = _Types()
        self.variable_types = {}

    def set_variable_type(self, variable, type_, **_kwargs):
        self.variable_types[variable] = type_


class _CFunction:
    def __init__(self, statements, variables_in_use):
        self.addr = 0x1000
        self.statements = statements
        self.variables_in_use = variables_in_use
        self.variable_manager = _VariableManager()
        self.refresh_count = 0

    def refresh(self):
        self.refresh_count += 1


class _Codegen:
    def __init__(self):
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self.show_local_types = False

    def next_idx(self, _name):
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _condition(offset, src_insn):
    return ConditionIR(
        op="eq",
        lhs=IRValue(MemSpace.SS, name="bp", offset=offset, size=2),
        rhs=IRValue(MemSpace.CONST, const=0, size=2),
        src_insn=src_insn,
    )


def _fixture(
    *,
    include_array_boundary,
    materialized_call_argument=True,
    include_base_variable=True,
    entry_sp_bias=0,
):
    codegen = _Codegen()
    vc_variable = SimStackVariable(-112 + entry_sp_bias, 112, base="bp", name="vc", region=0x1000)
    field_14_variable = SimStackVariable(-98 + entry_sp_bias, 2, base="bp", name="local_62", region=0x1000)
    field_18_variable = SimStackVariable(-94 + entry_sp_bias, 2, base="bp", name="local_5e", region=0x1000)
    array_variable = SimStackVariable(-90 + entry_sp_bias, 86, base="bp", name="aTemp", region=0x1000)
    vc = CVariable(vc_variable, variable_type=SimTypeBottom(), codegen=codegen)
    field_14 = CVariable(field_14_variable, variable_type=SimTypeShort(False), codegen=codegen)
    field_18 = CVariable(field_18_variable, variable_type=SimTypeShort(False), codegen=codegen)
    array = CVariable(
        array_variable,
        variable_type=SimTypeArray(SimTypeShort(False), 43),
        codegen=codegen,
    )
    call = CFunctionCall(
        "unknown_output_call",
        SimpleNamespace(addr=0x3000),
        [CUnaryOp("Reference", vc, codegen=codegen)] if materialized_call_argument else [],
        codegen=codegen,
    )
    condition = CBinaryOp(
        "LogicalOr",
        CBinaryOp(
            "CmpEQ",
            field_18,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        CBinaryOp(
            "CmpEQ",
            field_14,
            CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    body = CStatements([], codegen=codegen)
    statements = [
        CExpressionStatement(call, codegen=codegen),
        CIfElse([(condition, body)], codegen=codegen),
    ]
    if include_array_boundary:
        statements.insert(1, CExpressionStatement(array, codegen=codegen))
    root = CStatements(statements, codegen=codegen)
    variables_in_use = {
        field_14_variable: field_14,
        field_18_variable: field_18,
        array_variable: array,
    }
    if include_base_variable:
        variables_in_use[vc_variable] = vc
    codegen.cfunc = _CFunction(root, variables_in_use)
    for variable, cvar, bp_offset in (
        (vc_variable, vc, -112),
        (field_14_variable, field_14, -98),
        (field_18_variable, field_18, -94),
        (array_variable, array, -90),
    ):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=cvar,
            bp_offset=bp_offset,
            entry_sp_offset=variable.offset,
            size=variable.size,
        )
    summary = CallsiteSummary8616(
        callsite_addr=0x1035,
        target_addr=0x3000,
        return_addr=0x103A,
        kind="direct_far",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=False,
        push_arg_sources=(("seg", "ss"), ("bp_addr", -112)),
    )
    codegen._inertia_callsite_summaries = {id(call): summary} if materialized_call_argument else {}
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}
    return codegen, condition, (field_14_variable, field_18_variable)


def test_call_output_stack_fields_use_typed_call_ir_and_aggregate_boundary():
    codegen, condition, carrier_variables = _fixture(include_array_boundary=True)
    conditions = (_condition(-94, 0x103F), _condition(-98, 0x1048))

    result = lower_call_output_stack_fields_in_condition_8616(codegen, condition, conditions)

    assert result.stats.classified_fact_count == 2
    assert result.stats.materialized_count == 2
    assert len(result.facts) == 1
    fact = result.facts[0]
    assert fact.base_offset == -112
    assert fact.boundary_offset == -90
    assert [(field.relative_offset, field.width) for field in fact.fields] == [(14, 2), (18, 2)]
    assert isinstance(result.expression.lhs.lhs, CVariableField)
    assert result.expression.lhs.lhs.field.field == "field_18"
    assert isinstance(result.expression.rhs.lhs, CVariableField)
    assert result.expression.rhs.lhs.field.field == "field_14"
    assert isinstance(codegen.cfunc.variable_manager.variable_types[fact.base_variable], SimStruct)
    assert codegen.show_local_types is True

    refresh_count_before_pruning = codegen.cfunc.refresh_count
    removed = prune_materialized_call_output_stack_carriers_8616(codegen)

    assert removed == 2
    assert all(variable not in codegen.cfunc.variables_in_use for variable in carrier_variables)
    assert codegen.cfunc.refresh_count == refresh_count_before_pruning + 1


def test_call_output_stack_fields_use_machine_bp_coordinate_registry():
    codegen, condition, carrier_variables = _fixture(
        include_array_boundary=True,
        entry_sp_bias=-2,
    )
    conditions = (_condition(-94, 0x103F), _condition(-98, 0x1048))

    result = lower_call_output_stack_fields_in_condition_8616(codegen, condition, conditions)

    assert result.stats.classified_fact_count == 2
    assert result.stats.materialized_count == 2
    assert isinstance(result.expression.lhs.lhs, CVariableField)
    assert isinstance(result.expression.rhs.lhs, CVariableField)
    assert prune_materialized_call_output_stack_carriers_8616(codegen) == 2
    assert all(variable not in codegen.cfunc.variables_in_use for variable in carrier_variables)


def test_call_output_stack_base_prefers_exact_projection_over_contained_subview():
    codegen, condition, _carrier_variables = _fixture(
        include_array_boundary=True,
        materialized_call_argument=False,
        entry_sp_bias=-2,
    )
    projected_owner = next(
        variable
        for variable in codegen.cfunc.variables_in_use
        if isinstance(variable, SimStackVariable) and variable.name == "vc"
    )
    contained = SimStackVariable(
        projected_owner.offset,
        1,
        base="bp",
        name="vc_low_byte",
        region=0x1000,
    )
    codegen.cfunc.variables_in_use[contained] = CVariable(
        contained,
        variable_type=SimTypeBottom(),
        codegen=codegen,
    )
    conditions = (_condition(-94, 0x103F), _condition(-98, 0x1048))

    result = lower_call_output_stack_fields_in_condition_8616(codegen, condition, conditions)

    assert result.stats.materialized_count == 2
    assert len(result.facts) == 1
    assert result.facts[0].base_variable is projected_owner


def test_call_output_stack_fields_refuse_without_closed_aggregate_boundary():
    codegen, condition, _carrier_variables = _fixture(include_array_boundary=False)
    conditions = (_condition(-94, 0x103F), _condition(-98, 0x1048))

    facts, stats = recover_call_output_stack_object_facts_8616(codegen, conditions)
    result = lower_call_output_stack_fields_in_condition_8616(codegen, condition, conditions)

    assert facts == ()
    assert stats.classified_fact_count == 0
    assert result.expression is condition
    assert result.stats.materialized_count == 0
    assert isinstance(condition.lhs.lhs, CVariable)
    assert isinstance(condition.rhs.lhs, CVariable)


def test_call_output_stack_fields_use_typed_inventory_before_ast_arguments_exist():
    codegen, condition, _carrier_variables = _fixture(
        include_array_boundary=True,
        materialized_call_argument=False,
        include_base_variable=False,
    )
    conditions = (_condition(-94, 0x103F), _condition(-98, 0x1048))

    result = lower_call_output_stack_fields_in_condition_8616(codegen, condition, conditions)

    assert result.stats.classified_fact_count == 2
    assert result.stats.materialized_count == 2
    assert len(result.facts) == 1
    assert result.facts[0].base_offset == -112
    assert result.facts[0].base_variable in codegen.cfunc.variables_in_use
    assert isinstance(result.expression.lhs.lhs, CVariableField)
    assert isinstance(result.expression.rhs.lhs, CVariableField)


def test_call_output_stack_fields_replay_proven_boundary_after_ast_regeneration():
    codegen, condition, carrier_variables = _fixture(
        include_array_boundary=True,
        entry_sp_bias=-2,
    )
    conditions = (_condition(-94, 0x103F), _condition(-98, 0x1048))

    initial = lower_call_output_stack_fields_in_condition_8616(
        codegen,
        condition,
        conditions,
    )
    codegen.cfunc.statements.statements.pop(1)
    field_14 = codegen.cfunc.variables_in_use[carrier_variables[0]]
    field_18 = codegen.cfunc.variables_in_use[carrier_variables[1]]
    regenerated = CBinaryOp(
        "LogicalOr",
        CBinaryOp(
            "CmpEQ",
            field_18,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        CBinaryOp(
            "CmpEQ",
            field_14,
            CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    replayed = lower_call_output_stack_fields_in_condition_8616(
        codegen,
        regenerated,
        conditions,
    )
    base = replayed.facts[0].base_cvar
    base.variable_type = SimTypeShort(False)
    del codegen._inertia_stack_variable_coordinate_registry_8616
    type_replayed = reapply_call_output_stack_object_types_8616(codegen)

    assert initial.stats.materialized_count == 2
    assert replayed.stats.classified_fact_count == 2
    assert replayed.stats.materialized_count == 2
    assert isinstance(replayed.expression.lhs.lhs, CVariableField)
    assert isinstance(replayed.expression.rhs.lhs, CVariableField)
    assert type_replayed is True
    assert isinstance(base.variable_type, SimStruct)


def test_call_output_stack_fields_refuse_persisted_fact_without_exact_callsite():
    codegen, condition, carrier_variables = _fixture(include_array_boundary=True)
    conditions = (_condition(-94, 0x103F), _condition(-98, 0x1048))
    lower_call_output_stack_fields_in_condition_8616(codegen, condition, conditions)
    codegen.cfunc.statements.statements.pop(1)
    codegen._inertia_callsite_summaries = {}
    codegen._inertia_callsite_summary_inventory_8616 = {}
    field_14 = codegen.cfunc.variables_in_use[carrier_variables[0]]
    field_18 = codegen.cfunc.variables_in_use[carrier_variables[1]]
    regenerated = CBinaryOp(
        "LogicalOr",
        CBinaryOp(
            "CmpEQ",
            field_18,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        CBinaryOp(
            "CmpEQ",
            field_14,
            CConstant(2, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    refused = lower_call_output_stack_fields_in_condition_8616(
        codegen,
        regenerated,
        conditions,
    )

    assert refused.facts == ()
    assert refused.stats.classified_fact_count == 0
    assert refused.stats.materialized_count == 0
    assert isinstance(refused.expression.lhs.lhs, CVariable)
    assert isinstance(refused.expression.rhs.lhs, CVariable)


def _wide_condition_fixture(*, include_summary=True, ast_high_offset=-2, monkeypatch=None):
    codegen = _Codegen()
    if monkeypatch is not None:
        from x86_16_condition_definition_fixtures import install_condition_definition_block

        install_condition_definition_block(
            monkeypatch, codegen.project, address=0x1000,
            data=b"\xe8\x00\x00\x90\x90\x3b\x56\xfe\x90\x90\x3b\x56\xfe\x90\x90\x3b\x46\xfc",
        )
    low_variable = SimStackVariable(-4, 2, base="bp", name="goal_lo", region=0x1000)
    high_variable = SimStackVariable(ast_high_offset, 2, base="bp", name="goal_hi", region=0x1000)
    wide_variable = SimStackVariable(-4, 4, base="bp", name="goal", region=0x1000)
    low = CVariable(low_variable, variable_type=SimTypeShort(False), codegen=codegen)
    high = CVariable(high_variable, variable_type=SimTypeShort(True), codegen=codegen)
    wide = CVariable(wide_variable, variable_type=SimTypeLong(False), codegen=codegen)
    dx = CVariable(
        SimRegisterVariable(4, 2, name="dx"),
        variable_type=SimTypeShort(True),
        codegen=codegen,
    )
    ax = CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = CFunctionCall(
        "clock",
        SimpleNamespace(
            addr=0x3000,
            prototype=SimTypeFunction((), SimTypeLong(True)),
            prototype_libname=None,
        ),
        [],
        codegen=codegen,
    )
    expression = CBinaryOp(
        "LogicalOr",
        CBinaryOp("CmpGT", dx, high, codegen=codegen),
        CBinaryOp(
            "LogicalAnd",
            CBinaryOp("CmpGE", dx, high, codegen=codegen),
            CBinaryOp("CmpGT", ax, low, codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    root = CStatements(
        [
            CExpressionStatement(call, codegen=codegen),
            CIfElse([(expression, CStatements([], codegen=codegen))], codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc = _CFunction(
        root,
        {
            low_variable: low,
            high_variable: high,
            wide_variable: wide,
        },
    )
    summary = CallsiteSummary8616(
        callsite_addr=0x1000,
        target_addr=0x3000,
        return_addr=0x1003,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
        return_shape=CallsiteReturnShape8616.DX_AX.value,
        return_use_kind=CallsiteReturnUseKind8616.CONDITION,
    )
    codegen._inertia_callsite_summaries = {id(call): summary} if include_summary else {}
    codegen._inertia_callsite_summary_inventory_8616 = (
        {summary.callsite_addr: summary} if include_summary else {}
    )
    conditions = (
        ConditionIR(
            op="sle",
            lhs=IRValue(MemSpace.REG, name="dx", offset=4, size=2),
            rhs=IRValue(MemSpace.SS, name="bp", offset=-2, size=2),
            src_insn=0x1005,
        ),
        ConditionIR(
            op="sge",
            lhs=IRValue(MemSpace.REG, name="dx", offset=4, size=2),
            rhs=IRValue(MemSpace.SS, name="bp", offset=-2, size=2),
            src_insn=0x100A,
        ),
        ConditionIR(
            op="ule",
            lhs=IRValue(MemSpace.REG, name="ax", offset=0, size=2),
            rhs=IRValue(MemSpace.SS, name="bp", offset=-4, size=2),
            src_insn=0x100F,
        ),
    )
    return codegen, expression, conditions, call, wide


@pytest.mark.parametrize("cast_high_view", (False, True))
def test_wide_call_return_condition_joins_typed_dx_ax_and_stack_pair(cast_high_view, monkeypatch):
    codegen, expression, conditions, call, wide = _wide_condition_fixture(monkeypatch=monkeypatch)
    if cast_high_view:
        expression.lhs.rhs = CSemanticCast8616(
            SimTypeShort(False),
            SimTypeShort(True),
            expression.lhs.rhs,
            codegen=codegen,
        )

    result = lower_wide_call_return_condition_chain_8616(codegen, expression, conditions)

    assert result.expression.op == "CmpGT"
    assert isinstance(result.expression.lhs, CTypeCast)
    assert result.expression.lhs.expr is call
    assert result.consumed_call is call
    assert result.consumed_callsite is codegen._inertia_callsite_summaries[id(call)]
    assert isinstance(result.expression.lhs.type, SimTypeLong)
    assert result.expression.lhs.type.signed is True
    assert isinstance(result.expression.rhs, CTypeCast)
    assert result.expression.rhs.expr is wide
    assert isinstance(result.expression.rhs.type, SimTypeLong)
    assert result.expression.rhs.type.signed is True
    assert isinstance(wide.variable_type, SimTypeLong)
    assert wide.variable_type.signed is True
    assert result.stats.raw_fact_count == 1
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0
    assert codegen._inertia_wide_call_return_condition_stats_8616 is result.stats


def test_wide_call_return_condition_refuses_without_typed_callsite(monkeypatch):
    codegen, expression, conditions, _call, _wide = _wide_condition_fixture(include_summary=False, monkeypatch=monkeypatch)

    result = lower_wide_call_return_condition_chain_8616(codegen, expression, conditions)

    assert result.expression is expression
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1
    assert result.consumed_call is None
    assert result.consumed_callsite is None


def test_wide_call_return_condition_consumes_typed_low_word_projection(monkeypatch):
    """Resolve a masked low-word view from its typed four-byte stack owner."""
    codegen, expression, conditions, call, wide = _wide_condition_fixture(monkeypatch=monkeypatch)
    projected_low = materialize_typed_condition_stack_operand_8616(
        codegen,
        base="bp",
        offset=-4,
        size=2,
        storage_size=4,
        name="goal",
        signed=False,
    )
    assert projected_low is not None
    expression.rhs.rhs.rhs = projected_low

    result = lower_wide_call_return_condition_chain_8616(codegen, expression, conditions)

    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0
    assert isinstance(result.expression.rhs, CTypeCast)
    assert result.expression.rhs.expr is wide
    assert result.consumed_call is call


def test_wide_call_return_condition_uses_inventory_before_ast_summary_attachment(monkeypatch):
    codegen, expression, conditions, call, _wide = _wide_condition_fixture(monkeypatch=monkeypatch)
    del codegen._inertia_callsite_summaries
    call.tags = SimpleNamespace(get=lambda key: 0x1000 if key == "ins_addr" else None)

    result = lower_wide_call_return_condition_chain_8616(codegen, expression, conditions)

    assert result.stats.materialized_count == 1
    assert isinstance(result.expression.lhs, CTypeCast)
    assert result.expression.lhs.expr is call
    assert codegen._inertia_callsite_summaries[id(call)].callsite_addr == 0x1000


def test_wide_call_return_condition_binds_direct_callee_from_typed_summary(monkeypatch):
    codegen, expression, conditions, call, _wide = _wide_condition_fixture(monkeypatch=monkeypatch)
    call.callee_func = SimpleNamespace(addr=0x300)
    callee = SimpleNamespace(
        addr=0x3000,
        name="sub_3000",
        prototype=SimTypeFunction([], SimTypeLong(True)).with_arch(codegen.project.arch),
        prototype_libname=None,
    )
    original_project = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda *, addr, create: callee
            if addr == 0x3000 and create is False
            else None
        )
    )
    codegen.project._inertia_original_project = SimpleNamespace(kb=original_project)
    codegen.project._inertia_original_linear_delta = 0x2D00

    result = lower_wide_call_return_condition_chain_8616(codegen, expression, conditions)

    assert result.stats.materialized_count == 1
    assert call.callee_func is callee


def test_wide_call_return_condition_joins_negated_non_break_form_with_wide_low_view(monkeypatch):
    codegen, expression, conditions, call, wide = _wide_condition_fixture(monkeypatch=monkeypatch)
    dx = expression.lhs.lhs
    high = expression.lhs.rhs
    ax = expression.rhs.rhs.lhs
    negated_non_break = CUnaryOp(
        "Not",
        CBinaryOp(
            "LogicalOr",
            CBinaryOp("CmpLT", dx, high, codegen=codegen),
            CBinaryOp(
                "LogicalAnd",
                CBinaryOp("CmpEQ", dx, high, codegen=codegen),
                CBinaryOp("CmpLE", ax, wide, codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    result = lower_wide_call_return_condition_chain_8616(
        codegen,
        negated_non_break,
        conditions,
    )

    assert result.expression.op == "CmpGT"
    assert isinstance(result.expression.lhs, CTypeCast)
    assert result.expression.lhs.expr is call
    assert isinstance(result.expression.rhs, CTypeCast)
    assert result.expression.rhs.expr is wide
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_select_wide_call_return_condition_chain_refuses_ambiguous_typed_pair():
    _codegen, _expression, conditions, _call, _wide = _wide_condition_fixture()
    root, high_ge, low_le = conditions
    duplicate_high_ge = replace(high_ge)
    duplicate_low_le = replace(low_le)

    assert select_wide_call_return_condition_chain_8616(root, conditions) == conditions
    assert (
        select_wide_call_return_condition_chain_8616(
            root,
            (*conditions, duplicate_high_ge, duplicate_low_le),
        )
        is None
    )


@pytest.mark.parametrize("register_name", ("ax", "v15"))
@pytest.mark.parametrize("wrapped", (False, True))
def test_prune_materialized_wide_condition_call_carrier_consumes_exact_ax_assignment(
    register_name,
    wrapped,
):
    codegen, expression, _conditions, call, _wide = _wide_condition_fixture()
    ax = expression.rhs.rhs.lhs
    ax.variable.name = register_name
    carrier = CAssignment(ax, call, codegen=codegen)
    branch = codegen.cfunc.statements.statements[1]
    codegen.cfunc.statements.statements[0] = (
        CExpressionStatement(carrier, codegen=codegen) if wrapped else carrier
    )
    branch.condition_and_nodes = [(call, branch.condition_and_nodes[0][1])]

    removed = prune_materialized_wide_condition_call_carrier_8616(codegen, call)

    assert removed == 1
    assert codegen.cfunc.statements.statements == [branch]
    assert branch.condition_and_nodes[0][0] is call


def test_wide_call_return_condition_refuses_unproven_stack_adjacency(monkeypatch):
    codegen, expression, conditions, _call, _wide = _wide_condition_fixture(ast_high_offset=-1, monkeypatch=monkeypatch)

    result = lower_wide_call_return_condition_chain_8616(codegen, expression, conditions)

    assert result.expression is expression
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1
