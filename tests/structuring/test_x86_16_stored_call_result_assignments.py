from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from inertia.semantics.callsite_summary import (
    CallsiteReturnUseKind8616,
    CallsiteSummary8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)

from inertia.structuring.shared_call_result_aliases import (
    CallResultAliasOwnershipVerdict8616,
    materialize_shared_call_result_aliases_8616,
)
from inertia.structuring.stored_call_result_assignments import (
    StoredCallResultAssignmentRefusalReason8616,
    StoredCallResultAssignmentVerdict8616,
    materialize_stored_call_result_assignments_8616,
)


class _AstCodegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self.cstyle_null_cmp = True
        self._next_idx = 0

    def next_idx(self, _name: str) -> int:
        self._next_idx += 1
        return self._next_idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _summary(callsite_addr: int, store_addr: int) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=None,
        return_addr=callsite_addr + 3,
        kind="near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register="ax",
        return_used=True,
        return_store_destination=("bp", 6),
        return_store_width=2,
        return_store_instruction_addr=store_addr,
        return_use_kind=CallsiteReturnUseKind8616.VALUE,
    )


def _stack_value(codegen: _AstCodegen) -> structured_c.CVariable:
    return structured_c.CVariable(
        SimStackVariable(6, 2, base="bp", name="value"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _eax_value(codegen: _AstCodegen) -> structured_c.CVariable:
    return structured_c.CVariable(
        SimRegisterVariable(codegen.project.arch.get_register_offset("eax"), 4, name="eax"),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )


def _indirect_call(
    codegen: _AstCodegen,
    value: structured_c.CVariable,
    callsite_addr: int,
) -> structured_c.CFunctionCall:
    return structured_c.CFunctionCall(
        "fn",
        SimpleNamespace(
            addr=None,
            name="fn",
            prototype=SimpleNamespace(
                returnty=SimTypeShort(False).with_arch(codegen.project.arch)
            ),
            prototype_libname=None,
        ),
        [value],
        tags={"ins_addr": callsite_addr},
        codegen=codegen,
    )


def test_materializes_indirect_call_results_into_exact_stack_argument() -> None:
    codegen = _AstCodegen()
    value = _stack_value(codegen)
    first_call = _indirect_call(codegen, value, 0x100E)
    second_call = _indirect_call(codegen, value, 0x101A)
    eax = _eax_value(codegen)
    first_assignment = structured_c.CAssignment(eax, first_call, codegen=codegen)
    wrong_destination = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="fn"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    first_store_artifact = structured_c.CAssignment(
        wrong_destination,
        eax,
        tags={"ins_addr": 0x1014},
        codegen=codegen,
    )
    second_statement = structured_c.CExpressionStatement(second_call, codegen=codegen)
    second_store_artifact = structured_c.CAssignment(
        wrong_destination,
        eax,
        tags={"ins_addr": 0x1020},
        codegen=codegen,
    )
    root = structured_c.CStatements(
        [first_assignment, first_store_artifact, second_statement, second_store_artifact],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_callsite_summaries = {
        id(first_call): _summary(0x100E, 0x1014),
        id(second_call): _summary(0x101A, 0x1020),
    }

    result = materialize_stored_call_result_assignments_8616(codegen)

    assert result.verdict is StoredCallResultAssignmentVerdict8616.MATERIALIZED
    assert result.changed
    assert isinstance(first_assignment.lhs.variable, SimStackVariable)
    assert first_assignment.lhs.variable.offset == 6
    assert len(root.statements) == 2
    second_assignment = root.statements[1]
    assert isinstance(second_assignment, structured_c.CAssignment)
    assert isinstance(second_assignment.lhs.variable, SimStackVariable)
    assert second_assignment.rhs is second_call
    assert (
        result.stats.raw_fact_count,
        result.stats.normalized_fact_count,
        result.stats.classified_fact_count,
        result.stats.materialized_count,
        result.stats.failure_count,
    ) == (2, 2, 2, 2, 0)


def test_materializes_call_nested_in_return_register_lane_merge() -> None:
    codegen = _AstCodegen()
    value = _stack_value(codegen)
    call = _indirect_call(codegen, value, 0x100E)
    eax = _eax_value(codegen)
    lane_merge = structured_c.CBinaryOp(
        "Or",
        structured_c.CBinaryOp(
            "And",
            eax,
            structured_c.CConstant(0xFFFF0000, SimTypeLong(False), codegen=codegen),
            codegen=codegen,
        ),
        structured_c.CBinaryOp(
            "And",
            call,
            structured_c.CConstant(0xFFFF, SimTypeLong(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    owner = structured_c.CAssignment(
        structured_c.CVariable(
            SimMemoryVariable(
                0x1_0000,
                4,
                name="inertia_eax",
                category="inertia_gp_register_state",
            ),
            variable_type=SimTypeLong(False),
            codegen=codegen,
        ),
        lane_merge,
        tags={"ins_addr": 0x100E},
        codegen=codegen,
    )
    store = structured_c.CAssignment(
        value,
        eax,
        tags={"ins_addr": 0x1014},
        codegen=codegen,
    )
    root = structured_c.CStatements([owner, store], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x100E, 0x1014)}

    result = materialize_stored_call_result_assignments_8616(codegen)

    assert result.verdict is StoredCallResultAssignmentVerdict8616.MATERIALIZED
    assert result.stats.materialized_count == 1
    assert root.statements == [owner]
    assert isinstance(owner.lhs, structured_c.CVariable)
    assert isinstance(owner.lhs.variable, SimStackVariable)
    assert owner.lhs.variable.offset == 6
    assert owner.rhs is lane_merge
    assert isinstance(lane_merge.rhs, structured_c.CBinaryOp)
    assert lane_merge.rhs.lhs is call


def test_does_not_own_assignment_with_multiple_nested_calls() -> None:
    codegen = _AstCodegen()
    value = _stack_value(codegen)
    first_call = _indirect_call(codegen, value, 0x100E)
    second_call = _indirect_call(codegen, value, 0x1011)
    eax = _eax_value(codegen)
    ambiguous_rhs = structured_c.CBinaryOp("Add", first_call, second_call, codegen=codegen)
    owner = structured_c.CAssignment(eax, ambiguous_rhs, codegen=codegen)
    store = structured_c.CAssignment(
        value,
        eax,
        tags={"ins_addr": 0x1014},
        codegen=codegen,
    )
    root = structured_c.CStatements([owner, store], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_callsite_summaries = {
        id(first_call): _summary(0x100E, 0x1014),
        id(second_call): _summary(0x1011, 0x1014),
    }

    result = materialize_stored_call_result_assignments_8616(codegen)

    assert result.verdict is StoredCallResultAssignmentVerdict8616.NO_CANDIDATE
    assert not result.changed
    assert root.statements == [owner, store]
    assert owner.lhs is eax


def test_rebinds_regenerated_call_by_exact_callsite_tag() -> None:
    codegen = _AstCodegen()
    value = _stack_value(codegen)
    previous_call = _indirect_call(codegen, value, 0x100E)
    regenerated_call = _indirect_call(codegen, value, 0x100E)
    statement = structured_c.CExpressionStatement(regenerated_call, codegen=codegen)
    root = structured_c.CStatements([statement], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_callsite_summaries = {id(previous_call): _summary(0x100E, 0x1014)}

    result = materialize_stored_call_result_assignments_8616(codegen)

    assert result.verdict is StoredCallResultAssignmentVerdict8616.MATERIALIZED
    assignment = root.statements[0]
    assert isinstance(assignment, structured_c.CAssignment)
    assert assignment.rhs is regenerated_call


def test_refuses_when_exact_stack_destination_has_no_owned_variable() -> None:
    codegen = _AstCodegen()
    call = structured_c.CFunctionCall(
        "fn",
        SimpleNamespace(addr=None, name="fn"),
        [structured_c.CConstant(5, SimTypeShort(False), codegen=codegen)],
        tags={"ins_addr": 0x100E},
        codegen=codegen,
    )
    statement = structured_c.CExpressionStatement(call, codegen=codegen)
    root = structured_c.CStatements([statement], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x100E, 0x1014)}

    result = materialize_stored_call_result_assignments_8616(codegen)

    assert result.verdict is StoredCallResultAssignmentVerdict8616.UNKNOWN_REFUSE
    assert not result.changed
    assert root.statements == [statement]
    assert result.refusals[0].reason is (
        StoredCallResultAssignmentRefusalReason8616.DESTINATION_VARIABLE_MISSING
    )


def test_materializes_projected_entry_sp_variable_for_machine_bp_destination() -> None:
    codegen = _AstCodegen()
    projected_variable = SimStackVariable(4, 2, base="bp", name="value")
    value = structured_c.CVariable(
        projected_variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = _indirect_call(codegen, value, 0x100E)
    statement = structured_c.CExpressionStatement(call, codegen=codegen)
    root = structured_c.CStatements([statement], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x100E, 0x1014)}
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected_variable,
        cvar=value,
        bp_offset=6,
        entry_sp_offset=4,
        size=2,
    )

    result = materialize_stored_call_result_assignments_8616(codegen)

    assert result.verdict is StoredCallResultAssignmentVerdict8616.MATERIALIZED
    assignment = root.statements[0]
    assert isinstance(assignment, structured_c.CAssignment)
    assert assignment.rhs is call
    assert isinstance(assignment.lhs.variable, SimStackVariable)
    assert assignment.lhs.variable.offset == 4


def test_exact_store_owns_shared_dirty_call_result_before_alias_rewrite() -> None:
    codegen = _AstCodegen()
    value = _stack_value(codegen)
    call = _indirect_call(codegen, value, 0x100E)
    owner = structured_c.CAssignment(
        structured_c.CDirtyExpression(SimpleNamespace(varid=808), codegen=codegen),
        call,
        tags={"ins_addr": 0x1014},
        codegen=codegen,
    )
    aliases = [
        structured_c.CAssignment(
            structured_c.CDirtyExpression(SimpleNamespace(varid=varid), codegen=codegen),
            call,
            tags={"ins_addr": 0x1017, "vex_stmt_idx": vex_stmt_idx},
            codegen=codegen,
        )
        for varid, vex_stmt_idx in ((835, 35), (836, 36))
    ]
    root = structured_c.CStatements([owner, *aliases], codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=root)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x100E, 0x1014)}

    assignment_result = materialize_stored_call_result_assignments_8616(codegen)
    alias_result = materialize_shared_call_result_aliases_8616(codegen)

    assert assignment_result.verdict is StoredCallResultAssignmentVerdict8616.MATERIALIZED
    assert assignment_result.stats.failure_count == 0
    assert isinstance(owner.lhs, structured_c.CVariable)
    assert isinstance(owner.lhs.variable, SimStackVariable)
    assert alias_result.verdict is CallResultAliasOwnershipVerdict8616.MATERIALIZED
    assert all(isinstance(alias.rhs, structured_c.CVariable) for alias in aliases)
    assert sum(
        isinstance(statement.rhs, structured_c.CFunctionCall)
        for statement in root.statements
        if isinstance(statement, structured_c.CAssignment)
    ) == 1
