from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
)

from inertia.structuring.shared_call_result_aliases import (
    CallResultAliasOwnershipVerdict8616,
    CallResultAliasRefusalReason8616,
    materialize_shared_call_result_aliases_8616,
)


class _AstCodegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self._next_idx = 0

    def next_idx(self, _name: str) -> int:
        self._next_idx += 1
        return self._next_idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _summary(*, destination: tuple[str, int] = ("bp", -12)) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x1094,
        target_addr=0x11E7,
        return_addr=0x1097,
        kind="near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register="ax",
        return_used=True,
        return_store_destination=destination,
        return_store_width=2,
        return_store_instruction_addr=0x1097,
    )


def _call(codegen: _AstCodegen) -> structured_c.CFunctionCall:
    return structured_c.CFunctionCall(
        "MapInEMSSprite",
        SimpleNamespace(addr=0x11E7, name="MapInEMSSprite"),
        [
            structured_c.CConstant(2, SimTypeShort(False), codegen=codegen),
            structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        ],
        tags={"ins_addr": 0x1094},
        codegen=codegen,
    )


def _stack_destination(codegen: _AstCodegen) -> structured_c.CVariable:
    return structured_c.CVariable(
        SimStackVariable(-12, 2, base="bp", name="mseg"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _dirty(codegen: _AstCodegen, varid: int) -> structured_c.CDirtyExpression:
    return structured_c.CDirtyExpression(
        SimpleNamespace(varid=varid, name=f"t{varid}"),
        codegen=codegen,
    )


def _assignment(
    codegen: _AstCodegen,
    lhs: structured_c.CExpression,
    rhs: structured_c.CExpression,
    *,
    statement_index: int,
    include_position: bool = True,
) -> structured_c.CAssignment:
    tags = (
        {
            "ins_addr": 0x1094,
            "vex_block_addr": 0x108A,
            "vex_stmt_idx": statement_index,
        }
        if include_position
        else {}
    )
    return structured_c.CAssignment(lhs, rhs, tags=tags, codegen=codegen)


def _surface(
    codegen: _AstCodegen,
    statements: list[structured_c.CStatement],
    call: structured_c.CFunctionCall,
    summary: CallsiteSummary8616 | None = None,
) -> _AstCodegen:
    codegen.cfunc = SimpleNamespace(
        statements=structured_c.CStatements(statements, codegen=codegen)
    )
    codegen._inertia_callsite_summaries = {id(call): summary or _summary()}
    return codegen


def test_exact_stack_owner_rewrites_later_shared_call_assignments() -> None:
    codegen = _AstCodegen()
    call = _call(codegen)
    owner = _assignment(codegen, _stack_destination(codegen), call, statement_index=10)
    alias = _assignment(codegen, _dirty(codegen, 630), call, statement_index=20)
    _surface(codegen, [owner, alias, alias], call)

    result = materialize_shared_call_result_aliases_8616(codegen)

    assert result.verdict is CallResultAliasOwnershipVerdict8616.MATERIALIZED
    assert result.changed is True
    assert owner.rhs is call
    assert isinstance(alias.rhs, structured_c.CVariable)
    assert alias.rhs is not owner.lhs
    assert isinstance(alias.rhs.variable, SimStackVariable)
    assert alias.rhs.variable.offset == -12
    assert sum(
        isinstance(statement.rhs, structured_c.CFunctionCall)
        for statement in codegen.cfunc.statements.statements
        if isinstance(statement, structured_c.CAssignment)
    ) == 1
    assert (
        result.stats.raw_fact_count,
        result.stats.normalized_fact_count,
        result.stats.classified_fact_count,
        result.stats.materialized_count,
        result.stats.failure_count,
        result.stats.rewritten_assignment_count,
    ) == (1, 1, 1, 1, 0, 1)


def test_projected_stack_owner_matches_machine_bp_destination() -> None:
    codegen = _AstCodegen()
    call = _call(codegen)
    projected_variable = SimStackVariable(-14, 2, base="bp", name="mseg")
    projected_destination = structured_c.CVariable(
        projected_variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    owner = _assignment(codegen, projected_destination, call, statement_index=10)
    alias = _assignment(codegen, _dirty(codegen, 630), call, statement_index=20)
    _surface(codegen, [owner, alias], call)
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=projected_variable,
        cvar=projected_destination,
        bp_offset=-12,
        entry_sp_offset=-14,
        size=2,
    )

    result = materialize_shared_call_result_aliases_8616(codegen)

    assert result.verdict is CallResultAliasOwnershipVerdict8616.MATERIALIZED
    assert isinstance(alias.rhs, structured_c.CVariable)
    assert alias.rhs.variable.offset == -14


def test_alias_before_exact_stack_owner_refuses() -> None:
    codegen = _AstCodegen()
    call = _call(codegen)
    alias = _assignment(codegen, _dirty(codegen, 630), call, statement_index=5)
    owner = _assignment(codegen, _stack_destination(codegen), call, statement_index=10)
    _surface(codegen, [alias, owner], call)

    result = materialize_shared_call_result_aliases_8616(codegen)

    assert result.verdict is CallResultAliasOwnershipVerdict8616.UNKNOWN_REFUSE
    assert result.changed is False
    assert alias.rhs is call
    assert result.refusals[0].reason is CallResultAliasRefusalReason8616.STRUCTURED_ORDER_UNKNOWN


def test_missing_unique_exact_stack_owner_refuses() -> None:
    codegen = _AstCodegen()
    call = _call(codegen)
    first = _assignment(codegen, _dirty(codegen, 629), call, statement_index=10)
    second = _assignment(codegen, _dirty(codegen, 630), call, statement_index=20)
    _surface(codegen, [first, second], call)

    result = materialize_shared_call_result_aliases_8616(codegen)

    assert result.verdict is CallResultAliasOwnershipVerdict8616.UNKNOWN_REFUSE
    assert result.changed is False
    assert result.refusals[0].reason is CallResultAliasRefusalReason8616.DESTINATION_NOT_UNIQUE


def test_non_stack_destination_refuses() -> None:
    codegen = _AstCodegen()
    call = _call(codegen)
    first = _assignment(codegen, _dirty(codegen, 629), call, statement_index=10)
    second = _assignment(codegen, _dirty(codegen, 630), call, statement_index=20)
    _surface(codegen, [first, second], call, _summary(destination=("global", 0x7000)))

    result = materialize_shared_call_result_aliases_8616(codegen)

    assert result.verdict is CallResultAliasOwnershipVerdict8616.UNKNOWN_REFUSE
    assert result.refusals[0].reason is CallResultAliasRefusalReason8616.DESTINATION_NOT_EXACT_STACK


def test_missing_source_position_uses_exact_summary_and_structured_order() -> None:
    codegen = _AstCodegen()
    call = _call(codegen)
    owner = _assignment(codegen, _stack_destination(codegen), call, statement_index=10)
    alias = _assignment(
        codegen,
        _dirty(codegen, 630),
        call,
        statement_index=20,
        include_position=False,
    )
    _surface(codegen, [owner, alias], call)

    result = materialize_shared_call_result_aliases_8616(codegen)

    assert result.verdict is CallResultAliasOwnershipVerdict8616.MATERIALIZED
    assert isinstance(alias.rhs, structured_c.CVariable)


def test_nested_alias_without_dominance_proof_refuses() -> None:
    codegen = _AstCodegen()
    call = _call(codegen)
    owner = _assignment(codegen, _stack_destination(codegen), call, statement_index=10)
    alias = _assignment(codegen, _dirty(codegen, 630), call, statement_index=20)
    nested = structured_c.CStatements([alias], codegen=codegen)
    _surface(codegen, [owner, nested], call)

    result = materialize_shared_call_result_aliases_8616(codegen)

    assert result.verdict is CallResultAliasOwnershipVerdict8616.UNKNOWN_REFUSE
    assert result.refusals[0].reason is CallResultAliasRefusalReason8616.STRUCTURED_ORDER_UNKNOWN


def test_intervening_result_destination_write_refuses() -> None:
    codegen = _AstCodegen()
    call = _call(codegen)
    owner = _assignment(codegen, _stack_destination(codegen), call, statement_index=10)
    clobber = _assignment(
        codegen,
        _stack_destination(codegen),
        structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
        statement_index=15,
    )
    alias = _assignment(codegen, _dirty(codegen, 630), call, statement_index=20)
    _surface(codegen, [owner, clobber, alias], call)

    result = materialize_shared_call_result_aliases_8616(codegen)

    assert result.verdict is CallResultAliasOwnershipVerdict8616.UNKNOWN_REFUSE
    assert result.refusals[0].reason is CallResultAliasRefusalReason8616.INTERVENING_EFFECT_CONFLICT


def test_distinct_call_nodes_are_not_identity_aliases() -> None:
    codegen = _AstCodegen()
    first_call = _call(codegen)
    second_call = _call(codegen)
    first = _assignment(codegen, _stack_destination(codegen), first_call, statement_index=10)
    second = _assignment(codegen, _dirty(codegen, 630), second_call, statement_index=20)
    _surface(codegen, [first, second], first_call)
    codegen._inertia_callsite_summaries[id(second_call)] = _summary()

    result = materialize_shared_call_result_aliases_8616(codegen)

    assert result.verdict is CallResultAliasOwnershipVerdict8616.NO_CANDIDATE
    assert result.changed is False
    assert first.rhs is first_call
    assert second.rhs is second_call
