from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeLong, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimStackVariable
from inertia.semantics.callsite_summary import CallsiteSummary8616

from inertia.structuring.stored_call_result_contracts import (
    StoredCallResultOccurrenceVerdict8616,
    StoredCallResultRefusalReason8616,
)
from inertia.structuring.stored_call_result_occurrences import (
    materialize_stored_call_result_occurrences_8616,
)
from inertia.validation.validation_call_multiplicity import (
    validate_required_callsite_multiplicity_8616,
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


def _summary(
    *,
    destination: tuple[str, int] = ("global", 0xB48),
    width: int = 4,
) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x104AF,
        target_addr=0x1137E,
        return_addr=0x104B2,
        kind="near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="dx:ax",
        return_used=True,
        return_store_destination=destination,
        return_store_width=width,
        return_store_instruction_addr=0x104B2,
    )


def _call(codegen: _AstCodegen, *, argument: int | None = None) -> structured_c.CFunctionCall:
    args = (
        []
        if argument is None
        else [structured_c.CConstant(argument, SimTypeShort(False), codegen=codegen)]
    )
    return structured_c.CFunctionCall(
        "sub_1137e",
        SimpleNamespace(addr=0x1137E, name="sub_1137e"),
        args,
        tags={"ins_addr": 0x104AF},
        codegen=codegen,
    )


def _global_destination(codegen: _AstCodegen, *, addr: int = 0xB48) -> structured_c.CVariable:
    return structured_c.CVariable(
        SimMemoryVariable(addr, 4, name="g_0B48"),
        variable_type=SimTypeLong(False),
        codegen=codegen,
    )


def _surface(
    codegen: _AstCodegen,
    root: structured_c.CStatements,
    calls: tuple[structured_c.CFunctionCall, ...],
    summary: CallsiteSummary8616 | None = None,
) -> _AstCodegen:
    codegen.cfunc = SimpleNamespace(statements=root)
    active_summary = summary or _summary()
    codegen._inertia_callsite_summaries = {id(call): active_summary for call in calls}
    return codegen


def test_nested_adjacent_global_result_owner_removes_standalone_clone() -> None:
    codegen = _AstCodegen()
    standalone_call = _call(codegen)
    assigned_call = _call(codegen)
    standalone_statement = structured_c.CExpressionStatement(
        standalone_call,
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(
        _global_destination(codegen),
        assigned_call,
        codegen=codegen,
    )
    call_group = structured_c.CStatements([standalone_statement], codegen=codegen)
    assignment_group = structured_c.CStatements([assignment], codegen=codegen)
    body = structured_c.CStatements(
        [
            structured_c.CStatements([], codegen=codegen),
            structured_c.CStatements([], codegen=codegen),
            call_group,
            assignment_group,
        ],
        codegen=codegen,
    )
    root = structured_c.CStatements([body], codegen=codegen)
    _surface(codegen, root, (standalone_call, assigned_call))

    before = validate_required_callsite_multiplicity_8616(codegen, root)
    result = materialize_stored_call_result_occurrences_8616(codegen)
    after = validate_required_callsite_multiplicity_8616(codegen, root)

    assert not before.passed
    assert before.issues[0].actual_count == 2
    assert result.verdict is StoredCallResultOccurrenceVerdict8616.MATERIALIZED
    assert result.changed is True
    assert call_group.statements == []
    assert assignment_group.statements == [assignment]
    assert assignment.rhs is assigned_call
    assert id(standalone_call) not in codegen._inertia_callsite_summaries
    assert codegen._inertia_callsite_summaries[id(assigned_call)] == _summary()
    assert after.passed
    assert (
        result.stats.raw_fact_count,
        result.stats.normalized_fact_count,
        result.stats.classified_fact_count,
        result.stats.materialized_count,
        result.stats.failure_count,
        result.stats.removed_standalone_count,
    ) == (1, 1, 1, 1, 0, 1)


def test_same_parent_adjacent_stack_result_owner_is_supported() -> None:
    codegen = _AstCodegen()
    standalone_call = _call(codegen)
    assigned_call = _call(codegen)
    standalone = structured_c.CExpressionStatement(standalone_call, codegen=codegen)
    destination = structured_c.CVariable(
        SimStackVariable(-12, 2, base="bp", name="result"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(destination, assigned_call, codegen=codegen)
    root = structured_c.CStatements([standalone, assignment], codegen=codegen)
    _surface(
        codegen,
        root,
        (standalone_call, assigned_call),
        _summary(destination=("bp", -12), width=2),
    )

    result = materialize_stored_call_result_occurrences_8616(codegen)

    assert result.verdict is StoredCallResultOccurrenceVerdict8616.MATERIALIZED
    assert root.statements == [assignment]


def test_wrong_result_destination_refuses_without_mutation() -> None:
    codegen = _AstCodegen()
    standalone_call = _call(codegen)
    assigned_call = _call(codegen)
    standalone = structured_c.CExpressionStatement(standalone_call, codegen=codegen)
    assignment = structured_c.CAssignment(
        _global_destination(codegen, addr=0xB4A),
        assigned_call,
        codegen=codegen,
    )
    root = structured_c.CStatements([standalone, assignment], codegen=codegen)
    _surface(codegen, root, (standalone_call, assigned_call))

    result = materialize_stored_call_result_occurrences_8616(codegen)

    assert result.verdict is StoredCallResultOccurrenceVerdict8616.UNKNOWN_REFUSE
    assert result.changed is False
    assert root.statements == [standalone, assignment]
    assert result.refusals[0].reason is StoredCallResultRefusalReason8616.RETURN_STORE_NOT_PROVEN


def test_nonadjacent_result_store_refuses_without_moving_call() -> None:
    codegen = _AstCodegen()
    standalone_call = _call(codegen)
    assigned_call = _call(codegen)
    unrelated_call = structured_c.CExpressionStatement(
        structured_c.CFunctionCall(
            "other",
            SimpleNamespace(addr=0x12000, name="other"),
            [],
            tags={"ins_addr": 0x104B0},
            codegen=codegen,
        ),
        codegen=codegen,
    )
    standalone = structured_c.CExpressionStatement(standalone_call, codegen=codegen)
    assignment = structured_c.CAssignment(
        _global_destination(codegen),
        assigned_call,
        codegen=codegen,
    )
    root = structured_c.CStatements(
        [standalone, unrelated_call, assignment],
        codegen=codegen,
    )
    _surface(codegen, root, (standalone_call, assigned_call))

    result = materialize_stored_call_result_occurrences_8616(codegen)

    assert result.verdict is StoredCallResultOccurrenceVerdict8616.UNKNOWN_REFUSE
    assert result.changed is False
    assert root.statements == [standalone, unrelated_call, assignment]
    assert result.refusals[0].reason is StoredCallResultRefusalReason8616.STRUCTURED_ORDER_UNKNOWN


def test_different_arguments_refuse_without_deleting_either_call() -> None:
    codegen = _AstCodegen()
    standalone_call = _call(codegen, argument=1)
    assigned_call = _call(codegen, argument=2)
    standalone = structured_c.CExpressionStatement(standalone_call, codegen=codegen)
    assignment = structured_c.CAssignment(
        _global_destination(codegen),
        assigned_call,
        codegen=codegen,
    )
    root = structured_c.CStatements([standalone, assignment], codegen=codegen)
    _surface(codegen, root, (standalone_call, assigned_call))

    result = materialize_stored_call_result_occurrences_8616(codegen)

    assert result.verdict is StoredCallResultOccurrenceVerdict8616.UNKNOWN_REFUSE
    assert result.changed is False
    assert root.statements == [standalone, assignment]
    assert result.refusals[0].reason is StoredCallResultRefusalReason8616.CALL_SURFACE_CONFLICT
