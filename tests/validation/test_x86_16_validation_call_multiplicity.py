from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_variable import SimMemoryVariable
from inertia.semantics.callsite_summary import CallsiteSummary8616
from archinfo import ArchX86

from inertia.validation.tail_validation import (
    refresh_x86_16_final_semantic_validation_8616,
)
from inertia.validation.validation_call_multiplicity import (
    CallsiteMultiplicityIssueKind8616,
    validate_required_callsite_multiplicity_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self._inertia_callsite_summaries: dict[int, CallsiteSummary8616] = {}
        self._inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616] = {}
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _summary(callsite_addr: int, *, target_addr: int = 0x2000) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=target_addr,
        return_addr=callsite_addr + 3,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
    )


def _call(codegen: _Codegen, callsite_addr: int) -> CFunctionCall:
    return CFunctionCall(
        "sample_counter",
        SimpleNamespace(addr=0x2000),
        [],
        tags={"ins_addr": callsite_addr},
        codegen=codegen,
    )


def test_assignment_rhs_call_materializes_one_exact_callsite() -> None:
    codegen = _Codegen()
    call = _call(codegen, 0x1010)
    destination = CVariable(SimMemoryVariable(0x3000, 2), codegen=codegen)
    root = CStatements([CAssignment(destination, call, codegen=codegen)], codegen=codegen)
    codegen._inertia_callsite_summaries = {id(call): _summary(0x1010)}

    report = validate_required_callsite_multiplicity_8616(codegen, root)

    assert report.passed
    assert report.raw_fact_count == 1
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 1
    assert report.failure_count == 0


def test_assignment_and_standalone_duplicate_fail_exact_callsite_multiplicity() -> None:
    codegen = _Codegen()
    value_call = _call(codegen, 0x1010)
    duplicate_call = _call(codegen, 0x1010)
    destination = CVariable(SimMemoryVariable(0x3000, 2), codegen=codegen)
    root = CStatements(
        [
            CExpressionStatement(duplicate_call, codegen=codegen),
            CAssignment(destination, value_call, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {id(value_call): _summary(0x1010)}

    report = validate_required_callsite_multiplicity_8616(codegen, root)

    assert not report.passed
    assert report.raw_fact_count == 2
    assert report.normalized_fact_count == 1
    assert report.classified_fact_count == 1
    assert report.materialized_count == 0
    assert report.failure_count == 1
    assert report.issues[0].kind is CallsiteMultiplicityIssueKind8616.DUPLICATE_FINAL_CALLSITE
    assert report.issue_tokens() == (
        "callsite-multiplicity:duplicate-final-callsite:callsite=0x1010:"
        "target=0x2000:expected=1:actual=2",
    )


def test_shared_call_node_at_two_ast_edges_fails_exact_callsite_multiplicity() -> None:
    """A shared node renders twice and must count as two call evaluations."""
    codegen = _Codegen()
    call = _call(codegen, 0x1010)
    destination = CVariable(SimMemoryVariable(0x3000, 2), codegen=codegen)
    root = CStatements(
        [
            CExpressionStatement(call, codegen=codegen),
            CAssignment(destination, call, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen._inertia_callsite_summaries = {id(call): _summary(0x1010)}

    report = validate_required_callsite_multiplicity_8616(codegen, root)

    assert not report.passed
    assert report.raw_fact_count == 2
    assert report.failure_count == 1
    assert report.issues[0].actual_count == 2


def test_untagged_same_target_clone_fails_aggregate_multiplicity() -> None:
    """Catch a condition clone even when only the assignment retained callsite tags."""
    codegen = _Codegen()
    exact_call = _call(codegen, 0x1010)
    untagged_clone = CFunctionCall(
        "sample_counter",
        SimpleNamespace(addr=0x2000),
        [],
        codegen=codegen,
    )
    root = CStatements([exact_call, untagged_clone], codegen=codegen)
    codegen._inertia_callsite_summaries = {id(exact_call): _summary(0x1010)}

    report = validate_required_callsite_multiplicity_8616(codegen, root)

    assert not report.passed
    assert report.raw_fact_count == 2
    assert report.failure_count == 1
    issue = report.issues[0]
    assert issue.kind is CallsiteMultiplicityIssueKind8616.DUPLICATE_FINAL_TARGET
    assert issue.callsite_addr is None
    assert issue.target_addr == 0x2000
    assert issue.expected_count == 1
    assert issue.actual_count == 2
    assert report.issue_tokens() == (
        "callsite-multiplicity:duplicate-final-target:callsite=aggregate:"
        "target=0x2000:expected=1:actual=2",
    )


def test_same_target_at_two_distinct_machine_callsites_is_not_a_duplicate() -> None:
    codegen = _Codegen()
    first = _call(codegen, 0x1010)
    second = _call(codegen, 0x1020)
    root = CStatements([first, second], codegen=codegen)
    codegen._inertia_callsite_summaries = {id(first): _summary(0x1010)}
    codegen._inertia_callsite_summary_inventory_8616 = {
        0x1010: _summary(0x1010),
        0x1020: _summary(0x1020),
    }

    report = validate_required_callsite_multiplicity_8616(codegen, root)

    assert report.passed
    assert report.raw_fact_count == 2
    assert report.normalized_fact_count == 2
    assert report.materialized_count == 2


def test_final_semantic_refresh_persists_duplicate_callsite_failure() -> None:
    codegen = _Codegen()
    first = _call(codegen, 0x1010)
    second = _call(codegen, 0x1010)
    root = CStatements([first, second], codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, arg_list=[], statements=root)
    codegen._inertia_callsite_summaries = {id(first): _summary(0x1010)}
    codegen._inertia_tail_validation_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }

    report = refresh_x86_16_final_semantic_validation_8616(codegen.project, codegen)

    issue = (
        "callsite-multiplicity:duplicate-final-callsite:callsite=0x1010:"
        "target=0x2000:expected=1:actual=2"
    )
    assert not report.passed
    assert report.callsite_multiplicity.issue_tokens() == (issue,)
    postprocess = codegen._inertia_tail_validation_snapshot["postprocess"]
    assert postprocess["semantic_failures"] == {"callsite_multiplicity": (issue,)}
    assert postprocess["final_semantic_guard"]["callsite_multiplicity"] == {
        "raw_fact_count": 2,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }
