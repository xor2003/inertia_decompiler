from __future__ import annotations

from inertia.semantics.callsite_summary import CallsiteSummary8616
import inertia.lowering.callsite_prototype_declarations as declarations_module
from inertia.lowering.callee_argument_count_evidence import (
    CalleeArgumentCountEvidence8616,
    CalleeArgumentCountVerdict8616,
)
from inertia.lowering.callee_argument_width_evidence import (
    CalleeArgumentWidthEvidence8616,
    CalleeArgumentWidthVerdict8616,
)


def test_incomplete_callee_arity_uses_unprototyped_return_declaration(monkeypatch) -> None:
    count_evidence = CalleeArgumentCountEvidence8616(
        target_addr=0x1137E,
        verdict=CalleeArgumentCountVerdict8616.UNKNOWN,
        raw_fact_count=4,
        normalized_fact_count=4,
        classified_fact_count=3,
        materialized_count=3,
        failure_count=1,
    )
    width_evidence = CalleeArgumentWidthEvidence8616(
        target_addr=0x1137E,
        verdict=CalleeArgumentWidthVerdict8616.UNKNOWN,
        raw_fact_count=4,
        failure_count=4,
        count_evidence=count_evidence,
    )
    summary = CallsiteSummary8616(
        callsite_addr=0x10683,
        target_addr=0x1137E,
        return_addr=0x10686,
        kind="near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
        return_shape="dx_ax",
    )
    monkeypatch.setattr(
        declarations_module,
        "collect_callee_argument_width_evidence_8616",
        lambda _project, _target: width_evidence,
    )

    declaration = declarations_module._program_arity_fallback_decl_8616(
        object(),
        summary,
        "sub_1137e",
        "unsigned long",
    )

    assert declaration == "unsigned long sub_1137e();"
