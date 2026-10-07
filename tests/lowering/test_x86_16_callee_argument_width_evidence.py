from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.ir import AddressStatus, MemSpace
import inertia.lowering.callee_argument_width_evidence as width_module
from inertia.lowering.callee_argument_count_evidence import (
    CalleeArgumentCountEvidence8616,
    CalleeArgumentCountVerdict8616,
)
from inertia.lowering.callee_argument_width_evidence import (
    CalleeArgumentWidthVerdict8616,
    collect_callee_argument_width_evidence_8616,
)


def _summary(
    callsite_addr: int,
    *,
    widths_in_push_order: tuple[int, ...],
) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=0x200,
        return_addr=callsite_addr + 3,
        kind="near",
        arg_count=len(widths_in_push_order),
        arg_widths=widths_in_push_order,
        stack_cleanup=sum(widths_in_push_order),
        return_register=None,
        return_used=False,
        push_arg_sources=tuple(
            ("imm", index) for index in range(len(widths_in_push_order))
        ),
    )


def _count_evidence(
    summaries: tuple[CallsiteSummary8616, ...],
    *,
    argument_count: int,
) -> CalleeArgumentCountEvidence8616:
    count = len(summaries)
    return CalleeArgumentCountEvidence8616(
        target_addr=0x200,
        verdict=CalleeArgumentCountVerdict8616.CONSISTENT,
        argument_count=argument_count,
        raw_fact_count=count,
        normalized_fact_count=count,
        classified_fact_count=count,
        materialized_count=count,
        callsite_summaries=summaries,
    )


def test_width_contract_maps_source_order_to_exact_ss_bp_storage(monkeypatch) -> None:
    count_evidence = _count_evidence(
        (_summary(0x110, widths_in_push_order=(2, 4)),),
        argument_count=2,
    )
    monkeypatch.setattr(
        width_module,
        "collect_callee_argument_count_evidence_8616",
        lambda _project, _target: count_evidence,
    )

    evidence = collect_callee_argument_width_evidence_8616(SimpleNamespace(), 0x200)

    assert evidence.verdict is CalleeArgumentWidthVerdict8616.CONSISTENT
    assert evidence.closes_census is True
    assert evidence.argument_widths == (4, 2)
    assert tuple(
        (address.space, address.base, address.offset, address.size, address.status)
        for address in evidence.argument_storage
    ) == (
        (MemSpace.SS, ("bp",), 4, 4, AddressStatus.STABLE),
        (MemSpace.SS, ("bp",), 8, 2, AddressStatus.STABLE),
    )


def test_width_contract_consumes_explicit_logical_widths_over_physical_pushes(monkeypatch) -> None:
    summary = replace(
        _summary(0x110, widths_in_push_order=(2, 2)),
        logical_arg_widths=(4,),
    )
    count_evidence = _count_evidence((summary,), argument_count=1)
    monkeypatch.setattr(
        width_module,
        "collect_callee_argument_count_evidence_8616",
        lambda _project, _target: count_evidence,
    )

    evidence = collect_callee_argument_width_evidence_8616(SimpleNamespace(), 0x200)

    assert evidence.closes_census is True
    assert evidence.argument_widths == (4,)
    assert evidence.widths_by_offset == ((4, 4),)


def test_width_contract_accepts_proven_zero_argument_census(monkeypatch) -> None:
    count_evidence = _count_evidence(
        (_summary(0x110, widths_in_push_order=()),),
        argument_count=0,
    )
    monkeypatch.setattr(
        width_module,
        "collect_callee_argument_count_evidence_8616",
        lambda _project, _target: count_evidence,
    )

    evidence = collect_callee_argument_width_evidence_8616(SimpleNamespace(), 0x200)

    assert evidence.closes_census is True
    assert evidence.argument_count == 0
    assert evidence.argument_storage == ()
    assert evidence.argument_widths == ()


def test_width_contract_refuses_incomplete_count_census(monkeypatch) -> None:
    incomplete = CalleeArgumentCountEvidence8616(
        target_addr=0x200,
        verdict=CalleeArgumentCountVerdict8616.UNKNOWN,
        raw_fact_count=2,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=1,
        callsite_summaries=(_summary(0x110, widths_in_push_order=(2,)),),
    )
    monkeypatch.setattr(
        width_module,
        "collect_callee_argument_count_evidence_8616",
        lambda _project, _target: incomplete,
    )

    evidence = collect_callee_argument_width_evidence_8616(SimpleNamespace(), 0x200)

    assert evidence.verdict is CalleeArgumentWidthVerdict8616.UNKNOWN
    assert evidence.closes_census is False
    assert evidence.argument_storage == ()
    assert evidence.argument_widths == ()
