from __future__ import annotations

from types import SimpleNamespace

from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.semantics.callsite_summary_program import (
    ProgramCallsiteSummaryFact8616,
    attach_program_callsite_summary_evidence_8616,
    program_callsite_summary_evidence_8616,
    program_callsite_summary_evidence_from_facts_8616,
)
from inertia.lowering.callee_callsite_contracts import (
    CalleeCallsiteCensus8616,
    CalleeCallsiteFact8616,
    attach_callee_callsite_censuses_8616,
    callee_callsite_censuses_by_addr_8616,
)

from inertia.cli.project_evidence_transport import (
    transfer_callee_callsite_censuses_8616,
    transfer_program_callsite_summary_evidence_8616,
)


def test_project_callee_callsite_transfer_adds_rebased_target_alias() -> None:
    source = SimpleNamespace()
    summary = CallsiteSummary8616(
        0x10110,
        0x10808,
        0x10113,
        "direct_near",
        0,
        (),
        0,
        None,
        False,
    )
    fact = CalleeCallsiteFact8616(
        source,
        SimpleNamespace(addr=0x10100),
        0x10808,
        0x10100,
        0x10110,
        summary,
    )
    census = CalleeCallsiteCensus8616(0x10808, (fact,), 1, 1, 0)
    attach_callee_callsite_censuses_8616(source, {0x10808: census})
    destination = SimpleNamespace(
        _inertia_original_project=source,
        _inertia_original_linear_delta=0xF808,
    )

    assert transfer_callee_callsite_censuses_8616(source, destination) == 1

    transported = callee_callsite_censuses_by_addr_8616(destination)
    assert set(transported) == {0x1000, 0x10808}
    assert transported[0x1000].facts == census.facts
    assert transported[0x1000].facts[0].evidence_project is source


def test_project_transport_copies_program_callsite_summaries() -> None:
    source = SimpleNamespace()
    summary = CallsiteSummary8616(
        0x110,
        0x200,
        0x113,
        "direct_near",
        0,
        (),
        0,
        None,
        False,
    )
    attach_program_callsite_summary_evidence_8616(
        source,
        program_callsite_summary_evidence_from_facts_8616(
            (ProgramCallsiteSummaryFact8616(0x100, 0x110, summary),)
        ),
    )
    destination = SimpleNamespace()

    assert transfer_program_callsite_summary_evidence_8616(source, destination) == 1
    assert program_callsite_summary_evidence_8616(destination) == (
        program_callsite_summary_evidence_8616(source)
    )
