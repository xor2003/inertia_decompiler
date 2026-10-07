"""Tests for typed caller-census transport into isolated CLI workers."""

from __future__ import annotations

from types import SimpleNamespace

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

import inertia.cli.cli_core as cli_core


def test_serial_worker_round_trip_rebinds_callsite_evidence_owner(
    tmp_path,
    monkeypatch,
) -> None:
    """A clean worker receives the exact parent census without rediscovery."""
    source = SimpleNamespace()
    census = CalleeCallsiteCensus8616(
        target_addr=0x200,
        facts=(
            CalleeCallsiteFact8616(
                evidence_project=source,
                caller_function=None,
                evidence_target_addr=0x200,
                caller_addr=0x100,
                callsite_addr=0x110,
                summary=None,
            ),
        ),
        raw_fact_count=1,
        normalized_fact_count=0,
        failure_count=1,
    )
    attach_callee_callsite_censuses_8616(source, {0x200: census})
    attach_program_callsite_summary_evidence_8616(
        source,
        program_callsite_summary_evidence_from_facts_8616(
            (ProgramCallsiteSummaryFact8616(0x100, 0x110, None),)
        ),
    )
    evidence_path = tmp_path / "worker-evidence.json"

    assert cli_core._write_serial_clean_worker_evidence_8616(source, evidence_path) == 0

    destination = SimpleNamespace()
    monkeypatch.setenv(
        cli_core._SERIAL_CLEAN_WORKER_EVIDENCE_ENV_8616,
        str(evidence_path),
    )
    assert cli_core._hydrate_serial_clean_worker_evidence_8616(destination) == 0

    transported = callee_callsite_censuses_by_addr_8616(destination)[0x200]
    assert transported.raw_fact_count == 1
    assert transported.normalized_fact_count == 0
    assert transported.failure_count == 1
    assert transported.facts[0].evidence_project is destination
    assert transported.facts[0].callsite_addr == 0x110
    program_summaries = program_callsite_summary_evidence_8616(destination)
    assert program_summaries is not None
    assert program_summaries.facts[0].caller_addr == 0x100
    assert program_summaries.facts[0].callsite_addr == 0x110
