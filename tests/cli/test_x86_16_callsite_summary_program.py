"""Tests for caller-indexed program callsite summary evidence."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
import inertia.semantics.callsite_summary_program as program_module
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.semantics.callsite_summary_program import (
    ProgramCallsiteSummaryFact8616,
    attach_program_callsite_summary_evidence_8616,
    build_callsite_summary_inventory_with_program_evidence_8616,
    program_callsite_summary_evidence_from_facts_8616,
    retained_program_callsite_summary_inventory_8616,
)
from inertia.semantics.callsite_summary_program_codec import (
    program_callsite_summary_evidence_from_record_8616,
    program_callsite_summary_evidence_record_8616,
)


def _summary(callsite_addr: int, target_addr: int = 0x200) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr,
        target_addr,
        callsite_addr + 3,
        "direct_near",
        0,
        (),
        0,
        None,
        False,
    )


def test_program_callsite_summary_codec_round_trips_exact_facts() -> None:
    evidence = program_callsite_summary_evidence_from_facts_8616(
        (
            ProgramCallsiteSummaryFact8616(0x100, 0x110, _summary(0x110)),
            ProgramCallsiteSummaryFact8616(0x100, 0x120, None),
        )
    )

    restored = program_callsite_summary_evidence_from_record_8616(
        json.loads(
            json.dumps(program_callsite_summary_evidence_record_8616(evidence))
        )
    )

    assert restored == evidence
    assert restored.raw_fact_count == 2
    assert restored.classified_fact_count == restored.materialized_count == 1
    assert restored.failure_count == 1


def test_program_summary_inventory_builds_only_missing_callsites(monkeypatch) -> None:
    project = SimpleNamespace()
    evidence = program_callsite_summary_evidence_from_facts_8616(
        (ProgramCallsiteSummaryFact8616(0x100, 0x110, _summary(0x110)),)
    )
    attach_program_callsite_summary_evidence_8616(project, evidence)
    calls: list[tuple[int, ...]] = []

    def build_missing(_function: object, addresses: tuple[int, ...]) -> dict[int, CallsiteSummary8616]:
        calls.append(addresses)
        return {address: _summary(address, 0x300) for address in addresses}

    monkeypatch.setattr(
        program_module,
        "build_callsite_summary_inventory_8616",
        build_missing,
    )

    inventory = build_callsite_summary_inventory_with_program_evidence_8616(
        project,
        SimpleNamespace(addr=0x100),
        (0x110, 0x120),
    )

    assert calls == [(0x120,)]
    assert inventory[0x110].target_addr == 0x200
    assert inventory[0x120].target_addr == 0x300


def test_retained_program_summary_inventory_does_not_build_missing_callsites() -> None:
    project = SimpleNamespace()
    evidence = program_callsite_summary_evidence_from_facts_8616(
        (ProgramCallsiteSummaryFact8616(0x100, 0x110, _summary(0x110)),)
    )
    attach_program_callsite_summary_evidence_8616(project, evidence)

    inventory = retained_program_callsite_summary_inventory_8616(
        project,
        SimpleNamespace(addr=0x100),
        (0x110, 0x120),
    )

    assert inventory == {0x110: _summary(0x110)}


def test_program_callsite_summary_refuses_conflicting_coordinate() -> None:
    with pytest.raises(ValueError, match="conflicting summaries"):
        program_callsite_summary_evidence_from_facts_8616(
            (
                ProgramCallsiteSummaryFact8616(0x100, 0x110, _summary(0x110)),
                ProgramCallsiteSummaryFact8616(
                    0x100,
                    0x110,
                    _summary(0x110, 0x300),
                ),
            )
        )
