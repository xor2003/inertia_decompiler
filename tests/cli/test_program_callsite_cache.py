"""Tests for persistent typed program callsite evidence."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.semantics.callsite_summary_program import (
    ProgramCallsiteSummaryFact8616,
    program_callsite_summary_evidence_from_facts_8616,
)
from inertia.lowering.callee_callsite_contracts import (
    CalleeCallsiteCensus8616,
    CalleeCallsiteFact8616,
    attach_callee_callsite_censuses_8616,
    callee_callsite_censuses_by_addr_8616,
)

import inertia.cli.cache as recovery_cache_module
import inertia.cli.program_callsite_cache as cache_module
from inertia.cli.cache_source_manifest import (
    PROGRAM_CALLSITE_CACHE_SOURCE_FILES,
    RecoveryCacheSourceScope8616,
)
from inertia.cli.program_callsite_cache import (
    PersistedProgramCallsiteEvidence8616,
    attach_program_callsite_evidence_8616,
    load_program_callsite_cache_8616,
    program_callsite_evidence_from_project_8616,
    store_program_callsite_cache_8616,
)


def _summary() -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x110,
        target_addr=0x200,
        return_addr=0x113,
        kind="near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
    )


def _attach_source_evidence(
    project: object,
    *,
    include_caller_ranges: bool = True,
) -> None:
    if include_caller_ranges:
        cast(
            SimpleNamespace,
            project,
        )._inertia_caller_function_ranges_8616 = ((0x100, 0x120),)
    summary = _summary()
    fact = CalleeCallsiteFact8616(
        evidence_project=project,
        caller_function=SimpleNamespace(addr=0x100),
        evidence_target_addr=0x200,
        caller_addr=0x100,
        callsite_addr=0x110,
        summary=summary,
    )
    attach_callee_callsite_censuses_8616(
        project,
        {
            0x200: CalleeCallsiteCensus8616(
                target_addr=0x200,
                facts=(fact,),
                raw_fact_count=1,
                normalized_fact_count=1,
                failure_count=0,
            )
        },
    )
    summaries = program_callsite_summary_evidence_from_facts_8616(
        (ProgramCallsiteSummaryFact8616(0x100, 0x110, summary),)
    )
    cache_module.attach_program_callsite_summary_evidence_8616(project, summaries)


def test_program_callsite_cache_round_trip_rebinds_active_project(monkeypatch) -> None:
    source = SimpleNamespace()
    _attach_source_evidence(source)
    evidence = program_callsite_evidence_from_project_8616(source)
    stored: dict[str, object] = {}

    def store(_namespace: str, _key: dict[str, object], record: dict[str, object]) -> None:
        stored.update(record)

    monkeypatch.setattr(cache_module, "_store_cache_json", store)
    store_program_callsite_cache_8616({"binary": "fixture"}, source, evidence)

    destination = SimpleNamespace()
    monkeypatch.setattr(
        cache_module,
        "_load_cache_json",
        lambda _namespace, _key: stored,
    )
    restored = load_program_callsite_cache_8616(
        {"binary": "fixture"},
        destination,
    )

    assert restored is not None
    attach_program_callsite_evidence_8616(destination, restored)
    census = callee_callsite_censuses_by_addr_8616(destination)[0x200]
    assert census.complete is True
    assert census.facts[0].evidence_project is destination
    assert census.facts[0].caller_function is None
    assert destination._inertia_caller_function_ranges_8616 == ((0x100, 0x120),)
    assert restored.summaries.facts[0].summary == _summary()


def test_program_callsite_cache_refuses_incoherent_projection() -> None:
    project = SimpleNamespace()
    _attach_source_evidence(project)
    evidence = program_callsite_evidence_from_project_8616(project)
    incoherent = PersistedProgramCallsiteEvidence8616(
        evidence.caller_ranges,
        evidence.censuses_by_target,
        program_callsite_summary_evidence_from_facts_8616(
            (
                ProgramCallsiteSummaryFact8616(
                    0x100,
                    0x110,
                    replace(_summary(), push_arg_sources=(("imm", 7),)),
                ),
            )
        ),
    )

    assert incoherent.closed is False
    with pytest.raises(ValueError, match="projection is incoherent"):
        attach_program_callsite_evidence_8616(SimpleNamespace(), incoherent)


def test_program_callsite_cache_refuses_missing_or_changed_range_coverage() -> None:
    missing = SimpleNamespace()
    _attach_source_evidence(missing, include_caller_ranges=False)
    with pytest.raises(ValueError, match="no complete caller-range evidence"):
        program_callsite_evidence_from_project_8616(missing)

    source = SimpleNamespace()
    _attach_source_evidence(source)
    evidence = program_callsite_evidence_from_project_8616(source)
    destination = SimpleNamespace(
        _inertia_caller_function_ranges_8616=((0x200, 0x220),)
    )
    with pytest.raises(ValueError, match="caller-range coverage changed"):
        attach_program_callsite_evidence_8616(destination, evidence)


def test_program_callsite_cache_uses_narrow_source_scope(
    monkeypatch,
    tmp_path: Path,
) -> None:
    binary = tmp_path / "fixture.exe"
    binary.write_bytes(b"MZ-program-callsites")
    observed_sources: list[tuple[Path, ...]] = []
    monkeypatch.setattr(
        recovery_cache_module,
        "_cache_source_digest",
        lambda paths: observed_sources.append(paths) or "program-callsite-digest",
    )

    key = recovery_cache_module._recovery_cache_key(
        binary_path=binary,
        kind="program_callsite_evidence",
        source_scope=RecoveryCacheSourceScope8616.PROGRAM_CALLSITE,
    )

    relative_paths = {
        path.relative_to(Path(__file__).resolve().parents[2]).as_posix()
        for path in PROGRAM_CALLSITE_CACHE_SOURCE_FILES
    }
    assert key is not None
    assert observed_sources == [PROGRAM_CALLSITE_CACHE_SOURCE_FILES]
    assert (
        "inertia/lowering/"
        "project_callee_callsite_collection.py"
    ) in relative_paths
    assert (
        "inertia/lowering/"
        "register_local_declarations.py"
    ) not in relative_paths
    assert {
        "inertia/alias/callsite_stack_merge.py",
        "inertia/alias/domains.py",
        "inertia/alias/partial_register_address_break.py",
        "inertia/alias/register_reaching_source.py",
    } <= relative_paths
    assert (
        "inertia/alias/stack_coordinate_projection.py"
        not in relative_paths
    )
