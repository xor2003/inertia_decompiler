from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.semantics.callsite_summary_program import (
    program_callsite_summary_evidence_8616,
)
from inertia.semantics.callsite_target_inventory import (
    CallsiteTargetInventory8616,
)
import inertia.lowering.callee_callsite_census as callee_callsite_census
import inertia.lowering.callee_range_callsite_facts as range_facts
import inertia.lowering.project_callee_callsite_collection as collection
from inertia.lowering.callee_callsite_codec import (
    callee_callsite_census_map_from_record_8616,
    callee_callsite_census_map_record_8616,
)
from inertia.lowering.callee_callsite_contracts import (
    CalleeCallsiteCensus8616,
    CalleeCallsiteFact8616,
    attach_callee_callsite_censuses_8616,
    callee_callsite_censuses_by_addr_8616,
)

from inertia.lowering.analysis_helpers import (
    CallTargetKind8616,
    CallTargetSeed,
)
from inertia.semantics.callsite_summary_request import (
    CallsiteCleanupProjectRole8616,
    CallsiteSummaryRequestCache8616,
)
from inertia.semantics.terminal_stack_cleanup import (
    TerminalStackCleanupEvidence8616,
)


def _summary(callsite_addr: int, target_addr: int) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=callsite_addr,
        target_addr=target_addr,
        return_addr=callsite_addr + 3,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
        push_arg_sources=(("imm", 7),),
        push_arg_instruction_addrs=(callsite_addr - 2,),
    )


@pytest.mark.parametrize("canonical_target", [None, 0x2200])
def test_range_facts_require_resolved_canonical_target(monkeypatch, canonical_target):
    from capstone import CS_ARCH_X86, CS_MODE_16, Cs

    project = SimpleNamespace(
        arch=SimpleNamespace(capstone=Cs(CS_ARCH_X86, CS_MODE_16)),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda address, size: bytes.fromhex("e8 fd 10"))),
    )
    caller = SimpleNamespace(addr=0x1100, size=3)
    monkeypatch.setattr(range_facts, "exact_function_range_inventory_8616",
                        lambda *args: SimpleNamespace(boundaries=(caller,)))
    monkeypatch.setattr(range_facts, "canonicalize_x86_16_padding_call_target_8616",
                        lambda *args: canonical_target)
    monkeypatch.setattr(range_facts, "summarize_x86_16_callsite",
                        lambda *args: _summary(0x1100, 0x2200))
    ranges = ((0x1100, 0x1103),)
    indexed = range_facts._range_direct_calls_by_target_8616(project, ranges)
    facts = range_facts.collect_range_callsite_facts_8616(project, ranges)
    if canonical_target is None:
        assert indexed == {}
        assert facts == ()
    else:
        assert tuple(indexed) == (canonical_target,)
        assert len(facts) == 1
        assert facts[0].evidence_target_addr == canonical_target


def _census(project: object, target_addr: int = 0x2200) -> CalleeCallsiteCensus8616:
    fact = CalleeCallsiteFact8616(
        evidence_project=project,
        caller_function=SimpleNamespace(addr=0x1100),
        evidence_target_addr=target_addr,
        caller_addr=0x1100,
        callsite_addr=0x1110,
        summary=_summary(0x1110, target_addr),
    )
    return CalleeCallsiteCensus8616(target_addr, (fact,), 1, 1, 0)


def test_callee_callsite_codec_round_trips_and_rebinds_owner() -> None:
    source = SimpleNamespace()
    attach_callee_callsite_censuses_8616(source, {0x2200: _census(source)})
    record = callee_callsite_census_map_record_8616(source)
    decoded_json = json.loads(json.dumps(record, sort_keys=True))
    destination = SimpleNamespace()

    restored = callee_callsite_census_map_from_record_8616(
        destination,
        decoded_json,
    )

    fact = restored[0x2200].facts[0]
    assert fact.evidence_project is destination
    assert fact.caller_function is None
    assert fact.summary == _summary(0x1110, 0x2200)


def test_callee_callsite_codec_rejects_duplicate_targets() -> None:
    source = SimpleNamespace()
    attach_callee_callsite_censuses_8616(source, {0x2200: _census(source)})
    record = callee_callsite_census_map_record_8616(source)

    with pytest.raises(ValueError, match="duplicate targets"):
        callee_callsite_census_map_from_record_8616(
            SimpleNamespace(),
            [record[0], record[0]],
        )


def test_complete_project_collection_scans_each_function_once_and_publishes_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = SimpleNamespace()
    functions = (SimpleNamespace(addr=0x1100, size=0x30),)
    targets = (
        CallTargetSeed(
            0x1110,
            0x2200,
            0x1113,
            CallTargetKind8616.DIRECT_NEAR_CALL,
        ),
        CallTargetSeed(
            0x1120,
            0x2200,
            0x1123,
            CallTargetKind8616.DIRECT_NEAR_CALL,
        ),
    )
    calls = {"neighbors": 0, "summaries": 0, "ranges": 0}

    def neighbors(_function: object) -> list[CallTargetSeed]:
        calls["neighbors"] += 1
        return list(targets)

    def summarize(
        _function: object,
        callsite_addr: int,
        *,
        target_inventory: CallsiteTargetInventory8616,
        request_cache: CallsiteSummaryRequestCache8616,
    ) -> CallsiteSummary8616:
        calls["summaries"] += 1
        assert target_inventory.seeds == targets
        assert isinstance(request_cache, CallsiteSummaryRequestCache8616)
        return _summary(callsite_addr, 0x2200)

    def range_facts(
        _project: object,
        _ranges: tuple[tuple[int, int], ...],
        *,
        excluded_fact_keys: frozenset[tuple[int, int]],
    ) -> tuple[CalleeCallsiteFact8616, ...]:
        calls["ranges"] += 1
        assert excluded_fact_keys == frozenset(
            {(0x2200, 0x1110), (0x2200, 0x1120)}
        )
        return ()

    monkeypatch.setattr(collection, "collect_neighbor_call_targets", neighbors)
    monkeypatch.setattr(collection, "summarize_x86_16_callsite", summarize)
    monkeypatch.setattr(collection, "collect_range_callsite_facts_8616", range_facts)

    result = collection.collect_complete_project_callee_callsites_8616(
        project,
        functions,
    )

    assert result.target_addrs == (0x2200,)
    assert result.raw_fact_count == result.materialized_count == 2
    assert result.failure_count == 0
    assert result.summary_request_stats.raw_fact_count == 0
    assert calls == {"neighbors": 1, "summaries": 2, "ranges": 1}
    program_summaries = program_callsite_summary_evidence_8616(project)
    assert program_summaries is not None
    assert program_summaries.materialized_count == 2
    assert program_summaries.facts[0].caller_addr == 0x1100
    assert program_summaries.facts[0].callsite_addr == 0x1110
    monkeypatch.setattr(
        callee_callsite_census,
        "collect_neighbor_call_targets",
        lambda _function: pytest.fail("cached census must not rescan functions"),
    )
    assert callee_callsite_census.collect_callee_callsite_census_8616(
        project,
        0x2200,
    ) == callee_callsite_censuses_by_addr_8616(project)[0x2200]


def test_summary_request_reuses_typed_refusal_with_closed_accounting() -> None:
    cache = CallsiteSummaryRequestCache8616()
    refusal = TerminalStackCleanupEvidence8616(
        frozenset(),
        1,
        0,
        0,
        0,
        1,
    )
    calls = 0

    def collect() -> TerminalStackCleanupEvidence8616:
        nonlocal calls
        calls += 1
        return refusal

    first = cache.terminal_cleanup(
        CallsiteCleanupProjectRole8616.CURRENT,
        0x2200,
        collect,
    )
    second = cache.terminal_cleanup(
        CallsiteCleanupProjectRole8616.CURRENT,
        0x2200,
        collect,
    )

    assert first is second is refusal
    assert calls == 1
    stats = cache.stats()
    assert stats.raw_fact_count == stats.materialized_count == 2
    assert stats.build_count == stats.reuse_count == 1
