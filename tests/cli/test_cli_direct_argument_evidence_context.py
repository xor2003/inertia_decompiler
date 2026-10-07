from __future__ import annotations

from types import SimpleNamespace

from inertia.semantics.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)

from inertia.cli import cli_function_discovery


def test_direct_argument_context_attaches_framed_ranges_and_entry_aliases(monkeypatch) -> None:
    source_project = SimpleNamespace()
    target_project = SimpleNamespace()
    evidence_project = SimpleNamespace()
    ranges = ((0x1000, 0x1080), (0x1100, 0x1180))

    monkeypatch.setattr(
        cli_function_discovery,
        "isolated_discovery_evidence_project_8616",
        lambda project: evidence_project,
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "_rank_pre_entry_source_function_seeds_8616",
        lambda project: (0x1000, 0x1100),
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "_binary_padding_entry_aliases_8616",
        lambda project, seed: (seed, seed + 0x10),
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "_pre_entry_source_function_ranges_8616",
        lambda project, seeds: ranges,
    )

    attached = cli_function_discovery.attach_direct_target_argument_evidence_context_8616(
        source_project,
        target_project,
        0x1010,
    )

    assert attached is True
    assert target_project._inertia_caller_function_ranges_8616 == ranges
    assert target_project._inertia_caller_target_aliases_8616 == (0x1000, 0x1010)


def test_direct_argument_context_refuses_unknown_target(monkeypatch) -> None:
    project = SimpleNamespace()
    monkeypatch.setattr(
        cli_function_discovery,
        "isolated_discovery_evidence_project_8616",
        lambda source: project,
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "_rank_pre_entry_source_function_seeds_8616",
        lambda source: (0x1000,),
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "_binary_padding_entry_aliases_8616",
        lambda source, seed: (seed,),
    )

    assert (
        cli_function_discovery.attach_direct_target_argument_evidence_context_8616(
            project,
            SimpleNamespace(),
            0x2000,
        )
        is False
    )


def test_direct_argument_context_accepts_nonseed_with_closed_caller_evidence(
    monkeypatch,
) -> None:
    source_project = SimpleNamespace()
    target_project = SimpleNamespace()
    evidence_project = SimpleNamespace()
    target_addr = 0x2000
    ranges = ((0x1000, 0x1080),)
    caller_evidence = CallerReturnUseEvidence8616(
        target_addr=target_addr,
        verdict=CallerReturnUseVerdict8616.USED,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1,
        failure_count=0,
        used_callsite_count=1,
        unused_callsite_count=0,
        callsite_addrs=(0x1010,),
        facts=(
            CallerReturnUseFact8616(
                caller_addr=0x1000,
                callsite_addr=0x1010,
                verdict=CallerReturnUseVerdict8616.USED,
                kind=CallsiteReturnUseKind8616.VALUE,
                witness_instruction_addr=0x1013,
            ),
        ),
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "isolated_discovery_evidence_project_8616",
        lambda project: evidence_project,
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "_rank_pre_entry_source_function_seeds_8616",
        lambda project: (0x1000,),
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "_binary_padding_entry_aliases_8616",
        lambda project, seed: (seed,),
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "_pre_entry_source_function_ranges_8616",
        lambda project, seeds: ranges,
    )
    original_evidence_lookup = cli_function_discovery.caller_return_use_evidence_by_addr_8616
    monkeypatch.setattr(
        cli_function_discovery,
        "caller_return_use_evidence_by_addr_8616",
        lambda project: {target_addr: caller_evidence}
        if project is source_project else original_evidence_lookup(project),
    )

    assert cli_function_discovery.attach_direct_target_argument_evidence_context_8616(
        source_project,
        target_project,
        target_addr,
    )
    assert target_project._inertia_caller_function_ranges_8616 == ranges
    assert target_project._inertia_caller_target_aliases_8616 == (target_addr,)
    assert cli_function_discovery.caller_return_use_evidence_by_addr_8616(target_project)[target_addr] == caller_evidence
