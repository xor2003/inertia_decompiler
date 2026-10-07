from __future__ import annotations

from types import SimpleNamespace

import inertia.cli.project_argument_evidence_ranges as ranges_module


def test_project_argument_ranges_publish_only_closed_complete_census(
    monkeypatch,
) -> None:
    source = SimpleNamespace()
    destination = SimpleNamespace()
    monkeypatch.setattr(
        ranges_module,
        "isolated_discovery_evidence_project_8616",
        lambda project: project,
    )
    monkeypatch.setattr(
        ranges_module,
        "_rank_pre_entry_source_function_seeds_8616",
        lambda _project: [0x100, 0x120],
    )
    monkeypatch.setattr(
        ranges_module,
        "_pre_entry_source_function_ranges_8616",
        lambda _project, _seeds: ((0x100, 0x120), (0x120, 0x140), (0x200, 0x220)),
    )

    result = ranges_module.attach_project_argument_evidence_ranges_8616(
        source,
        destination,
    )

    assert result.complete
    assert destination._inertia_caller_function_ranges_8616 == result.function_ranges


def test_project_argument_ranges_refuse_partial_census(monkeypatch) -> None:
    source = SimpleNamespace()
    destination = SimpleNamespace()
    monkeypatch.setattr(
        ranges_module,
        "isolated_discovery_evidence_project_8616",
        lambda project: project,
    )
    monkeypatch.setattr(
        ranges_module,
        "_rank_pre_entry_source_function_seeds_8616",
        lambda _project: [0x100, 0x120],
    )
    monkeypatch.setattr(
        ranges_module,
        "_pre_entry_source_function_ranges_8616",
        lambda _project, _seeds: ((0x100, 0x120),),
    )

    result = ranges_module.attach_project_argument_evidence_ranges_8616(
        source,
        destination,
    )

    assert not result.complete
    assert not hasattr(destination, "_inertia_caller_function_ranges_8616")
