from __future__ import annotations

from types import SimpleNamespace

import pytest

from inertia.widening.global_object_layout import (
    GlobalObjectLayoutEvidence8616,
)
import inertia.cli.indexed_alias_program_publication as indexed_publication


def test_complete_source_collection_runs_only_in_whole_file_parent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    program = SimpleNamespace()
    ranges = SimpleNamespace()
    layout = GlobalObjectLayoutEvidence8616((), 0, 0, 0, 0)
    function = SimpleNamespace(addr=0x1000)
    parent_project = SimpleNamespace()
    worker_project = SimpleNamespace()
    collections: list[object] = []
    monkeypatch.setattr(
        indexed_publication._alias_program_parallel,
        "build_discovered_indexed_alias_program_bounded_8616",
        lambda _project, _selections: program,
    )
    monkeypatch.setattr(
        indexed_publication,
        "recover_global_object_layout_evidence_8616",
        lambda _program: layout,
    )
    monkeypatch.setattr(
        indexed_publication,
        "recover_program_bounded_global_object_ranges_8616",
        lambda _program, _layout: ranges,
    )
    monkeypatch.setattr(
        indexed_publication,
        "collect_complete_project_global_object_sources_8616",
        lambda project, _functions, _layout: collections.append(project),
    )
    monkeypatch.setattr(
        indexed_publication,
        "collect_complete_project_callee_callsites_8616",
        lambda _project, _functions: None,
    )

    indexed_publication.publish_discovered_indexed_alias_program_8616(
        parent_project,
        (function,),
        target_project=worker_project,
    )
    assert collections == []

    indexed_publication.publish_discovered_indexed_alias_program_8616(
        parent_project,
        (function,),
    )
    assert collections == [parent_project]
