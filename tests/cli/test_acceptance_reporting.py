"""Acceptance reporting preserves semantic evidence while closing rejected gates."""

from __future__ import annotations

import copy
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

import inertia.cli.tail_validation as TV
from inertia.cli.work_items import FunctionWorkItem, FunctionWorkResult, WorkItemStatus


def _clean_snapshot() -> dict[str, object]:
    """Return a snapshot whose structuring and postprocess stages are stable."""
    return {
        "structuring": {"status": "stable", "changed": False, "mode": "live_out"},
        "postprocess": {"status": "stable", "changed": False, "mode": "live_out"},
    }


def _changed_snapshot() -> dict[str, object]:
    """Return a snapshot whose postprocess stage reports a semantic change."""
    return {
        "structuring": {"status": "stable", "changed": False, "mode": "live_out"},
        "postprocess": {
            "status": "changed",
            "changed": True,
            "mode": "live_out",
            "verdict": "postprocess changed",
        },
    }


def _work_setup(
    tmp_path: Path,
    *,
    index: int,
    status: WorkItemStatus,
    snapshot: dict[str, object] | None,
    name: str = "_DisplayMaster",
) -> tuple[FunctionWorkItem, FunctionWorkResult]:
    """Build one real work item/result pair around dynamic-boundary doubles."""
    # Dynamic angr boundary: function/project are angr-managed attribute carriers,
    # so SimpleNamespace stands in exactly like the existing CLI tests do.
    project = SimpleNamespace(
        _inertia_tail_validation_enabled=True,
        filename=str(tmp_path / "COCKPIT.COD"),
    )
    function = SimpleNamespace(addr=0x10010 + index, name=name, project=project)
    function_cfg = SimpleNamespace()
    item = FunctionWorkItem(index=index, function_cfg=function_cfg, function=function)
    result = FunctionWorkResult(
        index=index,
        status=status.value,
        payload="",
        debug_output="",
        function=function,
        function_cfg=function_cfg,
        tail_validation=copy.deepcopy(snapshot) if snapshot is not None else None,
    )
    return item, result


def _as_str_mapping(value: object) -> Mapping[str, object]:
    assert isinstance(value, Mapping)
    return cast(Mapping[str, object], value)


def _as_mapping_rows(value: object) -> list[Mapping[str, object]]:
    assert isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))
    return [cast(Mapping[str, object], row) for row in value if isinstance(row, Mapping)]


@pytest.fixture
def emitted_summaries(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    """Capture the real keyword payload handed to the surface emitter."""
    captured: list[dict[str, object]] = []

    def _capture(**kwargs: object) -> None:
        captured.append(dict(kwargs))

    monkeypatch.setattr(TV, "emit_tail_validation_surface_summary", _capture)
    return captured


def _emit_single(
    tmp_path: Path,
    function_tasks: Sequence[FunctionWorkItem],
    result_map: Mapping[int, FunctionWorkResult],
    captured: list[dict[str, object]],
) -> dict[str, object]:
    """Run the public console entry point and return the emitted kwargs."""
    binary = tmp_path / "COCKPIT.COD"
    binary.write_bytes(b"PROC")
    before = len(captured)
    TV.emit_tail_validation_console_summary(function_tasks, result_map, binary_path=binary)
    assert len(captured) == before + 1
    return captured[-1]


def test_public_emit_tail_validation_console_summary_is_exposed() -> None:
    """The staged module must keep the public emit entry points callable."""
    assert callable(TV.emit_tail_validation_console_summary)
    assert callable(TV.emit_tail_validation_surface_summary)


def test_validation_failed_with_clean_snapshot_reports_acceptance_failure(
    tmp_path: Path, emitted_summaries: list[dict[str, object]]
) -> None:
    """VALIDATION_FAILED + clean semantic snapshot: gate held, headline honest.

    Expected red on the saved baseline, which exempts this case and emits the
    clean surface. The overlay must not relabel the semantic verdict as
    ``changed`` and must preserve every snapshot status and count.
    """
    snapshot = _clean_snapshot()
    snapshot_before = copy.deepcopy(snapshot)
    item, result = _work_setup(
        tmp_path, index=1, status=WorkItemStatus.VALIDATION_FAILED, snapshot=snapshot
    )

    emitted = _emit_single(tmp_path, [item], {1: result}, emitted_summaries)
    surface = _as_str_mapping(emitted["surface"])
    summary = _as_str_mapping(emitted["summary"])

    assert surface["severity"] == "acceptance_failed"
    assert surface["merge_gate"] is False
    assert isinstance(surface["merge_gate"], bool)
    assert bool(surface.get("merge_gate", False)) is False
    headline = str(surface["headline"])
    assert "acceptance failed" in headline
    assert "semantic tail checks clean" in headline
    assert "1 functions" in headline

    # Semantic evidence must survive the acceptance overlay untouched.
    assert summary["severity"] == "clean"
    assert surface["changed_function_count"] == 0
    assert surface["passed_function_count"] == 1
    records = _as_mapping_rows(emitted["records"])
    assert len(records) == 1
    assert _as_str_mapping(records[0]["structuring"])["status"] == "stable"
    assert _as_str_mapping(records[0]["postprocess"])["status"] == "stable"

    # Caller-owned inputs are never mutated by the overlay.
    assert result.tail_validation == snapshot_before
    assert snapshot == snapshot_before
    assert result.status == WorkItemStatus.VALIDATION_FAILED.value


def test_validation_failed_with_changed_snapshot_keeps_semantic_verdict(
    tmp_path: Path, emitted_summaries: list[dict[str, object]]
) -> None:
    """A real semantic mismatch keeps its own honest headline and bool gate."""
    item, result = _work_setup(
        tmp_path, index=1, status=WorkItemStatus.VALIDATION_FAILED, snapshot=_changed_snapshot()
    )

    emitted = _emit_single(tmp_path, [item], {1: result}, emitted_summaries)
    surface = _as_str_mapping(emitted["surface"])

    assert surface["severity"] == "changed"
    assert surface["merge_gate"] is False
    assert isinstance(surface["merge_gate"], bool)
    assert str(surface["headline"]) == "whole-tail validation failed across 1 functions"
    assert surface["changed_function_count"] == 1


def test_ok_result_with_clean_snapshot_stays_clean(
    tmp_path: Path, emitted_summaries: list[dict[str, object]]
) -> None:
    """Positive case: an accepted clean run keeps the clean surface unchanged."""
    item, result = _work_setup(
        tmp_path, index=1, status=WorkItemStatus.OK, snapshot=_clean_snapshot()
    )

    emitted = _emit_single(tmp_path, [item], {1: result}, emitted_summaries)
    surface = _as_str_mapping(emitted["surface"])

    assert surface["severity"] == "clean"
    assert surface["merge_gate"] is True
    assert isinstance(surface["merge_gate"], bool)
    assert str(surface["headline"]) == "whole-tail validation clean across 1 functions"
    assert surface.get("acceptance_validation_failed") is not True


def test_uncollected_result_keeps_uncollected_surface(
    tmp_path: Path, emitted_summaries: list[dict[str, object]]
) -> None:
    """Uncollected case: a missing snapshot stays an aggregate-owned verdict."""
    item, result = _work_setup(
        tmp_path, index=1, status=WorkItemStatus.UNCOLLECTED, snapshot=None
    )

    emitted = _emit_single(tmp_path, [item], {1: result}, emitted_summaries)
    surface = _as_str_mapping(emitted["surface"])

    assert surface["severity"] == "uncollected"
    assert surface["merge_gate"] is False
    assert isinstance(surface["merge_gate"], bool)
    assert str(surface["headline"]) == "whole-tail validation not collected across 1 functions"
    assert surface.get("acceptance_validation_failed") is not True


def test_acceptance_failure_scans_all_results(
    tmp_path: Path, emitted_summaries: list[dict[str, object]]
) -> None:
    """Multiple results: one VALIDATION_FAILED among clean results still blocks."""
    tasks: list[FunctionWorkItem] = []
    result_map: dict[int, FunctionWorkResult] = {}
    for index, status in (
        (1, WorkItemStatus.OK),
        (2, WorkItemStatus.VALIDATION_FAILED),
        (3, WorkItemStatus.OK),
    ):
        item, result = _work_setup(
            tmp_path,
            index=index,
            status=status,
            snapshot=_clean_snapshot(),
            name=f"_proc_{index}",
        )
        tasks.append(item)
        result_map[index] = result

    emitted = _emit_single(tmp_path, tasks, result_map, emitted_summaries)
    surface = _as_str_mapping(emitted["surface"])

    assert emitted["scanned"] == 3
    assert len(_as_mapping_rows(emitted["records"])) == 3
    assert surface["severity"] == "acceptance_failed"
    assert surface["merge_gate"] is False
    assert isinstance(surface["merge_gate"], bool)
    assert "3 functions" in str(surface["headline"])
    assert surface["passed_function_count"] == 3
    assert surface["changed_function_count"] == 0


def test_acceptance_overlay_binds_to_console_and_detail_cache_salt(
    tmp_path: Path, emitted_summaries: list[dict[str, object]]
) -> None:
    """Accepted vs rejected runs over identical tails must not share cache keys.

    Expected red on the saved baseline, where the rejected clean run produces
    the same surface payload and therefore the same cache paths.
    """
    snapshot = _clean_snapshot()
    ok_item, ok_result = _work_setup(
        tmp_path, index=1, status=WorkItemStatus.OK, snapshot=snapshot
    )
    failed_item, failed_result = _work_setup(
        tmp_path, index=1, status=WorkItemStatus.VALIDATION_FAILED, snapshot=snapshot
    )

    accepted = _emit_single(tmp_path, [ok_item], {1: ok_result}, emitted_summaries)
    rejected = _emit_single(tmp_path, [failed_item], {1: failed_result}, emitted_summaries)

    accepted_console = accepted["console_cache_path"]
    rejected_console = rejected["console_cache_path"]
    accepted_detail = accepted["detail_cache_path"]
    rejected_detail = rejected["detail_cache_path"]
    assert isinstance(accepted_console, Path) and isinstance(rejected_console, Path)
    assert isinstance(accepted_detail, Path) and isinstance(rejected_detail, Path)
    assert accepted_console != rejected_console
    assert accepted_detail != rejected_detail
    assert _as_str_mapping(accepted["surface"]) != _as_str_mapping(rejected["surface"])


def test_emit_does_not_mutate_caller_state(
    tmp_path: Path, emitted_summaries: list[dict[str, object]]
) -> None:
    """The overlay copies the aggregate surface; caller inputs stay untouched."""
    snapshot = _clean_snapshot()
    snapshot_before = copy.deepcopy(snapshot)
    item, result = _work_setup(
        tmp_path, index=1, status=WorkItemStatus.VALIDATION_FAILED, snapshot=snapshot
    )
    result_map = {1: result}

    _emit_single(tmp_path, [item], result_map, emitted_summaries)

    assert result_map == {1: result}
    assert result.status == WorkItemStatus.VALIDATION_FAILED.value
    assert result.tail_validation == snapshot_before
    assert snapshot == snapshot_before
    assert item.index == 1
