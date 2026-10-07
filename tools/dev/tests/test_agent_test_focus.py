from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Final

import pytest

from tools.dev import agent_test_focus

_REPO_FILES: Final[tuple[str, ...]] = (
    "inertia/lowering/analysis_helpers.py",
    "inertia/frontend/x86_16/calling_convention_compat.py",
    "inertia/structuring/decompiler_structuring_stage.py",
)


def test_extract_layer_from_docstring_prefers_structuring() -> None:
    assert (
        agent_test_focus._extract_layer_from_docstring(
            "inertia/structuring/decompiler_structuring_stage.py",
        )
        == "structuring"
    )


def test_infer_layers_for_structuring_stage_is_structuring() -> None:
    assert "structuring" in agent_test_focus._infer_layers_for_path(_REPO_FILES[2])


def test_plan_can_skip_shared_baseline_for_focused_runs() -> None:
    plans = agent_test_focus._plan("frontend", (_REPO_FILES[1],), include_shared=False)
    assert plans
    assert plans[-1].layer != "shared-baseline"


def test_main_outputs_json_when_requested(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = agent_test_focus.main(["--files", _REPO_FILES[0], "--no-infer-changed", "--json"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out
    start = captured.out.find("{")
    end = captured.out.rfind("}")
    payload = json.loads(captured.out[start:end + 1])
    assert payload["selected_tests"]
    assert payload["plans"]
    assert payload["selected_tests_with_reasons"]


def test_materialized_test_reasons_for_shared_and_focused_tests() -> None:
    plans = agent_test_focus._plan("frontend", (_REPO_FILES[0],), include_shared=False)
    selected = agent_test_focus._materialize_selected_tests(plans)
    assert selected
    reasons = {entry.reason for entry in selected}
    assert "layer-anchor" in reasons


def test_json_only_requires_json_flag() -> None:
    with pytest.raises(SystemExit):
        agent_test_focus.main(["--json-only"])


def test_json_payload_observes_max_tests_with_reasons(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = agent_test_focus.main(
        [
            "--files",
            *_REPO_FILES,
            "--no-infer-changed",
            "--json",
            "--run",
            "--max-tests",
            "1",
            "--no-shared",
        ]
    )
    assert exit_code == 0
    captured = capsys.readouterr()
    start = captured.out.find("{")
    end = captured.out.rfind("}")
    payload = json.loads(captured.out[start:end + 1])
    assert payload["truncated"]
    assert payload["max_tests"] == 1
    assert len(payload["selected_tests"]) == 1
    assert len(payload["selected_tests_with_reasons"]) == 1


def test_main_respects_max_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = SimpleNamespace(tests=())

    def _capture(selected_tests: tuple[str, ...], _args: object) -> int:
        captured.tests = selected_tests
        return 0

    monkeypatch.setattr(agent_test_focus, "_run_pytest", _capture)
    exit_code = agent_test_focus.main(
        [
            "--files",
            *_REPO_FILES,
            "--no-infer-changed",
            "--run",
            "--max-tests",
            "2",
            "--no-shared",
        ]
    )

    assert exit_code == 0
    assert len(captured.tests) == 2


def test_compiler_tool_context_selects_local_regression(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = agent_test_focus.main([
        "--files", "tools/compiler_id/report.py", "--context", "--json", "--json-only", "--no-shared",
    ])
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["selected_tests"] == ["tools/compiler_id/tests/test_flags.py"]
    assert payload["context"]["owners"][0]["name"] == "compiler_detector"


def test_comparator_has_explicit_routing() -> None:
    assert "comparator" in agent_test_focus._infer_layers_for_path("tools/dosunit/compare/straightline_ssa.py")
