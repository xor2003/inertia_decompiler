from __future__ import annotations

from pathlib import Path

from meta_harness.config import LlmConfig, RuntimeConfig
from meta_harness.orchestrator import MetaHarness


def _make_cfg(monkeypatch, tmp_path: Path) -> tuple[RuntimeConfig, LlmConfig]:
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    cfg = RuntimeConfig.from_env([])
    llm_cfg = LlmConfig.from_env()
    return cfg, llm_cfg


def test_reviewer_step_prunes_completed_plan_items(monkeypatch, tmp_path):
    cfg, llm_cfg = _make_cfg(monkeypatch, tmp_path)
    cfg.plan_path.write_text(
        "1. Done: remove me.\n"
        "Why now: already completed.\n\n"
        "2. [pending] keep me.\n"
        "Why now: still active.\n",
        encoding="utf-8",
    )

    harness = MetaHarness(cfg, llm_cfg)
    log_file = tmp_path / "reviewer.log"

    def fake_run_role(role: str, model: str, prompt: str, *, resume: bool = False, resume_context: str = "") -> Path:
        log_file.write_text(
            "Task packet status: done\n"
            "Remaining steps: 1\n"
            "Green level: focused-item-green\n",
            encoding="utf-8",
        )
        return log_file

    monkeypatch.setattr(harness, "check_stop_file", lambda: None)
    monkeypatch.setattr(harness, "preflight_resource_check", lambda _context: None)
    monkeypatch.setattr(harness, "mark_cycle_step", lambda *args, **kwargs: None)
    monkeypatch.setattr(harness, "save_role_markers", lambda *args, **kwargs: None)
    monkeypatch.setattr(harness, "capture_cycle_artifact", lambda *args, **kwargs: None)
    monkeypatch.setattr(harness, "capture_cycle_snapshot", lambda *args, **kwargs: None)
    monkeypatch.setattr(harness, "update_policy_decision", lambda *args, **kwargs: None)
    monkeypatch.setattr(harness, "run_role", fake_run_role)

    remaining = harness.reviewer_step()

    assert remaining == "1"
    assert cfg.plan_path.read_text(encoding="utf-8") == "2. [pending] keep me.\nWhy now: still active.\n"
    assert harness.current_plan_item.startswith("2.")
    assert harness.current_task_packet["item_id"] == "2"
