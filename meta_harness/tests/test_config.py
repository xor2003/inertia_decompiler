from __future__ import annotations

import math
from pathlib import Path

from meta_harness.config import (
    CORE_EVIDENCE_INPUT_FILES,
    DEFAULT_EVIDENCE_INPUT_FILES,
    F14_EVIDENCE_INPUT_FILES,
    LlmConfig,
    RuntimeConfig,
)


def test_runtime_config_reads_multiline_evidence_files(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    monkeypatch.setenv("EVIDENCE_INPUT_FILES", "a.txt\nb.txt\n")
    cfg = RuntimeConfig.from_env([])
    assert cfg.evidence_input_files == ["a.txt", "b.txt"]


def test_runtime_config_reads_repo_harness_config_file(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    monkeypatch.delenv("HARNESS_CONFIG", raising=False)
    harness_conf = tmp_path / ".codex_harness.conf"
    harness_conf.write_text(
        'SWEEP_LABEL="LIFE2 focused sweep"\n'
        'COMPARE_INPUT_DESCRIPTION="LIFE2 direct decompilation outputs, focused harness logs, and the current code state, treating LIFE.EXE as the same program without helper metadata: compare behavior, recovered functions, and output quality against LIFE.EXE, but do not import or reuse LIFE.EXE helper metadata"\n'
        'PRIMARY_PRIORITY="raise LIFE2.EXE decompilation toward LIFE.EXE output quality while treating LIFE.EXE and LIFE2.EXE as the same code without helpers from LIFE.EXE"\n'
        'SECONDARY_PRIORITY="recover roughly the same function count and comparable decompiled output for LIFE2.EXE as for LIFE.EXE, and prefer fully optimized output, but emit partially optimized decompiled functions instead of dropping to raw failure when a timeout happens"\n'
        'GENERAL_IMPROVEMENT_RULE="Never add hacks specific to one source file or one sample; fixes must be general-purpose improvements, and for this repo treat LIFE.EXE as the same codebase oracle for LIFE2.EXE while never using LIFE.EXE as a source of helper metadata."\n'
        'REPO_STANDING_TASKS=$\'task one\\ntask two\'\n'
        'EVIDENCE_INPUT_FILES=$\'LIFE2.EXE\\nPLAN.md\'\n'
        'SWEEP_CMD="python -m demo life2"\n',
        encoding="utf-8",
    )
    monkeypatch.delenv("EVIDENCE_INPUT_FILES", raising=False)
    monkeypatch.delenv("SWEEP_LABEL", raising=False)
    monkeypatch.delenv("SWEEP_CMD", raising=False)

    cfg = RuntimeConfig.from_env([])

    assert cfg.sweep_label == "LIFE2 focused sweep"
    assert cfg.evidence_input_files == ["LIFE2.EXE", "PLAN.md"]
    assert cfg.sweep_cmd == "python -m demo life2"
    assert (
        cfg.compare_input_description
        == "LIFE2 direct decompilation outputs, focused harness logs, and the current code state, treating LIFE.EXE as the same program without helper metadata: compare behavior, recovered functions, and output quality against LIFE.EXE, but do not import or reuse LIFE.EXE helper metadata"
    )
    assert (
        cfg.primary_priority
        == "raise LIFE2.EXE decompilation toward LIFE.EXE output quality while treating LIFE.EXE and LIFE2.EXE as the same code without helpers from LIFE.EXE"
    )
    assert (
        cfg.secondary_priority
        == "recover roughly the same function count and comparable decompiled output for LIFE2.EXE as for LIFE.EXE, and prefer fully optimized output, but emit partially optimized decompiled functions instead of dropping to raw failure when a timeout happens"
    )
    assert (
        cfg.general_improvement_rule
        == "Never add hacks specific to one source file or one sample; fixes must be general-purpose improvements, and for this repo treat LIFE.EXE as the same codebase oracle for LIFE2.EXE while never using LIFE.EXE as a source of helper metadata."
    )
    assert cfg.repo_standing_tasks == ["task one", "task two"]


def test_environment_overrides_repo_harness_config(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    (tmp_path / ".codex_harness.conf").write_text('SWEEP_LABEL="from-file"\n', encoding="utf-8")
    monkeypatch.setenv("SWEEP_LABEL", "from-env")

    cfg = RuntimeConfig.from_env([])

    assert cfg.sweep_label == "from-env"


def test_runtime_config_uses_default_evidence_files(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    monkeypatch.delenv("EVIDENCE_INPUT_FILES", raising=False)
    cfg = RuntimeConfig.from_env([])
    assert cfg.evidence_input_files == DEFAULT_EVIDENCE_INPUT_FILES
    expected_f14 = F14_EVIDENCE_INPUT_FILES[: max(1, math.ceil(len(F14_EVIDENCE_INPUT_FILES) * 0.10))]
    assert cfg.evidence_input_files == CORE_EVIDENCE_INPUT_FILES + expected_f14


def test_llm_config_provider_override(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("REVIEWER_PROVIDER", "codex")
    cfg = LlmConfig.from_env()
    assert cfg.provider_for_key("worker") == "ollama"
    assert cfg.provider_for_key("reviewer") == "codex"


def test_runtime_config_uses_default_operator_comments_file(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    cfg = RuntimeConfig.from_env([])
    assert cfg.operator_comments_file == tmp_path / "HARNESS_COMMENTS.md"


def test_runtime_config_uses_default_runtime_record_files(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    cfg = RuntimeConfig.from_env([])
    assert cfg.history_log_file == tmp_path / ".codex_automation" / "history.jsonl"
    assert cfg.maintenance_file == tmp_path / ".codex_automation" / "maintenance.json"
    assert cfg.preflight_state_file == tmp_path / ".codex_automation" / "preflight.json"
    assert cfg.session_ledger_file == tmp_path / ".codex_automation" / "sessions.jsonl"


def test_runtime_config_uses_default_consecutive_worker_failure_limit(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    cfg = RuntimeConfig.from_env([])
    assert cfg.max_consecutive_worker_failures == 3
    assert cfg.worker_stall_failure_limit == 2
    assert cfg.auto_commit_enabled is False
    assert cfg.auto_commit_require_clean_start is True
    assert cfg.unattended_max_cycles == 0
    assert cfg.background_maintenance_enabled is True
    assert cfg.maintenance_compaction_limit == 200
    assert cfg.scheduled_maintenance_interval_cycles == 3


def test_runtime_config_uses_default_worker_session_log_budget(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    cfg = RuntimeConfig.from_env([])
    assert cfg.max_worker_session_log_bytes == 512 * 1024


def test_runtime_config_uses_web_ui_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    cfg = RuntimeConfig.from_env([])
    assert cfg.web_ui_enabled is True
    assert cfg.web_ui_auto_open is True
    assert cfg.web_ui_host == "127.0.0.1"
    assert cfg.web_ui_port == 8765


def test_runtime_config_uses_compact_prompt_defaults_and_default_models(monkeypatch, tmp_path):
    monkeypatch.setenv("ROOT_DIR", str(tmp_path))
    cfg = RuntimeConfig.from_env([])
    assert cfg.compact_prompts is True
    assert cfg.delta_resume_prompts is True
    assert cfg.planner_model == "gpt-5.4"
    assert cfg.reviewer_model == "gpt-5.4-mini"
    assert cfg.worker_stall_model == "gpt-5.4"
    assert cfg.worker_stall_escalation_threshold == 1
    assert cfg.crash_reviewer_model == "gpt-5.4"
