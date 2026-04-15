from __future__ import annotations

import math
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


CORE_EVIDENCE_INPUT_FILES = [
    "cod/BIOSFUNC.COD",
    "cod/DOSFUNC.COD",
    "cod/OVERLAY.COD",
    "cod/default/BYTEOPS.COD",
    "cod/default/STRLEN.COD",
]

F14_EVIDENCE_INPUT_FILES = [
    "cod/f14/3DLOADER.COD",
    "cod/f14/3DPLANES.COD",
    "cod/f14/ADICRT.COD",
    "cod/f14/BILLASM.COD",
    "cod/f14/BULLETS.COD",
    "cod/f14/CARR.COD",
    "cod/f14/COCKPIT.COD",
    "cod/f14/MONOPRIN.COD",
    "cod/f14/NHORZ.COD",
    "cod/f14/OVL.COD",
    "cod/f14/PLANES3.COD",
    "cod/f14/RIOHEAD.COD",
    "cod/f14/RIOMAP.COD",
    "cod/f14/SAVEMODE.COD",
    "cod/f14/VDI.COD",
]

DEFAULT_EVIDENCE_INPUT_FILES = CORE_EVIDENCE_INPUT_FILES + F14_EVIDENCE_INPUT_FILES[
    :max(1, math.ceil(len(F14_EVIDENCE_INPUT_FILES) * 0.10))
]


def _split_env_lines(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name, "")
    if not raw:
        return list(default)
    return [line for line in raw.splitlines() if line.strip()]


_HARNESS_CONFIG_KEYS = (
    "ROOT_DIR",
    "PLAN_PATH",
    "EVIDENCE_LOG_FILE",
    "STATUS_FILE",
    "LAST_LOG_FILE",
    "CODEX_TIMEOUT_SECS",
    "CODEX_MEMORY_LIMIT_MB",
    "PLANNER_PROVIDER",
    "CHECKER_PROVIDER",
    "WORKER_PROVIDER",
    "REVIEWER_PROVIDER",
    "CRASH_REVIEWER_PROVIDER",
    "LLM_PROVIDER",
    "OLLAMA_CMD",
    "LLAMACPP_CMD",
    "LLAMACPP_EXTRA_ARGS",
    "LOCAL_MODEL_MAX_RETRIES",
    "LOCAL_MODEL_MIN_OUTPUT_BYTES",
    "LOCAL_MODEL_FALLBACK_PROVIDER",
    "LOCAL_MODEL_FALLBACK_MODEL",
    "LOCAL_MODEL_FALLBACK_CONTEXT",
    "STATE_DIR",
    "EVIDENCE_SUBSET_DIR",
    "SWEEP_TIMEOUT_SECS",
    "SWEEP_SUBPROCESS_TIMEOUT_SECS",
    "RUN_SH_PATH",
    "PYTHON_BIN",
    "LOG_DIR",
    "RUNS_DIR",
    "STOP_FILE",
    "LOCK_FILE",
    "CHAT_LOG_FILE",
    "HISTORY_LOG_FILE",
    "MAINTENANCE_FILE",
    "OPERATOR_COMMENTS_FILE",
    "PROMPT_DIR",
    "PREFLIGHT_STATE_FILE",
    "SESSION_LEDGER_FILE",
    "AUTO_COMMIT_ENABLED",
    "AUTO_COMMIT_REQUIRE_CLEAN_START",
    "UNATTENDED_MAX_CYCLES",
    "BACKGROUND_MAINTENANCE_ENABLED",
    "MAINTENANCE_COMPACTION_LIMIT",
    "SCHEDULED_MAINTENANCE_INTERVAL_CYCLES",
    "COMPACT_PROMPTS",
    "DELTA_RESUME_PROMPTS",
    "KEEP_LOG_COUNT",
    "MIN_FREE_DISK_MB",
    "MIN_FREE_RAM_MB",
    "PAUSE_WHEN_RAM_BELOW_MB",
    "MAX_STATE_DIR_MB",
    "MAX_SINGLE_ARTIFACT_MB",
    "MAX_WORKER_ITERS",
    "MAX_CONSECUTIVE_WORKER_FAILURES",
    "WORKER_STALL_FAILURE_LIMIT",
    "MAX_WORKER_SESSION_LOG_BYTES",
    "WORKER_SLEEP_SECS",
    "PLANNER_PAUSE_SECS",
    "STATUS_HEARTBEAT_SECS",
    "WEB_UI_ENABLED",
    "WEB_UI_AUTO_OPEN",
    "WEB_UI_HOST",
    "WEB_UI_PORT",
    "WEB_UI_POLL_SECS",
    "MAX_SELF_RESTARTS",
    "SELF_RESTART_COUNT",
    "WORKER_FINISH_TOKEN",
    "SWEEP_LABEL",
    "SWEEP_CMD",
    "PROJECT_NAME",
    "PROJECT_DESCRIPTION",
    "RULES_FILE",
    "PRIMARY_PRIORITY",
    "SECONDARY_PRIORITY",
    "GENERAL_IMPROVEMENT_RULE",
    "ARCHITECTURE_GUIDANCE",
    "EVIDENCE_KIND",
    "COMPARE_INPUT_DESCRIPTION",
    "REPO_STANDING_TASKS",
    "PLANNER_MODEL",
    "CHECKER_MODEL",
    "WORKER_MODEL",
    "WORKER_STALL_MODEL",
    "WORKER_STALL_ESCALATION_THRESHOLD",
    "REVIEWER_MODEL",
    "CRASH_REVIEWER_MODEL",
    "EVIDENCE_INPUT_FILES",
)


def _load_harness_config_env(environ: dict[str, str]) -> dict[str, str]:
    root_dir = Path(environ.get("ROOT_DIR", os.getcwd())).resolve()
    config_path = Path(environ.get("HARNESS_CONFIG", root_dir / ".codex_harness.conf"))
    if not config_path.exists():
        return {}
    script = r"""
set -a
source "$1"
shift
for key in "$@"; do
  if [[ "$key" == "EVIDENCE_INPUT_FILES" ]]; then
    if declare -p EVIDENCE_INPUT_FILES >/dev/null 2>&1; then
      decl="$(declare -p EVIDENCE_INPUT_FILES 2>/dev/null || true)"
      if [[ "$decl" == declare\ -a* ]]; then
        printf 'EVIDENCE_INPUT_FILES=%s\0' "$(printf '%s\n' "${EVIDENCE_INPUT_FILES[@]}")"
      elif [[ -n "${EVIDENCE_INPUT_FILES-}" ]]; then
        printf 'EVIDENCE_INPUT_FILES=%s\0' "${EVIDENCE_INPUT_FILES}"
      fi
    fi
    continue
  fi
  if [[ -n "${!key+x}" ]]; then
    printf '%s=%s\0' "$key" "${!key}"
  fi
done
"""
    result = subprocess.run(
        ["bash", "-lc", script, "codex_harness", str(config_path), *_HARNESS_CONFIG_KEYS],
        capture_output=True,
        text=False,
        check=False,
        env={**os.environ, "ROOT_DIR": str(root_dir), **environ},
    )
    if result.returncode != 0:
        return {}
    loaded: dict[str, str] = {}
    for chunk in result.stdout.split(b"\0"):
        if not chunk:
            continue
        key, _, value = chunk.partition(b"=")
        if not key:
            continue
        loaded[key.decode("utf-8", errors="replace")] = value.decode("utf-8", errors="replace")
    return loaded


def _merged_env() -> dict[str, str]:
    merged = _load_harness_config_env(os.environ)
    merged.update(os.environ)
    return merged


@dataclass(frozen=True)
class LlmConfig:
    root_dir: Path
    plan_path: Path
    evidence_log_file: Path
    status_file: Path
    last_log_file: Path
    codex_timeout_secs: int
    codex_memory_limit_mb: int
    planner_provider: str
    checker_provider: str
    worker_provider: str
    reviewer_provider: str
    crash_reviewer_provider: str
    default_provider: str
    ollama_cmd: str
    llamacpp_cmd: str
    llamacpp_extra_args: str
    local_model_max_retries: int
    local_model_min_output_bytes: int
    local_model_fallback_provider: str
    local_model_fallback_model: str
    local_model_fallback_context: str

    @classmethod
    def from_env(cls) -> "LlmConfig":
        env = _merged_env()
        root_dir = Path(env.get("ROOT_DIR", os.getcwd())).resolve()
        return cls(
            root_dir=root_dir,
            plan_path=Path(env.get("PLAN_PATH", root_dir / "PLAN.md")),
            evidence_log_file=Path(env.get("EVIDENCE_LOG_FILE", root_dir / ".codex_automation" / "evidence.log")),
            status_file=Path(env.get("STATUS_FILE", root_dir / ".codex_automation" / "status.txt")),
            last_log_file=Path(env.get("LAST_LOG_FILE", root_dir / ".codex_automation" / "last.log")),
            codex_timeout_secs=int(env.get("CODEX_TIMEOUT_SECS", "180")),
            codex_memory_limit_mb=int(env.get("CODEX_MEMORY_LIMIT_MB", "6144")),
            planner_provider=env.get("PLANNER_PROVIDER", env.get("LLM_PROVIDER", "codex")),
            checker_provider=env.get("CHECKER_PROVIDER", env.get("LLM_PROVIDER", "codex")),
            worker_provider=env.get("WORKER_PROVIDER", env.get("LLM_PROVIDER", "codex")),
            reviewer_provider=env.get("REVIEWER_PROVIDER", env.get("LLM_PROVIDER", "codex")),
            crash_reviewer_provider=env.get(
                "CRASH_REVIEWER_PROVIDER", env.get("LLM_PROVIDER", "codex")
            ),
            default_provider=env.get("LLM_PROVIDER", "codex"),
            ollama_cmd=env.get("OLLAMA_CMD", "ollama"),
            llamacpp_cmd=env.get("LLAMACPP_CMD", "llama-cli"),
            llamacpp_extra_args=env.get("LLAMACPP_EXTRA_ARGS", ""),
            local_model_max_retries=int(env.get("LOCAL_MODEL_MAX_RETRIES", "2")),
            local_model_min_output_bytes=int(env.get("LOCAL_MODEL_MIN_OUTPUT_BYTES", "120")),
            local_model_fallback_provider=env.get("LOCAL_MODEL_FALLBACK_PROVIDER", ""),
            local_model_fallback_model=env.get("LOCAL_MODEL_FALLBACK_MODEL", ""),
            local_model_fallback_context=env.get(
                "LOCAL_MODEL_FALLBACK_CONTEXT",
                "Use the same prompt but produce a stricter, more concrete answer that follows all required output markers exactly.",
            ),
        )

    def provider_for_key(self, key: str) -> str:
        return {
            "planner": self.planner_provider,
            "checker": self.checker_provider,
            "worker": self.worker_provider,
            "reviewer": self.reviewer_provider,
            "crash-reviewer": self.crash_reviewer_provider,
        }.get(key, self.default_provider)


@dataclass(frozen=True)
class RuntimeConfig:
    root_dir: Path
    harness_config: Path
    run_sh_path: Path
    python_bin: Path
    plan_path: Path
    state_dir: Path
    log_dir: Path
    runs_dir: Path
    stop_file: Path
    lock_file: Path
    status_file: Path
    last_log_file: Path
    chat_log_file: Path
    history_log_file: Path
    maintenance_file: Path
    operator_comments_file: Path
    prompt_dir: Path
    evidence_subset_dir: Path
    evidence_log_file: Path
    preflight_state_file: Path
    session_ledger_file: Path
    auto_commit_enabled: bool
    auto_commit_require_clean_start: bool
    unattended_max_cycles: int
    background_maintenance_enabled: bool
    maintenance_compaction_limit: int
    scheduled_maintenance_interval_cycles: int
    compact_prompts: bool
    delta_resume_prompts: bool
    codex_memory_limit_mb: int
    keep_log_count: int
    min_free_disk_mb: int
    min_free_ram_mb: int
    pause_when_ram_below_mb: int
    max_state_dir_mb: int
    max_single_artifact_mb: int
    max_worker_iters: int
    max_consecutive_worker_failures: int
    worker_stall_failure_limit: int
    max_worker_session_log_bytes: int
    worker_sleep_secs: int
    planner_pause_secs: int
    codex_timeout_secs: int
    status_heartbeat_secs: float
    web_ui_enabled: bool
    web_ui_auto_open: bool
    web_ui_host: str
    web_ui_port: int
    web_ui_poll_secs: float
    max_self_restarts: int
    self_restart_count: int
    worker_finish_token: str
    sweep_label: str
    sweep_cmd: str
    project_name: str
    project_description: str
    rules_file: Path
    primary_priority: str
    secondary_priority: str
    general_improvement_rule: str
    architecture_guidance: str
    evidence_kind: str
    compare_input_description: str
    repo_standing_tasks: list[str]
    planner_model: str
    checker_model: str
    worker_model: str
    worker_stall_model: str
    worker_stall_escalation_threshold: int
    reviewer_model: str
    crash_reviewer_model: str
    evidence_input_files: list[str]
    original_args: list[str]

    @classmethod
    def from_env(cls, argv: list[str]) -> "RuntimeConfig":
        env = _merged_env()
        root_dir = Path(env.get("ROOT_DIR", os.getcwd())).resolve()
        state_dir = Path(env.get("STATE_DIR", root_dir / ".codex_automation"))
        evidence_subset_dir = Path(env.get("EVIDENCE_SUBSET_DIR", state_dir / "evidence_subset"))
        sweep_timeout = int(env.get("SWEEP_TIMEOUT_SECS", "20"))
        sweep_subprocess_timeout = int(env.get("SWEEP_SUBPROCESS_TIMEOUT_SECS", "600"))
        default_sweep_cmd = (
            f'./.venv/bin/python -u scripts/decompile_cod_dir.py "{evidence_subset_dir}" '
            f"--timeout {sweep_timeout} --subprocess-timeout {sweep_subprocess_timeout}"
        )
        return cls(
            root_dir=root_dir,
            harness_config=Path(env.get("HARNESS_CONFIG", root_dir / ".codex_harness.conf")),
            run_sh_path=Path(env.get("RUN_SH_PATH", root_dir / "run.sh")),
            python_bin=Path(env.get("PYTHON_BIN", sys.executable if "sys" in globals() else "python3")),
            plan_path=Path(env.get("PLAN_PATH", root_dir / "PLAN.md")),
            state_dir=state_dir,
            log_dir=Path(env.get("LOG_DIR", state_dir / "logs")),
            runs_dir=Path(env.get("RUNS_DIR", state_dir / "cycles")),
            stop_file=Path(env.get("STOP_FILE", root_dir / "STOP")),
            lock_file=Path(env.get("LOCK_FILE", state_dir / "run.lock")),
            status_file=Path(env.get("STATUS_FILE", state_dir / "status.txt")),
            last_log_file=Path(env.get("LAST_LOG_FILE", state_dir / "last.log")),
            chat_log_file=Path(env.get("CHAT_LOG_FILE", state_dir / "chat.jsonl")),
            history_log_file=Path(env.get("HISTORY_LOG_FILE", state_dir / "history.jsonl")),
            maintenance_file=Path(env.get("MAINTENANCE_FILE", state_dir / "maintenance.json")),
            operator_comments_file=Path(env.get("OPERATOR_COMMENTS_FILE", root_dir / "HARNESS_COMMENTS.md")),
            prompt_dir=Path(env.get("PROMPT_DIR", state_dir / "prompts")),
            evidence_subset_dir=evidence_subset_dir,
            evidence_log_file=Path(env.get("EVIDENCE_LOG_FILE", state_dir / "evidence.log")),
            preflight_state_file=Path(env.get("PREFLIGHT_STATE_FILE", state_dir / "preflight.json")),
            session_ledger_file=Path(env.get("SESSION_LEDGER_FILE", state_dir / "sessions.jsonl")),
            auto_commit_enabled=env.get("AUTO_COMMIT_ENABLED", "0").strip().lower() in {"1", "true", "yes"},
            auto_commit_require_clean_start=env.get("AUTO_COMMIT_REQUIRE_CLEAN_START", "1").strip().lower()
            not in {"0", "false", "no"},
            unattended_max_cycles=int(env.get("UNATTENDED_MAX_CYCLES", "0")),
            background_maintenance_enabled=env.get("BACKGROUND_MAINTENANCE_ENABLED", "1").strip().lower()
            not in {"0", "false", "no"},
            maintenance_compaction_limit=int(env.get("MAINTENANCE_COMPACTION_LIMIT", "200")),
            scheduled_maintenance_interval_cycles=int(env.get("SCHEDULED_MAINTENANCE_INTERVAL_CYCLES", "3")),
            compact_prompts=env.get("COMPACT_PROMPTS", "1").strip().lower() not in {"0", "false", "no"},
            delta_resume_prompts=env.get("DELTA_RESUME_PROMPTS", "1").strip().lower()
            not in {"0", "false", "no"},
            codex_memory_limit_mb=int(env.get("CODEX_MEMORY_LIMIT_MB", "6144")),
            keep_log_count=int(env.get("KEEP_LOG_COUNT", "40")),
            min_free_disk_mb=int(env.get("MIN_FREE_DISK_MB", "8192")),
            min_free_ram_mb=int(env.get("MIN_FREE_RAM_MB", "4096")),
            pause_when_ram_below_mb=int(env.get("PAUSE_WHEN_RAM_BELOW_MB", "6144")),
            max_state_dir_mb=int(env.get("MAX_STATE_DIR_MB", "12288")),
            max_single_artifact_mb=int(env.get("MAX_SINGLE_ARTIFACT_MB", "1024")),
            max_worker_iters=int(env.get("MAX_WORKER_ITERS", "40")),
            max_consecutive_worker_failures=int(env.get("MAX_CONSECUTIVE_WORKER_FAILURES", "3")),
            worker_stall_failure_limit=int(env.get("WORKER_STALL_FAILURE_LIMIT", "2")),
            max_worker_session_log_bytes=int(env.get("MAX_WORKER_SESSION_LOG_BYTES", str(512 * 1024))),
            worker_sleep_secs=int(env.get("WORKER_SLEEP_SECS", "4")),
            planner_pause_secs=int(env.get("PLANNER_PAUSE_SECS", "60")),
            codex_timeout_secs=int(env.get("CODEX_TIMEOUT_SECS", "180")),
            status_heartbeat_secs=float(env.get("STATUS_HEARTBEAT_SECS", "60")),
            web_ui_enabled=env.get("WEB_UI_ENABLED", "1").strip().lower() not in {"0", "false", "no"},
            web_ui_auto_open=env.get("WEB_UI_AUTO_OPEN", "1").strip().lower() not in {"0", "false", "no"},
            web_ui_host=env.get("WEB_UI_HOST", "127.0.0.1"),
            web_ui_port=int(env.get("WEB_UI_PORT", "8765")),
            web_ui_poll_secs=float(env.get("WEB_UI_POLL_SECS", "2")),
            max_self_restarts=int(env.get("MAX_SELF_RESTARTS", "5")),
            self_restart_count=int(env.get("SELF_RESTART_COUNT", "0")),
            worker_finish_token=env.get("WORKER_FINISH_TOKEN", "Global Remaining steps: 0"),
            sweep_label=env.get("SWEEP_LABEL", "curated evidence sweep"),
            sweep_cmd=env.get("SWEEP_CMD", default_sweep_cmd),
            project_name=env.get("PROJECT_NAME", root_dir.name),
            project_description=env.get("PROJECT_DESCRIPTION", "software repository"),
            rules_file=Path(env.get("RULES_FILE", root_dir / "AGENTS.md")),
            primary_priority=env.get("PRIMARY_PRIORITY", "improve correctness first"),
            secondary_priority=env.get(
                "SECONDARY_PRIORITY", "improve recompilation, maintainability, and automation quality second"
            ),
            general_improvement_rule=env.get(
                "GENERAL_IMPROVEMENT_RULE",
                "Never add hacks specific to one source file or one sample; fixes must be general-purpose improvements.",
            ),
            architecture_guidance=env.get(
                "ARCHITECTURE_GUIDANCE",
                "Prefer the earliest correct layer in the pipeline and avoid pushing semantics into late rewrite.",
            ),
            evidence_kind=env.get("EVIDENCE_KIND", "generated artifacts and repository analysis evidence"),
            compare_input_description=env.get(
                "COMPARE_INPUT_DESCRIPTION", "the relevant source inputs, generated outputs, and the current code state"
            ),
            repo_standing_tasks=[line for line in env.get("REPO_STANDING_TASKS", "").splitlines() if line.strip()],
            planner_model=env.get("PLANNER_MODEL", "gpt-5.4"),
            checker_model=env.get("CHECKER_MODEL", "gpt-5.4-mini"),
            worker_model=env.get("WORKER_MODEL", "gpt-5.4-mini"),
            worker_stall_model=env.get("WORKER_STALL_MODEL", "gpt-5.4"),
            worker_stall_escalation_threshold=int(env.get("WORKER_STALL_ESCALATION_THRESHOLD", "1")),
            reviewer_model=env.get("REVIEWER_MODEL", "gpt-5.4-mini"),
            crash_reviewer_model=env.get("CRASH_REVIEWER_MODEL", "gpt-5.4"),
            evidence_input_files=[line for line in env.get("EVIDENCE_INPUT_FILES", "").splitlines() if line.strip()]
            or list(DEFAULT_EVIDENCE_INPUT_FILES),
            original_args=argv,
        )

    def export_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "ROOT_DIR": str(self.root_dir),
                "PLAN_PATH": str(self.plan_path),
                "STATUS_FILE": str(self.status_file),
                "EVIDENCE_LOG_FILE": str(self.evidence_log_file),
                "HISTORY_LOG_FILE": str(self.history_log_file),
                "MAINTENANCE_FILE": str(self.maintenance_file),
                "PREFLIGHT_STATE_FILE": str(self.preflight_state_file),
                "SESSION_LEDGER_FILE": str(self.session_ledger_file),
                "AUTO_COMMIT_ENABLED": "1" if self.auto_commit_enabled else "0",
                "AUTO_COMMIT_REQUIRE_CLEAN_START": "1" if self.auto_commit_require_clean_start else "0",
                "UNATTENDED_MAX_CYCLES": str(self.unattended_max_cycles),
                "BACKGROUND_MAINTENANCE_ENABLED": "1" if self.background_maintenance_enabled else "0",
                "MAINTENANCE_COMPACTION_LIMIT": str(self.maintenance_compaction_limit),
                "SCHEDULED_MAINTENANCE_INTERVAL_CYCLES": str(self.scheduled_maintenance_interval_cycles),
                "CODEX_TIMEOUT_SECS": str(self.codex_timeout_secs),
                "STATUS_HEARTBEAT_SECS": str(self.status_heartbeat_secs),
                "WEB_UI_ENABLED": "1" if self.web_ui_enabled else "0",
                "WEB_UI_AUTO_OPEN": "1" if self.web_ui_auto_open else "0",
                "WEB_UI_HOST": self.web_ui_host,
                "WEB_UI_PORT": str(self.web_ui_port),
                "WEB_UI_POLL_SECS": str(self.web_ui_poll_secs),
                "CODEX_MEMORY_LIMIT_MB": str(self.codex_memory_limit_mb),
                "MAX_WORKER_SESSION_LOG_BYTES": str(self.max_worker_session_log_bytes),
                "WORKER_STALL_FAILURE_LIMIT": str(self.worker_stall_failure_limit),
                "WORKER_STALL_MODEL": str(self.worker_stall_model),
                "WORKER_STALL_ESCALATION_THRESHOLD": str(self.worker_stall_escalation_threshold),
                "REPO_STANDING_TASKS": "\n".join(self.repo_standing_tasks),
                "COMPACT_PROMPTS": "1" if self.compact_prompts else "0",
                "DELTA_RESUME_PROMPTS": "1" if self.delta_resume_prompts else "0",
                "HARNESS_CONFIG": str(self.harness_config),
                "RUN_SH_PATH": str(self.run_sh_path),
                "PYTHON_BIN": str(self.python_bin),
            }
        )
        return env
