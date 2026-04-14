from __future__ import annotations

import re
import shlex
import subprocess
import os
import json
from datetime import datetime
from pathlib import Path
from typing import Callable

try:
    import resource
except ImportError:  # pragma: no cover
    resource = None

from .config import LlmConfig
from .procguard import register_child_process, unregister_child_process


SESSION_RE = re.compile(r"session id:\s*(\S+)", re.IGNORECASE)
LOCAL_BAD_PATTERNS = (
    "as an ai",
    "i can't access",
    "i cant access",
    "need more context",
    "cannot complete without",
)


def backend_supports_sessions(provider: str) -> bool:
    return provider == "codex"


def is_local_provider(provider: str) -> bool:
    return provider in {"ollama", "llamacpp"}


def extract_session_id(text: str) -> str:
    match = SESSION_RE.search(text)
    return match.group(1) if match else ""


def _timestamp() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _build_codex_memory_preexec_fn(memory_limit_mb: int) -> Callable[[], None] | None:
    if memory_limit_mb <= 0 or resource is None:
        return None

    limit_bytes = memory_limit_mb * 1024 * 1024

    def _set_limits() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (limit_bytes, limit_bytes))
        if hasattr(resource, "RLIMIT_DATA"):
            resource.setrlimit(resource.RLIMIT_DATA, (limit_bytes, limit_bytes))

    return _set_limits


def _provider_env(config: LlmConfig) -> dict[str, str]:
    env = os.environ.copy()
    root = str(config.root_dir)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{root}:{existing}" if existing else root
    return env


def build_effective_prompt(
    key: str,
    provider: str,
    base_prompt: str,
    config: LlmConfig,
    previous_log_path: str,
) -> str:
    if not is_local_provider(provider):
        return base_prompt
    extra = [
        "",
        "Local-model guardrails:",
        "- Follow the instructions literally.",
        "- Do not refuse, summarize vaguely, or switch to meta commentary.",
        "- Always include the exact required line markers, especially: Global Remaining steps: N",
        "- Be concrete and deterministic.",
        f"- If you reference project evidence, use {config.evidence_log_file}, {config.plan_path}, {config.status_file}, and the current repository state.",
    ]
    if previous_log_path:
        extra.append(f"- Previous {key} log for continuity: {previous_log_path}")
    return base_prompt + "\n" + "\n".join(extra) + "\n"


def validate_output(key: str, provider: str, log_path: Path, config: LlmConfig) -> bool:
    if not is_local_provider(provider):
        return True
    if not log_path.exists() or log_path.stat().st_size < config.local_model_min_output_bytes:
        return False
    text = log_path.read_text(encoding="utf-8", errors="replace")
    if key in {"planner", "checker", "worker", "reviewer"} and not re.search(r"Global Remaining steps:\s*\d+", text):
        return False
    if key in {"planner", "checker", "reviewer"}:
        lowered = text.lower()
        if "correctness" not in lowered or "recompilation" not in lowered:
            return False
    lowered = text.lower()
    if any(pattern in lowered for pattern in LOCAL_BAD_PATTERNS):
        return False
    if key == "planner" and not config.plan_path.exists():
        return False
    return True


def _append_to_logs(outputs: tuple[object, ...], text: str) -> None:
    for out in outputs:
        out.write(text)
        out.flush()


def _run_and_mirror_output(
    cmd: list[str],
    *,
    log_file: Path,
    config: LlmConfig,
    header: str,
    env: dict[str, str],
    proc_name: str,
    stdin=None,
    preexec_fn: Callable[[], None] | None = None,
) -> int:
    config.last_log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("w", encoding="utf-8") as out, config.last_log_file.open("w", encoding="utf-8") as mirror:
        outputs = (out, mirror)
        _append_to_logs(outputs, header)
        proc = subprocess.Popen(
            cmd,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            preexec_fn=preexec_fn,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        register_child_process(config.status_file.parent, proc.pid, proc_name, str(config.root_dir), _timestamp())
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                _append_to_logs(outputs, line)
            rc = proc.wait()
        finally:
            unregister_child_process(config.status_file.parent, proc.pid)
    footer = f"[{_timestamp()}] end rc={rc}\n"
    with log_file.open("a", encoding="utf-8") as out, config.last_log_file.open("a", encoding="utf-8") as mirror:
        _append_to_logs((out, mirror), footer)
    return rc


def run_provider_once(
    provider: str,
    mode: str,
    model: str,
    prompt: str,
    prompt_file: Path,
    log_file: Path,
    config: LlmConfig,
    session_id: str = "",
    timeout_secs: int | None = None,
) -> int:
    effective_timeout_secs = int(timeout_secs or config.codex_timeout_secs)
    timeout_cmd = ["timeout", "--foreground", f"{effective_timeout_secs}s"]
    codex_preexec = _build_codex_memory_preexec_fn(config.codex_memory_limit_mb)
    provider_env = _provider_env(config)
    header = (
        f"[{_timestamp()}] start provider={provider} mode={mode} model={model} "
        f"prompt={prompt_file.name} root={config.root_dir}\n"
    )
    if provider == "codex":
        if mode == "resume":
            cmd = [
                "codex",
                "exec",
                "resume",
                "--model",
                model,
                "--dangerously-bypass-approvals-and-sandbox",
                session_id,
                prompt,
            ]
        else:
            cmd = [
                "codex",
                "exec",
                "--model",
                model,
                "-C",
                str(config.root_dir),
                "--dangerously-bypass-approvals-and-sandbox",
                prompt,
            ]
        return _run_and_mirror_output(
            timeout_cmd + cmd,
            log_file=log_file,
            config=config,
            header=header,
            env=provider_env,
            proc_name="codex",
            preexec_fn=codex_preexec,
        )
    if provider == "ollama":
        with prompt_file.open("rb") as inp:
            return _run_and_mirror_output(
                timeout_cmd + [config.ollama_cmd, "run", model],
                log_file=log_file,
                config=config,
                header=header,
                env=provider_env,
                proc_name="ollama",
                stdin=inp,
            )
    if provider == "llamacpp":
        cmd = timeout_cmd + [config.llamacpp_cmd, "-m", model]
        if config.llamacpp_extra_args:
            cmd.extend(shlex.split(config.llamacpp_extra_args))
        cmd.extend(["-f", str(prompt_file)])
        return _run_and_mirror_output(
            cmd,
            log_file=log_file,
            config=config,
            header=header,
            env=provider_env,
            proc_name="llamacpp",
        )
    if provider == "mock":
        scenario_path = os.environ.get("MOCK_PROVIDER_SCRIPT", "").strip()
        if not scenario_path:
            raise ValueError("MOCK_PROVIDER_SCRIPT is required for provider=mock")
        role = prompt_file.name.split(".", 1)[0]
        responses = []
        with Path(scenario_path).open("r", encoding="utf-8") as fp:
            for raw_line in fp:
                line = raw_line.strip()
                if not line:
                    continue
                responses.append(json.loads(line))
        index_file = Path(os.environ.get("MOCK_PROVIDER_INDEX_FILE", str(Path(scenario_path).with_suffix(".idx"))))
        try:
            index = int(index_file.read_text(encoding="utf-8").strip()) if index_file.exists() else 0
        except ValueError:
            index = 0
        if index >= len(responses):
            raise ValueError(f"Mock provider script exhausted at index {index}")
        entry = responses[index]
        index_file.parent.mkdir(parents=True, exist_ok=True)
        index_file.write_text(str(index + 1), encoding="utf-8")
        output = str(entry.get("output", ""))
        exit_code = int(entry.get("exit_code", 0))
        entry_role = str(entry.get("role", "") or "")
        entry_mode = str(entry.get("mode", "") or "")
        if entry_role and entry_role not in {"*", role}:
            raise ValueError(f"Mock provider role mismatch: expected {role}, got {entry_role}")
        if entry_mode and entry_mode not in {"*", mode}:
            raise ValueError(f"Mock provider mode mismatch: expected {mode}, got {entry_mode}")
        session_hint = str(entry.get("session_id", "") or "")
        config.last_log_file.parent.mkdir(parents=True, exist_ok=True)
        with log_file.open("w", encoding="utf-8") as out, config.last_log_file.open("w", encoding="utf-8") as mirror:
            outputs = (out, mirror)
            _append_to_logs(outputs, header)
            if session_hint:
                _append_to_logs(outputs, f"session id: {session_hint}\n")
            if output:
                _append_to_logs(outputs, output if output.endswith("\n") else output + "\n")
        footer = f"[{_timestamp()}] end rc={exit_code}\n"
        with log_file.open("a", encoding="utf-8") as out, config.last_log_file.open("a", encoding="utf-8") as mirror:
            _append_to_logs((out, mirror), footer)
        return exit_code
    raise ValueError(f"Unsupported provider: {provider}")
