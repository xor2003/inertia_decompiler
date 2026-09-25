#!/usr/bin/env python3
"""Resume Codex repair loops with explicit status and goal commands.

Layer: Tooling/gates.
Responsibility: automate bounded Codex resume loops without owning decompiler semantics.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import json
import shlex
import subprocess
import time
from pathlib import Path


class StopReason(enum.Enum):
    """Structured reason why the resume loop stopped."""

    GOAL_CMD_TRUE = "goal_cmd_true"
    GOAL_MARKER_EXISTS = "goal_marker_exists"
    STAGNATED = "stagnated"
    MAX_ITERATIONS = "max_iterations"
    STOP_FILE = "stop_file"
    CODEX_ERROR = "codex_error"


@dataclasses.dataclass(frozen=True)
class LoopConfig:
    """Configuration for one bounded Codex resume loop."""

    prompt: str
    max_iterations: int
    stagnation_limit: int
    sleep_sec: float
    out_dir: Path
    marker_file: Path
    goal_marker_file: Path | None
    goal_stop_reason: str | None
    stop_file: Path | None
    goal_cmd: str | None
    status_cmd: str | None
    resume_last: bool
    session_id: str | None
    codex_bin: str
    cwd: Path
    extra_codex_args: tuple[str, ...]
    dry_run: bool


@dataclasses.dataclass(frozen=True)
class IterationResult:
    """Observed output and status for one Codex loop iteration."""

    iteration: int
    elapsed_sec: float
    codex_returncode: int
    codex_output_path: Path
    status_returncode: int | None
    status_output_path: Path | None
    quality_score: int


def _run_shell(cmd: str, *, cwd: Path) -> tuple[int, str]:
    proc = subprocess.run(
        ["bash", "-lc", cmd],
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc.returncode, proc.stdout or ""


def _run_codex_iteration(cfg: LoopConfig, iteration: int) -> IterationResult:
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    codex_output_path = cfg.out_dir / f"iter_{iteration:04d}.codex.log"
    status_output_path: Path | None = None

    cmd = [
        cfg.codex_bin,
        "exec",
        "-C",
        str(cfg.cwd),
        *cfg.extra_codex_args,
        "resume",
    ]
    if cfg.resume_last:
        cmd.append("--last")
    elif cfg.session_id:
        cmd.append(cfg.session_id)
    cmd.append(cfg.prompt)

    t0 = time.monotonic()
    if cfg.dry_run:
        code = 0
        output = f"[dry-run] {' '.join(shlex.quote(x) for x in cmd)}\n"
    else:
        proc = subprocess.run(
            cmd,
            cwd=str(cfg.cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        code = proc.returncode
        output = proc.stdout or ""
    elapsed = time.monotonic() - t0
    codex_output_path.write_text(output, encoding="utf-8")

    status_rc: int | None = None
    quality_score = 0
    if cfg.status_cmd:
        status_output_path = cfg.out_dir / f"iter_{iteration:04d}.status.log"
        if cfg.dry_run:
            status_rc = 0
            status_out = f"[dry-run] {cfg.status_cmd}\n"
        else:
            status_rc, status_out = _run_shell(cfg.status_cmd, cwd=cfg.cwd)
        status_output_path.write_text(status_out, encoding="utf-8")
        quality_score = 1 if status_rc == 0 else 0

    return IterationResult(
        iteration=iteration,
        elapsed_sec=elapsed,
        codex_returncode=code,
        codex_output_path=codex_output_path,
        status_returncode=status_rc,
        status_output_path=status_output_path,
        quality_score=quality_score,
    )


def _goal_met(cfg: LoopConfig) -> StopReason | None:
    if cfg.goal_marker_file is not None and cfg.goal_marker_file.exists():
        if cfg.goal_stop_reason:
            try:
                payload = json.loads(cfg.goal_marker_file.read_text(encoding="utf-8"))
            except Exception:
                payload = None
            if isinstance(payload, dict) and str(payload.get("stop_reason", "")).strip() == cfg.goal_stop_reason:
                return StopReason.GOAL_MARKER_EXISTS
        else:
            return StopReason.GOAL_MARKER_EXISTS
    if cfg.goal_cmd:
        rc, _ = _run_shell(cfg.goal_cmd, cwd=cfg.cwd)
        if rc == 0:
            return StopReason.GOAL_CMD_TRUE
    return None


def _write_marker(
    cfg: LoopConfig, reason: StopReason, best: IterationResult | None, last: IterationResult | None
) -> None:
    cfg.marker_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "stop_reason": reason.value,
        "timestamp_unix": int(time.time()),
        "best_iteration": None if best is None else best.iteration,
        "last_iteration": None if last is None else last.iteration,
        "best_quality_score": None if best is None else best.quality_score,
        "last_quality_score": None if last is None else last.quality_score,
        "best_codex_log": None if best is None else str(best.codex_output_path),
        "last_codex_log": None if last is None else str(last.codex_output_path),
    }
    cfg.marker_file.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


@dataclasses.dataclass
class _CodexLoopState8616:
    """Mutable loop state carried across resume iterations."""

    best: IterationResult | None = None
    last: IterationResult | None = None
    stagnation: int = 0


def _run_loop_iteration_8616(cfg: LoopConfig, i: int, state: _CodexLoopState8616) -> StopReason | None:
    """Execute one resume iteration, returning a stop reason or None."""
    res = _run_codex_iteration(cfg, i)
    state.last = res
    if res.codex_returncode != 0:
        _write_marker(cfg, StopReason.CODEX_ERROR, state.best, state.last)
        return StopReason.CODEX_ERROR

    improved = state.best is None or res.quality_score > state.best.quality_score
    if improved:
        state.best = res
        state.stagnation = 0
    else:
        state.stagnation += 1

    print(
        f"[codex-loop] iter={res.iteration} sec={res.elapsed_sec:.1f} "
        f"codex_rc={res.codex_returncode} status_rc={res.status_returncode} "
        f"quality={res.quality_score} stagnation={state.stagnation}"
    )
    print(f"[codex-loop] codex_log={res.codex_output_path}")
    if res.status_output_path is not None:
        print(f"[codex-loop] status_log={res.status_output_path}")

    post_goal = _goal_met(cfg)
    if post_goal is not None:
        _write_marker(cfg, post_goal, state.best, state.last)
        return post_goal
    if state.stagnation >= cfg.stagnation_limit:
        _write_marker(cfg, StopReason.STAGNATED, state.best, state.last)
        return StopReason.STAGNATED
    return None


def run_loop(cfg: LoopConfig) -> StopReason:
    """Run Codex resume iterations until an explicit stop condition is met."""
    state = _CodexLoopState8616()

    for i in range(1, cfg.max_iterations + 1):
        if cfg.stop_file is not None and cfg.stop_file.exists():
            _write_marker(cfg, StopReason.STOP_FILE, state.best, state.last)
            return StopReason.STOP_FILE

        pre_goal = _goal_met(cfg)
        if pre_goal is not None:
            _write_marker(cfg, pre_goal, state.best, state.last)
            return pre_goal

        stop = _run_loop_iteration_8616(cfg, i, state)
        if stop is not None:
            return stop
        if i < cfg.max_iterations:
            time.sleep(cfg.sleep_sec)

    _write_marker(cfg, StopReason.MAX_ITERATIONS, state.best, state.last)
    return StopReason.MAX_ITERATIONS


def _parse_args() -> LoopConfig:
    p = argparse.ArgumentParser(description="Harness loop above `codex resume`.")
    p.add_argument("--prompt", required=True, help="Prompt sent to `codex resume` each iteration.")
    p.add_argument("--max-iterations", type=int, default=200)
    p.add_argument("--stagnation-limit", type=int, default=30)
    p.add_argument("--sleep-sec", type=float, default=0.5)
    p.add_argument("--out-dir", type=Path, default=Path("angr_platforms/.cache/codex_resume_loop"))
    p.add_argument("--marker-file", type=Path, default=Path("angr_platforms/.cache/codex_resume_loop/DONE.marker.json"))
    p.add_argument(
        "--goal-marker-file",
        type=Path,
        default=Path("angr_platforms/.cache/auto_decomp_loop/DONE.marker.json"),
        help="Goal marker file to watch (default: auto_decomp_loop done marker).",
    )
    p.add_argument(
        "--goal-stop-reason",
        default="goals_met",
        help="When --goal-marker-file exists, require this stop_reason value inside marker JSON (default: goals_met). Use empty string to accept any marker.",
    )
    p.add_argument("--stop-file", type=Path, default=None, help="External kill-switch file.")
    p.add_argument("--goal-cmd", default=None, help="Shell command; exit code 0 means done.")
    p.add_argument(
        "--status-cmd",
        default="test -f angr_platforms/.cache/auto_decomp_loop/DONE.marker.json",
        help="Shell command to collect status each iteration.",
    )
    p.add_argument("--session-id", default=None, help="Explicit session id/thread for `codex resume`.")
    p.add_argument(
        "--last",
        dest="resume_last",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use --last with `codex resume` (default: true). Use --no-last to require --session-id.",
    )
    p.add_argument("--codex-bin", default="codex")
    p.add_argument("--cwd", type=Path, default=Path.cwd())
    p.add_argument(
        "--extra-codex-args",
        default="--dangerously-bypass-approvals-and-sandbox",
        help="Extra args passed to `codex resume` (shell-split).",
    )
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    if not bool(args.resume_last) and not args.session_id:
        p.error("--no-last requires --session-id")

    return LoopConfig(
        prompt=args.prompt,
        max_iterations=max(1, int(args.max_iterations)),
        stagnation_limit=max(1, int(args.stagnation_limit)),
        sleep_sec=max(0.0, float(args.sleep_sec)),
        out_dir=args.out_dir,
        marker_file=args.marker_file,
        goal_marker_file=args.goal_marker_file,
        goal_stop_reason=(str(args.goal_stop_reason).strip() or None),
        stop_file=args.stop_file,
        goal_cmd=args.goal_cmd,
        status_cmd=args.status_cmd,
        resume_last=bool(args.resume_last),
        session_id=str(args.session_id) if args.session_id is not None else None,
        codex_bin=args.codex_bin,
        cwd=args.cwd.resolve(),
        extra_codex_args=tuple(shlex.split(args.extra_codex_args)),
        dry_run=bool(args.dry_run),
    )


def main() -> int:
    """Run the Codex resume loop from command-line arguments."""
    cfg = _parse_args()
    reason = run_loop(cfg)
    print(f"[codex-loop] stop_reason={reason.value} marker={cfg.marker_file}")
    return 0 if reason != StopReason.CODEX_ERROR else 2


if __name__ == "__main__":
    raise SystemExit(main())
