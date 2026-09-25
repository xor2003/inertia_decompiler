#!/usr/bin/env python3
"""Run bounded autonomous decompilation repair loops from explicit stop criteria.

Layer: Tooling/gates.
Responsibility: iterate decompilation quality gates and stop only from typed loop outcomes.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import json
import os
import re
import subprocess
import time
from pathlib import Path


class TailVerdict(enum.Enum):
    CLEAN = "clean"
    FAILED = "failed"
    UNKNOWN = "unknown"
    UNCOLLECTED = "uncollected"
    MISSING = "missing"


class StopReason(enum.Enum):
    GOALS_MET = "goals_met"
    STAGNATED = "stagnated"
    MAX_ITERATIONS = "max_iterations"
    STOP_FILE = "stop_file"
    COMMAND_ERROR = "command_error"


@dataclasses.dataclass(frozen=True)
class IterationStats:
    iteration: int
    elapsed_sec: float
    returncode: int
    function_count: int
    asm_fallback_count: int
    c_fallback_count: int
    decompiled_count: int
    tail_verdict: TailVerdict
    tail_total: int
    tail_clean: int
    tail_failed: int
    tail_unknown: int
    tail_uncollected: int
    tail_missing: int
    dead_setup_candidates: int
    dead_setup_pruned: int
    dead_setup_refused: int
    dead_setup_escaped: int
    report_path: Path
    log_path: Path

    def quality_tuple(self) -> tuple[int, int, int, int, int]:
        # higher is better
        return (
            self.tail_clean,
            -self.tail_failed,
            -self.tail_uncollected,
            -self.asm_fallback_count,
            -self.dead_setup_escaped,
        )


@dataclasses.dataclass(frozen=True)
class LoopConfig:
    binary: Path
    timeout: int
    include_library_functions: bool
    max_functions: int
    max_iterations: int
    stagnation_limit: int
    sleep_sec: float
    out_dir: Path
    marker_file: Path
    stop_file: Path | None
    gate_require_zero_asm_fallback: bool


_FUNCTION_LINE_RE = re.compile(r"(?m)^(?:\[[0-9:]+\]\s+)?/\*\s+==\s+function\s+")
_TAIL_CLEAN_RE = re.compile(r"whole-tail validation clean across (\d+) functions", re.IGNORECASE)
_TAIL_FAILED_RE = re.compile(r"whole-tail validation failed across (\d+) functions", re.IGNORECASE)
_TAIL_UNKNOWN_RE = re.compile(r"whole-tail validation unknown across (\d+) functions", re.IGNORECASE)
_TAIL_UNCOLLECTED_RE = re.compile(r"whole-tail validation not collected across (\d+) functions", re.IGNORECASE)
_TAIL_COVERAGE_RE = re.compile(r"coverage=(\d+)\s+missing=(\d+)\s+unknown=(\d+)")
_DEAD_SETUP_SUMMARY_RE = re.compile(
    r"summary:\s+dead_setup_candidates=(\d+)\s+dead_setup_pruned=(\d+)\s+dead_setup_refused=(\d+)\s+dead_setup_escaped=(\d+)",
    re.IGNORECASE,
)


def _sum_tail_matches(pattern: re.Pattern[str], output: str) -> int:
    """Sum the first capture group of every tail-stat match."""
    return sum(int(m.group(1)) for m in pattern.finditer(output))


def _tail_verdict_8616(clean: int, failed: int, unknown: int, uncollected: int, missing: int) -> TailVerdict:
    """Rank the tail-validation outcome from aggregated counters."""
    if failed > 0:
        return TailVerdict.FAILED
    if uncollected > 0:
        return TailVerdict.UNCOLLECTED
    if unknown > 0:
        return TailVerdict.UNKNOWN
    if missing > 0:
        return TailVerdict.MISSING
    if clean > 0:
        return TailVerdict.CLEAN
    return TailVerdict.UNCOLLECTED


def _parse_tail_stats(output: str) -> tuple[TailVerdict, int, int, int, int, int, int]:
    clean = _sum_tail_matches(_TAIL_CLEAN_RE, output)
    failed = _sum_tail_matches(_TAIL_FAILED_RE, output)
    unknown = _sum_tail_matches(_TAIL_UNKNOWN_RE, output)
    uncollected = _sum_tail_matches(_TAIL_UNCOLLECTED_RE, output)
    missing = 0
    total = 0

    for m in _TAIL_COVERAGE_RE.finditer(output):
        total = max(total, int(m.group(1)))
        missing = max(missing, int(m.group(2)))
        unknown = max(unknown, int(m.group(3)))

    if total == 0:
        # fallback estimate from verdict counts
        total = clean + failed + unknown + uncollected
    if missing == 0 and total > 0:
        seen = clean + failed + unknown + uncollected
        missing = max(0, total - seen)

    verdict = _tail_verdict_8616(clean, failed, unknown, uncollected, missing)
    return verdict, total, clean, failed, unknown, uncollected, missing


def _count_functions(output: str) -> int:
    return len(_FUNCTION_LINE_RE.findall(output))


def _parse_dead_setup_summary(output: str) -> tuple[int, int, int, int]:
    candidates = 0
    pruned = 0
    refused = 0
    escaped = 0
    for m in _DEAD_SETUP_SUMMARY_RE.finditer(output):
        candidates = max(candidates, int(m.group(1)))
        pruned = max(pruned, int(m.group(2)))
        refused = max(refused, int(m.group(3)))
        escaped = max(escaped, int(m.group(4)))
    return candidates, pruned, refused, escaped


def _run_iteration(cfg: LoopConfig, iteration: int) -> IterationStats:
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    log_path = cfg.out_dir / f"iter_{iteration:04d}.log"
    report_path = cfg.out_dir / f"iter_{iteration:04d}.json"

    cmd = [
        str(Path(".venv/bin/python")),
        "decompile.py",
        "--alternate-source-c",
        "--timeout",
        str(cfg.timeout),
        "--max-functions",
        str(cfg.max_functions),
    ]
    if cfg.include_library_functions:
        cmd.append("--include-library-functions")
    cmd.append(str(cfg.binary))

    env = dict(os.environ)
    env["INERTIA_ENABLE_TAIL_VALIDATION"] = "1"
    env.setdefault("INERTIA_DISABLE_TIMING", "1")

    t0 = time.monotonic()
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )
    elapsed = time.monotonic() - t0
    output = proc.stdout or ""
    log_path.write_text(output, encoding="utf-8")

    verdict, tail_total, tail_clean, tail_failed, tail_unknown, tail_uncollected, tail_missing = _parse_tail_stats(
        output
    )
    dead_setup_candidates, dead_setup_pruned, dead_setup_refused, dead_setup_escaped = _parse_dead_setup_summary(output)
    stats = IterationStats(
        iteration=iteration,
        elapsed_sec=elapsed,
        returncode=proc.returncode,
        function_count=_count_functions(output),
        asm_fallback_count=output.lower().count("/* == asm fallback == */"),
        c_fallback_count=output.lower().count("/* == c (non-optimized fallback) == */"),
        decompiled_count=output.lower().count("/* == c == */"),
        tail_verdict=verdict,
        tail_total=tail_total,
        tail_clean=tail_clean,
        tail_failed=tail_failed,
        tail_unknown=tail_unknown,
        tail_uncollected=tail_uncollected,
        tail_missing=tail_missing,
        dead_setup_candidates=dead_setup_candidates,
        dead_setup_pruned=dead_setup_pruned,
        dead_setup_refused=dead_setup_refused,
        dead_setup_escaped=dead_setup_escaped,
        report_path=report_path,
        log_path=log_path,
    )
    report_path.write_text(
        json.dumps(
            {
                "iteration": stats.iteration,
                "elapsed_sec": round(stats.elapsed_sec, 3),
                "returncode": stats.returncode,
                "function_count": stats.function_count,
                "asm_fallback_count": stats.asm_fallback_count,
                "c_fallback_count": stats.c_fallback_count,
                "decompiled_count": stats.decompiled_count,
                "tail_verdict": stats.tail_verdict.value,
                "tail_total": stats.tail_total,
                "tail_clean": stats.tail_clean,
                "tail_failed": stats.tail_failed,
                "tail_unknown": stats.tail_unknown,
                "tail_uncollected": stats.tail_uncollected,
                "tail_missing": stats.tail_missing,
                "dead_setup_candidates": stats.dead_setup_candidates,
                "dead_setup_pruned": stats.dead_setup_pruned,
                "dead_setup_refused": stats.dead_setup_refused,
                "dead_setup_escaped": stats.dead_setup_escaped,
                "log_path": str(stats.log_path),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return stats


def _goals_met(cfg: LoopConfig, stats: IterationStats) -> bool:
    if stats.tail_total <= 0:
        return False
    if stats.tail_failed != 0 or stats.tail_unknown != 0 or stats.tail_uncollected != 0 or stats.tail_missing != 0:
        return False
    if cfg.gate_require_zero_asm_fallback and stats.asm_fallback_count != 0:
        return False
    return stats.dead_setup_escaped == 0


def _print_status(stats: IterationStats, best: IterationStats | None, stagnation: int) -> None:
    best_iter = best.iteration if best is not None else stats.iteration
    print(
        f"[loop] iter={stats.iteration} rc={stats.returncode} sec={stats.elapsed_sec:.1f} "
        f"func={stats.function_count} c={stats.decompiled_count} c_fallback={stats.c_fallback_count} "
        f"asm={stats.asm_fallback_count} tail={stats.tail_verdict.value} "
        f"(clean={stats.tail_clean} failed={stats.tail_failed} unknown={stats.tail_unknown} "
        f"uncollected={stats.tail_uncollected} missing={stats.tail_missing} total={stats.tail_total}) "
        f"dead_setup=(cand={stats.dead_setup_candidates} pruned={stats.dead_setup_pruned} "
        f"refused={stats.dead_setup_refused} escaped={stats.dead_setup_escaped}) "
        f"best_iter={best_iter} stagnation={stagnation}"
    )
    print(f"[loop] report={stats.report_path} log={stats.log_path}")


def _write_marker(
    marker_path: Path, reason: StopReason, best: IterationStats | None, last: IterationStats | None
) -> None:
    marker_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "stop_reason": reason.value,
        "timestamp_unix": int(time.time()),
        "best_iteration": None if best is None else best.iteration,
        "last_iteration": None if last is None else last.iteration,
        "best_tail_verdict": None if best is None else best.tail_verdict.value,
        "last_tail_verdict": None if last is None else last.tail_verdict.value,
        "best_report_path": None if best is None else str(best.report_path),
        "last_report_path": None if last is None else str(last.report_path),
    }
    marker_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def run_loop(cfg: LoopConfig) -> StopReason:
    best: IterationStats | None = None
    last: IterationStats | None = None
    stagnation = 0

    for iteration in range(1, cfg.max_iterations + 1):
        if cfg.stop_file is not None and cfg.stop_file.exists():
            _write_marker(cfg.marker_file, StopReason.STOP_FILE, best, last)
            return StopReason.STOP_FILE

        stats = _run_iteration(cfg, iteration)
        last = stats
        improved = best is None or stats.quality_tuple() > best.quality_tuple()
        if improved:
            best = stats
            stagnation = 0
        else:
            stagnation += 1
        _print_status(stats, best, stagnation)

        if stats.returncode not in (0, 4):
            _write_marker(cfg.marker_file, StopReason.COMMAND_ERROR, best, last)
            return StopReason.COMMAND_ERROR
        if _goals_met(cfg, stats):
            _write_marker(cfg.marker_file, StopReason.GOALS_MET, best, last)
            return StopReason.GOALS_MET
        if stagnation >= cfg.stagnation_limit:
            _write_marker(cfg.marker_file, StopReason.STAGNATED, best, last)
            return StopReason.STAGNATED
        if iteration < cfg.max_iterations:
            time.sleep(cfg.sleep_sec)

    _write_marker(cfg.marker_file, StopReason.MAX_ITERATIONS, best, last)
    return StopReason.MAX_ITERATIONS


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Auto-run decompilation quality loop until tail-validation goals are met.")
    p.add_argument("binary", type=Path, help="Binary path (for example SORTDEMO.EXE).")
    p.add_argument("--timeout", type=int, default=60, help="Per decompile.py run timeout seconds.")
    p.add_argument(
        "--include-library-functions", action="store_true", help="Run whole sweep including library functions."
    )
    p.add_argument("--max-functions", type=int, default=0, help="Pass-through max functions (0 = all).")
    p.add_argument("--max-iterations", type=int, default=200, help="Hard cap for loop iterations.")
    p.add_argument(
        "--stagnation-limit", type=int, default=20, help="Stop if no quality improvement across N iterations."
    )
    p.add_argument("--sleep-sec", type=float, default=0.5, help="Sleep between iterations.")
    p.add_argument(
        "--out-dir",
        type=Path,
        default=Path("angr_platforms/.cache/auto_decomp_loop"),
        help="Output directory for logs/reports.",
    )
    p.add_argument(
        "--marker-file",
        type=Path,
        default=Path("angr_platforms/.cache/auto_decomp_loop/DONE.marker.json"),
        help="Marker file written on loop stop.",
    )
    p.add_argument("--stop-file", type=Path, default=None, help="Optional external stop trigger file.")
    p.add_argument(
        "--allow-asm-fallback",
        action="store_true",
        help="Do not require asm fallback count to be zero for success.",
    )
    return p


def main() -> int:
    args = _build_parser().parse_args()
    cfg = LoopConfig(
        binary=args.binary,
        timeout=max(1, int(args.timeout)),
        include_library_functions=bool(args.include_library_functions),
        max_functions=max(0, int(args.max_functions)),
        max_iterations=max(1, int(args.max_iterations)),
        stagnation_limit=max(1, int(args.stagnation_limit)),
        sleep_sec=max(0.0, float(args.sleep_sec)),
        out_dir=args.out_dir,
        marker_file=args.marker_file,
        stop_file=args.stop_file,
        gate_require_zero_asm_fallback=not bool(args.allow_asm_fallback),
    )
    reason = run_loop(cfg)
    print(f"[loop] stop_reason={reason.value} marker={cfg.marker_file}")
    return (
        0
        if reason in (StopReason.GOALS_MET, StopReason.STOP_FILE, StopReason.MAX_ITERATIONS, StopReason.STAGNATED)
        else 2
    )


if __name__ == "__main__":
    raise SystemExit(main())
