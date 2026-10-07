#!/usr/bin/env python3
"""Benchmark real-byte x86-16 block lifting and report latency percentiles.

Layer: Tooling/gates.
Responsibility: measure frontend lifting latency without changing decompiler semantics.

Run:
  PYTHONPATH=. ./.venv/bin/python tools/dev/benchmark_x86_16_block_lift_real.py
"""

from __future__ import annotations

import argparse
import statistics
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

from inertia.cli.project_loading import _build_project


def _percentile(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    if q <= 0:
        return sorted_values[0]
    if q >= 1:
        return sorted_values[-1]
    idx = (len(sorted_values) - 1) * q
    lo = int(idx)
    hi = min(lo + 1, len(sorted_values) - 1)
    frac = idx - lo
    return sorted_values[lo] * (1.0 - frac) + sorted_values[hi] * frac


def _bench(
    project: object,
    project_builder: Callable[[], object],
    addrs: list[int],
    rounds: int,
    *,
    cold: bool,
) -> tuple[list[float], dict[int, list[float]]]:
    timings_ms: list[float] = []
    per_addr: dict[int, list[float]] = {addr: [] for addr in addrs}

    for _ in range(rounds):
        if cold:
            project = project_builder()
        for addr in addrs:
            t0 = time.perf_counter()
            # Dynamic angr project boundary: the benchmark only needs its factory/block surface.
            project_dynamic = cast(Any, project)
            _ = project_dynamic.factory.block(addr).vex
            dt = (time.perf_counter() - t0) * 1000.0
            timings_ms.append(dt)
            per_addr[addr].append(dt)
    return timings_ms, per_addr


def _print_stats(
    label: str, timings_ms: list[float], per_addr: dict[int, list[float]], addrs: list[int], rounds: int
) -> None:
    timings_ms.sort()
    p50 = _percentile(timings_ms, 0.50)
    p95 = _percentile(timings_ms, 0.95)
    p99 = _percentile(timings_ms, 0.99)

    print(f"[{label}] samples={len(timings_ms)} rounds={rounds} blocks={len(addrs)}")
    print(f"[{label}] lift_ms_p50={p50:.3f}")
    print(f"[{label}] lift_ms_p95={p95:.3f}")
    print(f"[{label}] lift_ms_p99={p99:.3f}")
    print(f"[{label}] lift_ms_mean={statistics.fmean(timings_ms):.3f}")
    print(f"[{label}] per_block_mean_ms:")
    for addr in addrs:
        vals = per_addr[addr]
        print(f"  [{label}] 0x{addr:05x}: {statistics.fmean(vals):.3f}")


def main() -> None:
    """Run warm and/or cold block-lifting timing samples."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=50)
    ap.add_argument(
        "--mode",
        choices=("warm", "cold", "both"),
        default="both",
        help="warm: reuse caches, cold: clear cache each round, both: run both",
    )
    args = ap.parse_args()

    def _build_sortdemo_project() -> object:
        return _build_project(
            path=Path("./SORTDEMO.EXE"),
            force_blob=False,
            base_addr=0x1000,
            entry_point=0x1000,
        )

    project = _build_sortdemo_project()
    # Representative hot-path function entry blocks from SORTDEMO.
    addrs = [
        0x10CE0,  # QuickSort
        0x10C18,  # ShellSort
        0x10B50,  # ExchangeSort
        0x10A88,  # PercolateDown
        0x109E8,  # PercolateUp
        0x108D0,  # BubbleSort
        0x10808,  # InsertionSort
        0x10560,  # InitBars
        0x10498,  # DrawTime
        0x102E0,  # RunMenu
    ]

    if args.mode in {"warm", "both"}:
        warm_times, warm_per_addr = _bench(project, _build_sortdemo_project, addrs, args.rounds, cold=False)
        _print_stats("warm", warm_times, warm_per_addr, addrs, args.rounds)
    if args.mode in {"cold", "both"}:
        cold_times, cold_per_addr = _bench(project, _build_sortdemo_project, addrs, args.rounds, cold=True)
        _print_stats("cold", cold_times, cold_per_addr, addrs, args.rounds)


if __name__ == "__main__":
    main()
