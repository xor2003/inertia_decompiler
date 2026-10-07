#!/usr/bin/env python3
"""Layer: Tooling/performance.

Responsibility: measure uncached SORTDEMO SSA lowering and persist parity evidence.
Run once per backend in fresh processes; existing VEX caches are not consumed.
"""

from __future__ import annotations

import argparse
import cProfile
import json
import resource
import sys
import time
from pathlib import Path

ROOT: Path = Path(__file__).resolve().parents[2]
for path in (ROOT,):
    sys.path.insert(0, str(path))


def main() -> None:
    """Save semantic artifacts separately from timing and backend metadata."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--functions", type=int, default=5)
    parser.add_argument("--profile", type=Path, help="Profile lowering only; do not use instrumented timings as a speed benchmark")
    args = parser.parse_args()
    start = time.perf_counter()
    cpu = time.process_time()
    from tools.dosunit.catalog.discovery import discover_functions
    from tools.dosunit.compare.straightline_ssa import lower_straightline_ssa_document

    catalog = discover_functions(exe_path=ROOT / "SORTDEMO.EXE", map_path=ROOT / "SORTDEMO.MAP", cod_listing_path=ROOT / "SORTDEMO.COD")
    catalog["functions"] = [
        function for function in catalog["functions"]
        if function.get("confidence") == "high" and isinstance(function.get("size"), int) and 32 <= function["size"] <= 300
    ][:args.functions]
    from inertia.frontend.x86_16 import lift_86_16
    from inertia.frontend.x86_16.public_api import VEX_BACKEND

    lowering_start = time.perf_counter()
    lowering_cpu = time.process_time()
    profiler = cProfile.Profile()
    if args.profile is not None:
        profiler.enable()
    document = lower_straightline_ssa_document(
        exe_path=ROOT / "SORTDEMO.EXE", functions_catalog=catalog,
        max_blocks_per_function=128, max_insns_per_function=256, scan_limit=0x1000,
        max_function_ms=60000,
    )
    if args.profile is not None:
        profiler.disable()
        profiler.dump_stats(str(args.profile))
    metrics = {
        "backend": VEX_BACKEND.value, "module": lift_86_16.__file__,
        "profiled": args.profile is not None,
        "wall_seconds": time.perf_counter() - start, "cpu_seconds": time.process_time() - cpu,
        "lowering_wall_seconds": time.perf_counter() - lowering_start,
        "lowering_cpu_seconds": time.process_time() - lowering_cpu,
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "counters": document["counters"],
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "ssa.json").write_text(json.dumps({key: document[key] for key in ("functions", "refusals", "counters")}, sort_keys=True, indent=2) + "\n")
    (args.out / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    print(json.dumps(metrics, sort_keys=True))


if __name__ == "__main__":
    main()
