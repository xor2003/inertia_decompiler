"""Write a single decompiler recovery artifact for diagnostics.

Layer: Tooling/gates.
Responsibility: write bounded recovery diagnostics without changing decompiler semantics.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia.cli.targeted_recovery_artifact import (  # noqa: E402
    write_x86_16_targeted_cod_recovery_artifact,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write a bounded targeted recovery artifact for one COD PROC.")
    parser.add_argument("cod_path", type=Path)
    parser.add_argument("proc_name")
    parser.add_argument("output", type=Path)
    parser.add_argument("--timeout", type=int, default=5)
    parser.add_argument("--mode", default="scan-safe")
    args = parser.parse_args(argv)

    result = write_x86_16_targeted_cod_recovery_artifact(
        args.cod_path,
        args.proc_name,
        args.output,
        timeout_sec=args.timeout,
        mode=args.mode,
    )
    print(f"path: {result.write_result.path}")
    print(f"proc: {result.proc_name}")
    print(f"confidence: {result.confidence_status}")
    print(f"fallback: {result.fallback_kind}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
