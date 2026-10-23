#!/usr/bin/env python3
"""Layer: Tooling/build.

Responsibility: compile the authoritative Python IR source-graph binding in
pure mode through the shared ``build_cython_vex`` machinery. Generated C,
objects, the extension and its manifest stay under ignored
``.cache/cython-source-graph/``; the Python source remains interpretable.
"""

from __future__ import annotations

import argparse
import fcntl
import importlib.util
import sys
from pathlib import Path

ROOT: Path = Path(__file__).resolve().parents[2]

SOURCE: Path = ROOT / "inertia/ir/source_graph_binding.py"
MODULE: str = "inertia.ir.source_graph_binding"
CACHE: Path = ROOT / ".cache/cython-source-graph"


def main() -> None:
    """Build optional acceleration without importing the IR package."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="Regenerate C and rebuild even if compiler outputs exist")
    args = parser.parse_args()
    for dependency in ("Cython", "setuptools"):
        if importlib.util.find_spec(dependency) is None:
            raise SystemExit(f"Missing {dependency}; install Cython>=3.2 and setuptools into {sys.executable}")
    sys.path.insert(0, str(ROOT))
    from tools.dev.build_cython_vex import build

    CACHE.mkdir(parents=True, exist_ok=True)
    with (CACHE / "build.lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        print(build(source=SOURCE, module=MODULE, cache=CACHE, force=args.force))


if __name__ == "__main__":
    main()
