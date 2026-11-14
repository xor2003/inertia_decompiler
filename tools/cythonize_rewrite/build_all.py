"""Layer: Tooling/cythonize.

Responsibility: cython-compile every ``*.py`` module of the package into an
in-place extension module (``<module>.cpython-*.so`` next to the source), in
parallel. ``.so`` files shadow ``.py`` on import, so modules that fail to
compile transparently fall back to interpreted execution.

Phase 1 (``--check-only`` or as the pre-pass): run ``cython`` per file,
collect compile errors to JSON for codemod iteration.

Phase 2 (default): cythonize + gcc via setuptools, parallel, into place.

Usage:
  python tools/cythonize_rewrite/build_all.py inertia --check-only --jobs 8
  python tools/cythonize_rewrite/build_all.py inertia --build --jobs 8
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
VENV_PY = ROOT / ".venv" / "bin" / "python"
CYTHON = ROOT / ".venv" / "bin" / "cython"


def _module_name(root: pathlib.Path, path: pathlib.Path) -> str:
    """Dotted module name for ``path`` under package ``root``."""
    rel = path.relative_to(root.parent)
    return ".".join(rel.with_suffix("").parts)


def _check_one(path_s: str) -> tuple[str, str | None]:
    """Compile one file to C; return (path, error-text-or-None)."""
    path = pathlib.Path(path_s)
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / (path.stem + ".c")
        proc = subprocess.run(
            [str(CYTHON), "-3", "-o", str(out), str(path)],
            capture_output=True, text=True, timeout=300,
        )
        if proc.returncode == 0:
            return path_s, None
        return path_s, (proc.stderr or proc.stdout or "unknown error")[-4000:]


def check(root: pathlib.Path, jobs: int, report: pathlib.Path | None) -> int:
    """Phase 1: syntax/declaration check of every module, error manifest."""
    paths = [str(p) for p in sorted(root.rglob("*.py"))]
    with mp.Pool(jobs) as pool:
        results = pool.map(_check_one, paths, chunksize=4)
    errors = {p: e for p, e in results if e}
    ok = sum(1 for _, e in results if e is None)
    print(json.dumps({"checked": len(paths), "ok": ok, "failed": len(errors)}))
    if report:
        report.write_text(json.dumps(errors, indent=1, sort_keys=True) + "\n")
    return 0 if not errors else 1


def build(root: pathlib.Path, jobs: int, report: pathlib.Path | None) -> int:
    """Phase 2: cythonize + compile all modules in place via setuptools."""
    from Cython.Build import cythonize
    from setuptools import Distribution, Extension
    from setuptools.command.build_ext import build_ext

    cflags = os.environ.get("CYTHON_CFLAGS", "-O2")
    paths = sorted(root.rglob("*.py"))
    exts = [
        Extension(
            _module_name(root, p),
            sources=[str(p)],
            extra_compile_args=[cflags, "-w"],
        )
        for p in paths
    ]
    directives = {
        "language_level": 3,
        "infer_types": True,
        "binding": True,
    }
    # Modules that cannot compile (PEP-810 ``lazy import`` and other
    # unsupported constructs) are excluded; without a ``.so`` their ``.py``
    # is imported interpreted — graceful degradation, never a hard failure.
    exts = cythonize(
        exts,
        compiler_directives=directives,
        nthreads=jobs,
        build_dir=str(ROOT / "build" / "cython-all"),
        exclude_failures=True,
    )
    dist = Distribution({"name": "inertia-cython", "ext_modules": exts})
    cmd = build_ext(dist)
    cmd.inplace = True
    cmd.parallel = jobs
    cmd.ensure_finalized()
    cmd.run()
    return 0


def main() -> None:
    """Entry point: dispatch check or build phase."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", type=pathlib.Path)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--check-only", action="store_true")
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--report", type=pathlib.Path)
    args = ap.parse_args()

    if args.check_only:
        sys.exit(check(args.root, args.jobs, args.report))
    if args.build:
        sys.exit(build(args.root, args.jobs, args.report))
    ap.print_help()


if __name__ == "__main__":
    main()
