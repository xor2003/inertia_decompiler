"""Layer: Tooling/cythonize.

Responsibility: build all cythonizable ``inertia`` modules in place, in
per-directory batches.  Each batch is cythonized, compiled to ``.so``
next to its source, then its generated ``.c``/``.o`` intermediates are
removed — keeps peak disk usage to one batch on small filesystems.
Modules that fail to cythonize are excluded and stay interpreted.

Usage:
  CYTHON_CFLAGS=-O2 python tools/cythonize_rewrite/build_batches.py inertia [jobs]
"""

from __future__ import annotations

import collections
import os
import pathlib
import shutil
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _module_name(root: pathlib.Path, path: pathlib.Path) -> str:
    rel = path.relative_to(root.parent)
    return ".".join(rel.with_suffix("").parts)


def _batch_dirs(root: pathlib.Path) -> dict[pathlib.Path, list[pathlib.Path]]:
    """Group py files by their parent dir (one build batch per dir)."""
    groups: dict[pathlib.Path, list[pathlib.Path]] = collections.defaultdict(list)
    for p in sorted(root.rglob("*.py")):
        groups[p.parent].append(p)
    return dict(groups)


def _build_batch(root: pathlib.Path, files: list[pathlib.Path],
                 build_dir: pathlib.Path, jobs: int) -> tuple[int, int]:
    """Cythonize+compile one batch; return (built, failed)."""
    from Cython.Build import cythonize
    from setuptools import Distribution, Extension
    from setuptools.command.build_ext import build_ext

    cflags = os.environ.get("CYTHON_CFLAGS", "-O2")
    exts = [
        Extension(
            _module_name(root, p),
            sources=[str(p)],
            extra_compile_args=[cflags, "-w"],
        )
        for p in files
    ]
    exts = cythonize(
        exts,
        compiler_directives={
            "language_level": 3,
            "infer_types": True,
            "binding": True,
        },
        nthreads=jobs,
        build_dir=str(build_dir),
        exclude_failures=True,
        quiet=True,
    )
    if not exts:
        return 0, len(files)
    dist = Distribution({"name": "inertia-cython", "ext_modules": exts})
    cmd = build_ext(dist)
    cmd.inplace = True
    cmd.parallel = jobs
    cmd.build_temp = str(build_dir / "tmp")
    cmd.ensure_finalized()
    cmd.run()
    return len(exts), len(files) - len(exts)


def main() -> int:
    root = pathlib.Path(sys.argv[1]).resolve()
    jobs = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    build_root = ROOT / "build" / "cython-all"
    total_built = total_failed = 0
    groups = _batch_dirs(root)
    for i, (d, files) in enumerate(sorted(groups.items()), 1):
        batch_dir = build_root / d.name
        batch_dir.mkdir(parents=True, exist_ok=True)
        try:
            built, failed = _build_batch(root, files, batch_dir, jobs)
        except Exception as exc:  # noqa: BLE001 - record batch failure
            print(f"[{i}/{len(groups)}] {d.name}: ERROR {exc}", flush=True)
            built, failed = 0, len(files)
        total_built += built
        total_failed += failed
        sos = len(list(d.glob("*.cpython-*.so")))
        print(f"[{i}/{len(groups)}] {d.name}: built={built} failed={failed} so={sos}",
              flush=True)
        shutil.rmtree(batch_dir, ignore_errors=True)  # drop .c/.o intermediates
    print(json_line := f"BUILT={total_built} FAILED={total_failed}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
