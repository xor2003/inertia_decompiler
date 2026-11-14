#!/usr/bin/env python3
"""Layer: Tooling/build.

Responsibility: compile the mypyc hotspot cohort (``build_mypyc.TARGET_MODULES``)
in pure Python mode through the shared ``build_cython_vex`` machinery. Generated
C, objects, extensions and manifests stay under ignored
``.cache/cython-hotspots/<module-path>/``; every Python source remains
interpretable and unchanged. ``inertia/hotspot_import.py`` activates a verified
extension per module through the shared schema-1 manifest contract.
"""

from __future__ import annotations

import argparse
import fcntl
import importlib.util
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

ROOT: Path = Path(__file__).resolve().parents[2]
CACHE_ROOT: Path = ROOT / ".cache/cython-hotspots"
COHORT_SCHEMA: int = 1


def _module_source(module: str, root: Path) -> Path:
    """Resolve a dotted module name to its authoritative Python source."""
    return root.joinpath(*module.split(".")).with_suffix(".py")


def _module_cache(module: str, cache_root: Path) -> Path:
    """Return the per-module confinement directory mirroring the package path."""
    return cache_root.joinpath(*module.split("."))


def _build_one(module: str, cache_root: str, force: bool) -> str:
    """Compile one module in a worker process and return its extension path."""
    root = Path(__file__).resolve().parents[2]
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    from tools.dev.build_cython_vex import build

    return str(
        build(
            source=_module_source(module, root),
            module=module,
            cache=_module_cache(module, Path(cache_root)),
            force=force,
        )
    )


def _write_cohort_manifest(cache_root: Path, modules: list[str]) -> Path:
    """Publish the exact built module list for the import boundary."""
    payload = {
        "schema": COHORT_SCHEMA,
        "modules": sorted(modules),
    }
    temporary = cache_root / f"cohort.{os.getpid()}.json"
    temporary.write_text(json.dumps(payload, indent=2) + "\n")
    target = cache_root / "cohort.json"
    temporary.replace(target)
    return target


def _run_cohort_build(modules: list[str], cache_root: Path, jobs: int, force: bool) -> int:
    """Compile every cohort module and report per-module failures."""
    failures: dict[str, str] = {}
    with ProcessPoolExecutor(max_workers=max(1, jobs)) as pool:
        futures = {
            pool.submit(_build_one, module, str(cache_root), force): module
            for module in modules
        }
        for future, module in futures.items():
            try:
                artifact = future.result()
            except Exception as exc:
                failures[module] = str(exc)[:200]
            else:
                print(f"{module} -> {artifact}")
    if failures:
        for module, reason in sorted(failures.items()):
            print(f"FAILED {module}: {reason}", file=sys.stderr)
        return 1
    print(_write_cohort_manifest(cache_root, modules))
    return 0


def main(argv: list[str] | None = None) -> int:
    """Build the hotspot cohort with bounded parallelism."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force", action="store_true",
        help="Regenerate C and rebuild even if compiler outputs exist",
    )
    parser.add_argument(
        "--jobs", type=int, default=max(1, (os.cpu_count() or 1) - 1),
        help="Maximum parallel module builds; defaults to the host CPU count minus one.",
    )
    parser.add_argument(
        "--cache-root", type=Path, default=CACHE_ROOT,
        help="Override the confinement root (default .cache/cython-hotspots).",
    )
    parser.add_argument(
        "--module", action="append", default=[],
        help="Build only the named module(s) instead of the full cohort.",
    )
    args = parser.parse_args(argv)

    for dependency in ("Cython", "setuptools"):
        if importlib.util.find_spec(dependency) is None:
            raise SystemExit(
                f"Missing {dependency}; install Cython>=3.2 and setuptools into {sys.executable}"
            )
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from tools.dev.build_mypyc import TARGET_MODULES

    modules = list(dict.fromkeys(args.module)) or list(TARGET_MODULES)
    unknown = [module for module in modules if module not in TARGET_MODULES]
    if unknown:
        raise SystemExit(f"Module(s) outside the hotspot cohort: {', '.join(sorted(unknown))}")
    missing = [module for module in modules if not _module_source(module, ROOT).is_file()]
    if missing:
        raise SystemExit(f"Missing authoritative sources: {', '.join(sorted(missing))}")

    cache_root = args.cache_root.resolve()
    cache_root.mkdir(parents=True, exist_ok=True)
    with (cache_root / "build.lock").open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        return _run_cohort_build(modules, cache_root, args.jobs, args.force)


if __name__ == "__main__":
    raise SystemExit(main())
