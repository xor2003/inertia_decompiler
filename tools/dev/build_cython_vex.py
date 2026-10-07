#!/usr/bin/env python3
"""Layer: Tooling/build.

Responsibility: compile the authoritative Python 16-bit VEX lifter in pure mode.
No generated files are installed beside sources; interpretation stays available.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import sys
import sysconfig
from pathlib import Path
from typing import Any

ROOT: Path = Path(__file__).resolve().parents[2]
SOURCE: Path = ROOT / "inertia/frontend/x86_16/lift_86_16.py"
DIRECTIVES: dict[str, int | bool] = {"language_level": 3, "annotation_typing": False, "binding": True, "infer_types": False}
COMPILE_ARGS: tuple[str, ...] = ("-O2", "-g0")


def _digest(path: Path) -> str:
    """Hash the exact authoritative source or built extension."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(*, force: bool = False, annotate_only: bool = False) -> Path:
    """Build a source/ABI-specific extension and atomically publish its manifest.

    Python annotations describe owned contracts, not C storage. Disabling
    annotation typing and inference preserves arbitrary-width integers,
    subclass acceptance, None handling, and dynamic Gymrat method binding.
    """
    from Cython import __version__ as cython_version
    from Cython.Build import cythonize
    from setuptools import Distribution, Extension

    cache = ROOT / ".cache/cython-vex"
    if annotate_only:
        annotated = cythonize(
            [Extension("inertia.frontend.x86_16.lift_86_16", [str(SOURCE)])],
            build_dir=str(cache / "annotation"), compiler_directives=DIRECTIVES,
            annotate=True, force=force,
        )
        return Path(annotated[0].sources[0]).with_suffix(".html")
    identity = {
        "schema": 1,
        "source_sha256": _digest(SOURCE),
        "cache_tag": sys.implementation.cache_tag,
        "soabi": sysconfig.get_config_var("SOABI"),
        "cython": cython_version,
        "compiler": os.environ.get("CC", sysconfig.get_config_var("CC")),
        "extra_compile_args": list(COMPILE_ARGS),
        "directives": DIRECTIVES,
    }
    key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()[:20]
    cohort = cache / key
    cohort.mkdir(parents=True, exist_ok=True)
    os.environ["TMPDIR"] = str(cohort)
    # Python tracebacks and annotation HTML retain source diagnostics. Emitting
    # DWARF for this large generated C file adds build work and artifact size.
    extension = Extension("inertia.frontend.x86_16.lift_86_16", [str(SOURCE)], extra_compile_args=list(COMPILE_ARGS))
    modules = cythonize([extension], build_dir=str(cohort / "cgen"), compiler_directives=DIRECTIVES, force=force)
    distribution = Distribution({"ext_modules": modules})
    command: Any = distribution.get_command_obj("build_ext")  # setuptools' dynamic command API
    command.build_lib = str(cohort / "lib")
    command.build_temp = str(cohort / "temp")
    command.force = force
    command.ensure_finalized()
    command.run()
    artifact = Path(command.get_outputs()[0])
    if _digest(SOURCE) != identity["source_sha256"]:
        raise RuntimeError("Lifter source changed during compilation; rebuild before activation")
    identity["extension"] = str(artifact.relative_to(cache))
    identity["extension_sha256"] = _digest(artifact)
    temporary = cache / f"active.{os.getpid()}.json"
    temporary.write_text(json.dumps(identity, indent=2) + "\n")
    temporary.replace(cache / "active.json")
    return artifact


def main() -> None:
    """Build optional acceleration without importing the frontend package."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="Regenerate C and rebuild even if compiler outputs exist")
    parser.add_argument("--annotate-only", action="store_true", help="Generate Python-interaction HTML without building or activating an extension")
    args = parser.parse_args()
    for dependency in ("Cython", "setuptools"):
        if importlib.util.find_spec(dependency) is None:
            raise SystemExit(f"Missing {dependency}; install Cython>=3.2 and setuptools into {sys.executable}")
    cache = ROOT / ".cache/cython-vex"
    cache.mkdir(parents=True, exist_ok=True)
    lock_name = "annotation.lock" if args.annotate_only else "build.lock"
    with (cache / lock_name).open("a") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        print(build(force=args.force, annotate_only=args.annotate_only))


if __name__ == "__main__":
    main()
