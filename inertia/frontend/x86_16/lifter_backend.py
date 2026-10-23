"""Layer: Frontend/runtime.

Responsibility: require a verified Cython build for normal Python VEX lifting,
while retaining explicit interpreted and opportunistic diagnostic modes.
The source remains authoritative; this module introduces no instruction semantics.
Manifest verification itself is owned by ``inertia.native_bundle``.
"""

from __future__ import annotations

import os
from enum import StrEnum
from pathlib import Path

from inertia.native_bundle import BUILD_SCHEMA, file_digest, verified_bundle_directory

LIFTER_SOURCE: str = "inertia/frontend/x86_16/lift_86_16.py"
LIFTER_EXTENSION: str = "lift_86_16"
PACKAGE_BUNDLE: str = "cython-vex"

__all__ = [
    "BUILD_SCHEMA",
    "LIFTER_SOURCE",
    "PACKAGE_BUNDLE",
    "LifterBackend",
    "activate_lifter_backend",
    "file_digest",
    "verified_extension_directory",
    "verified_packaged_extension_directory",
]


class LifterBackend(StrEnum):
    """Select interpretation, required compilation, or verified opportunistic use."""

    PYTHON = "python"
    CYTHON = "cython"
    AUTO = "auto"


def _verified_extension_directory(manifest_path: Path, confinement: Path, source: Path) -> Path | None:
    """Apply the shared schema/ABI/source/digest/confinement checks to one manifest."""
    directory: Path | None = verified_bundle_directory(manifest_path, confinement, source, LIFTER_EXTENSION)
    return directory


def verified_extension_directory(root: Path) -> Path | None:
    """Return a source/ABI/artifact-matched build, or reject an obsolete cache."""
    cache = root / ".cache/cython-vex"
    return _verified_extension_directory(cache / "active.json", cache, root / LIFTER_SOURCE)


def verified_packaged_extension_directory(package_dir: Path) -> Path | None:
    """Return a verified extension bundled beside an isolated copied lifter.

    Flat package copies such as the isolated mypyc import tree carry no
    repository ``.cache`` layout. A staged bundle mirrors the same manifest
    contract inside the copied package directory, and ``source_sha256`` must
    match the copied ``lift_86_16.py`` bytes rather than the repository source.
    """
    bundle = package_dir / PACKAGE_BUNDLE
    return _verified_extension_directory(bundle / "active.json", bundle, package_dir / Path(LIFTER_SOURCE).name)


def activate_lifter_backend(package_path: list[str], *, package_dir: Path | None = None) -> LifterBackend:
    """Prepend a verified extension directory before the lifter's first import.

    Normal startup requires Cython and fails loudly if its build is absent or
    stale. Explicit python mode retains interpretation for diagnostics; auto
    remains an opt-in compatibility mode with a visible Python fallback.
    The extension has the canonical module name, preserving registration and
    pickle identities. Selection must happen before any frontend imports.
    A verified bundle staged beside this copied file takes precedence over the
    repository cache so isolated package trees use their own bound artifact.
    An explicit package directory binds selection to the actual lifter owner
    while its verifier and source packages migrate independently.
    """
    value = os.environ.get("INERTIA_VEX_BACKEND", LifterBackend.CYTHON.value)
    try:
        mode = LifterBackend(value)
    except ValueError as exc:
        raise ValueError(f"Invalid INERTIA_VEX_BACKEND={value!r}; choose python, cython, or auto") from exc
    if mode is LifterBackend.PYTHON:
        return mode
    module_path = Path(__file__).resolve()
    directory = verified_packaged_extension_directory(module_path.parent if package_dir is None else package_dir)
    if directory is None:
        directory = verified_extension_directory(module_path.parents[3])
    if directory is None:
        if mode is LifterBackend.CYTHON:
            raise ImportError("Cython VEX build missing or stale; run tools/dev/build_cython_vex.py or use INERTIA_VEX_BACKEND=python")
        return LifterBackend.PYTHON
    package_path.insert(0, str(directory))
    return LifterBackend.CYTHON
