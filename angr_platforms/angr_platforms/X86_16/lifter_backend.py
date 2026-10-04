"""Layer: Frontend/runtime.

Responsibility: require a verified Cython build for normal Python VEX lifting,
while retaining explicit interpreted and opportunistic diagnostic modes.
The source remains authoritative; this module introduces no instruction semantics.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import sysconfig
from enum import StrEnum
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path

LIFTER_SOURCE: str = "angr_platforms/angr_platforms/X86_16/lift_86_16.py"
PACKAGE_BUNDLE: str = "cython-vex"
BUILD_SCHEMA: int = 1


class LifterBackend(StrEnum):
    """Select interpretation, required compilation, or verified opportunistic use."""

    PYTHON = "python"
    CYTHON = "cython"
    AUTO = "auto"


def file_digest(path: Path) -> str:
    """Fingerprint source or extension bytes without relying on timestamps."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _verified_extension_directory(manifest_path: Path, confinement: Path, source: Path) -> Path | None:
    """Apply the schema/ABI/source/digest/confinement checks to one manifest layout."""
    try:
        manifest = json.loads(manifest_path.read_text())
        if not isinstance(manifest, dict):
            return None
        if manifest["schema"] != BUILD_SCHEMA:
            return None
        if manifest["cache_tag"] != sys.implementation.cache_tag or manifest["soabi"] != sysconfig.get_config_var("SOABI"):
            return None
        if manifest["source_sha256"] != file_digest(source):
            return None
        relative_path = manifest["extension"]
        if not isinstance(relative_path, str):
            return None
        extension = (confinement / relative_path).resolve()
        if not extension.is_relative_to(confinement.resolve()):
            return None
        if extension.name not in {"lift_86_16" + suffix for suffix in EXTENSION_SUFFIXES}:
            return None
        if manifest["extension_sha256"] != file_digest(extension):
            return None
    except (OSError, ValueError, KeyError, TypeError):
        return None
    return extension.parent


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


def activate_lifter_backend(package_path: list[str]) -> LifterBackend:
    """Prepend a verified extension directory before the lifter's first import.

    Normal startup requires Cython and fails loudly if its build is absent or
    stale. Explicit python mode retains interpretation for diagnostics; auto
    remains an opt-in compatibility mode with a visible Python fallback.
    The extension has the canonical module name, preserving registration and
    pickle identities. Selection must happen before any frontend imports.
    A verified bundle staged beside this copied file takes precedence over the
    repository cache so isolated package trees use their own bound artifact.
    """
    value = os.environ.get("INERTIA_VEX_BACKEND", LifterBackend.CYTHON.value)
    try:
        mode = LifterBackend(value)
    except ValueError as exc:
        raise ValueError(f"Invalid INERTIA_VEX_BACKEND={value!r}; choose python, cython, or auto") from exc
    if mode is LifterBackend.PYTHON:
        return mode
    module_path = Path(__file__).resolve()
    directory = verified_packaged_extension_directory(module_path.parent)
    if directory is None:
        directory = verified_extension_directory(module_path.parents[3])
    if directory is None:
        if mode is LifterBackend.CYTHON:
            raise ImportError("Cython VEX build missing or stale; run scripts/build_cython_vex.py or use INERTIA_VEX_BACKEND=python")
        return LifterBackend.PYTHON
    package_path.insert(0, str(directory))
    return LifterBackend.CYTHON
