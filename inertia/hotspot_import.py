# cython: language_level=3, infer_types=True
"""Layer: IR import boundary.

Responsibility: select verified native builds for the compiled hotspot cohort
(the modules listed by ``tools/dev/build_mypyc.TARGET_MODULES``) only when each
module is requested. The authoritative Python sources remain interpretable;
compiled use is optional acceleration through the shared bundle verifier.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations
import cython

import json
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from importlib.abc import MetaPathFinder
from importlib.machinery import ExtensionFileLoader, ModuleSpec, PathFinder
from pathlib import Path
from types import ModuleType

from inertia.native_bundle import verified_bundle_directory
import dataclasses

HOTSPOT_CACHE: str = ".cache/cython-hotspots"
HOTSPOT_COHORT_MANIFEST: str = "cohort.json"
BACKEND_ENV: str = "INERTIA_HOTSPOT_BACKEND"


class HotspotBackend(StrEnum):
    """Select interpretation, required compilation, or verified opportunistic use."""

    PYTHON = "python"
    CYTHON = "cython"
    AUTO = "auto"


@dataclasses.dataclass(frozen=True, )
class HotspotImportSelection:
    """Bind a startup backend to its verified import search path."""

    backend: HotspotBackend
    search_path: object


@cython.ccall
def _backend_mode() -> HotspotBackend:
    """Resolve the configured backend or reject unknown values loudly."""
    value: object
    value = os.environ.get(BACKEND_ENV, HotspotBackend.AUTO.value)
    try:
        return HotspotBackend(value)
    except ValueError as exc:
        raise ValueError(
            f"Invalid {BACKEND_ENV}={value!r}; choose python, cython, or auto"
        ) from exc


class HotspotImportFinder(MetaPathFinder):
    """Resolve compiled manifests for cohort modules without touching others.

    The cohort is data, not a duplicated list: ``cohort.json`` under the cache
    root names the modules the builder produced, and each module owns a
    schema-1 ``active.json`` manifest beside it. ``cython`` mode requires a
    verified artifact for every cohort member and fails loudly on a missing
    or stale build; ``auto`` uses a verified build when present and otherwise
    interprets Python; ``python`` never loads a cached extension.
    """

    def __init__(self, package_dir: Path, cache_dir: Path | None = None) -> None:
        """Retain the canonical source package and the build confinement root."""
        self.package_dir: Path = package_dir
        self.cache_dir: Path = (
            cache_dir
            if cache_dir is not None
            else package_dir.parent / HOTSPOT_CACHE
        )
        self._backend: HotspotBackend | None = None
        self._cohort: object = None

    def backend(self) -> HotspotBackend:
        """Resolve the one-time backend mode for this process."""
        if self._backend is None:
            self._backend = _backend_mode()
        return self._backend

    def cohort(self) -> object:
        """Read the builder-published module list once per process."""
        if self._cohort is None:
            try:
                payload = json.loads((self.cache_dir / HOTSPOT_COHORT_MANIFEST).read_text())
                members = payload.get("modules", ()) if isinstance(payload, dict) else ()
                self._cohort = frozenset(
                    member for member in iter(members) if isinstance(member, str)
                )
            except (OSError, ValueError, AttributeError):
                self._cohort = frozenset()
        return self._cohort

    def find_spec(
        self, fullname: object, path: Sequence[str] | None = None, target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        """Use an extension-only lookup for a verified cohort member."""
        directory: object
        spec: object
        parts = fullname.split(".")
        if len(parts) < 2 or parts[0] != "inertia":
            return None
        source = self.package_dir.joinpath(*parts[1:]).with_suffix(".py")
        if not source.is_file():
            return None
        backend = self.backend()
        if backend is HotspotBackend.PYTHON:
            return None
        module_cache = self.cache_dir.joinpath(*parts)
        directory = verified_bundle_directory(
            module_cache / "active.json", module_cache, source, parts[-1],
        )
        if directory is None:
            if backend is HotspotBackend.CYTHON and (
                fullname in self.cohort() or (module_cache / "active.json").is_file()
            ):
                raise ImportError(
                    f"Cython hotspot build for {fullname} missing or stale; run "
                    "tools/dev/build_cython_hotspots.py or use "
                    f"{BACKEND_ENV}=python"
                )
            return None
        spec = PathFinder.find_spec(fullname, [str(directory)])
        if spec is None or not isinstance(spec.loader, ExtensionFileLoader):
            raise ImportError(
                f"Verified Cython hotspot {fullname} disappeared before import; "
                "rebuild the native bundle"
            )
        return spec


_FINDER: HotspotImportFinder = HotspotImportFinder(Path(__file__).resolve().parent)


def install_hotspot_import() -> None:
    """Register this cohort import boundary once without selecting a backend."""
    if not any(finder is _FINDER for finder in iter(sys.meta_path)):
        sys.meta_path.insert(0, _FINDER)


@cython.ccall
def selected_hotspot_backend() -> HotspotBackend:
    """Expose the verified choice to diagnostics and acceptance checks."""
    return _FINDER.backend()
