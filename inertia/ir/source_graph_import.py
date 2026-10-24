"""Layer: IR import boundary.

Responsibility: select the verified native source-graph binding only when its
module is requested. The authoritative Python source remains interpretable;
compiled use is optional acceleration through the shared bundle verifier.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from importlib.abc import MetaPathFinder
from importlib.machinery import ExtensionFileLoader, ModuleSpec, PathFinder
from importlib.util import spec_from_file_location
from pathlib import Path
from types import ModuleType

from inertia.native_bundle import verified_bundle_directory

SOURCE_GRAPH_MODULE: str = "inertia.ir.source_graph_binding"
SOURCE_GRAPH_SOURCE: str = "source_graph_binding.py"
SOURCE_GRAPH_EXTENSION: str = "source_graph_binding"
SOURCE_GRAPH_CACHE: str = ".cache/cython-source-graph"
BACKEND_ENV: str = "INERTIA_SOURCE_GRAPH_BACKEND"


class SourceGraphBackend(StrEnum):
    """Select interpretation, required compilation, or verified opportunistic use."""

    PYTHON = "python"
    CYTHON = "cython"
    AUTO = "auto"


@dataclass(frozen=True, slots=True)
class SourceGraphImportSelection:
    """Bind a startup backend to its verified import search paths."""

    backend: SourceGraphBackend
    search_paths: tuple[str, ...]


def _backend_mode() -> SourceGraphBackend:
    """Resolve the configured backend or reject unknown values loudly."""
    value = os.environ.get(BACKEND_ENV, SourceGraphBackend.AUTO.value)
    try:
        return SourceGraphBackend(value)
    except ValueError as exc:
        raise ValueError(
            f"Invalid {BACKEND_ENV}={value!r}; choose python, cython, or auto"
        ) from exc


class SourceGraphImportFinder(MetaPathFinder):
    """Handle exactly one module without changing other IR imports."""

    def __init__(self, package_dir: Path, cache_dir: Path | None = None) -> None:
        """Retain the canonical source package and the build confinement root."""
        self.package_dir: Path = package_dir
        self.cache_dir: Path = (
            cache_dir
            if cache_dir is not None
            else package_dir.parents[1] / SOURCE_GRAPH_CACHE
        )
        self._selection: SourceGraphImportSelection | None = None

    def selection(self) -> SourceGraphImportSelection:
        """Verify and retain the one-time backend choice for this process."""
        if self._selection is None:
            paths = [str(self.package_dir)]
            backend = self._activate(paths)
            self._selection = SourceGraphImportSelection(backend, tuple(paths))
        return self._selection

    def _activate(self, paths: list[str]) -> SourceGraphBackend:
        """Prepend a verified extension directory before the module's first import.

        Staged acceleration defaults to ``auto``: a verified build is used
        when present and exact interpretation otherwise. ``cython`` requires
        the verified artifact and fails loudly on a missing or stale build;
        ``python`` never loads the cached extension.
        """
        mode = _backend_mode()
        if mode is SourceGraphBackend.PYTHON:
            return mode
        directory = verified_bundle_directory(
            self.cache_dir / "active.json", self.cache_dir,
            self.package_dir / SOURCE_GRAPH_SOURCE, SOURCE_GRAPH_EXTENSION,
        )
        if directory is None:
            if mode is SourceGraphBackend.CYTHON:
                raise ImportError(
                    "Cython source-graph build missing or stale; run "
                    "tools/dev/build_cython_source_graph.py or use "
                    f"{BACKEND_ENV}=python"
                )
            return SourceGraphBackend.PYTHON
        paths.insert(0, str(directory))
        return SourceGraphBackend.CYTHON

    def find_spec(
        self, fullname: str, path: Sequence[str] | None = None, target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        """Use an extension-only lookup for native mode and exact source for Python."""
        if fullname != SOURCE_GRAPH_MODULE:
            return None
        selection = self.selection()
        if selection.backend is SourceGraphBackend.PYTHON:
            return spec_from_file_location(fullname, self.package_dir / SOURCE_GRAPH_SOURCE)
        spec = PathFinder.find_spec(fullname, selection.search_paths[:1])
        if spec is None or not isinstance(spec.loader, ExtensionFileLoader):
            raise ImportError("Verified Cython source graph disappeared before import; rebuild the native bundle")
        return spec


_FINDER: SourceGraphImportFinder = SourceGraphImportFinder(Path(__file__).resolve().parent)


def install_source_graph_import() -> None:
    """Register this narrow import boundary once without selecting a backend."""
    if not any(finder is _FINDER for finder in sys.meta_path):
        sys.meta_path.insert(0, _FINDER)


def selected_source_graph_backend() -> SourceGraphBackend:
    """Expose the verified choice to diagnostics and acceptance checks."""
    return _FINDER.selection().backend
