"""Layer: frontend import boundary.

Responsibility: select the verified native lifter only when its module is requested.
Pure architecture and backend contracts must not initialize the legacy pipeline.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from dataclasses import dataclass
from importlib.abc import MetaPathFinder
from importlib.machinery import ExtensionFileLoader, ModuleSpec, PathFinder
from importlib.util import spec_from_file_location
from pathlib import Path
from types import ModuleType

from .lifter_backend import LifterBackend, activate_lifter_backend

LIFTER_MODULE: str = "inertia.frontend.x86_16.lift_86_16"


@dataclass(frozen=True, slots=True)
class LifterImportSelection:
    """Bind a startup backend to its verified import search paths."""

    backend: LifterBackend
    search_paths: tuple[str, ...]


class LifterImportFinder(MetaPathFinder):
    """Handle exactly one module without changing other frontend imports."""

    def __init__(self, package_dir: Path) -> None:
        """Retain the canonical source package; defer verification until requested."""
        self.package_dir: Path = package_dir
        self._selection: LifterImportSelection | None = None

    def selection(self) -> LifterImportSelection:
        """Verify and retain the same one-time backend choice as legacy startup."""
        if self._selection is None:
            paths = [str(self.package_dir)]
            backend = activate_lifter_backend(paths, package_dir=self.package_dir)
            self._selection = LifterImportSelection(backend, tuple(paths))
        return self._selection

    def find_spec(
        self, fullname: str, path: Sequence[str] | None = None, target: ModuleType | None = None,
    ) -> ModuleSpec | None:
        """Use an extension-only lookup for native mode and exact source for Python."""
        if fullname != LIFTER_MODULE:
            return None
        selection = self.selection()
        if selection.backend is LifterBackend.PYTHON:
            return spec_from_file_location(fullname, self.package_dir / "lift_86_16.py")
        spec = PathFinder.find_spec(fullname, selection.search_paths[:1])
        if spec is None or not isinstance(spec.loader, ExtensionFileLoader):
            raise ImportError("Verified Cython lifter disappeared before import; rebuild the native bundle")
        return spec


_FINDER: LifterImportFinder = LifterImportFinder(Path(__file__).resolve().parent)


def install_lifter_import() -> None:
    """Register this narrow import boundary once without selecting a backend."""
    if not any(finder is _FINDER for finder in sys.meta_path):
        sys.meta_path.insert(0, _FINDER)


def selected_lifter_backend() -> LifterBackend:
    """Expose the verified choice to the historical public package surface."""
    return _FINDER.selection().backend
