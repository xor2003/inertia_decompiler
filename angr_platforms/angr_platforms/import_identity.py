"""Resolve legacy platform imports to canonical module objects.

Layer: Frontend/runtime package surface.
Responsibility: preserve module and contract identity across X86_16 import paths.
"""

from __future__ import annotations

import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import sys
from collections.abc import Sequence
from types import ModuleType

_CANONICAL_ROOT = "angr_platforms.X86_16"
_LEGACY_ROOT = "angr_platforms.angr_platforms.X86_16"


class _AliasLoader(importlib.abc.Loader):
    """Import the canonical module once and retain its canonical metadata."""

    def __init__(self, canonical_name: str) -> None:
        self.canonical_name = canonical_name
        self.canonical_spec: importlib.machinery.ModuleSpec | None = None

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType:
        """Resolve canonical code only after the alias spec has been selected."""
        module = importlib.import_module(self.canonical_name)
        self.canonical_spec = module.__spec__
        return module

    def exec_module(self, module: ModuleType) -> None:
        """Restore the spec overwritten by import machinery without reexecution."""
        module.__spec__ = self.canonical_spec


class _AliasFinder(importlib.abc.MetaPathFinder):
    """Claim only legacy X86_16 paths, including children imported lazily."""

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None = None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        """Describe an alias without executing canonical code during discovery."""
        if fullname != _LEGACY_ROOT and not fullname.startswith(_LEGACY_ROOT + "."):
            return None
        canonical_name = _CANONICAL_ROOT + fullname[len(_LEGACY_ROOT):]
        return importlib.util.spec_from_loader(fullname, _AliasLoader(canonical_name))


_FINDER = _AliasFinder()


def install_x86_16_legacy_import_alias() -> None:
    """Install the cold import adapter once before importing platform modules."""
    if _FINDER not in sys.meta_path:
        sys.meta_path.insert(0, _FINDER)
