"""Alias-layer package exports.

Layer: Alias.
Responsibility: owns storage identity and stack-slot identity.
Owns storage identity and stack-slot identity.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from importlib import import_module
from types import ModuleType
from typing import TYPE_CHECKING

__all__ = (
    "alias_model",
    "domains",
    "state",
    "transfer",
)

if TYPE_CHECKING:
    from . import alias_model, domains, state, transfer


def __getattr__(name: str) -> ModuleType:
    if name == "alias_model":
        return import_module(f"{__name__}.alias_model")
    if name == "domains":
        return import_module(f"{__name__}.domains")
    if name == "state":
        return import_module(f"{__name__}.state")
    if name == "transfer":
        return import_module(f"{__name__}.transfer")
    raise AttributeError(name)
