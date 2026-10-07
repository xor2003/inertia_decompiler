"""Adapt third-party structured-node tag containers.

Layer: Helper boundary.
Responsibility: copy Python or Rust-backed angr structured-node tags into an
owned dictionary without adding or interpreting semantic evidence.

Package ownership contract (canonical inertia/lowering package):
Layer: Types/Lowering.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, cast


class _StructuredTagItems8616(Protocol):
    """Dictionary-like tag container exposed by angr structured nodes."""

    def items(self) -> Iterable[tuple[object, object]]:
        """Return tag key/value entries."""


def copy_structured_tags_8616(tags: object) -> dict[str, object] | None:
    """Return a lossless owned copy of one supported third-party tag map."""
    try:
        items = tuple(cast(_StructuredTagItems8616, tags).items())
    except (AttributeError, TypeError, ValueError):
        return None
    if not all(isinstance(key, str) for key, _value in items):
        return None
    return {cast(str, key): value for key, value in items}


__all__ = ["copy_structured_tags_8616"]
