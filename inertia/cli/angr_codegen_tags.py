"""Normalize third-party structured-codegen tag containers.

Layer: CLI/fallback/reporting.
Responsibility: copy Python or Rust-backed angr C-node tags into the owned
dictionary shape consumed by Inertia pipeline contracts. This adapter preserves
all tag entries and does not infer semantic evidence.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, cast


class _TagItems8616(Protocol):
    """Dictionary-like third-party tag container."""

    def items(self) -> Iterable[tuple[object, object]]:
        """Return tag key/value entries."""


class _TaggedCodegenNode8616(Protocol):
    """Writable tag field exposed by an angr structured C node."""

    tags: object


def normalize_codegen_node_tags_8616(node: object) -> object:
    """Replace one dictionary-like third-party tag container with a dictionary."""
    tagged = cast(_TaggedCodegenNode8616, node)
    try:
        raw_tags = tagged.tags
    except AttributeError:
        return node
    if isinstance(raw_tags, dict):
        return node
    try:
        items = tuple(cast(_TagItems8616, raw_tags).items())
    except (AttributeError, TypeError, ValueError):
        return node
    if not all(isinstance(key, str) for key, _value in items):
        return node
    tagged.tags = {cast(str, key): value for key, value in items}
    return node


__all__ = ["normalize_codegen_node_tags_8616"]
