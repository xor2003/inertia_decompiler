"""Reuse exact function boundaries across consumers of one binary image.

Layer: Frontend.
Responsibility: index immutable, binary-framed function boundaries by the exact
range inventory that requested them. This module caches Frontend reachability
facts only; it does not infer signatures, aliases, types, or structured flow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, cast

from .frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)

__all__ = [
    "ExactFunctionRangeInventory8616",
    "exact_function_entry_boundary_8616",
    "exact_function_range_inventory_8616",
]


@dataclass(frozen=True, slots=True)
class ExactFunctionRangeInventory8616:
    """Closed Frontend boundaries for one exact immutable range inventory."""

    ranges: tuple[tuple[int, int], ...]
    boundaries: tuple[ExactFunctionRangeBoundary8616, ...] = field(
        compare=False,
    )


class _ProjectSurface8616(Protocol):
    """Dynamic angr project plus the owned Frontend inventory cache."""

    _inertia_exact_function_range_inventories_8616: dict[
        tuple[tuple[int, int], ...],
        ExactFunctionRangeInventory8616,
    ]


class _MemorySurface8616(Protocol):
    """Third-party loader memory used to prove one padding alias."""

    def load(self, addr: int, size: int) -> bytes | bytearray | memoryview:
        """Load exact binary bytes from one mapped range."""
        ...


class _MainObjectSurface8616(Protocol):
    """Inclusive loaded-image bounds supplied by the third-party loader."""

    min_addr: int
    max_addr: int


class _LoaderSurface8616(Protocol):
    """Third-party loader fields used by callable-entry matching."""

    memory: _MemorySurface8616
    main_object: _MainObjectSurface8616


class _BoundaryProjectSurface8616(Protocol):
    """Third-party project fields used by callable-entry matching."""

    loader: _LoaderSurface8616


def _range_is_inside_mapped_image_8616(project: object, start: int, end: int) -> bool:
    """Return whether a range is contained by authoritative loader bounds.

    Synthetic tests and compatibility projects may not expose a main object; in
    that case the exact boundary builder remains the authority. When bounds are
    available, never ask the lifter to canonicalize an absent original-binary
    range into a rebased slice.
    """
    try:
        main_object = cast(_BoundaryProjectSurface8616, project).loader.main_object
        min_addr = main_object.min_addr
        max_addr = main_object.max_addr
    except AttributeError:
        return True
    if not isinstance(min_addr, int) or not isinstance(max_addr, int):
        return True
    return min_addr <= start < end <= max_addr + 1


def _inventory_cache_8616(
    project: object,
) -> dict[tuple[tuple[int, int], ...], ExactFunctionRangeInventory8616]:
    """Return the owned cache at the dynamic third-party project boundary."""
    surface = cast(_ProjectSurface8616, project)
    try:
        cache = surface._inertia_exact_function_range_inventories_8616
    except AttributeError:
        cache = {}
        surface._inertia_exact_function_range_inventories_8616 = cache
    if not isinstance(cache, dict):
        raise TypeError("exact function-range inventory cache must be a dict")
    return cache


def exact_function_range_inventory_8616(
    project: object,
    ranges: tuple[tuple[int, int], ...],
) -> ExactFunctionRangeInventory8616:
    """Build each exact boundary once for one immutable binary range inventory."""
    cache = _inventory_cache_8616(project)
    cached = cache.get(ranges)
    if cached is not None:
        return cached

    boundaries = tuple(
        boundary
        for start, end in ranges
        if _range_is_inside_mapped_image_8616(project, start, end)
        if (boundary := exact_function_range_boundary_8616(project, start, end))
        is not None
    )
    inventory = ExactFunctionRangeInventory8616(
        ranges=ranges,
        boundaries=boundaries,
    )
    cache[ranges] = inventory
    return inventory


def _boundary_has_callable_entry_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    target_addr: int,
) -> bool:
    """Prove that a range start reaches one framed entry through padding only."""
    if target_addr == boundary.addr:
        return True
    prefix_size = target_addr - boundary.addr
    if not 0 < prefix_size <= 0x80:
        return False
    try:
        memory = cast(_BoundaryProjectSurface8616, project).loader.memory
        prefix = bytes(memory.load(boundary.addr, prefix_size))
        prologue = bytes(memory.load(target_addr, 3))
    except (AttributeError, KeyError, TypeError, ValueError):
        return False
    return (
        len(prefix) == prefix_size
        and all(byte in {0x00, 0x90, 0xCC} for byte in prefix)
        and prologue in {b"\x55\x8b\xec", b"\x55\x89\xe5"}
    )


def exact_function_entry_boundary_8616(
    project: object,
    target_addr: int,
    ranges: tuple[tuple[int, int], ...],
) -> ExactFunctionRangeBoundary8616 | None:
    """Resolve one exact range boundary for a direct callable entry or alias."""
    inventory = exact_function_range_inventory_8616(project, ranges)
    matches = tuple(
        boundary
        for boundary in inventory.boundaries
        if _boundary_has_callable_entry_8616(project, boundary, target_addr)
    )
    return matches[0] if len(matches) == 1 else None
