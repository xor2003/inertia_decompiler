"""Retain immutable decoded-function evidence within one analysis request.

Layer: traits/summaries/confidence.
Responsibility: deduplicate binary fact collection while invalidating entries
when a function's decoded block surface changes. Mutable C AST, alias,
prototype, and validation state must never be stored here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast


class FunctionEvidenceKind8616(Enum):
    """Authoritative classes of immutable per-function binary evidence."""

    INSTRUCTION_SUMMARIES = "instruction_summaries"
    NEAR_POINTER_ARGUMENTS = "near_pointer_arguments"
    DIRECT_GLOBAL_LOADS = "direct_global_loads"
    DIRECT_GLOBAL_STORES = "direct_global_stores"
    INDEXED_GLOBAL_LOAD_SITES = "indexed_global_load_sites"
    INDEXED_GLOBAL_STORES = "indexed_global_stores"
    FAR_POINTER_SEGMENTED_LOADS = "far_pointer_segmented_loads"
    NEIGHBOR_CALL_TARGETS = "neighbor_call_targets"
    DIRECT_GLOBAL_INSTRUCTION_VIEWS = "direct_global_instruction_views"
    DIRECT_GLOBAL_REGISTER_UPDATES = "direct_global_register_updates"
    REGISTER_SOURCE_BLOCKS = "register_source_blocks"
    TERMINAL_AX_RETURNS = "terminal_ax_returns"


@dataclass(frozen=True, slots=True)
class FunctionBinaryIdentity8616:
    """Stable binary identity, with object identity only as a last resort."""

    address: int | None
    object_identity: int | None


@dataclass(frozen=True, slots=True)
class FunctionBinarySurface8616:
    """Request-local binary identity and decoded extent for one function."""

    identity: FunctionBinaryIdentity8616
    size: int
    blocks: tuple[tuple[int, int], ...]
    callsites: tuple[tuple[int, int | None, int | None], ...]
    content_identity: bytes | None


@dataclass(frozen=True, slots=True)
class FunctionEvidenceInventory8616:
    """One immutable binary evidence projection for a function surface."""

    surface: FunctionBinarySurface8616
    evidence: tuple[object, ...]
    fallback_owner: object | None


class _BlockBoundary8616(Protocol):
    """Dynamic angr block fields needed for cache invalidation."""

    addr: int
    size: int


class _FunctionBoundary8616(Protocol):
    """Dynamic angr function fields used by the evidence inventory."""

    addr: int
    size: int
    blocks: Sequence[_BlockBoundary8616]

    def get_call_sites(self) -> Iterable[int]:
        """Return machine callsite addresses known by the recovered CFG."""
        ...

    def get_call_target(self, callsite_addr: int) -> int | None:
        """Return the recovered target for one machine callsite."""
        ...

    def get_call_return(self, callsite_addr: int) -> int | None:
        """Return the recovered continuation for one machine callsite."""
        ...


class _ProjectInventoryBoundary8616(Protocol):
    """Dynamic project field retaining request-owned evidence inventories."""

    _inertia_function_evidence_inventories_8616: dict[
        tuple[FunctionEvidenceKind8616, FunctionBinaryIdentity8616],
        FunctionEvidenceInventory8616,
    ]


def _callsite_surface_8616(
    boundary: _FunctionBoundary8616,
) -> tuple[tuple[int, int | None, int | None], ...]:
    """Snapshot each proven callsite with its target and continuation."""
    try:
        callsite_addrs = tuple(boundary.get_call_sites())
    except (AttributeError, TypeError):
        callsite_addrs = ()
    callsites: list[tuple[int, int | None, int | None]] = []
    for raw_callsite_addr in callsite_addrs:
        try:
            callsite_addr = int(raw_callsite_addr)
            target = boundary.get_call_target(callsite_addr)
            return_addr = boundary.get_call_return(callsite_addr)
        except (AttributeError, TypeError, ValueError):
            continue
        callsites.append(
            (
                callsite_addr,
                target if isinstance(target, int) else None,
                return_addr if isinstance(return_addr, int) else None,
            )
        )
    return tuple(sorted(callsites))


def _function_binary_surface_8616(
    function: object,
    *,
    content_identity: bytes | None,
    include_callsites: bool,
) -> FunctionBinarySurface8616:
    """Snapshot stable binary coordinates and the decoded block surface."""
    boundary = cast(_FunctionBoundary8616, function)
    try:
        address = int(boundary.addr)
    except (AttributeError, TypeError, ValueError):
        address = None
    identity = FunctionBinaryIdentity8616(
        address=address,
        object_identity=None if address is not None else id(function),
    )
    try:
        function_size = int(boundary.size)
    except (AttributeError, TypeError, ValueError):
        function_size = -1
    try:
        blocks = tuple(boundary.blocks)
    except (AttributeError, TypeError):
        blocks = ()
    extents: list[tuple[int, int]] = []
    for block in blocks:
        try:
            block_addr = int(block.addr)
        except AttributeError:
            block_addr = id(block)
        try:
            size = int(block.size)
        except AttributeError:
            size = -1
        extents.append((block_addr, size))
    callsites = _callsite_surface_8616(boundary) if include_callsites else ()
    return FunctionBinarySurface8616(
        identity,
        function_size,
        tuple(sorted(extents)),
        tuple(sorted(callsites)),
        content_identity,
    )


def collect_function_binary_evidence_8616[EvidenceT8616](
    project: object | None,
    function: object,
    *,
    kind: FunctionEvidenceKind8616,
    builder: Callable[[object | None, object], Iterable[EvidenceT8616]],
    content_identity: bytes | None = None,
) -> tuple[EvidenceT8616, ...]:
    """Return cached immutable evidence or collect it for the current surface."""
    if project is None:
        return tuple(builder(project, function))
    include_callsites = kind is FunctionEvidenceKind8616.NEIGHBOR_CALL_TARGETS
    surface = _function_binary_surface_8616(
        function,
        content_identity=content_identity,
        include_callsites=include_callsites,
    )
    typed_project = cast(_ProjectInventoryBoundary8616, project)
    try:
        inventories = typed_project._inertia_function_evidence_inventories_8616
    except AttributeError:
        inventories = {}
        typed_project._inertia_function_evidence_inventories_8616 = inventories
    key = (kind, surface.identity)
    cached = inventories.get(key)
    fallback_owner_matches = (
        cached is not None
        and (surface.identity.address is not None or cached.fallback_owner is function)
    )
    if cached is not None and cached.surface == surface and fallback_owner_matches:
        return cast(tuple[EvidenceT8616, ...], cached.evidence)
    evidence = tuple(builder(project, function))
    collected_surface = _function_binary_surface_8616(
        function,
        content_identity=content_identity,
        include_callsites=include_callsites,
    )
    fallback_owner = function if surface.identity.address is None else None
    collected_key = (kind, collected_surface.identity)
    inventories[collected_key] = FunctionEvidenceInventory8616(
        collected_surface,
        cast(tuple[object, ...], evidence),
        fallback_owner,
    )
    return evidence
