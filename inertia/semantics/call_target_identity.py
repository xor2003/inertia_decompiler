"""Canonicalize direct-call addresses across x86-16 project coordinate spaces.

Layer: Traits/summaries.
Responsibility: preserve one typed call-target identity across active images,
rebased exact slices, and original binary images.
Forbidden: call recovery, AST mutation, rendered-C matching, or validation
acceptance decisions.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, cast

from inertia.lowering.analysis_helpers import canonicalize_x86_16_padding_call_target_8616

__all__ = (
    "normalize_x86_16_call_target_addr_8616",
    "normalize_x86_16_direct_call_target_8616",
    "resolve_x86_16_call_target_function_8616",
    "resolve_x86_16_canonical_call_target_function_8616",
    "x86_16_call_targets_equivalent_8616",
)


class _MainObjectSurface8616(Protocol):
    """Third-party loader image bounds used for address normalization."""

    linked_base: object
    max_addr: object


class _LoaderSurface8616(Protocol):
    """Third-party loader surface containing the active main object."""

    main_object: object


class _ProjectAddressSurface8616(Protocol):
    """Dynamic angr project address metadata used by exact-slice recovery."""

    loader: object
    _inertia_original_project: object
    _inertia_original_linear_delta: object


class _FunctionSurface8616(Protocol):
    """Third-party angr function identity used by target resolution."""

    addr: int
    name: str


class _FunctionManagerSurface8616(Protocol):
    """Third-party angr function manager used by exact candidate lookup."""

    def function(self, *, addr: int, create: bool) -> _FunctionSurface8616 | None:
        """Return one exact existing function without creating it."""


class _KnowledgeBaseSurface8616(Protocol):
    """Third-party angr knowledge base containing functions."""

    functions: _FunctionManagerSurface8616
    labels: Mapping[int, object]


class _ProjectFunctionSurface8616(_ProjectAddressSurface8616, Protocol):
    """Project fields required to resolve a canonical call target."""

    kb: _KnowledgeBaseSurface8616


def _project_image_bounds_8616(project: object) -> tuple[int, int] | None:
    """Return half-open linked image bounds from a third-party project."""
    try:
        loader = cast(_ProjectAddressSurface8616, project).loader
        main_object = cast(_LoaderSurface8616, loader).main_object
        linked_base = cast(_MainObjectSurface8616, main_object).linked_base
        max_addr = cast(_MainObjectSurface8616, main_object).max_addr
    except AttributeError:
        return None
    if isinstance(linked_base, int) and isinstance(max_addr, int):
        return linked_base, linked_base + max_addr + 1
    return None


def _addr_in_image_bounds_8616(addr: int, bounds: tuple[int, int] | None) -> bool:
    """Return whether an address belongs to the supplied half-open image."""
    return bounds is not None and bounds[0] <= addr < bounds[1]


def _project_has_exact_target_evidence_8616(project: object, addr: int) -> bool:
    """Return whether a third-party project owns an exact label or function."""
    try:
        knowledge_base = cast(_ProjectFunctionSurface8616, project).kb
    except AttributeError:
        return False
    try:
        labels = knowledge_base.labels
    except AttributeError:
        labels = {}
    if isinstance(labels, Mapping) and addr in labels:
        return True
    try:
        return knowledge_base.functions.function(addr=addr, create=False) is not None
    except AttributeError:
        return False


def normalize_x86_16_direct_call_target_8616(
    target: int,
    linked_base: int | None,
    image_end: int | None,
) -> int | None:
    """Normalize a direct target between linked and image-relative coordinates."""
    if isinstance(linked_base, int):
        if target < linked_base:
            linked_target = linked_base + target
            if image_end is None or linked_target < image_end:
                return linked_target
        elif image_end is None or target < image_end:
            return target
        unbased_target = target - linked_base
        if 0 <= unbased_target < 0x10000:
            return unbased_target
        return None
    return target


def normalize_x86_16_call_target_addr_8616(project: object, target_addr: int | None) -> int | None:
    """Return one canonical target address for active and rebased projects."""
    if not isinstance(target_addr, int):
        return None

    def _canonicalize(addr: int | None) -> int | None:
        if not isinstance(addr, int):
            return None
        return canonicalize_x86_16_padding_call_target_8616(project, addr)

    project_surface = cast(_ProjectAddressSurface8616, project)
    try:
        original_project = project_surface._inertia_original_project
        original_delta = project_surface._inertia_original_linear_delta
    except AttributeError:
        original_project = None
        original_delta = None
    if original_project is not None and isinstance(original_delta, int):
        original_bounds = _project_image_bounds_8616(original_project)
        if _addr_in_image_bounds_8616(target_addr, original_bounds) or _project_has_exact_target_evidence_8616(
            original_project,
            target_addr,
        ):
            return _canonicalize(target_addr)
        original_target = target_addr + original_delta
        if _addr_in_image_bounds_8616(original_target, original_bounds) or _project_has_exact_target_evidence_8616(
            original_project,
            original_target,
        ):
            return _canonicalize(original_target)

    active_bounds = _project_image_bounds_8616(project)
    linked_base = active_bounds[0] if active_bounds is not None else None
    image_end = active_bounds[1] if active_bounds is not None else None
    return _canonicalize(
        normalize_x86_16_direct_call_target_8616(target_addr, linked_base, image_end)
    )


def x86_16_call_targets_equivalent_8616(
    project: object,
    lhs_addr: int | None,
    rhs_addr: int | None,
) -> bool:
    """Compare two targets after exact active/original address normalization."""
    lhs = normalize_x86_16_call_target_addr_8616(project, lhs_addr)
    rhs = normalize_x86_16_call_target_addr_8616(project, rhs_addr)
    return lhs is not None and rhs is not None and lhs == rhs


def resolve_x86_16_call_target_function_8616(
    project: object,
    target_addr: int | None,
) -> _FunctionSurface8616 | None:
    """Resolve one canonical target to its exact active-project function."""
    if not isinstance(target_addr, int):
        return None
    project_surface = cast(_ProjectFunctionSurface8616, project)
    try:
        functions = project_surface.kb.functions
    except AttributeError:
        return None

    candidates = [target_addr]
    try:
        original_delta = project_surface._inertia_original_linear_delta
    except AttributeError:
        original_delta = None
    if isinstance(original_delta, int):
        candidates.extend((target_addr - original_delta, target_addr + original_delta))

    active_bounds = _project_image_bounds_8616(project)
    if active_bounds is not None:
        linked_base = active_bounds[0]
        candidates.extend((target_addr - linked_base, target_addr + linked_base))

    seen: set[int] = set()
    for candidate_addr in candidates:
        if candidate_addr < 0 or candidate_addr in seen:
            continue
        seen.add(candidate_addr)
        function = functions.function(addr=candidate_addr, create=False)
        if function is not None and x86_16_call_targets_equivalent_8616(
            project,
            function.addr,
            target_addr,
        ):
            return function
    return None


def resolve_x86_16_canonical_call_target_function_8616(
    project: object,
    target_addr: int | None,
) -> _FunctionSurface8616 | None:
    """Prefer the original-image function for one canonical direct target."""
    project_surface = cast(_ProjectAddressSurface8616, project)
    try:
        original_project = project_surface._inertia_original_project
    except AttributeError:
        original_project = None
    if original_project is not None:
        original_function = resolve_x86_16_call_target_function_8616(
            original_project,
            target_addr,
        )
        if original_function is not None:
            return original_function
    return resolve_x86_16_call_target_function_8616(project, target_addr)
