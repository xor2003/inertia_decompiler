"""Layer: CLI/fallback/reporting.

Responsibility: bind explicit entry extents and collect bounded native descendant edges.
A partial entry index never certifies whole-program reachability or CRT startup.
"""
from __future__ import annotations

from inertia.frontend.x86_16.declared_function_entry import (
    DeclaredFunctionEntryAdmission8616,
    revalidate_declared_function_entry_8616,
)
from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedCallerCensus8616,
    DecodedDirectCallsiteIndex8616,
    DecodedFarCallTarget8616,
    DirectCallTargetResolver8616,
    _boundary_instruction_address_8616,
    build_boundary_direct_callsite_index_8616,
    build_decoded_direct_callsite_index_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    bounded_entry_function_boundary_8616,
    mapped_entry_function_boundary_8616,
)
from inertia.frontend.x86_16.frontend_invocation_inventory import (
    InvocationInventoryBudget8616,
    _mapped_bounds_8616,
)
from inertia.frontend.x86_16.mz_invocation_source import MzInvocationSource8616


def declared_entries_current_8616(
    entries: tuple[DeclaredFunctionEntryAdmission8616, ...],
    projection: MzInvocationSource8616,
    environment_sha256: str | None,
) -> bool:
    """Reauthenticate every immutable entry under the current source/load/environment."""
    if type(entries) is not tuple:
        return False
    if not entries:
        return True
    if environment_sha256 is None:
        return False
    heads: set[int] = set()
    for entry in entries:
        if type(entry) is not DeclaredFunctionEntryAdmission8616 or not revalidate_declared_function_entry_8616(
            entry, source=projection.source, loaded_module=projection.module,
            environment_sha256=environment_sha256,
        ) or entry.spec.load_segment != projection.load_segment:
            return False
        head = (entry.spec.entry_segment << 4) + entry.spec.entry_offset
        if head in heads:
            return False
        heads.add(head)
    return True


def _native_descendants_8616(
    boundary: ExactFunctionRangeBoundary8616,
    index: DecodedDirectCallsiteIndex8616,
    resolver: DirectCallTargetResolver8616,
) -> tuple[set[int], set[int]]:
    """Retain all named obligations; enqueue only native near calls in this image."""
    targets: set[int] = set()
    eligible: set[int] = set()
    bounds = _mapped_bounds_8616(boundary.project, boundary.addr)
    for census in index.caller_censuses:
        for instruction in census.instructions:
            resolved = resolver(instruction)
            target = resolved.target_addr if isinstance(resolved, DecodedFarCallTarget8616) else resolved
            if type(target) is not int:
                continue
            targets.add(target)
            if not isinstance(bounds, tuple) or not bounds[0] <= target <= bounds[1]:
                continue
            address = _boundary_instruction_address_8616(instruction)
            for row in index.for_target(target):
                coordinates = row.encoded_near_coordinates()
                if row.callsite_addr == address and coordinates is not None and coordinates[1] == target:
                    eligible.add(target)
    return targets, eligible


def _declared_or_mapped_boundary_8616(
    project: object, head: int,
    roots: dict[int, DeclaredFunctionEntryAdmission8616],
) -> ExactFunctionRangeBoundary8616 | None:
    """Keep declared bounds authoritative and decode descendants without premises."""
    entry = roots.get(head)
    if entry is None:
        return mapped_entry_function_boundary_8616(project, head)
    return bounded_entry_function_boundary_8616(
        project, head, entry.spec.range_start, entry.spec.range_end,
    )


def build_declared_entry_index_8616(
    project: object,
    entries: tuple[DeclaredFunctionEntryAdmission8616, ...],
    resolver: DirectCallTargetResolver8616,
    budget: InvocationInventoryBudget8616 | None,
) -> tuple[DecodedDirectCallsiteIndex8616, tuple[int, ...]]:
    """Collect declared callers and native near-call descendants under shared caps.

    Each head is attempted once. Failed and unattempted heads stay pending;
    closed descendant rows establish caller bytes only, never startup or entry
    state. Explicit roots keep their declared extents even when called again.
    No invocation proof, conditional boundary, or callee effect is fabricated.
    """
    limits = budget or InvocationInventoryBudget8616()
    roots = {(entry.spec.entry_segment << 4) + entry.spec.entry_offset: entry for entry in entries}
    queue = list(roots)[:limits.max_root_inputs]
    seen = set(roots)
    pending = set(roots)
    closed: set[int] = set()
    censuses: list[DecodedCallerCensus8616] = []
    instruction_count = 0
    for position, head in enumerate(queue):
        if position >= limits.max_boundaries:
            break
        boundary = _declared_or_mapped_boundary_8616(project, head, roots)
        if boundary is None:
            continue
        if boundary.project is not project or boundary.addr != head:
            raise ValueError("declared descendant boundary does not bind its project and head")
        count = len(boundary.reachable_instruction_addrs)
        if instruction_count + count > limits.max_instructions:
            continue
        index = build_boundary_direct_callsite_index_8616(boundary, direct_target_resolver=resolver)
        instruction_count += count
        censuses.extend(index.caller_censuses)
        closed.add(head)
        targets, eligible = _native_descendants_8616(boundary, index, resolver)
        pending.update(targets)
        queue.extend(sorted(eligible - seen))
        seen.update(eligible)
    combined = build_decoded_direct_callsite_index_8616(
        tuple(censuses), direct_target_resolver=resolver,
        instruction_address_resolver=_boundary_instruction_address_8616,
    )
    return combined, tuple(sorted(pending - closed))
