"""Layer: IR.
Responsibility: reuse authenticated native import surfaces within one request.

This cache retains no proof verdict. Every consumer still performs its native
census and consumed-row equality checks. Unknown mutable metadata disables reuse.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, cast

from capstone import CsInsn

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_capstone_block import DirectCapstoneBlock8616, DirectCapstoneInstruction8616
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616

from .core import IRFunctionArtifact
from .function_ir_registry import _existing_registry_8616
from .raw_boot_blocked_prefix import _architecture_key_8616


@dataclass(frozen=True, slots=True)
class RawBootNativeSurfaceRecord8616:
    """An imported surface with a value snapshot of all mutable authorities."""

    project: object
    source: object
    boundary: ExactFunctionRangeBoundary8616
    artifact: IRFunctionArtifact
    key: tuple[object, ...]
    artifact_key: str
    pinned: tuple[object, ...]


@dataclass(slots=True)
class RawBootNativeSurfaceCache8616:
    """Request-local imports; a fresh resolution always starts empty."""

    records: dict[int, RawBootNativeSurfaceRecord8616] = field(default_factory=dict)
    reuse_count: int = 0


def _json_key_8616(value: object) -> str | None:
    """Snapshot owned JSON projections, refusing unknown object metadata."""
    try:
        return json.dumps(value, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        return None


def _registry_snapshot_8616(
    registry: Mapping[int, IRFunctionArtifact] | None,
) -> tuple[tuple[tuple[int, IRFunctionArtifact], ...], tuple[tuple[int, int, str], ...]] | None:
    """Retain registry entries only with a JSON snapshot of every authority."""
    items = () if registry is None else tuple(sorted(registry.items()))
    snapshots: list[tuple[int, int, str]] = []
    for address, artifact in items:
        snapshot = _json_key_8616(artifact.to_dict())
        if snapshot is None:
            return None
        snapshots.append((address, id(artifact), snapshot))
    return items, tuple(snapshots)


def _decoded_instruction_key_8616(row: object) -> tuple[object, ...] | None:
    """Snapshot canonical Capstone detail without admitting unknown decoders."""
    if type(row) is not DirectCapstoneInstruction8616:
        return None
    decoded = cast(DirectCapstoneInstruction8616, row)
    if type(decoded.insn) is not CsInsn:
        return None
    native = cast(Any, decoded.insn)  # Capstone ctypes details are an external mutable contract.
    if not native._raw.detail:
        return None
    detail = bytes(native._raw.detail.contents)
    return (decoded.address, decoded.size, decoded.mnemonic, decoded.op_str,
            native.id, native.address, native.size,
            bytes(native.bytes), native.mnemonic, native.op_str, detail)


def _native_surface_key_8616(
    project: object, boundary: ExactFunctionRangeBoundary8616,
    importer: Callable[[object, ExactFunctionRangeBoundary8616], IRFunctionArtifact | None],
    *, raw_lift_only: bool = False,
) -> tuple[tuple[object, ...], tuple[object, ...]] | None:
    """Bind bytes, decoded metadata, graph and native import producers.

    Returns the freshness key together with the identity-only authorities that
    must stay reachable while a record retains it; a freed authority can have
    its ``id()`` recycled by a different owner behind an unchanged key.
    ``raw_lift_only`` admits serialized conditional return-lift inputs, never
    their proof authority. Completed-artifact callers must keep the default.
    """
    from .status_flag_lift_context import status_flag_native_policy_key_8616
    from .vex_import import build_x86_16_ir_function_artifact

    external = cast(Any, project)  # angr loader and architecture are external contracts.
    arch = external.arch
    if type(arch) is not Arch86_16 or boundary.project is not project:
        return None
    if boundary.conditional_edges and not raw_lift_only:
        return None
    info = _json_key_8616(boundary.info)
    continuation_key = _raw_continuation_input_key_8616(boundary, raw_lift_only)
    if info is None or continuation_key is None:
        return None
    blocks: list[object] = []
    for block in boundary.blocks:
        if type(block) is not DirectCapstoneBlock8616:
            return None
        try:
            mapped = bytes(external.loader.memory.load(block.addr, block.size))
        except KeyError:
            return None
        if len(mapped) != block.size or mapped != block.code:
            return None
        instructions: list[object] = []
        for row in block.instructions:
            instruction = _decoded_instruction_key_8616(row)
            if instruction is None:
                return None
            instructions.append(instruction)
        blocks.append((block.addr, block.size, block.code, tuple(instructions)))
    key = (
        id(arch), _architecture_key_8616(arch), id(importer),
        id(build_x86_16_ir_function_artifact),
        boundary.addr, boundary.size, boundary.decode_lower_bound,
        boundary.block_addrs_set, boundary.reachable_instruction_addrs,
        boundary.successor_edges, tuple(blocks), info,
        status_flag_native_policy_key_8616(project, boundary.addr),
        continuation_key,
        tuple((edge.block_addr, edge.instruction_addr, edge.target_addr)
              for edge in boundary.conditional_edges),
    )
    pinned = (arch, importer, build_x86_16_ir_function_artifact)
    return key, pinned


def _raw_continuation_input_key_8616(
    boundary: ExactFunctionRangeBoundary8616, raw_lift_only: bool,
) -> tuple[object, ...] | None:
    """Snapshot return-lift inputs without caching their invocation authority.

    The raw lifter consumes the proved return-block set. Retain the full owned
    diagnostic projection as well, so changed records and counts invalidate
    reuse. Premise identity/authentication belongs to each semantic consumer;
    this key must never authorize replay of a previously proved invocation.
    """
    from inertia.frontend.x86_16.frontend_near_return_continuation import (
        NearReturnContinuationArtifact8616,
    )

    continuation = boundary.near_return_continuations
    if continuation is None:
        return ()
    if not raw_lift_only or type(continuation) is not NearReturnContinuationArtifact8616:
        return None
    serialized = _json_key_8616(continuation.to_dict())
    return None if serialized is None else (serialized, continuation.proven_block_addrs)


def _surface_key_8616(
    project: object, boundary: ExactFunctionRangeBoundary8616,
    importer: Callable[[object, ExactFunctionRangeBoundary8616], IRFunctionArtifact | None],
) -> tuple[tuple[object, ...], tuple[object, ...]] | None:
    """Add semantic registry freshness for finished artifacts, beyond raw lifts."""
    native = _native_surface_key_8616(project, boundary, importer)
    if native is None:
        return None
    registry = _existing_registry_8616(project)
    snapshot = _registry_snapshot_8616(registry)
    if snapshot is None:
        return None
    items, registry_key = snapshot
    return (
        (*native[0], id(registry), registry_key),
        (*native[1], registry, *(artifact for _address, artifact in items)),
    )


def request_raw_boot_native_import_8616(
    cache: RawBootNativeSurfaceCache8616, project: object, source: object,
    boundary: ExactFunctionRangeBoundary8616,
    importer: Callable[[object, ExactFunctionRangeBoundary8616], IRFunctionArtifact | None],
    *, should_abort: Callable[[], bool] | None = None,
) -> IRFunctionArtifact | None:
    """Reuse unchanged surfaces only while the caller's work budget is live.

    The optional abort predicate is execution policy, never cache authority.
    Expiry evicts retained evidence rather than exposing it to a late consumer.
    """
    if should_abort is not None and should_abort():
        cache.records.pop(boundary.addr, None)
        return None
    snapshot = _surface_key_8616(project, boundary, importer)
    retained = cache.records.pop(boundary.addr, None)
    if retained is not None and snapshot is not None:
        same_owners = retained.project is project and retained.source is source and retained.boundary is boundary
        unchanged = retained.key == snapshot[0] and _json_key_8616(retained.artifact.to_dict()) == retained.artifact_key
        if should_abort is not None and should_abort():
            return None
        if same_owners and unchanged:
            cache.records[boundary.addr] = retained
            cache.reuse_count += 1
            return retained.artifact
    if should_abort is not None and should_abort():
        return None
    artifact = importer(project, boundary)
    if artifact is None or (should_abort is not None and should_abort()):
        return None
    after = _surface_key_8616(project, boundary, importer)
    artifact_key = _json_key_8616(artifact.to_dict())
    if should_abort is not None and should_abort():
        return None
    if snapshot is not None and after == snapshot and artifact_key is not None:
        cache.records[boundary.addr] = RawBootNativeSurfaceRecord8616(
            project, source, boundary, artifact, snapshot[0], artifact_key, snapshot[1],
        )
    return artifact
