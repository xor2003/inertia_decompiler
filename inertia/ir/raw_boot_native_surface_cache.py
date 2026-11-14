# cython: language_level=3, infer_types=True
"""Layer: IR.
Responsibility: reuse authenticated native import surfaces within one request.

This cache retains no proof verdict. Every consumer still performs its native
census and consumed-row equality checks. Unknown mutable metadata disables reuse.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""
from __future__ import annotations
import typing
import cython

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
import dataclasses
import operator


@dataclasses.dataclass(frozen=True, )
class RawBootNativeSurfaceRecord8616:
    """An imported surface with a value snapshot of all mutable authorities."""

    project: object
    source: object
    boundary: ExactFunctionRangeBoundary8616
    artifact: IRFunctionArtifact
    key: object
    artifact_key: object
    pinned: object


@cython.dataclasses.dataclass()
class RawBootNativeSurfaceCache8616:
    """Request-local imports; a fresh resolution always starts empty."""

    records: object = field(default_factory=dict)
    reuse_count: cython.longlong = 0


@cython.ccall
def _json_key_8616(value: object) -> object:
    """Snapshot owned JSON projections, refusing unknown object metadata."""
    try:
        return json.dumps(value, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        return None


@cython.ccall
def _registry_snapshot_8616(
    registry: object,
) -> object:
    """Retain registry entries only with a JSON snapshot of every authority."""
    snapshot: object
    address: object
    artifact: object
    items = () if registry is None else tuple(sorted(tuple(registry.items())))
    snapshots: list[tuple[cython.longlong, cython.longlong, str]] = []
    for address, artifact in items:
        snapshot = _json_key_8616(artifact.to_dict())
        if snapshot is None:
            return None
        snapshots.append((address, id(artifact), snapshot))
    return items, tuple(snapshots)


@cython.ccall
def _decoded_instruction_key_8616(row: object) -> object:
    """Snapshot canonical Capstone detail without admitting unknown decoders."""
    if type(row) is not DirectCapstoneInstruction8616:
        return None
    decoded = row
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
    *, raw_lift_only: cython.bint = False,
) -> object:
    """Bind bytes, decoded metadata, graph and native import producers.

    Returns the freshness key together with the identity-only authorities that
    must stay reachable while a record retains it; a freed authority can have
    its ``id()`` recycled by a different owner behind an unchanged key.
    ``raw_lift_only`` admits serialized conditional return-lift inputs, never
    their proof authority. Completed-artifact callers must keep the default.
    """
    continuation_key: object
    info: object
    instruction: object
    block: object
    row: object
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
        if operator.ne(len(mapped), block.size) or operator.ne(mapped, block.code):
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
              for edge in iter(boundary.conditional_edges)),
    )
    pinned = (arch, importer, build_x86_16_ir_function_artifact)
    return key, pinned


@cython.ccall
def _raw_continuation_input_key_8616(
    boundary: ExactFunctionRangeBoundary8616, raw_lift_only: cython.bint,
) -> object:
    """Snapshot return-lift inputs without caching their invocation authority.

    The raw lifter consumes the proved return-block set. Retain the full owned
    diagnostic projection as well, so changed records and counts invalidate
    reuse. Premise identity/authentication belongs to each semantic consumer;
    this key must never authorize replay of a previously proved invocation.
    """
    continuation: object
    serialized: object
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
) -> object:
    """Add semantic registry freshness for finished artifacts, beyond raw lifts."""
    native: object
    snapshot: object
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
        (*native[1], registry, *(artifact for _address, artifact in iter(items))),
    )


@cython.ccall
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
    artifact: object
    artifact_key: object
    retained: object
    snapshot: object
    if should_abort is not None and should_abort():
        cache.records.pop(boundary.addr, None)
        return None
    snapshot = _surface_key_8616(project, boundary, importer)
    retained = cache.records.pop(boundary.addr, None)
    if retained is not None and snapshot is not None:
        same_owners = retained.project is project and retained.source is source and retained.boundary is boundary
        unchanged = operator.eq(retained.key, snapshot[0]) and operator.eq(_json_key_8616(retained.artifact.to_dict()), retained.artifact_key)
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
    if snapshot is not None and operator.eq(after, snapshot) and artifact_key is not None:
        cache.records[boundary.addr] = RawBootNativeSurfaceRecord8616(
            project, source, boundary, artifact, snapshot[0], artifact_key, snapshot[1],
        )
    return artifact
