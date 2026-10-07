"""Decode CFG-owned function blocks directly from exact loaded bytes.

Layer: Frontend.
Responsibility: publish immutable per-block Capstone instruction evidence from
CFG-owned extents without entering VEX lifting or assigning semantic effects.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast

from .frontend_capstone_decode import decode_exact_capstone_block_8616


class _GraphNodeBoundary8616(Protocol):
    """Exact CFG block coordinates exposed by an angr function graph."""

    addr: int
    size: int


class _GraphBoundary8616(Protocol):
    """Narrow graph node surface needed for block extent collection."""

    nodes: Iterable[_GraphNodeBoundary8616]


class _FunctionBoundary8616(Protocol):
    """Narrow third-party function surface used by direct block decoding."""

    addr: int
    block_addrs_set: Iterable[int]
    graph: _GraphBoundary8616


class _LoaderMemoryBoundary8616(Protocol):
    """Loaded-memory byte reader used at the Frontend boundary."""

    def load(self, address: int, size: int) -> object:
        """Read one exact loaded address range."""


class _LoaderBoundary8616(Protocol):
    """Narrow project loader surface used by direct block decoding."""

    memory: _LoaderMemoryBoundary8616


class _ProjectBoundary8616(Protocol):
    """Project fields and cache owned by exact function block decoding."""

    loader: _LoaderBoundary8616
    _inertia_function_block_decode_artifacts_8616: dict[
        int,
        FunctionBlockDecodeArtifact8616,
    ]


class FunctionBlockDecodeStatus8616(Enum):
    """Typed result of exact function block decoding."""

    COMPLETE = "complete"
    REFUSED = "refused"


class FunctionBlockDecodeFailureReason8616(Enum):
    """Reason direct exact-byte decoding could not close."""

    MISSING_FUNCTION_IDENTITY = "missing_function_identity"
    MISSING_BLOCK_SURFACE = "missing_block_surface"
    INCOHERENT_GRAPH_EXTENTS = "incoherent_graph_extents"
    BYTE_READ_FAILED = "byte_read_failed"
    DECODE_INCOMPLETE = "decode_incomplete"


@dataclass(frozen=True, slots=True)
class FunctionBlockDecodeFailure8616:
    """One exact block or function-level decode refusal."""

    block_addr: int | None
    reason: FunctionBlockDecodeFailureReason8616
    detail: str = ""


@dataclass(frozen=True, slots=True)
class FunctionDecodedBlock8616:
    """Immutable Capstone instruction evidence for one exact CFG block."""

    address: int
    size: int
    code: bytes
    instructions: tuple[object, ...]


@dataclass(frozen=True, slots=True)
class FunctionBlockDecodeArtifact8616:
    """Closed direct-decode artifact for one exact function block surface."""

    function_entry: int | None
    blocks: tuple[FunctionDecodedBlock8616, ...]
    content_identity: bytes | None
    status: FunctionBlockDecodeStatus8616
    failures: tuple[FunctionBlockDecodeFailure8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether every CFG block was decoded from exact bytes."""
        return (
            self.status is FunctionBlockDecodeStatus8616.COMPLETE
            and self.raw_fact_count > 0
            and self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count == self.materialized_count
            and self.failure_count == 0
            and not self.failures
            and self.content_identity is not None
        )

    def instructions_by_block(self) -> dict[int, tuple[object, ...]]:
        """Return exact block-address instruction ownership."""
        return {block.address: block.instructions for block in self.blocks}


def _refused_artifact_8616(
    function_entry: int | None,
    reason: FunctionBlockDecodeFailureReason8616,
    *,
    block_addr: int | None = None,
    detail: str = "",
) -> FunctionBlockDecodeArtifact8616:
    """Build one closed typed refusal for an unavailable decode boundary."""
    return FunctionBlockDecodeArtifact8616(
        function_entry=function_entry,
        blocks=(),
        content_identity=None,
        status=FunctionBlockDecodeStatus8616.REFUSED,
        failures=(FunctionBlockDecodeFailure8616(block_addr, reason, detail),),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=0,
        failure_count=1,
    )


def _function_block_extents_8616(
    function: object,
) -> tuple[int | None, tuple[tuple[int, int], ...]] | FunctionBlockDecodeArtifact8616:
    """Return graph extents only when they exactly cover owned block addresses."""
    boundary = cast(_FunctionBoundary8616, function)
    try:
        entry = int(boundary.addr)
    except (AttributeError, TypeError, ValueError):
        return _refused_artifact_8616(
            None,
            FunctionBlockDecodeFailureReason8616.MISSING_FUNCTION_IDENTITY,
        )
    try:
        owned_addrs = frozenset(int(address) for address in boundary.block_addrs_set)
    except (AttributeError, TypeError, ValueError):
        owned_addrs = frozenset()
    if not owned_addrs:
        return _refused_artifact_8616(
            entry,
            FunctionBlockDecodeFailureReason8616.MISSING_BLOCK_SURFACE,
        )
    try:
        graph_nodes = tuple(boundary.graph.nodes)
    except (AttributeError, TypeError):
        graph_nodes = ()
    extents: dict[int, int] = {}
    for node in graph_nodes:
        try:
            address = int(node.addr)
            size = int(node.size)
        except (AttributeError, TypeError, ValueError):
            continue
        if address not in owned_addrs or address < 0 or size <= 0:
            continue
        previous = extents.setdefault(address, size)
        if previous != size:
            return _refused_artifact_8616(
                entry,
                FunctionBlockDecodeFailureReason8616.INCOHERENT_GRAPH_EXTENTS,
                block_addr=address,
                detail=f"conflicting sizes {previous} and {size}",
            )
    if frozenset(extents) != owned_addrs:
        return _refused_artifact_8616(
            entry,
            FunctionBlockDecodeFailureReason8616.INCOHERENT_GRAPH_EXTENTS,
            detail="CFG graph extents do not cover the owned block surface",
        )
    return entry, tuple(sorted(extents.items()))


def _content_identity_8616(
    entry: int,
    block_bytes: Sequence[tuple[int, int, bytes]],
) -> bytes:
    """Return a deterministic content identity for exact block coordinates."""
    digest = hashlib.sha256()
    digest.update((entry & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little", signed=False))
    for address, size, code in block_bytes:
        digest.update(address.to_bytes(8, "little", signed=False))
        digest.update(size.to_bytes(8, "little", signed=False))
        digest.update(code)
    return digest.digest()


def _read_function_block_bytes_8616(
    boundary: _ProjectBoundary8616,
    entry: int,
    extents: tuple[tuple[int, int], ...],
) -> list[tuple[int, int, bytes]] | FunctionBlockDecodeArtifact8616:
    """Load exact bytes for every graph extent or return a typed refusal."""
    block_bytes: list[tuple[int, int, bytes]] = []
    for address, size in extents:
        try:
            code = bytes(cast(Any, boundary.loader.memory.load(address, size)))
        except Exception as error:
            return _refused_artifact_8616(
                entry,
                FunctionBlockDecodeFailureReason8616.BYTE_READ_FAILED,
                block_addr=address,
                detail=f"{type(error).__name__}: {error}",
            )
        if len(code) != size:
            return _refused_artifact_8616(
                entry,
                FunctionBlockDecodeFailureReason8616.BYTE_READ_FAILED,
                block_addr=address,
                detail=f"expected={size} actual={len(code)}",
            )
        block_bytes.append((address, size, code))
    return block_bytes


def collect_function_block_decode_artifact_8616(
    project: object,
    function: object,
) -> FunctionBlockDecodeArtifact8616:
    """Decode exact CFG block bytes directly, with mutation-aware reuse."""
    extents_or_refusal = _function_block_extents_8616(function)
    if isinstance(extents_or_refusal, FunctionBlockDecodeArtifact8616):
        return extents_or_refusal
    entry, extents = extents_or_refusal
    assert entry is not None
    boundary = cast(_ProjectBoundary8616, project)
    block_bytes_or_refusal = _read_function_block_bytes_8616(boundary, entry, extents)
    if isinstance(block_bytes_or_refusal, FunctionBlockDecodeArtifact8616):
        return block_bytes_or_refusal
    block_bytes = block_bytes_or_refusal
    content_identity = _content_identity_8616(entry, block_bytes)
    try:
        cache = boundary._inertia_function_block_decode_artifacts_8616
    except (AttributeError, TypeError):
        cache = {}
        with suppress(AttributeError, TypeError):
            boundary._inertia_function_block_decode_artifacts_8616 = cache
    if not isinstance(cache, dict):
        cache = {}
    cached = cache.get(entry)
    if cached is not None and cached.content_identity == content_identity:
        return cached
    decoded_blocks: list[FunctionDecodedBlock8616] = []
    failures: list[FunctionBlockDecodeFailure8616] = []
    for address, size, code in block_bytes:
        decoded = decode_exact_capstone_block_8616(project, address, code)
        block = decoded.block
        if not decoded.complete or block is None:
            detail = decoded.failure.detail if decoded.failure is not None else "decode refused"
            failures.append(
                FunctionBlockDecodeFailure8616(
                    address,
                    FunctionBlockDecodeFailureReason8616.DECODE_INCOMPLETE,
                    detail,
                )
            )
            continue
        decoded_blocks.append(
            FunctionDecodedBlock8616(address, size, code, block.instructions)
        )
    fact_count = len(block_bytes)
    artifact = FunctionBlockDecodeArtifact8616(
        function_entry=entry,
        blocks=tuple(decoded_blocks),
        content_identity=content_identity,
        status=(
            FunctionBlockDecodeStatus8616.COMPLETE
            if not failures and len(decoded_blocks) == fact_count
            else FunctionBlockDecodeStatus8616.REFUSED
        ),
        failures=tuple(failures),
        raw_fact_count=fact_count,
        normalized_fact_count=fact_count,
        classified_fact_count=fact_count,
        materialized_count=len(decoded_blocks),
        failure_count=len(failures),
    )
    if artifact.complete and isinstance(cache, dict):
        cache[entry] = artifact
    return artifact
