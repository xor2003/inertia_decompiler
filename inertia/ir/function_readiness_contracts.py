"""Source-bound function readiness and lifecycle contracts.

Layer: IR.
Responsibility: bind published function artifacts to the exact source generation
(entry, boundary block bytes, CFG edges) they were built from, record typed
provenance for that binding, and expose the canonical six-stage lifecycle
vocabulary every dependent stage consumes. Pure observation reads loader memory
only; it never lifts, rebuilds, or mutates analysis state.

Owns typed Value, Address, Condition, instruction facts, and lossless
normalization. Do not perform alias-state ownership, widening,
lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting
work here. Do not recover semantics from COD, source, assembly, or rendered C
text.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import struct
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import CodeType, FunctionType
from typing import Protocol, cast

from archinfo import Arch

from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)

__all__ = [
    "FUNCTION_LIFECYCLE_STAGES_8616",
    "FunctionLifecycleStage8616",
    "FunctionSourceBinding8616",
    "FunctionSourceBindingProvenance8616",
    "FunctionSourceBlock8616",
    "FunctionSourceRevision8616",
    "FunctionSourceScope8616",
    "bind_function_source_owner_8616",
    "function_artifact_body_digest_8616",
    "function_build_attestation_8616",
    "function_source_boundary_8616",
    "observed_function_artifact_source_revision_8616",
    "observed_function_source_revision_8616",
    "record_function_build_attestation_8616",
    "reobserve_function_source_revision_8616",
    "requires_function_source_observation_8616",
]


class FunctionLifecycleStage8616(StrEnum):
    """Canonical function evidence lifecycle stages, in pipeline order.

    Values are the authoritative stage labels; the legacy public ordering
    projection ``CORE_DECOMPILER_PIPELINE_ORDER_8616`` derives from this enum.
    """

    IR = "IR"
    ALIAS = "Alias"
    WIDENING = "Widening"
    TYPES = "Types"
    STRUCTURING = "Structuring"
    REWRITE = "Rewrite"


FUNCTION_LIFECYCLE_STAGES_8616: tuple[FunctionLifecycleStage8616, ...] = (
    FunctionLifecycleStage8616.IR,
    FunctionLifecycleStage8616.ALIAS,
    FunctionLifecycleStage8616.WIDENING,
    FunctionLifecycleStage8616.TYPES,
    FunctionLifecycleStage8616.STRUCTURING,
    FunctionLifecycleStage8616.REWRITE,
)


class FunctionSourceBindingProvenance8616(StrEnum):
    """How strongly a recorded source binding is authenticated.

    ``ATTESTED`` means the artifact itself carried a builder-bound revision and
    publication verified it against the current source. ``OBSERVED`` means the
    publisher could only record the generation visible at publication; the
    artifact does not prove it was built from that input.
    """

    ATTESTED = "attested"
    OBSERVED = "observed"


@dataclass(frozen=True, slots=True)
class FunctionSourceBlock8616:
    """Exact bytes of one boundary block consumed by a function artifact."""

    addr: int
    size: int
    sha256: str

    def to_dict(self) -> dict[str, object]:
        """Serialize this source block digest for diagnostics and artifacts."""
        return {"addr": self.addr, "size": self.size, "sha256": self.sha256}


class FunctionSourceScope8616(StrEnum):
    """Authority that frames the native source consumed by a producer."""

    CURRENT_FUNCTION = "current_function"
    EXACT_RANGE = "exact_range"


@dataclass(frozen=True, slots=True)
class FunctionSourceRevision8616:
    """One exact source generation: entry, boundary bytes, and CFG edges.

    Two revisions are equal only when the same entry address covers the same
    block byte extents and digests with the same intra-function edges. A change
    to any consumed byte, block extent, or edge yields a different revision.
    """

    function_addr: int
    blocks: tuple[FunctionSourceBlock8616, ...]
    edges: tuple[tuple[int, int], ...] = ()
    arch_key: str = ""
    producer_key: str = ""
    scope: FunctionSourceScope8616 = FunctionSourceScope8616.CURRENT_FUNCTION
    range_end: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this source revision for diagnostics and artifacts."""
        return {
            "function_addr": self.function_addr,
            "blocks": [block.to_dict() for block in self.blocks],
            "edges": [list(edge) for edge in self.edges],
            "arch_key": self.arch_key,
            "producer_key": self.producer_key,
            "scope": self.scope.value,
            "range_end": self.range_end,
        }


@dataclass(frozen=True, slots=True)
class FunctionSourceBinding8616:
    """Recorded binding between one published artifact and its source input.

    ``inputs`` carries the body digests of the exact parent artifacts this
    derivation consumed, so an authentic ancestor digest alone can never
    attest a foreign derived body.
    """

    revision: FunctionSourceRevision8616
    provenance: FunctionSourceBindingProvenance8616
    producer: str
    inputs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Serialize this binding for readiness diagnostics."""
        return {
            "revision": self.revision.to_dict(),
            "provenance": self.provenance.value,
            "producer": self.producer,
            "inputs": list(self.inputs),
        }


class _FunctionManager8616(Protocol):
    """Third-party function-manager surface used for exact lookup."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return an existing function without inventing a boundary."""
        ...


class _KnowledgeBase8616(Protocol):
    """Third-party knowledge-base surface used by this IR owner."""

    functions: _FunctionManager8616


class _MemorySurface8616(Protocol):
    """Third-party loader memory needed for exact block bytes."""

    def load(self, addr: int, size: int) -> bytes | bytearray | memoryview:
        """Read concrete loaded bytes."""
        ...


class _LoaderSurface8616(Protocol):
    """Third-party loader surface used only for source observation."""

    memory: _MemorySurface8616




class _ProjectSurface8616(Protocol):
    """Project surfaces consumed for boundary and byte observation."""

    kb: _KnowledgeBase8616
    loader: _LoaderSurface8616
    arch: Arch
    _inertia_caller_function_ranges_8616: tuple[tuple[int, int], ...]
    _inertia_function_source_owners_8616: dict[int, _FunctionManager8616]


class _BlockNode8616(Protocol):
    """Third-party CFG block identity without lifting the block."""

    addr: int
    size: int


class _GraphSurface8616(Protocol):
    """Third-party function graph used for exact CFG identity."""

    nodes: Iterable[object]
    edges: Iterable[tuple[object, object]]


class _GraphBoundary8616(Protocol):
    """Third-party boundary carrying a block graph."""

    graph: _GraphSurface8616


class _RangeBoundary8616(Protocol):
    """Owned range boundary carrying one contiguous framed extent."""

    addr: int
    size: int
    successor_edges: tuple[tuple[int, int], ...]


def function_source_boundary_8616(project: object, function_addr: int) -> object | None:
    """Return the canonical exact boundary for one function address.

    A producer's explicit CFG function manager takes precedence over the default
    project KB. Once bound, its missing function is a refusal, never permission
    to borrow another manager's frame. Pure lookup: never creates KB state.
    """
    surface = cast(_ProjectSurface8616, project)
    try:
        owners = surface._inertia_function_source_owners_8616
    except AttributeError:
        owners = {}
    owner = owners.get(function_addr)
    if owner is not None:
        try:
            return owner.function(addr=function_addr, create=False)
        except (AttributeError, KeyError, TypeError):
            return None
    try:
        function = surface.kb.functions.function(addr=function_addr, create=False)
    except (AttributeError, KeyError, TypeError):
        function = None
    if function is not None:
        return function
    try:
        ranges = surface._inertia_caller_function_ranges_8616
    except AttributeError:
        ranges = ()
    matching = tuple(
        (start, end)
        for start, end in ranges
        if isinstance(start, int) and isinstance(end, int) and start == function_addr and end > start
    )
    if len(matching) != 1:
        return None
    start, end = matching[0]
    return cast(object | None, exact_function_range_boundary_8616(project, start, end))


def bind_function_source_owner_8616(project: object, boundary: object) -> None:
    """Retain the real producer's live function manager, without copying its CFG.

    Native function builders may consume a function from an explicit analysis
    KB rather than ``project.kb``. Retain that actual manager so subsequent
    observations see replacement, removal and graph changes. Model boundaries
    and functions belonging to another project grant no new authority here.
    """
    from angr.knowledge_plugins.functions.function import Function

    if not isinstance(boundary, Function) or boundary.project is not project:
        return
    # Third-party angr Function ownership, not an Inertia data contract.
    manager = boundary._function_manager
    if manager is None:
        return
    # Function's backreference is a weak proxy. Keep the actual KB-owned manager
    # alive so source authority outlives the temporary CFG analysis object.
    manager = manager._kb.functions
    surface = cast(_ProjectSurface8616, project)
    try:
        owners = surface._inertia_function_source_owners_8616
    except AttributeError:
        owners = {}
        surface._inertia_function_source_owners_8616 = owners
    owners[boundary.addr] = cast(_FunctionManager8616, manager)


def _graph_block_edges_8616(
    boundary: object,
) -> tuple[tuple[tuple[int, int], ...], tuple[tuple[int, int], ...]] | None:
    """Extract per-block extents and edges from a graph-carrying boundary."""
    try:
        graph = cast(_GraphBoundary8616, boundary).graph
        raw_nodes = tuple(graph.nodes)
        raw_edges = tuple(graph.edges)
    except AttributeError:
        return None
    if not raw_nodes:
        return None
    coords: dict[int, int] = {}
    edges: set[tuple[int, int]] = set()
    for raw_node in raw_nodes:
        node = cast(_BlockNode8616, raw_node)
        try:
            addr, size = node.addr, node.size
        except AttributeError:
            return None
        if not isinstance(addr, int) or not isinstance(size, int) or size <= 0:
            return None
        coords[addr] = size
    for raw_source, raw_target in raw_edges:
        source = cast(_BlockNode8616, raw_source)
        target = cast(_BlockNode8616, raw_target)
        try:
            edge = (source.addr, target.addr)
        except AttributeError:
            continue
        if edge[0] in coords and edge[1] in coords:
            edges.add(edge)
    return tuple(sorted(coords.items())), tuple(sorted(edges))


def _range_block_edges_8616(
    boundary: object,
) -> tuple[tuple[tuple[int, int], ...], tuple[tuple[int, int], ...]] | None:
    """Extract the contiguous framed extent and proven edges of a range boundary."""
    range_boundary = cast(_RangeBoundary8616, boundary)
    try:
        start = range_boundary.addr
        size = range_boundary.size
    except AttributeError:
        return None
    if not isinstance(start, int) or not isinstance(size, int) or size <= 0:
        return None
    try:
        raw_successors = range_boundary.successor_edges
    except AttributeError:
        raw_successors = ()
    proven_edges = {
        (src, dst)
        for src, dst in raw_successors
        if isinstance(src, int)
        and isinstance(dst, int)
        and start <= src < start + size
        and start <= dst < start + size
    }
    return ((start, size),), tuple(sorted(proven_edges))


def _boundary_block_edges_8616(
    boundary: object,
) -> tuple[tuple[tuple[int, int], ...], tuple[tuple[int, int], ...]] | None:
    """Extract exact block coordinates and intra-function edges.

    Returns ``(coords, edges)`` with sorted ``(addr, size)`` block extents and
    sorted ``(src, dst)`` edges, or ``None`` when the boundary surface cannot
    name its consumed blocks.
    """
    graph_surface = _graph_block_edges_8616(boundary)
    if graph_surface is not None:
        return graph_surface
    return _range_block_edges_8616(boundary)


def observed_function_source_revision_8616(
    project: object,
    function_addr: int,
    *,
    boundary: object | None = None,
) -> FunctionSourceRevision8616 | None:
    """Observe the current source generation for one function boundary.

    Reads concrete loader bytes for every boundary block. Returns ``None``
    whenever evidence is incomplete (no boundary, no loader, unreadable bytes),
    so callers record "no observation" instead of guessing a generation.
    """
    if boundary is None:
        boundary = function_source_boundary_8616(project, function_addr)
    if boundary is None:
        return None
    extracted = _boundary_block_edges_8616(boundary)
    if extracted is None:
        return None
    coords, edges = extracted
    surface = cast(_ProjectSurface8616, project)
    blocks: list[FunctionSourceBlock8616] = []
    for addr, size in coords:
        try:
            data = bytes(surface.loader.memory.load(addr, size))
        except (AttributeError, KeyError, TypeError, ValueError):
            return None
        if len(data) != size:
            return None
        blocks.append(FunctionSourceBlock8616(addr=addr, size=size, sha256=hashlib.sha256(data).hexdigest()))
    identity_keys = _source_identity_keys_8616(project)
    if identity_keys is None:
        return None
    arch_key, producer_key = identity_keys
    return FunctionSourceRevision8616(
        function_addr=function_addr,
        blocks=tuple(blocks),
        edges=edges,
        arch_key=arch_key,
        producer_key=producer_key,
        scope=(
            FunctionSourceScope8616.EXACT_RANGE
            if isinstance(boundary, ExactFunctionRangeBoundary8616)
            else FunctionSourceScope8616.CURRENT_FUNCTION
        ),
        range_end=(
            boundary.addr + boundary.size
            if isinstance(boundary, ExactFunctionRangeBoundary8616)
            else None
        ),
    )


def reobserve_function_source_revision_8616(
    project: object,
    revision: FunctionSourceRevision8616,
) -> FunctionSourceRevision8616 | None:
    """Re-read the actual source scope retained by an attested producer.

    Explicit ranges are producer inputs, not inferred function-manager entries.
    Reconstruct their current native inventory rather than trusting saved blocks.
    Manager-framed sources still require their live canonical boundary.
    """
    if revision.scope is FunctionSourceScope8616.CURRENT_FUNCTION:
        if revision.range_end is not None:
            return None
        return observed_function_source_revision_8616(project, revision.function_addr)
    if revision.scope is not FunctionSourceScope8616.EXACT_RANGE:
        return None
    end = revision.range_end
    if not isinstance(end, int) or end <= revision.function_addr:
        return None
    boundary = exact_function_range_boundary_8616(project, revision.function_addr, end)
    if boundary is None:
        return None
    return observed_function_source_revision_8616(
        project, revision.function_addr, boundary=boundary,
    )


def observed_function_artifact_source_revision_8616(
    project: object,
    function_addr: int,
    artifact: object,
) -> FunctionSourceRevision8616 | None:
    """Observe the scope of an exact attested body, otherwise the live function.

    Bare revision fields never authorize an explicit scope: only the owning
    builder's recorded body attestation selects that scope for re-observation.
    """
    digest = function_artifact_body_digest_8616(artifact)
    binding = (
        None if digest is None
        else function_build_attestation_8616(project, function_addr, digest)
    )
    if binding is not None:
        return reobserve_function_source_revision_8616(project, binding.revision)
    return observed_function_source_revision_8616(project, function_addr)


def _implementation_constant_8616(value: object, depth: int = 0) -> str | None:
    """Encode supported CPython code constants without identity/name fallbacks."""
    if depth > 64:
        return None
    if isinstance(value, CodeType):
        fields = (
            "code", value.co_argcount, value.co_posonlyargcount,
            value.co_kwonlyargcount, value.co_nlocals, value.co_stacksize,
            value.co_flags, value.co_code, value.co_consts, value.co_names,
            value.co_varnames, value.co_freevars, value.co_cellvars,
            value.co_exceptiontable,
        )
        return _implementation_constant_8616(fields, depth + 1)
    if isinstance(value, FunctionType):
        return _function_implementation_constant_8616(value, depth + 1)
    if value is None:
        return "none"
    if value is Ellipsis:
        return "ellipsis"
    if type(value) is float:
        return "float:" + struct.pack(">d", value).hex()
    if type(value) is complex:
        return "complex:" + struct.pack(">dd", value.real, value.imag).hex()
    if type(value) in (bool, int, str, bytes):
        return f"{type(value).__name__}:{value!r}"
    return _implementation_collection_8616(value, depth)


def _function_implementation_constant_8616(
    producer: FunctionType,
    depth: int,
) -> str | None:
    """Bind function code, defaults and supported captured values structurally."""
    captured: list[str] = []
    if producer.__closure__ is not None:
        for cell in producer.__closure__:
            try:
                value: object = cell.cell_contents
            except ValueError:
                return None
            encoded = _implementation_constant_8616(value, depth + 1)
            if encoded is None:
                return None
            captured.append(encoded)
    fields = (
        "function", producer.__code__, producer.__defaults__,
        producer.__kwdefaults__, tuple(captured),
    )
    return _implementation_constant_8616(fields, depth + 1)


def _implementation_collection_8616(value: object, depth: int) -> str | None:
    """Hash each structural node so nested encodings never multiply escaping.

    Every observation still reads current code, defaults and captured values;
    no cached digest supplies authority after a mutable producer changes.
    """
    if isinstance(value, (tuple, frozenset)):
        items: list[str] = []
        for item in value:
            encoded = _implementation_constant_8616(item, depth + 1)
            if encoded is None:
                return None
            items.append(encoded)
        if isinstance(value, frozenset):
            items.sort()
        payload = json.dumps(items, ensure_ascii=True).encode("utf-8")
        return type(value).__name__ + ":sha256:" + hashlib.sha256(payload).hexdigest()
    if isinstance(value, dict):
        pairs: list[tuple[str, str]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                return None
            encoded = _implementation_constant_8616(item, depth + 1)
            if encoded is None:
                return None
            pairs.append((key, encoded))
        payload = json.dumps(sorted(pairs), ensure_ascii=True).encode("utf-8")
        return "mapping:sha256:" + hashlib.sha256(payload).hexdigest()
    return None


def _implementation_digest_8616(producer: object) -> str | None:
    """Bind Python code/defaults or a defining module; unknown is not proof."""
    if isinstance(producer, FunctionType):
        payload = _implementation_constant_8616(producer)
        if payload is None:
            return None
        return "code:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
    if isinstance(producer, type):
        return _class_implementation_digest_8616(producer)
    return None


def _class_implementation_digest_8616(producer: type[object]) -> str | None:
    """Freshly stream module bytes and bind live Python method code.

    Streaming preserves the exact concatenated-content digest while avoiding
    two complete module allocations on every source observation. No module
    contents or file metadata are retained as authority between observations.
    """
    module = inspect.getmodule(producer)
    if module is None:
        return None
    try:
        module_file = module.__file__
    except AttributeError:
        return None
    if not isinstance(module_file, str):
        return None
    try:
        with Path(module_file).open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256")
    except OSError:
        return None
    methods: list[tuple[str, str]] = []
    for name, member in vars(producer).items():
        if isinstance(member, FunctionType):
            encoded = _implementation_constant_8616(
                (member.__code__, member.__defaults__, member.__kwdefaults__)
            )
            if encoded is None:
                return None
            methods.append((name, encoded))
    identity = (producer.__module__, producer.__qualname__, sorted(methods))
    digest.update(json.dumps(identity, ensure_ascii=True).encode("utf-8"))
    return "module:" + digest.hexdigest()


def _source_identity_keys_8616(project: object) -> tuple[str, str] | None:
    """Bind real architecture and producer identities, never name strings.

    The architecture key reuses the canonical native arch authority, which
    captures mutable decoder/register state beyond ``arch.name``. The producer
    key binds the actual implementation of the lifter/builder callables
    resolved at observation time, so replacing one — even while preserving
    its module and qualified name — invalidates every revision built under
    it.
    """
    from inertia.frontend.x86_16.lift_86_16 import Lifter86_16
    from inertia.ir.raw_boot_blocked_prefix import _architecture_key_8616

    from . import vex_import

    surface = cast(_ProjectSurface8616, project)
    arch_key = ""
    try:
        arch = surface.arch
        arch_key = hashlib.sha256(repr(_architecture_key_8616(arch)).encode("utf-8")).hexdigest()
    except (AttributeError, TypeError, ValueError):
        return None
    producers = (
        vex_import._block_to_ir,
        vex_import.build_x86_16_ir_function_artifact,
        Lifter86_16,
    )
    names: list[str] = []
    for producer in producers:
        if not isinstance(producer, (FunctionType, type)):
            return None
        module = producer.__module__
        qualname = producer.__qualname__
        digest = _implementation_digest_8616(producer)
        if digest is None:
            return None
        names.append(f"{module}.{qualname}:{digest}")
    producer_key = hashlib.sha256("\x00".join(names).encode("utf-8")).hexdigest()
    return arch_key, producer_key


class _OriginalSourceProject8616(Protocol):
    """Expose the canonical original-project bridge at the native boundary."""

    _inertia_original_project: object


def requires_function_source_observation_8616(project: object) -> bool:
    """Keep native binary scopes distinct from independent model-only scopes.

    Native projects and their original-project adapters cannot acquire model
    proof merely because function metadata is unavailable. Object identity
    detects bridge cycles only; it is never a source or body fingerprint.
    Malformed cycles conservatively require observation.
    """
    from angr.project import Project

    current = project
    visited: set[int] = set()
    while id(current) not in visited:
        if isinstance(current, Project):
            return True
        visited.add(id(current))
        bridge = cast(_OriginalSourceProject8616, current)
        try:
            current = bridge._inertia_original_project
        except AttributeError:
            return False
    return True


def function_artifact_body_digest_8616(artifact: object) -> str | None:
    """Digest current owned bodies as finite DAGs, excluding lifecycle authority."""
    from .function_artifact import IRFunctionArtifact
    from .source_graph_binding import SourceGraphSerializationError8616, canonical_source_graph_8616
    from .ssa_function import SSAFunctionArtifact

    if isinstance(artifact, IRFunctionArtifact) and type(artifact) is IRFunctionArtifact:
        payload = artifact.non_block_payload_8616()
        try:
            payload["blocks"] = canonical_source_graph_8616(artifact.function_addr, artifact.blocks)
        except SourceGraphSerializationError8616:
            return None
    elif isinstance(artifact, SSAFunctionArtifact) and type(artifact) is SSAFunctionArtifact:
        payload = artifact.non_block_payload_8616()
        try:
            payload["blocks"] = artifact.canonical_blocks_payload_8616()
        except SourceGraphSerializationError8616:
            return None
    else:
        try:
            payload = cast(dict[str, object], artifact.to_dict())  # type: ignore[attr-defined]
        except AttributeError:
            return None
    payload.pop("source_revision", None)
    payload.pop("lifecycle_stage", None)
    payload.pop("lifecycle", None)
    try:
        encoded = json.dumps(payload, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError):
        return None
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class _BuildAttestationSurface8616(Protocol):
    """Project-owned build attestation ledger extension."""

    _inertia_function_build_attestations_8616: dict[
        tuple[int, str], FunctionSourceBinding8616
    ]


def record_function_build_attestation_8616(
    project: object,
    function_addr: int,
    body_digest: str,
    revision: FunctionSourceRevision8616,
    producer: str,
    *,
    inputs: Iterable[str] = (),
    boundary: object | None = None,
) -> FunctionSourceBinding8616:
    """Record, at actual build time, that this exact body consumed ``revision``.

    Only owned builders may attest: the record binds producer identity, the
    artifact body digest and the observed source generation atomically, so a
    copied revision value can never authenticate a foreign body. ``inputs``
    names the exact parent body digests a derived artifact consumed, so an
    authentic ancestor cannot attest a body it never produced. An explicit
    native boundary binds its actual live CFG owner for later re-observation.
    """
    surface = cast(_BuildAttestationSurface8616, project)
    try:
        ledger = surface._inertia_function_build_attestations_8616
    except AttributeError:
        ledger = {}
        surface._inertia_function_build_attestations_8616 = ledger
    if not isinstance(ledger, dict):
        raise TypeError("function build attestation ledger must be a dict")
    binding = FunctionSourceBinding8616(
        revision=revision,
        provenance=FunctionSourceBindingProvenance8616.ATTESTED,
        producer=producer,
        inputs=tuple(inputs),
    )
    ledger[(function_addr, body_digest)] = binding
    if boundary is not None:
        bind_function_source_owner_8616(project, boundary)
    return binding


def function_build_attestation_8616(
    project: object,
    function_addr: int,
    body_digest: str,
) -> FunctionSourceBinding8616 | None:
    """Return the recorded build attestation for one exact artifact body."""
    surface = cast(_BuildAttestationSurface8616, project)
    try:
        ledger = surface._inertia_function_build_attestations_8616
    except AttributeError:
        return None
    if not isinstance(ledger, dict):
        raise TypeError("function build attestation ledger must be a dict")
    return ledger.get((function_addr, body_digest))
