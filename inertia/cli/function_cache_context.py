"""Build complete semantic identity for one function-result cache lookup.

Layer: CLI/fallback/reporting.
Responsibility: serialize already-derived recovery and annotation evidence for
cache partitioning without inferring decompiler semantics.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol, cast

from inertia.cli.cache import _function_decompilation_cache_key
from inertia.cli.cache_runtime_contract import live_decompilation_diagnostics_requested_8616
from inertia.cli.lst_extract import LSTMetadata
from inertia.cli.sidecar_cache import lst_metadata_content_digest_8616
from inertia.cli.work_items import FunctionWorkItem
from inertia.frontend.x86_16.cod_extract import CODProcMetadata
from inertia.semantics.callsite_summary import caller_return_use_evidence_by_addr_8616
from inertia.semantics.compiler_helpers import x86_16_compiler_helper_targets_8616

type StableJsonValue = bool | int | float | str | list["StableJsonValue"] | dict[str, "StableJsonValue"] | None


class _GraphSurface8616(Protocol):
    """Dynamic third-party graph fields consumed for cache identity."""

    nodes: Iterable[object]
    edges: Iterable[object]

    def get_edge_data(self, source: object, destination: object) -> object:
        """Return dynamic graph metadata for one directed edge."""


class _FunctionSurface8616(Protocol):
    """Dynamic angr function fields consumed for cache identity."""

    block_addrs_set: Iterable[int]
    transition_graph: _GraphSurface8616
    info: Mapping[str, object]
    project: object


class _GraphNodeSurface8616(Protocol):
    """Dynamic angr graph-node address fields consumed for cache identity."""

    addr: int
    size: int


@dataclass(frozen=True, slots=True)
class FunctionCacheContext8616:
    """Deterministic semantic evidence digests for one recovered function."""

    recovery_shape_digest: str
    annotation_evidence_digest: str
    project_evidence_digest: str
    sidecar_metadata_digest: str | None


def _stable_json_value(value: object) -> StableJsonValue:
    """Normalize supported typed evidence into deterministic JSON values."""
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()}
    if isinstance(value, Path):
        return {"path": str(value)}
    if isinstance(value, Enum):
        return {"enum": value.__class__.__qualname__, "value": _stable_json_value(value.value)}
    if isinstance(value, Mapping):
        entries: list[tuple[StableJsonValue, StableJsonValue]] = [
            (_stable_json_value(key), _stable_json_value(item_value)) for key, item_value in value.items()
        ]
        entries.sort(key=lambda item: json.dumps(item[0], sort_keys=True, separators=(",", ":")))
        normalized_entries: list[StableJsonValue] = [{"key": key, "value": item_value} for key, item_value in entries]
        return {"mapping": normalized_entries}
    if isinstance(value, tuple | list):
        return {"sequence": [_stable_json_value(item) for item in value]}
    if isinstance(value, set | frozenset):
        items = [_stable_json_value(item) for item in value]
        items.sort(key=lambda item: json.dumps(item, sort_keys=True, separators=(",", ":")))
        return {"set": items}
    raise TypeError(f"unsupported function-cache evidence value: {type(value).__qualname__}")


def _stable_digest(value: object) -> str:
    """Return a SHA-256 digest for one canonical evidence value."""
    encoded = json.dumps(
        _stable_json_value(value),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _graph_node_record(node: object) -> tuple[int, int | None]:
    """Return a stable address/size pair from one dynamic graph node."""
    if isinstance(node, int):
        return node, None
    surface = cast(_GraphNodeSurface8616, node)
    try:
        addr = surface.addr
    except AttributeError as exc:
        raise TypeError("function CFG node has no integer address") from exc
    if not isinstance(addr, int):
        raise TypeError("function CFG node address must be int")
    try:
        size = surface.size
    except AttributeError:
        size = None
    if size is not None and not isinstance(size, int):
        raise TypeError("function CFG node size must be int or absent")
    return addr, size


def _function_recovery_shape_record(function: object) -> dict[str, object]:
    """Return recovered block, edge, and exact-region identity."""
    surface = cast(_FunctionSurface8616, function)
    try:
        block_addrs = tuple(sorted(int(addr) for addr in surface.block_addrs_set))
    except AttributeError:
        block_addrs = ()
    try:
        graph = surface.transition_graph
    except AttributeError:
        graph = None
    nodes: tuple[tuple[int, int | None], ...] = ()
    edges: tuple[tuple[tuple[int, int | None], tuple[int, int | None], object], ...] = ()
    if graph is not None:
        nodes = tuple(sorted(_graph_node_record(node) for node in graph.nodes))
        edge_records: list[tuple[tuple[int, int | None], tuple[int, int | None], object]] = []
        for edge in graph.edges:
            if not isinstance(edge, tuple) or len(edge) < 2:
                raise TypeError("function CFG edge must expose source and destination nodes")
            try:
                edge_data = graph.get_edge_data(edge[0], edge[1])
            except AttributeError:
                edge_data = None
            edge_records.append((_graph_node_record(edge[0]), _graph_node_record(edge[1]), edge_data))
        edge_records.sort(
            key=lambda record: (
                record[0],
                record[1],
                json.dumps(_stable_json_value(record[2]), sort_keys=True, separators=(",", ":")),
            )
        )
        edges = tuple(edge_records)
    try:
        info = surface.info
    except AttributeError:
        info = {}
    exact_region = info.get("x86_16_binary_exact_region") if isinstance(info, Mapping) else None
    return {
        "block_addrs": block_addrs,
        "nodes": nodes,
        "edges": edges,
        "exact_region": exact_region,
    }


def _annotation_evidence_record(
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: Mapping[int, tuple[str, int]] | None,
) -> dict[str, object]:
    """Return complete explicit annotation inputs used by CLI decompilation."""
    return {
        "cod_metadata": asdict(cod_metadata) if cod_metadata is not None else None,
        "synthetic_globals": synthetic_globals,
    }


def _project_evidence_record(project: object | None) -> dict[str, object]:
    """Return typed project evidence known to alter lowering or signatures."""
    if project is None:
        return {"caller_return_use": {}, "compiler_helper_targets": ()}
    caller_evidence = {
        addr: asdict(evidence) for addr, evidence in caller_return_use_evidence_by_addr_8616(project).items()
    }
    return {
        "caller_return_use": caller_evidence,
        "compiler_helper_targets": x86_16_compiler_helper_targets_8616(project),
    }


def build_function_cache_context_8616(
    item: FunctionWorkItem,
    *,
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: Mapping[int, tuple[str, int]] | None,
    lst_metadata: LSTMetadata | None,
) -> FunctionCacheContext8616:
    """Build complete cache evidence from one work item and explicit inputs."""
    try:
        project = cast(_FunctionSurface8616, item.function).project
    except AttributeError:
        project = None
    sidecar_digest = (
        lst_metadata_content_digest_8616(lst_metadata) if lst_metadata is not None else item.sidecar_metadata_digest
    )
    return FunctionCacheContext8616(
        recovery_shape_digest=_stable_digest(_function_recovery_shape_record(item.function)),
        annotation_evidence_digest=_stable_digest(_annotation_evidence_record(cod_metadata, synthetic_globals)),
        project_evidence_digest=_stable_digest(_project_evidence_record(project)),
        sidecar_metadata_digest=sidecar_digest,
    )


def function_decompilation_cache_key_8616(
    item: FunctionWorkItem,
    *,
    binary_path: Path | None,
    api_style: str,
    cod_metadata: CODProcMetadata | None,
    synthetic_globals: Mapping[int, tuple[str, int]] | None,
    lst_metadata: LSTMetadata | None,
    enable_structured_simplify: bool,
    enable_postprocess: bool,
) -> dict[str, object] | None:
    """Build a cache key or refuse reuse for unsupported semantic evidence."""
    if live_decompilation_diagnostics_requested_8616():
        return None
    try:
        context = build_function_cache_context_8616(
            item,
            cod_metadata=cod_metadata,
            synthetic_globals=synthetic_globals,
            lst_metadata=lst_metadata,
        )
    except TypeError:
        return None
    return _function_decompilation_cache_key(
        binary_path=binary_path,
        function_addr=item.original_addr,
        active_function_addr=item.active_addr,
        recovery_addr=item.recovery_addr,
        function_name=item.name,
        api_style=api_style,
        c_target=item.c_target,
        sidecar_metadata_digest=context.sidecar_metadata_digest,
        recovery_shape_digest=context.recovery_shape_digest,
        annotation_evidence_digest=context.annotation_evidence_digest,
        project_evidence_digest=context.project_evidence_digest,
        enable_structured_simplify=enable_structured_simplify,
        enable_postprocess=enable_postprocess,
    )
