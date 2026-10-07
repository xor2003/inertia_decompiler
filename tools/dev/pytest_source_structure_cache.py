"""Persist content-addressed pytest structure indexes for development gates.

Layer: Tooling/gates.
Responsibility: cache selectors and skip/xfail locations only; assertion,
subprocess, and evidence facts remain process-local and lazy.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import threading
from dataclasses import dataclass
from pathlib import Path

type SkipLinesByNode = tuple[tuple[str, tuple[int, ...]], ...]

_CACHE_SCHEMA = 1
_REPO_ROOT = Path(__file__).resolve().parents[2]
_CACHE_ROOT = _REPO_ROOT / ".inertia_decomp_cache" / "pytest_source_structure"


@dataclass(frozen=True, slots=True)
class CachedPytestStructure:
    """Validated persistent structural facts for one exact source version."""

    nodes: frozenset[str]
    skip_xfail_lines_by_node: SkipLinesByNode


def _implementation_digest() -> str:
    """Hash code and ABI inputs that define structural-index behavior."""

    digest = hashlib.sha256()
    digest.update((sys.implementation.cache_tag or "unknown-python-abi").encode("utf-8"))
    for path in (Path(__file__), Path(__file__).with_name("pytest_source_structure.py")):
        digest.update(path.resolve().as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


_IMPLEMENTATION_DIGEST = _implementation_digest()


def _cache_path(source_path: Path, skip_calls: frozenset[str]) -> Path | None:
    """Return the bounded cache location for one repository source and policy."""

    resolved = source_path.resolve()
    try:
        resolved.relative_to(_REPO_ROOT.resolve())
    except ValueError:
        return None
    digest = hashlib.sha256()
    digest.update(resolved.as_posix().encode("utf-8"))
    digest.update(b"\0")
    for call_name in sorted(skip_calls):
        digest.update(call_name.encode("utf-8"))
        digest.update(b"\0")
    return _CACHE_ROOT / f"{digest.hexdigest()}.json"


def _decode_skip_lines(value: object) -> SkipLinesByNode | None:
    """Decode deterministic selector/line pairs from an untrusted payload."""

    if not isinstance(value, list):
        return None
    decoded: list[tuple[str, tuple[int, ...]]] = []
    for item in value:
        if not isinstance(item, list) or len(item) != 2:
            return None
        selector, encoded_lines = item
        if not isinstance(selector, str) or not isinstance(encoded_lines, list):
            return None
        if any(type(line) is not int or line <= 0 for line in encoded_lines):
            return None
        decoded.append((selector, tuple(encoded_lines)))
    selectors = [selector for selector, _lines in decoded]
    if len(selectors) != len(set(selectors)):
        return None
    return tuple(decoded)


def load_cached_pytest_structure(
    source_path: Path,
    source_digest: str,
    skip_calls: frozenset[str],
) -> CachedPytestStructure | None:
    """Return a validated exact-content structure record, or a cache miss."""

    cache_path = _cache_path(source_path, skip_calls)
    if cache_path is None:
        return None
    try:
        payload: object = json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    if (
        payload.get("schema") != _CACHE_SCHEMA
        or payload.get("implementation_digest") != _IMPLEMENTATION_DIGEST
        or payload.get("source_path") != source_path.resolve().as_posix()
        or payload.get("source_digest") != source_digest
        or payload.get("skip_calls") != sorted(skip_calls)
    ):
        return None
    encoded_nodes = payload.get("nodes")
    if not isinstance(encoded_nodes, list) or any(not isinstance(node, str) for node in encoded_nodes):
        return None
    if len(encoded_nodes) != len(set(encoded_nodes)):
        return None
    skip_lines = _decode_skip_lines(payload.get("skip_xfail_lines_by_node"))
    nodes = frozenset(encoded_nodes)
    if skip_lines is None or {selector for selector, _lines in skip_lines} != {"", *nodes}:
        return None
    return CachedPytestStructure(nodes=nodes, skip_xfail_lines_by_node=skip_lines)


def store_cached_pytest_structure(
    source_path: Path,
    source_digest: str,
    skip_calls: frozenset[str],
    structure: CachedPytestStructure,
) -> None:
    """Atomically replace the bounded record for one source path and policy."""

    cache_path = _cache_path(source_path, skip_calls)
    if cache_path is None:
        return
    temporary = cache_path.with_name(
        f".{cache_path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
    )
    payload = {
        "schema": _CACHE_SCHEMA,
        "implementation_digest": _IMPLEMENTATION_DIGEST,
        "source_path": source_path.resolve().as_posix(),
        "source_digest": source_digest,
        "skip_calls": sorted(skip_calls),
        "nodes": sorted(structure.nodes),
        "skip_xfail_lines_by_node": [
            [selector, list(lines)] for selector, lines in structure.skip_xfail_lines_by_node
        ],
    }
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        temporary.replace(cache_path)
    except OSError:
        temporary.unlink(missing_ok=True)
