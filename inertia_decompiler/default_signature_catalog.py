from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from inertia_decompiler.signature_matching_policy import signature_matching_disabled
from signature_catalog import build_signature_catalog, discover_signature_inputs


def _catalog_manifest_path(output_path: Path) -> Path:
    return output_path.parent / "repo_signature_catalog.sources.txt"


def _catalog_tool_manifest_path(output_path: Path) -> Path:
    return output_path.parent / "repo_signature_catalog.tools.txt"


def _catalog_source_lines(catalog_root: Path) -> tuple[str, ...]:
    lines: list[str] = []
    for path in discover_signature_inputs((catalog_root,), recursive=True):
        if ".signature_catalog_cache" in path.parts:
            continue
        try:
            stat = path.stat()
        except OSError:
            continue
        lines.append(f"{path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}")
    return tuple(lines)


def _catalog_tool_lines(root: Path) -> tuple[str, ...]:
    tool_paths = (
        Path(__file__).resolve(),
        root / "signature_catalog.py",
        root / "omf_pat.py",
    )
    lines: list[str] = []
    for path in tool_paths:
        try:
            resolved = path.resolve()
            stat = resolved.stat()
        except OSError:
            continue
        lines.append(f"{resolved}|{stat.st_size}|{stat.st_mtime_ns}")
    return tuple(lines)


def _manifest_matches(manifest_path: Path, source_lines: tuple[str, ...]) -> bool:
    if not manifest_path.exists():
        return False
    try:
        existing = tuple(line.strip() for line in manifest_path.read_text().splitlines() if line.strip())
    except OSError:
        return False
    return existing == source_lines


def _write_manifest(manifest_path: Path, source_lines: tuple[str, ...]) -> None:
    manifest_path.write_text("".join(f"{line}\n" for line in source_lines))


@lru_cache(maxsize=2)
def default_signature_catalog_path(repo_root: Path | None = None) -> Path | None:
    """Return a cached repo-local signature catalog built from bundled and user-added PAT inputs."""
    if signature_matching_disabled():
        return None
    root = repo_root or Path(__file__).resolve().parents[1]
    catalog_root = root / "signature_catalogs"
    if not catalog_root.exists():
        return None
    cache_dir = catalog_root / ".signature_catalog_cache"
    output_path = cache_dir / "repo_signature_catalog.pat"
    manifest_path = _catalog_manifest_path(output_path)
    tool_manifest_path = _catalog_tool_manifest_path(output_path)
    force_refresh = os.environ.get("INERTIA_REBUILD_SIGNATURE_CATALOG", "").strip() not in {"", "0", "false", "False"}
    tool_lines = _catalog_tool_lines(root)
    if (
        output_path.exists()
        and manifest_path.exists()
        and _manifest_matches(tool_manifest_path, tool_lines)
        and not force_refresh
    ):
        return output_path
    source_lines = _catalog_source_lines(catalog_root)
    if output_path.exists() and _manifest_matches(manifest_path, source_lines):
        _write_manifest(tool_manifest_path, tool_lines)
        return output_path
    try:
        build_signature_catalog((catalog_root,), output_path, recursive=True, cache_dir=cache_dir)
        _write_manifest(manifest_path, source_lines)
        _write_manifest(tool_manifest_path, tool_lines)
    except Exception:
        return None
    return output_path if output_path.exists() else None
