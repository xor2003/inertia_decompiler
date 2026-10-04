"""Fingerprint source and test inputs used by pytest performance profiles.

Layer: Tooling/gates.
Responsibility: detect source-tree changes during one measured pytest run
without affecting test collection, execution, or outcomes.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

SOURCE_SNAPSHOT_ENV: str = "PYTEST_PROFILE_SOURCE_SNAPSHOT"

_IGNORED_DIRECTORY_NAMES: frozenset[str] = frozenset(
    {
        ".cache",
        ".codebase-memory",
        ".git",
        ".inertia_decomp_cache",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".signature_catalog_cache",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "venv",
    }
)
_SOURCE_SUFFIXES: frozenset[str] = frozenset(
    {".cfg", ".ini", ".json", ".mk", ".py", ".pyi", ".sh", ".toml", ".yaml", ".yml"}
)
_SOURCE_NAMES: frozenset[str] = frozenset({"Makefile"})


@dataclass(frozen=True, slots=True)
class SourceTreeSnapshot:
    """Stable digest and census for one relevant source-tree observation."""

    sha256: str
    file_count: int
    byte_count: int
    unstable_paths: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, object]:
        """Serialize the source snapshot into profile-safe scalar fields."""
        return {
            "sha256": self.sha256,
            "file_count": self.file_count,
            "byte_count": self.byte_count,
            "unstable_paths": list(self.unstable_paths),
        }

    def to_json(self) -> str:
        """Serialize the snapshot for inheritance by pytest workers."""
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, payload: str) -> SourceTreeSnapshot:
        """Parse a controller-created snapshot from a worker environment."""
        raw = json.loads(payload)
        if not isinstance(raw, dict):
            raise ValueError("source snapshot must be a JSON object")
        unstable_paths = raw.get("unstable_paths", [])
        if not isinstance(unstable_paths, list) or not all(isinstance(path, str) for path in unstable_paths):
            raise ValueError("source snapshot unstable_paths must be a string list")
        sha256 = raw.get("sha256")
        file_count = raw.get("file_count")
        byte_count = raw.get("byte_count")
        if not isinstance(sha256, str) or not isinstance(file_count, int) or not isinstance(byte_count, int):
            raise ValueError("source snapshot scalar fields are invalid")
        return cls(
            sha256=sha256,
            file_count=file_count,
            byte_count=byte_count,
            unstable_paths=tuple(unstable_paths),
        )

    def is_stable_with(self, other: SourceTreeSnapshot) -> bool:
        """Return whether both observations prove one unchanged source tree."""
        return not self.unstable_paths and not other.unstable_paths and self == other


def _source_paths(root: Path, included_roots: tuple[str, ...] | None = None) -> tuple[Path, ...]:
    """Return deterministic source paths within the requested relative roots."""
    paths: list[Path] = []
    selected_roots = (root,) if included_roots is None else tuple(root / relative for relative in included_roots)
    for selected_root in selected_roots:
        if selected_root.is_file():
            if selected_root.name in _SOURCE_NAMES or selected_root.suffix.lower() in _SOURCE_SUFFIXES:
                paths.append(selected_root)
            continue
        for directory, directory_names, file_names in os.walk(selected_root):
            directory_names[:] = sorted(name for name in directory_names if name not in _IGNORED_DIRECTORY_NAMES)
            directory_path = Path(directory)
            for file_name in sorted(file_names):
                path = directory_path / file_name
                if file_name in _SOURCE_NAMES or path.suffix.lower() in _SOURCE_SUFFIXES:
                    paths.append(path)
    return tuple(sorted(set(paths), key=lambda path: path.relative_to(root).as_posix()))


def source_tree_snapshot(root: Path, *, included_roots: tuple[str, ...] | None = None) -> SourceTreeSnapshot:
    """Hash selected source content and metadata, refusing torn observations."""
    digest = hashlib.sha256()
    file_count = 0
    byte_count = 0
    unstable_paths: list[str] = []
    for path in _source_paths(root, included_roots):
        relative_path = path.relative_to(root).as_posix()
        try:
            before = path.stat()
            content = path.read_bytes()
            after = path.stat()
        except OSError:
            unstable_paths.append(relative_path)
            continue
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            unstable_paths.append(relative_path)
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(after.st_mtime_ns).encode("ascii"))
        digest.update(b"\0")
        digest.update(content)
        digest.update(b"\0")
        file_count += 1
        byte_count += len(content)
    return SourceTreeSnapshot(
        sha256=digest.hexdigest(),
        file_count=file_count,
        byte_count=byte_count,
        unstable_paths=tuple(unstable_paths),
    )


def profile_artifact_has_stable_source(profile_path: Path) -> bool:
    """Return whether a written profile proves unchanged source inputs."""
    try:
        payload = json.loads(profile_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return False
    if not isinstance(payload, dict):
        return False
    source_state = payload.get("source_state")
    return isinstance(source_state, dict) and source_state.get("stable") is True
