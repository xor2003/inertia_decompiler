"""Resolve local FLAIR signature paths used by optional library classification.

Layer: Tooling/optional evidence.
Responsibility: resolve optional FLAIR tool paths without owning decompiler semantics.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]


def default_flair_startup_root() -> Path:
    """Return the repository-local default FLAIR startup root."""
    return _REPO_ROOT / "flair_startup"


def resolve_flair_root(flair_root: Path | None = None) -> Path:
    """Return the active FLAIR root directory.

    Hardcoded tool-paths are avoided.  The default is the repository-local
    ``flair_startup`` directory, with an explicit environment override via
    ``INERTIA_FLAIR_ROOT`` when needed.
    """
    if flair_root is not None:
        return flair_root
    env_root = os.environ.get("INERTIA_FLAIR_ROOT", "").strip()
    if env_root:
        return Path(env_root)
    return default_flair_startup_root()


def flair_signature_root(flair_root: Path | None = None) -> Path:
    """Backward-compatible alias used by callers expecting a named helper."""
    return resolve_flair_root(flair_root)


def copy_flair_patterns_to_local(
    source_root: Path,
    *,
    local_root: Path | None = None,
) -> tuple[Path, ...]:
    """Copy startup PAT assets from an external Flair root to local cache.

    Existing destination files are preserved by identity.
    """
    source = Path(source_root)
    target = local_root or default_flair_startup_root()
    copied: list[Path] = []

    if not source.exists():
        return tuple(copied)

    startup_source = source / "startup"
    startup_target = target / "startup"
    if startup_source.exists():
        startup_target.mkdir(parents=True, exist_ok=True)
        for source_pat in sorted(startup_source.rglob("*.pat")):
            rel = source_pat.relative_to(startup_source)
            destination = startup_target / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                shutil.copy2(source_pat, destination)
                copied.append(destination)

    for subdir in ("bin",):
        source_dir = source / subdir
        if source_dir.exists() and source_dir.is_dir():
            for source_entry in sorted(source_dir.rglob("*")):
                if source_entry.is_dir():
                    continue
                relative = source_entry.relative_to(source)
                destination = target / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                if not destination.exists():
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source_entry, destination)
                    copied.append(destination)

    return tuple(copied)
