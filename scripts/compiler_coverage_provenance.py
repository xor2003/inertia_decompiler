"""Fingerprint concrete inputs to the existing compiler round-trip owner.

Layer: Test infrastructure.
Responsibility: retain source and tool identity without treating hashes as
semantic coverage or silently assuming compiler defaults are unchanged.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def input_fingerprint(path: Path) -> dict[str, str | int]:
    """Hash a file or sorted toolchain tree, including relative file names."""
    if not path.exists():
        return {"path": str(path), "error": "missing"}
    if path.is_file():
        with path.open("rb") as stream:
            fingerprint = hashlib.file_digest(stream, "sha256").hexdigest()
        return {"path": str(path.resolve()), "sha256": fingerprint, "files": 1, "bytes": path.stat().st_size}
    files = sorted(item for item in path.rglob("*") if item.is_file())
    digest = hashlib.sha256()
    size = 0
    for item in files:
        relative = str(item.relative_to(path))
        with item.open("rb") as stream:
            content_digest = hashlib.file_digest(stream, "sha256").digest()
        digest.update(relative.encode("utf-8") + b"\0" + content_digest)
        size += item.stat().st_size
    return {"path": str(path.resolve()), "sha256": digest.hexdigest(), "files": len(files), "bytes": size}
