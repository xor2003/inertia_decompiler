"""Bounded process-local reuse for exact cache-input file digests.

Layer: CLI/fallback/reporting.
Responsibility: avoid rereading unchanged cache inputs while preserving SHA-256
content identity and refusing files that mutate during hashing.

Filesystem metadata is used only to admit a process-local memo hit. Persisted
cache keys continue to contain the content digest, never metadata alone.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import BinaryIO

_CACHE_FILE_DIGEST_MEMO_SIZE_8616: int = 128
_CACHE_FILE_DIGEST_READ_ATTEMPTS_8616: int = 3


@dataclass(frozen=True, slots=True)
class CacheFileStatIdentity8616:
    """Mutation-sensitive identity used only for process-local memo admission."""

    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, stat: os.stat_result) -> CacheFileStatIdentity8616:
        """Capture fields that change when file content or identity changes."""
        return cls(
            device=stat.st_dev,
            inode=stat.st_ino,
            size=stat.st_size,
            mtime_ns=stat.st_mtime_ns,
            ctime_ns=stat.st_ctime_ns,
        )


@dataclass(frozen=True, slots=True)
class CacheFileDigest8616:
    """Exact content digest paired with the stable file state that produced it."""

    resolved_path: Path
    stat_identity: CacheFileStatIdentity8616
    sha256: str


class CacheFileChangedDuringDigest8616(OSError):
    """Raised when no stable file generation can be hashed within the retry bound."""


def _stream_sha256_8616(stream: BinaryIO) -> str:
    """Hash one already-open binary stream without retaining its contents."""
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


@lru_cache(maxsize=_CACHE_FILE_DIGEST_MEMO_SIZE_8616)
def _sha256_for_stat_identity_8616(
    resolved_path: Path,
    expected: CacheFileStatIdentity8616,
) -> str:
    """Hash one file generation, refusing a mutation while the stream is open."""
    with resolved_path.open("rb") as stream:
        opened_before = CacheFileStatIdentity8616.from_stat(os.fstat(stream.fileno()))
        if opened_before != expected:
            raise CacheFileChangedDuringDigest8616(str(resolved_path))
        sha256 = _stream_sha256_8616(stream)
        opened_after = CacheFileStatIdentity8616.from_stat(os.fstat(stream.fileno()))
    if opened_after != expected:
        raise CacheFileChangedDuringDigest8616(str(resolved_path))
    return sha256


def cache_file_digest_8616(path: Path) -> CacheFileDigest8616:
    """Return an exact stable digest, retrying bounded concurrent mutations."""
    resolved_path = path.resolve()
    for _attempt in range(_CACHE_FILE_DIGEST_READ_ATTEMPTS_8616):
        before = CacheFileStatIdentity8616.from_stat(resolved_path.stat())
        try:
            sha256 = _sha256_for_stat_identity_8616(resolved_path, before)
        except CacheFileChangedDuringDigest8616:
            continue
        after = CacheFileStatIdentity8616.from_stat(resolved_path.stat())
        if before == after:
            return CacheFileDigest8616(
                resolved_path=resolved_path,
                stat_identity=before,
                sha256=sha256,
            )
    raise CacheFileChangedDuringDigest8616(str(resolved_path))


def clear_cache_file_digest_memo_8616() -> None:
    """Clear process-local digest reuse for tests and explicit lifecycle resets."""
    _sha256_for_stat_identity_8616.cache_clear()


def cache_file_fingerprint_8616(path: Path | None) -> dict[str, object] | None:
    """Return path-qualified exact content identity for one cache input."""
    if path is None:
        return None
    try:
        digest = cache_file_digest_8616(path)
    except OSError:
        return None
    return {
        "path": str(digest.resolved_path),
        "size": digest.stat_identity.size,
        "mtime_ns": digest.stat_identity.mtime_ns,
        "sha256": digest.sha256,
    }


def cache_content_fingerprint_8616(path: Path | None) -> dict[str, object] | None:
    """Return path-independent exact content identity for one cache input."""
    fingerprint = cache_file_fingerprint_8616(path)
    if fingerprint is None:
        return None
    return {key: fingerprint[key] for key in ("size", "sha256")}

