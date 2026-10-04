"""Layer: dosunit model identity (staging).

Responsibility: capture the native binding fingerprint once within one composite
model-seal calculation. Each independent seal calculation starts a fresh scope;
proof boundaries must never share a retained snapshot. This avoids repeated
source-tree reads in the dependency DAG without a persistent freshness cache.
"""
from __future__ import annotations

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class _NativeModelCapture:
    """One transient fingerprint captured by a single synchronous hash traversal."""

    value: str | None = None


_CURRENT: ContextVar[_NativeModelCapture | None] = ContextVar("native_model_hash_capture", default=None)


@contextmanager
def native_model_hash_snapshot() -> Iterator[None]:
    """Begin a fresh traversal, restoring any parent even on a loud exception.

    Always create a new capture, including for nested scopes. Callers use this
    only around digest construction, never around proof evaluation or the pair
    of before/after checks. Threads and unrelated contexts have no shared cache.
    """
    token = _CURRENT.set(_NativeModelCapture())
    try:
        yield
    finally:
        _CURRENT.reset(token)


def captured_native_model_hash() -> str | None:
    """Return this traversal's captured leaf, or require a fresh computation."""
    snapshot = _CURRENT.get()
    return None if snapshot is None else snapshot.value


def native_model_hash_snapshot_active() -> bool:
    """Whether a surrounding digest traversal already owns a fresh capture.

    Composite hash builders may join that traversal even before its first leaf
    is calculated. Proof evaluation and independent before/after checks must
    remain outside the capture, just as for ``native_model_hash_snapshot``.
    """
    return _CURRENT.get() is not None


def capture_native_model_hash(value: str) -> str:
    """Retain a computed native leaf only in the currently bounded traversal."""
    snapshot = _CURRENT.get()
    if snapshot is not None:
        snapshot.value = value
    return value


def native_model_snapshot_owner_hash() -> str:
    """Bind snapshot behavior as an explicit native-model dependency."""
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
