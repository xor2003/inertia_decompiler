"""Bounded cache for immutable exact-byte condition-relift artifacts.

Layer: IR.
Responsibility: reuse exact relift artifacts only when architecture identity
and every exact input byte and request field are unchanged. Callers decide
which typed outcomes are safe to publish without weakening their verdicts.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

__all__ = (
    "ConditionReliftArtifactCache8616",
    "ConditionReliftCacheRequest8616",
)

@dataclass(frozen=True, slots=True)
class ConditionReliftCacheRequest8616:
    """Exact immutable inputs that determine one condition-relift artifact."""

    block_bytes: tuple[tuple[int, int, bytes], ...]
    expected_condition_blocks: frozenset[int]


@runtime_checkable
class _LiftSemanticsKeyBoundary8616(Protocol):
    """Frontend boundary for architectures with stable lift semantics."""

    def lifting_semantics_key_8616(self) -> tuple[object, ...]:
        """Return immutable fields that determine exact-byte lifting."""


def _architecture_semantics_key_8616(
    architecture: object,
) -> tuple[object, ...] | None:
    """Return an owned lift key, retaining identity for unknown boundaries."""
    if not isinstance(architecture, _LiftSemanticsKeyBoundary8616):
        return None
    return architecture.lifting_semantics_key_8616()


@dataclass(frozen=True, slots=True)
class _ConditionReliftCacheEntry8616[ArtifactT]:
    """One architecture-scoped immutable cache entry."""

    architecture: object
    architecture_semantics_key: tuple[object, ...] | None
    request: ConditionReliftCacheRequest8616
    artifact: ArtifactT

    def matches_architecture(self, architecture: object) -> bool:
        """Match owned equivalent architectures or unknown exact identities."""
        candidate_key = _architecture_semantics_key_8616(architecture)
        if self.architecture_semantics_key is not None and candidate_key is not None:
            return self.architecture_semantics_key == candidate_key
        return self.architecture is architecture


class ConditionReliftArtifactCache8616[ArtifactT]:
    """Keep a fixed number of most-recent exact relift artifacts."""

    def __init__(self, *, max_entries: int) -> None:
        """Create a bounded cache with an explicit positive capacity."""
        if max_entries <= 0:
            msg = "condition relift cache capacity must be positive"
            raise ValueError(msg)
        self._max_entries = max_entries
        self._entries: list[_ConditionReliftCacheEntry8616[ArtifactT]] = []
        self._lock = threading.RLock()

    def lookup(self, architecture: object, request: ConditionReliftCacheRequest8616) -> ArtifactT | None:
        """Return and promote an exact lift-semantics cache hit."""
        with self._lock:
            for index, entry in enumerate(self._entries):
                if entry.matches_architecture(architecture) and entry.request == request:
                    if index != len(self._entries) - 1:
                        self._entries.append(self._entries.pop(index))
                    return entry.artifact
        return None

    def publish(
        self,
        architecture: object,
        request: ConditionReliftCacheRequest8616,
        artifact: ArtifactT,
    ) -> None:
        """Publish one caller-approved artifact and evict the oldest excess entry."""
        with self._lock:
            self._entries = [
                entry
                for entry in self._entries
                if not (entry.matches_architecture(architecture) and entry.request == request)
            ]
            self._entries.append(
                _ConditionReliftCacheEntry8616(
                    architecture,
                    _architecture_semantics_key_8616(architecture),
                    request,
                    artifact,
                )
            )
            del self._entries[: max(0, len(self._entries) - self._max_entries)]
