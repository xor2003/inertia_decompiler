"""Initialized-image admission shared by the two binary comparator tracks.

Layer: dosunit validation proof contracts.
Responsibility: distinguish function equivalence over shared input memory from
equivalence when each executable seeds its own loaded bytes. Different image
hashes leave a memory-relation obligation; they are neither automatic equality
nor automatic behavioral counterexamples. This owner proves only identity of
the mapped initial image, not startup or environmental behavior.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus


class InitialImageReason(StrEnum):
    """The initialized-memory relation discharged or still required."""

    IDENTICAL = "identical_loaded_image"
    MISSING = "loaded_image_identity_missing"
    RELATION_REQUIRED = "initialized_memory_relation_unproved"


@dataclass(frozen=True)
class LoadedStateIdentity:
    """Content and loader coordinates of all mapped initial program bytes."""

    sha256: str
    byte_count: int
    architecture: str
    width: int
    loader: str
    mapped_base: int
    linked_base: int
    entry: int

    @classmethod
    def from_document(cls, value: object) -> LoadedStateIdentity | None:
        """Validate a loader-report boundary; incomplete identities yield no proof."""
        if not isinstance(value, Mapping):
            return None
        text_fields = ("sha256", "architecture", "loader")
        number_fields = ("byte_count", "width", "mapped_base", "linked_base", "entry")
        if any(not isinstance(value.get(name), str) or not value[name] for name in text_fields):
            return None
        if any(type(value.get(name)) is not int or value[name] < 0 for name in number_fields):
            return None
        digest = value["sha256"]
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            return None
        if value["byte_count"] == 0 or value["width"] == 0:
            return None
        return cls(digest, value["byte_count"], value["architecture"], value["width"],
                   value["loader"], value["mapped_base"], value["linked_base"], value["entry"])


@dataclass(frozen=True)
class InitialImageRelation:
    """Separate, typed admission evidence for executable-seeded memory."""

    status: ProofStatus
    reason: InitialImageReason
    counters: FactCounters

    def to_document(self, function_status: ProofStatus) -> dict[str, Any]:
        """Publish initialized-function admission without claiming whole-program proof."""
        initialized_status = function_status
        if function_status is ProofStatus.PROVED and self.status is not ProofStatus.PROVED:
            initialized_status = ProofStatus.UNKNOWN
        return {
            "status": self.status.value,
            "reason": self.reason.value,
            "initialized_function_status": initialized_status.value,
            "scope": "mapped_initial_image_and_requested_function_inputs",
            "startup_and_environment_proved": False,
            "counters": {
                "raw_fact_count": self.counters.raw_fact_count,
                "normalized_fact_count": self.counters.normalized_fact_count,
                "classified_fact_count": self.counters.classified_fact_count,
                "materialized_count": self.counters.materialized_count,
                "failure_count": self.counters.failure_count,
            },
        }


def compare_initial_images(original: object, candidate: object) -> InitialImageRelation:
    """Prove identity only with complete matching content and loader coordinates.

    Code edits can change these hashes without changing execution. To admit
    such an edit, a future relational proof must cover the differing bytes and
    possible code-as-data aliases. A function proof with shared arbitrary
    memory does not discharge that relation.
    """
    left = LoadedStateIdentity.from_document(original)
    right = LoadedStateIdentity.from_document(candidate)
    if left is None or right is None:
        return InitialImageRelation(ProofStatus.UNKNOWN, InitialImageReason.MISSING,
                                    FactCounters(1, 1, 1, 1, 1))
    if left != right:
        return InitialImageRelation(ProofStatus.UNKNOWN, InitialImageReason.RELATION_REQUIRED,
                                    FactCounters(1, 1, 1, 1, 1))
    return InitialImageRelation(ProofStatus.PROVED, InitialImageReason.IDENTICAL,
                                FactCounters(1, 1, 1, 1, 0))
