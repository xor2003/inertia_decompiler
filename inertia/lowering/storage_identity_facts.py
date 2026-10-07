"""Retain typed segmented-global storage identities for final validation.

Layer: Types/Lowering.
Responsibility: record binary-proven segmented global storage identities after
their owning lowering pass materializes them in the structured C AST.
Consumes alias, widening, and typed facts, including instruction facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Do not validate final output or mutate postprocess output.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from inertia.ir.core import MemSpace

__all__ = [
    "GlobalStorageIdentityFact8616",
    "StorageIdentityEvidenceKind8616",
    "global_storage_identity_facts_8616",
    "record_global_storage_identity_fact_8616",
]


class StorageIdentityEvidenceKind8616(StrEnum):
    """Owning lowering proof that established one global storage identity."""

    DIRECT_GLOBAL_UPDATE = "direct-global-update"


@dataclass(frozen=True, slots=True)
class GlobalStorageIdentityFact8616:
    """One segmented global object identity retained after materialization."""

    space: MemSpace
    offset: int
    width: int
    name: str
    evidence_addr: int
    kind: StorageIdentityEvidenceKind8616

    def __post_init__(self) -> None:
        """Reject malformed owned facts before they reach final validation."""
        if self.space not in {MemSpace.DS, MemSpace.ES}:
            raise ValueError(
                "global storage identity requires DS or ES address space"
            )
        if not 0 <= self.offset <= 0xFFFF:
            raise ValueError("global storage identity offset must fit 16 bits")
        if self.width <= 0:
            raise ValueError("global storage identity width must be positive")
        if not self.name:
            raise ValueError("global storage identity name must be nonempty")
        if self.evidence_addr < 0:
            raise ValueError("global storage identity evidence address must be nonnegative")


class _StorageIdentityFactCarrier8616(Protocol):
    """Third-party codegen field used to retain owned storage facts."""

    _inertia_global_storage_identity_facts_8616: tuple[
        GlobalStorageIdentityFact8616, ...
    ]


def _fact_sort_key_8616(
    fact: GlobalStorageIdentityFact8616,
) -> tuple[str, int, int, str, int, str]:
    """Return deterministic storage-fact ordering independent of pass order."""
    return (
        fact.space.value,
        fact.offset,
        fact.width,
        fact.name,
        fact.evidence_addr,
        fact.kind.value,
    )


def global_storage_identity_facts_8616(
    codegen: object,
) -> tuple[GlobalStorageIdentityFact8616, ...]:
    """Read validated storage facts from the dynamic third-party codegen boundary."""
    carrier = cast(_StorageIdentityFactCarrier8616, codegen)
    try:
        facts = carrier._inertia_global_storage_identity_facts_8616
    except AttributeError:
        return ()
    if not isinstance(facts, tuple) or not all(
        isinstance(fact, GlobalStorageIdentityFact8616) for fact in facts
    ):
        raise TypeError(
            "_inertia_global_storage_identity_facts_8616 must be a tuple "
            "of GlobalStorageIdentityFact8616"
        )
    return facts


def record_global_storage_identity_fact_8616(
    codegen: object,
    fact: GlobalStorageIdentityFact8616,
) -> bool:
    """Record one typed global identity and return whether the fact was new."""
    if not isinstance(fact, GlobalStorageIdentityFact8616):
        raise TypeError("fact must be GlobalStorageIdentityFact8616")
    existing = global_storage_identity_facts_8616(codegen)
    if fact in existing:
        return False
    carrier = cast(_StorageIdentityFactCarrier8616, codegen)
    carrier._inertia_global_storage_identity_facts_8616 = tuple(
        sorted((*existing, fact), key=_fact_sort_key_8616)
    )
    return True
