# cython: language_level=3, infer_types=True
"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
import dataclasses
import builtins

BaseKey = typing.TypeAliasType("BaseKey", tuple[object, ...])
AccessTraitObjectHint = typing.TypeAliasType("AccessTraitObjectHint", Any)
AccessTraitEvidenceProfile = typing.TypeAliasType("AccessTraitEvidenceProfile", Any)

StableHints = typing.TypeAliasType("StableHints", dict[BaseKey, AccessTraitObjectHint])
EvidenceProfiles = typing.TypeAliasType("EvidenceProfiles", dict[BaseKey, AccessTraitEvidenceProfile])

__all__ = [
    "StorageObjectArtifact",
    "StorageObjectRecord",
    "StorageObjectRefusal",
    "build_storage_object_artifact",
    "build_storage_object_records_from_hints",
    "storage_object_record_for_key",
]


@dataclasses.dataclass(frozen=True)
class StorageObjectRecord:
    """Stable storage-object classification derived from access evidence."""

    base_key: BaseKey
    object_kind: object
    candidate_offsets: object

    def is_member_like(self) -> cython.bint:
        """Return whether this record represents a field/member access."""
        return self.object_kind == "member"

    def is_array_like(self) -> cython.bint:
        """Return whether this record represents indexed array-like access."""
        return self.object_kind == "array"

    def is_stack_like(self) -> cython.bint:
        """Return whether this record represents stack-object access."""
        return self.object_kind == "stack"

    def is_structural(self) -> cython.bint:
        """Return whether this record can guide structural cleanup."""
        return self.object_kind in {"member", "array", "stack"}

    def should_rename_stack(self) -> cython.bint:
        """Return whether stack naming may follow this structural record."""
        return self.is_structural()

    def primary_member_offset(self) -> int | None:
        """Return the primary member offset when this is a member-like record."""
        if not self.is_member_like() or not self.candidate_offsets:
            return None
        return self.candidate_offsets[0]


@dataclasses.dataclass(frozen=True)
class StorageObjectRefusal:
    """Reason storage-object evidence was refused for one base key."""

    base_key: BaseKey
    reason: object


@dataclasses.dataclass(frozen=True)
class StorageObjectArtifact:
    """Storage-object records plus explicit refusal reasons."""

    records: object
    refusals: object


@cython.ccall
def _record_from_hint(hint: AccessTraitObjectHint) -> StorageObjectRecord:
    _count: object
    _size: object
    offset: object
    offsets: list[cython.longlong] = []
    seen: set[cython.longlong] = set()
    for offset, _size, _count in hint.candidates:
        if offset in seen:
            continue
        seen.add(offset)
        offsets.append(offset)
    return StorageObjectRecord(
        base_key=hint.base_key,
        object_kind=hint.kind,
        candidate_offsets=tuple(offsets),
    )


@cython.ccall
def build_storage_object_records_from_hints(hints: StableHints) -> dict[BaseKey, StorageObjectRecord]:
    """Build stable storage-object records from accepted access hints."""
    return {base_key: _record_from_hint(hint) for base_key, hint in builtins.iter(hints.items())}


@cython.ccall
def build_storage_object_artifact(
    traits: object,
    *,
    build_access_trait_evidence_profiles: Callable[[dict[str, dict[BaseKey, object]]], EvidenceProfiles],
    build_stable_access_object_hints: Callable[[dict[str, dict[BaseKey, object]]], StableHints],
) -> StorageObjectArtifact:
    """Build storage-object records and refusal reasons from access traits."""
    base_key: object
    profile: object
    profiles = build_access_trait_evidence_profiles(traits)
    hints = build_stable_access_object_hints(traits)
    records = build_storage_object_records_from_hints(hints)
    refusals: dict[BaseKey, StorageObjectRefusal] = {}
    for base_key, profile in profiles.items():
        if not profile.has_any_evidence():
            continue
        if base_key in records:
            continue
        refusals[base_key] = StorageObjectRefusal(
            base_key=base_key,
            reason="mixed_or_unstable_evidence",
        )
    return StorageObjectArtifact(records=records, refusals=refusals)


@cython.ccall
def storage_object_record_for_key(
    records: object,
    base_key: object,
) -> StorageObjectRecord | None:
    """Return a storage-object record for a full or stack-shortened base key."""
    record: object
    record_map = records.records if isinstance(records, StorageObjectArtifact) else records
    if base_key is None:
        return None
    record = record_map.get(base_key)
    if record is not None:
        return record
    if len(base_key) == 4 and base_key[0] == "stack":
        return record_map.get(base_key[:3])
    return None
