from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .cli_access_object_hints import AccessTraitObjectHint, BaseKey
from .cli_access_profiles import AccessTraitEvidenceProfile

StableHints = dict[BaseKey, AccessTraitObjectHint]
EvidenceProfiles = dict[BaseKey, AccessTraitEvidenceProfile]

__all__ = [
    "StorageObjectArtifact",
    "StorageObjectRecord",
    "StorageObjectRefusal",
    "build_storage_object_artifact",
    "build_storage_object_records_from_hints",
    "storage_object_record_for_key",
]


@dataclass(frozen=True)
class StorageObjectRecord:
    base_key: BaseKey
    object_kind: str
    candidate_offsets: tuple[int, ...]

    def should_rename_stack(self) -> bool:
        return self.object_kind in {"member", "array", "stack"}

    def primary_member_offset(self) -> int | None:
        if self.object_kind != "member" or not self.candidate_offsets:
            return None
        return self.candidate_offsets[0]


@dataclass(frozen=True)
class StorageObjectRefusal:
    base_key: BaseKey
    reason: str


@dataclass(frozen=True)
class StorageObjectArtifact:
    records: dict[BaseKey, StorageObjectRecord]
    refusals: dict[BaseKey, StorageObjectRefusal]


def _record_from_hint(hint: AccessTraitObjectHint) -> StorageObjectRecord:
    offsets: list[int] = []
    seen: set[int] = set()
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


def build_storage_object_records_from_hints(hints: StableHints) -> dict[BaseKey, StorageObjectRecord]:
    return {base_key: _record_from_hint(hint) for base_key, hint in hints.items()}


def build_storage_object_artifact(
    traits: dict[str, dict[BaseKey, object]],
    *,
    build_access_trait_evidence_profiles: Callable[[dict[str, dict[BaseKey, object]]], EvidenceProfiles],
    build_stable_access_object_hints: Callable[[dict[str, dict[BaseKey, object]]], StableHints],
) -> StorageObjectArtifact:
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


def storage_object_record_for_key(
    records: dict[BaseKey, StorageObjectRecord] | StorageObjectArtifact,
    base_key: BaseKey | None,
) -> StorageObjectRecord | None:
    record_map = records.records if isinstance(records, StorageObjectArtifact) else records
    if base_key is None:
        return None
    record = record_map.get(base_key)
    if record is not None:
        return record
    if len(base_key) == 4 and base_key[0] == "stack":
        return record_map.get(base_key[:3])
    return None
