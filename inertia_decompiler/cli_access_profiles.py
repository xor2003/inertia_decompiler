from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, cast


NamingCandidate = tuple[int, int, int]


@dataclass(frozen=True)
class AccessTraitStrideEvidence:
    segment: str
    base_key: tuple[object, ...] | None
    index_key: tuple[object, ...] | None
    stride: int
    offset: int
    width: int
    count: int
    kind: str


@dataclass(frozen=True)
class AccessTraitEvidenceProfile:
    member_like: tuple[NamingCandidate, ...] = ()
    array_like: tuple[NamingCandidate, ...] = ()
    induction_like: tuple[NamingCandidate, ...] = ()
    stack_like: tuple[NamingCandidate, ...] = ()
    induction_evidence: tuple[AccessTraitStrideEvidence, ...] = ()
    stride_evidence: tuple[AccessTraitStrideEvidence, ...] = ()

    def _structured_candidates(self) -> tuple[NamingCandidate, ...]:
        candidates: list[NamingCandidate] = []
        seen: set[NamingCandidate] = set()
        for evidence in sorted(
            self.induction_evidence + self.stride_evidence,
            key=lambda item: (-item.count, item.offset, item.width, item.stride, item.kind),
        ):
            candidate = (evidence.offset, evidence.width, evidence.count)
            if candidate in seen:
                continue
            seen.add(candidate)
            candidates.append(candidate)
        return tuple(candidates)

    def naming_candidates(self, base_key: tuple[object, ...] | None = None) -> tuple[NamingCandidate, ...]:
        structured = self._structured_candidates()
        if base_key is not None and base_key and base_key[0] == "stack":
            ordered = self.stack_like + structured + self.member_like + self.array_like + self.induction_like
        else:
            ordered = structured + self.member_like + self.array_like + self.induction_like + self.stack_like

        deduped: list[NamingCandidate] = []
        seen: set[NamingCandidate] = set()
        for candidate in ordered:
            if candidate in seen:
                continue
            seen.add(candidate)
            deduped.append(candidate)
        return tuple(deduped)

    def has_any_evidence(self) -> bool:
        return bool(
            self.member_like
            or self.array_like
            or self.induction_like
            or self.stack_like
            or self.induction_evidence
            or self.stride_evidence
        )

    def best_rewrite_kind(self, base_key: tuple[object, ...] | None = None) -> str | None:
        if base_key is not None and base_key and base_key[0] == "stack" and self.stack_like:
            return "stack"
        structured_counts: dict[str, int] = {}
        for evidence in self.induction_evidence + self.stride_evidence:
            structured_counts[evidence.kind] = structured_counts.get(evidence.kind, 0) + max(int(evidence.count), 1)
        if structured_counts:
            dominant_kind = max(
                structured_counts.items(),
                key=lambda item: (item[1], {"induction_like": 3, "array_like": 2, "member_like": 1}.get(item[0], 0), item[0]),
            )[0]
            if dominant_kind == "induction_like":
                return "induction"
            if dominant_kind == "array_like":
                return "array"
            if dominant_kind == "member_like":
                return "member"
        if self.member_like and self.array_like:
            return None
        if self.array_like:
            return "array"
        if self.member_like:
            return "member"
        if self.induction_like:
            return "induction"
        if self.stack_like:
            return "stack"
        return None


@dataclass(frozen=True)
class AccessTraitRewriteDecision:
    base_key: tuple[object, ...]
    profile: AccessTraitEvidenceProfile

    def should_rename_stack(self) -> bool:
        return self.profile.best_rewrite_kind(self.base_key) in {"member", "array", "stack"}

    def preferred_kind(self) -> str | None:
        return self.profile.best_rewrite_kind(self.base_key)

    def candidate_field_names(self, access_trait_field_name) -> tuple[str, ...]:
        if self.preferred_kind() is None:
            return ()
        candidates = self.profile.naming_candidates(self.base_key)
        if not candidates:
            return ()
        names: list[str] = []
        seen: set[str] = set()
        for offset, _size, _count in candidates:
            field_name = access_trait_field_name(offset, 1)
            if field_name in seen:
                continue
            seen.add(field_name)
            names.append(field_name)
        return tuple(names)


def access_trait_profile_for_key(
    evidence_profiles: Mapping[tuple[object, ...], AccessTraitEvidenceProfile],
    base_key: tuple[object, ...],
) -> AccessTraitEvidenceProfile | None:
    profile = evidence_profiles.get(base_key)
    if profile is not None:
        return profile
    if len(base_key) == 4 and base_key[0] == "stack":
        return evidence_profiles.get(base_key[:3])
    return None


def build_access_trait_evidence_profiles(
    traits: dict[str, dict[tuple[object, ...], object]]
) -> dict[tuple[object, ...], AccessTraitEvidenceProfile]:
    raw_profiles: dict[tuple[object, ...], dict[str, list[object]]] = {}

    def add_bucket(
        bucket_name: str,
        category: str,
        base_index: int,
        offset_index: int,
        size_index: int | None = None,
    ) -> None:
        bucket = traits.get(bucket_name, {})
        if not isinstance(bucket, dict):
            return
        for key, count in bucket.items():
            if not isinstance(key, tuple) or len(key) <= max(base_index, offset_index):
                continue
            base_key = key[base_index]
            if not isinstance(base_key, tuple):
                continue
            offset = key[offset_index]
            if not isinstance(offset, int):
                continue
            size = 1
            if size_index is not None and len(key) > size_index:
                raw_size = key[size_index]
                if isinstance(raw_size, int):
                    size = raw_size
            if size not in {1, 2}:
                continue
            if not isinstance(count, int):
                continue
            profile = raw_profiles.setdefault(
                base_key,
                {
                    "member_like": [],
                    "array_like": [],
                    "induction_like": [],
                    "stack_like": [],
                    "induction_evidence": [],
                    "stride_evidence": [],
                },
            )
            cast(list[NamingCandidate], profile[category]).append((offset, size, count))
            if category in {"member_like", "stack_like"} and base_key[0] == "stack":
                cast(list[NamingCandidate], profile["stack_like"]).append((offset, size, count))

    def add_structured_bucket(bucket_name: str, profile_bucket: str, category: str | None = None) -> None:
        bucket = traits.get(bucket_name, {})
        if not isinstance(bucket, dict):
            return
        for evidence in bucket.values():
            if not isinstance(evidence, AccessTraitStrideEvidence):
                continue
            group_key = evidence.index_key
            if not isinstance(group_key, tuple):
                continue
            profile = raw_profiles.setdefault(
                group_key,
                {
                    "member_like": [],
                    "array_like": [],
                    "induction_like": [],
                    "stack_like": [],
                    "induction_evidence": [],
                    "stride_evidence": [],
                },
            )
            bucket_category = category or evidence.kind
            cast(list[NamingCandidate], profile[bucket_category]).append(
                (evidence.offset, evidence.width, evidence.count)
            )
            cast(list[AccessTraitStrideEvidence], profile[profile_bucket]).append(evidence)

    add_bucket("member_evidence", "member_like", 0, 1, 2)
    add_bucket("repeated_offset_widths", "member_like", 1, 2, 3)
    add_bucket("repeated_offsets", "member_like", 1, 2, None)
    add_bucket("base_const", "member_like", 1, 2, 3)
    add_bucket("array_evidence", "array_like", 0, 3, 4)
    add_bucket("base_stride_widths", "array_like", 1, 3, 4)
    add_bucket("base_stride", "array_like", 1, 3, 4)
    add_structured_bucket("induction_evidence", "induction_evidence", "induction_like")
    add_structured_bucket("stride_evidence", "stride_evidence")

    return {
        base_key: AccessTraitEvidenceProfile(
            member_like=tuple(cast(list[NamingCandidate], data["member_like"])),
            array_like=tuple(cast(list[NamingCandidate], data["array_like"])),
            induction_like=tuple(cast(list[NamingCandidate], data["induction_like"])),
            stack_like=tuple(cast(list[NamingCandidate], data["stack_like"])),
            induction_evidence=tuple(cast(list[AccessTraitStrideEvidence], data["induction_evidence"])),
            stride_evidence=tuple(cast(list[AccessTraitStrideEvidence], data["stride_evidence"])),
        )
        for base_key, data in raw_profiles.items()
    }


def access_trait_member_candidates(
    traits: dict[str, dict[tuple[object, ...], object]]
) -> dict[tuple[object, ...], list[NamingCandidate]]:
    profiles = build_access_trait_evidence_profiles(traits)
    return {
        base_key: list(profile.naming_candidates(base_key))
        for base_key, profile in profiles.items()
        if profile.has_any_evidence()
    }
