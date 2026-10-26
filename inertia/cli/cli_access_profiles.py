"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import cast

type NamingCandidate = tuple[int, int, int]


@dataclass(frozen=True)
class AccessTraitStrideEvidence:
    """Evidence that a storage access follows a stable base/index/stride pattern."""

    segment: str
    base_key: tuple[object, ...] | None
    index_key: tuple[object, ...] | None
    stride: int
    offset: int
    width: int
    count: int
    kind: str


@dataclass(frozen=True)
class AccessTraitInductionVar:
    """Induction-variable candidate derived from stable access evidence."""

    base_key: tuple[object, ...] | None
    index_key: tuple[object, ...] | None
    stride: int
    width: int
    offset: int
    count: int


@dataclass(frozen=True)
class InductionSummary:
    """Normalized induction summary for array-like or loop-carried access."""

    base_key: tuple[object, ...] | None
    index_key: tuple[object, ...] | None
    stride: int
    direction: str
    bound_candidate: int | None
    width: int
    offset: int
    count: int


@dataclass(frozen=True)
class AccessTraitEvidenceProfile:
    """Grouped access evidence used to choose safe cleanup naming hints."""

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
        """Return deduplicated candidate offsets ordered by evidence strength."""
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
        """Return whether this profile contains any accepted access evidence."""
        return bool(
            self.member_like
            or self.array_like
            or self.induction_like
            or self.stack_like
            or self.induction_evidence
            or self.stride_evidence
        )

    def best_rewrite_kind(self, base_key: tuple[object, ...] | None = None) -> str | None:
        """Return the safest rewrite category implied by this profile."""
        if base_key is not None and base_key and base_key[0] == "stack" and self.stack_like:
            return "stack"
        dominant_kind = self._dominant_structured_kind()
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

    def _dominant_structured_kind(self) -> str | None:
        """Return the dominant structured-evidence kind, or None."""
        structured_counts: dict[str, int] = {}
        for evidence in self.induction_evidence + self.stride_evidence:
            structured_counts[evidence.kind] = structured_counts.get(evidence.kind, 0) + max(int(evidence.count), 1)
        if not structured_counts:
            return None
        return max(
            structured_counts.items(),
            key=lambda item: (
                item[1],
                {"induction_like": 3, "array_like": 2, "member_like": 1}.get(item[0], 0),
                item[0],
            ),
        )[0]


def infer_induction_variable(profile: AccessTraitEvidenceProfile) -> AccessTraitInductionVar | None:
    """Return the induction variable candidate for a stable induction profile."""
    summary = infer_induction_summary(profile)
    if summary is None:
        return None
    return AccessTraitInductionVar(
        base_key=summary.base_key,
        index_key=summary.index_key,
        stride=summary.stride,
        width=summary.width,
        offset=summary.offset,
        count=summary.count,
    )


def infer_induction_summary(profile: AccessTraitEvidenceProfile) -> InductionSummary | None:
    """Return a normalized induction summary when evidence has one stable shape."""

    def _impl() -> InductionSummary | None:
        candidates = tuple(
            evidence
            for evidence in profile.induction_evidence + profile.stride_evidence
            if evidence.kind == "induction_like"
        )
        if not candidates:
            return None

        stride_set = {int(evidence.stride) for evidence in candidates}
        index_keys = {evidence.index_key for evidence in candidates}
        base_keys = {evidence.base_key for evidence in candidates}
        widths = {int(evidence.width) for evidence in candidates}
        if len(stride_set) != 1 or len(index_keys) != 1 or len(base_keys) != 1 or len(widths) != 1:
            return None

        best = max(
            candidates, key=lambda evidence: (int(evidence.count), int(evidence.width), -abs(int(evidence.offset)))
        )
        if int(best.count) < 2:
            return None
        return InductionSummary(
            base_key=best.base_key,
            index_key=best.index_key,
            stride=int(best.stride),
            direction="decrement" if int(best.stride) < 0 else "increment",
            bound_candidate=int(best.offset) if int(best.offset) != 0 else None,
            width=int(best.width),
            offset=int(best.offset),
            count=int(best.count),
        )

    return _impl()


@dataclass(frozen=True)
class AccessTraitRewriteDecision:
    """Decision helper for naming access-trait-backed storage objects."""

    base_key: tuple[object, ...]
    profile: AccessTraitEvidenceProfile

    def should_rename_stack(self) -> bool:
        """Return whether stack naming can follow this profile."""
        return self.profile.best_rewrite_kind(self.base_key) in {"member", "array", "stack"}

    def preferred_kind(self) -> str | None:
        """Return the preferred rewrite category for this base key."""
        return self.profile.best_rewrite_kind(self.base_key)

    def candidate_field_names(self, access_trait_field_name: Callable[[int, int], str]) -> tuple[str, ...]:
        """Return stable field-name candidates for this decision."""
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
    """Return an evidence profile, falling back from stack-region keys when needed."""
    profile = evidence_profiles.get(base_key)
    if profile is not None:
        return profile
    if len(base_key) == 4 and base_key[0] == "stack":
        return evidence_profiles.get(base_key[:3])
    return None


def _raw_profile_entry_8616(
    raw_profiles: dict[tuple[object, ...], dict[str, list[object]]],
    group_key: tuple[object, ...],
) -> dict[str, list[object]]:
    """Return the mutable raw-profile bucket set for one base key."""
    return raw_profiles.setdefault(
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


def _decoded_bucket_candidate_8616(
    key: object,
    count: object,
    base_index: int,
    offset_index: int,
    size_index: int | None,
) -> tuple[tuple[object, ...], int, int] | None:
    """Decode one raw bucket key into (base_key, offset, size), or None."""
    if not isinstance(key, tuple) or len(key) <= max(base_index, offset_index):
        return None
    base_key = key[base_index]
    if not isinstance(base_key, tuple):
        return None
    offset = key[offset_index]
    if not isinstance(offset, int):
        return None
    size = 1
    if size_index is not None and len(key) > size_index:
        raw_size = key[size_index]
        if isinstance(raw_size, int):
            size = raw_size
    if size not in {1, 2}:
        return None
    if not isinstance(count, int):
        return None
    return base_key, offset, size


def _add_access_trait_bucket_8616(
    raw_profiles: dict[tuple[object, ...], dict[str, list[object]]],
    traits: dict[str, dict[tuple[object, ...], object]],
    bucket_name: str,
    category: str,
    base_index: int,
    offset_index: int,
    size_index: int | None = None,
) -> None:
    """Fold one keyed trait bucket into the per-base raw profile lists."""
    bucket = traits.get(bucket_name, {})
    if not isinstance(bucket, dict):
        return
    for key, count in bucket.items():
        decoded = _decoded_bucket_candidate_8616(key, count, base_index, offset_index, size_index)
        if decoded is None:
            continue
        base_key, offset, size = decoded
        profile = _raw_profile_entry_8616(raw_profiles, base_key)
        cast(list[NamingCandidate], profile[category]).append((offset, size, count))
        if category in {"member_like", "stack_like"} and base_key[0] == "stack":
            cast(list[NamingCandidate], profile["stack_like"]).append((offset, size, count))


def _add_access_trait_structured_bucket_8616(
    raw_profiles: dict[tuple[object, ...], dict[str, list[object]]],
    traits: dict[str, dict[tuple[object, ...], object]],
    bucket_name: str,
    profile_bucket: str,
    category: str | None = None,
) -> None:
    """Fold one structured-evidence trait bucket into the raw profile lists."""
    bucket = traits.get(bucket_name, {})
    if not isinstance(bucket, dict):
        return
    for evidence in bucket.values():
        if not isinstance(evidence, AccessTraitStrideEvidence):
            continue
        group_key = evidence.index_key
        if not isinstance(group_key, tuple):
            continue
        profile = _raw_profile_entry_8616(raw_profiles, group_key)
        bucket_category = category or evidence.kind
        cast(list[NamingCandidate], profile[bucket_category]).append(
            (evidence.offset, evidence.width, evidence.count)
        )
        cast(list[AccessTraitStrideEvidence], profile[profile_bucket]).append(evidence)


def build_access_trait_evidence_profiles(
    traits: dict[str, dict[tuple[object, ...], object]],
) -> dict[tuple[object, ...], AccessTraitEvidenceProfile]:
    """Group raw access trait buckets into typed evidence profiles."""
    raw_profiles: dict[tuple[object, ...], dict[str, list[object]]] = {}

    _add_access_trait_bucket_8616(raw_profiles, traits, "member_evidence", "member_like", 0, 1, 2)
    _add_access_trait_bucket_8616(raw_profiles, traits, "repeated_offset_widths", "member_like", 1, 2, 3)
    _add_access_trait_bucket_8616(raw_profiles, traits, "repeated_offsets", "member_like", 1, 2, None)
    _add_access_trait_bucket_8616(raw_profiles, traits, "base_const", "member_like", 1, 2, 3)
    _add_access_trait_bucket_8616(raw_profiles, traits, "array_evidence", "array_like", 0, 3, 4)
    _add_access_trait_bucket_8616(raw_profiles, traits, "base_stride_widths", "array_like", 1, 3, 4)
    _add_access_trait_bucket_8616(raw_profiles, traits, "base_stride", "array_like", 1, 3, 4)
    _add_access_trait_structured_bucket_8616(raw_profiles, traits, "induction_evidence", "induction_evidence", "induction_like")
    _add_access_trait_structured_bucket_8616(raw_profiles, traits, "stride_evidence", "stride_evidence")

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
    traits: dict[str, dict[tuple[object, ...], object]],
) -> dict[tuple[object, ...], list[NamingCandidate]]:
    """Return member-name candidates for all bases with accepted evidence."""
    profiles = build_access_trait_evidence_profiles(traits)
    return {
        base_key: list(profile.naming_candidates(base_key))
        for base_key, profile in profiles.items()
        if profile.has_any_evidence()
    }
