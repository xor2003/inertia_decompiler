from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, TypeAlias


BaseKey: TypeAlias = tuple[object, ...]
NamingCandidate: TypeAlias = tuple[int, int, int]
TraitCache: TypeAlias = dict[str, dict[BaseKey, object]]
BuildAccessTraitEvidenceProfiles: TypeAlias = Callable[[TraitCache], dict[BaseKey, Any]]
AccessTraitFieldName: TypeAlias = Callable[[int, int], str]


@dataclass(frozen=True)
class AccessTraitObjectHint:
    base_key: BaseKey
    kind: str
    candidates: tuple[NamingCandidate, ...]

    def should_rename_stack(self) -> bool:
        return self.kind in {"member", "array", "stack"}

    def candidate_field_names(self, *, access_trait_field_name: AccessTraitFieldName) -> tuple[str, ...]:
        names: list[str] = []
        seen: set[str] = set()
        for offset, _size, _count in self.candidates:
            field_name = access_trait_field_name(offset, 1)
            if field_name in seen:
                continue
            seen.add(field_name)
            names.append(field_name)
        return tuple(names)


def _stable_hint_kind(profile: Any, base_key: BaseKey) -> str | None:
    structured_kinds = set()
    for evidence in getattr(profile, "induction_evidence", ()) + getattr(profile, "stride_evidence", ()):
        kind = getattr(evidence, "kind", None)
        if kind == "member_like":
            structured_kinds.add("member")
        elif kind == "array_like":
            structured_kinds.add("array")
        elif kind == "induction_like":
            structured_kinds.add("induction")
    if structured_kinds:
        return next(iter(structured_kinds)) if len(structured_kinds) == 1 else None
    if (
        base_key
        and base_key[0] == "stack"
        and getattr(profile, "stack_like", ())
        and not getattr(profile, "array_like", ())
        and not getattr(profile, "induction_like", ())
    ):
        return "stack"
    simple_kinds = set()
    if getattr(profile, "member_like", ()):
        simple_kinds.add("member")
    if getattr(profile, "array_like", ()):
        simple_kinds.add("array")
    if getattr(profile, "induction_like", ()):
        simple_kinds.add("induction")
    if len(simple_kinds) == 1:
        return next(iter(simple_kinds))
    if simple_kinds:
        return None
    if base_key and base_key[0] == "stack" and getattr(profile, "stack_like", ()):
        return "stack"
    return None


def _build_stable_access_object_hints(
    traits: TraitCache,
    *,
    build_access_trait_evidence_profiles: BuildAccessTraitEvidenceProfiles,
) -> dict[BaseKey, AccessTraitObjectHint]:
    profiles = build_access_trait_evidence_profiles(traits)
    hints: dict[BaseKey, AccessTraitObjectHint] = {}
    for base_key, profile in profiles.items():
        kind = _stable_hint_kind(profile, base_key)
        if kind is None:
            continue
        candidates = profile.naming_candidates(base_key)
        if not candidates:
            continue
        hints[base_key] = AccessTraitObjectHint(
            base_key=base_key,
            kind=kind,
            candidates=candidates,
        )
    return hints


def _stable_access_object_hint_for_key(
    hints: dict[BaseKey, AccessTraitObjectHint],
    base_key: BaseKey | None,
) -> AccessTraitObjectHint | None:
    if base_key is None:
        return None
    hint = hints.get(base_key)
    if hint is not None:
        return hint
    if len(base_key) == 4 and base_key[0] == "stack":
        return hints.get(base_key[:3])
    return None


def _has_stable_access_object_hints(
    codegen: Any,
    *,
    build_access_trait_evidence_profiles: BuildAccessTraitEvidenceProfiles,
) -> bool:
    cfunc = getattr(codegen, "cfunc", None)
    if cfunc is None:
        return False
    project = getattr(codegen, "project", None)
    if project is None:
        return False
    cache = getattr(project, "_inertia_access_traits", None)
    if not isinstance(cache, dict):
        return False
    traits = cache.get(getattr(cfunc, "addr", None))
    if not isinstance(traits, dict):
        return False
    return bool(
        _build_stable_access_object_hints(
            traits,
            build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        )
    )
