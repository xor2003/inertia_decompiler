from __future__ import annotations

from types import SimpleNamespace

from inertia.lowering.object_lowering import (
    AccessTraitObjectHint,
    BaseKey,
    _build_stable_access_object_hints,
    _has_stable_access_object_hints,
    _stable_access_object_hint_for_key,
    _stable_hint_kind,
)


class _Profile:
    member_like = ()
    array_like = ()
    induction_like = ()
    stack_like = ()
    induction_evidence = ()
    stride_evidence = ()

    def __init__(
        self,
        *,
        member_like: tuple[object, ...] = (),
        array_like: tuple[object, ...] = (),
        stack_like: tuple[object, ...] = (),
        candidates: tuple[tuple[int, int, int], ...] = (),
    ) -> None:
        self.member_like = member_like
        self.array_like = array_like
        self.stack_like = stack_like
        self._candidates = candidates

    def naming_candidates(self, _base_key: tuple[object, ...]) -> tuple[tuple[int, int, int], ...]:
        return self._candidates


def test_stable_hint_kind_prefers_single_simple_kind() -> None:
    profile = _Profile(member_like=(object(),), candidates=((4, 2, 1),))

    assert _stable_hint_kind(profile, ("global", 0x1000)) == "member"


def test_build_stable_access_object_hints_uses_profiles() -> None:
    base_key: BaseKey = ("stack", "bp", -4)
    traits: dict[str, dict[BaseKey, object]] = {"unused": {base_key: object()}}

    def build_profiles(_traits: dict[str, dict[tuple[object, ...], object]]) -> dict[tuple[object, ...], object]:
        return {base_key: _Profile(stack_like=(object(),), candidates=((0, 2, 1), (0, 2, 2)))}

    hints = _build_stable_access_object_hints(traits, build_access_trait_evidence_profiles=build_profiles)

    hint = hints[base_key]
    assert hint.should_rename_stack()
    assert hint.candidate_field_names(access_trait_field_name=lambda offset, _size: f"field_{offset}") == ("field_0",)


def test_stable_access_object_hint_for_stack_region_falls_back_to_base_slot() -> None:
    base_key = ("stack", "bp", -4)
    hint = AccessTraitObjectHint(base_key=base_key, kind="stack", candidates=((0, 2, 1),))

    assert _stable_access_object_hint_for_key({base_key: hint}, ("stack", "bp", -4, 0)) is hint


def test_has_stable_access_object_hints_requires_project_traits() -> None:
    base_key: BaseKey = ("global", 0x2000)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x401000),
        project=SimpleNamespace(_inertia_access_traits={0x401000: {"accesses": {base_key: object()}}}),
    )

    def build_profiles(_traits: dict[str, dict[tuple[object, ...], object]]) -> dict[tuple[object, ...], object]:
        return {base_key: _Profile(member_like=(object(),), candidates=((2, 2, 1),))}

    assert _has_stable_access_object_hints(codegen, build_access_trait_evidence_profiles=build_profiles)
