# cython: language_level=3, infer_types=True
"""Lower stable object and array accesses from typed address evidence.

Layer: Types/Lowering.
Responsibility: consumes alias, widening, and typed facts to remove segment-scale
carriers and materialize object-shaped accesses.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Callable, MutableMapping
from dataclasses import dataclass
from typing import Any

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimRegisterVariable
import dataclasses
import operator
import builtins

ClassifySegmentedDereference = typing.TypeAliasType("ClassifySegmentedDereference", Callable[[object, object], object | None])
FlattenCAddTerms = typing.TypeAliasType("FlattenCAddTerms", Callable[[object], list[object]])
UnwrapCCasts = typing.TypeAliasType("UnwrapCCasts", Callable[[object], object])
CConstantValue = typing.TypeAliasType("CConstantValue", Callable[[object], int | None])
SegmentRegName = typing.TypeAliasType("SegmentRegName", Callable[[object, object], str | None])
ProjectRewriteCache = typing.TypeAliasType("ProjectRewriteCache", Callable[[object], MutableMapping[str, MutableMapping[int, object]]])


@cython.ccall
def _dynamic_attr_8616(obj: object, name: object, default: object = None) -> Any:  # noqa: ANN401
    """Dynamic angr/codegen boundary: read optional third-party C-AST metadata."""
    return getattr(obj, name, default)


@cython.ccall
def _is_segment_scale_term_8616(
    term: object,
    project: object,
    *,
    unwrap_c_casts: UnwrapCCasts,
    c_constant_value: CConstantValue,
    segment_reg_name: SegmentRegName,
) -> cython.bint:
    """True when a C term is ``segment * 16`` or ``segment << 4`` scaling."""
    expected: object
    maybe_scale: object
    maybe_seg: object
    if not isinstance(term, structured_c.CBinaryOp):
        return False
    expected = 16 if term.op == "Mul" else 4 if term.op == "Shl" else None
    if expected is None:
        return False
    for maybe_seg, maybe_scale in ((term.lhs, term.rhs), (term.rhs, term.lhs)):
        if operator.ne(c_constant_value(unwrap_c_casts(maybe_scale)), expected):
            continue
        if segment_reg_name(unwrap_c_casts(maybe_seg), project) is not None:
            return True
    return False


def _match_segment_register_based_dereference(
    node: object,
    project: object,
    *,
    classify_segmented_dereference: ClassifySegmentedDereference,
    flatten_c_add_terms: FlattenCAddTerms,
    unwrap_c_casts: UnwrapCCasts,
    c_constant_value: CConstantValue,
    segment_reg_name: SegmentRegName,
) -> object:
    """Match a DS/ES dereference that can be lowered to an object base."""

    def _impl() -> object:
        base_term: object
        classified: object
        classified = classify_segmented_dereference(node, project)
        if (
            classified is None
            or _dynamic_attr_8616(classified, "addr_expr", None) is None
            or _dynamic_attr_8616(classified, "seg_name", None) not in {"ds", "es"}
            or _dynamic_attr_8616(classified, "kind", None) == "unknown"
        ):
            return None
        allows_object_rewrite = _dynamic_attr_8616(classified, "allows_object_rewrite", None)
        if not callable(allows_object_rewrite) or not allows_object_rewrite():
            return None

        addr_expr = _dynamic_attr_8616(classified, "addr_expr", None)
        base_term = _single_register_base_term_8616(
            addr_expr,
            project,
            flatten_c_add_terms=flatten_c_add_terms,
            unwrap_c_casts=unwrap_c_casts,
            c_constant_value=c_constant_value,
            segment_reg_name=segment_reg_name,
        )
        if base_term is None:
            return None
        return classified, base_term

    return _impl()


@cython.ccall
def _strip_segment_scale_from_addr_expr(
    addr_expr: object,
    project: object,
    *,
    flatten_c_add_terms: FlattenCAddTerms,
    unwrap_c_casts: UnwrapCCasts,
    c_constant_value: CConstantValue,
    segment_reg_name: SegmentRegName,
) -> object | None:
    """Return an address expression with DS/ES segment scaling removed."""
    term: object
    kept_terms = [
        term
        for term in builtins.iter(flatten_c_add_terms(addr_expr))
        if not _is_segment_scale_term_8616(
            unwrap_c_casts(term),
            project,
            unwrap_c_casts=unwrap_c_casts,
            c_constant_value=c_constant_value,
            segment_reg_name=segment_reg_name,
        )
    ]
    if not kept_terms:
        return None
    result = kept_terms[0]
    for term in kept_terms[1:]:
        result = structured_c.CBinaryOp("Add", result, term, codegen=_dynamic_attr_8616(term, "codegen", None))
    return result


@cython.ccall
def _single_register_base_term_8616(
    addr_expr: object,
    project: object,
    *,
    flatten_c_add_terms: FlattenCAddTerms,
    unwrap_c_casts: UnwrapCCasts,
    c_constant_value: CConstantValue,
    segment_reg_name: SegmentRegName,
) -> object | None:
    """Return the single register base term when the address has exactly one."""
    term: object
    base_terms: list[object] = []
    for term in flatten_c_add_terms(addr_expr):
        inner = unwrap_c_casts(term)
        if _is_segment_scale_term_8616(
            inner,
            project,
            unwrap_c_casts=unwrap_c_casts,
            c_constant_value=c_constant_value,
            segment_reg_name=segment_reg_name,
        ):
            continue
        if c_constant_value(inner) is not None:
            continue
        if isinstance(inner, structured_c.CVariable) and isinstance(
            _dynamic_attr_8616(inner, "variable", None), SimRegisterVariable
        ):
            base_terms.append(inner)
            continue
        return None
    if len(base_terms) != 1:
        return None
    return base_terms[0]


@cython.ccall
def _match_ss_stack_reference(
    node: object,
    project: object,
    *,
    project_rewrite_cache: ProjectRewriteCache,
    classify_segmented_dereference: ClassifySegmentedDereference,
) -> object | None:
    """Return a cached stack reference tuple when a classified SS access is proven."""
    classified: object
    cache = project_rewrite_cache(project).setdefault("ss_stack_reference", {})
    key = id(node)
    if key in cache:
        return cache[key]

    classified = classify_segmented_dereference(node, project)
    if (
        classified is not None
        and _dynamic_attr_8616(classified, "kind", None) == "stack"
        and _dynamic_attr_8616(classified, "stack_var", None) is not None
        and _dynamic_attr_8616(classified, "cvar", None) is not None
    ):
        result = (
            _dynamic_attr_8616(classified, "stack_var", None),
            _dynamic_attr_8616(classified, "cvar", None),
            _dynamic_attr_8616(classified, "extra_offset", None),
        )
        cache[key] = result
        return result

    cache[key] = None
    return None


BaseKey = typing.TypeAliasType("BaseKey", tuple[object, ...])
NamingCandidate = typing.TypeAliasType("NamingCandidate", tuple[int, int, int])
TraitCache = typing.TypeAliasType("TraitCache", dict[str, dict[BaseKey, object]])
BuildAccessTraitEvidenceProfiles = typing.TypeAliasType("BuildAccessTraitEvidenceProfiles", Callable[[TraitCache], dict[BaseKey, Any]])
AccessTraitFieldName = typing.TypeAliasType("AccessTraitFieldName", Callable[[int, int], str])


@dataclasses.dataclass(frozen=True)
class AccessTraitObjectHint:
    """Stable object-shape naming hint derived from typed access traits."""

    base_key: BaseKey
    kind: object
    candidates: object

    def should_rename_stack(self) -> cython.bint:
        """Return whether this hint is strong enough to rename stack objects."""
        return self.kind in {"member", "array", "stack"}

    def candidate_field_names(self, *, access_trait_field_name: AccessTraitFieldName) -> tuple[str, ...]:
        """Return deterministic field names for all unique candidate offsets."""
        _count: object
        _size: object
        offset: object
        names: list[str] = []
        seen: set[str] = set()
        for offset, _size, _count in self.candidates:
            field_name = access_trait_field_name(offset, 1)
            if field_name in seen:
                continue
            seen.add(field_name)
            names.append(field_name)
        return tuple(names)


def _stable_hint_kind(profile: object, base_key: BaseKey) -> object:
    """Return the single stable object-hint kind proven by an access profile."""

    def _impl() -> object:
        structured_kinds = _structured_hint_kinds_8616(profile)
        if structured_kinds:
            return next(iter(structured_kinds)) if len(structured_kinds) == 1 else None
        if (
            base_key
            and base_key[0] == "stack"
            and _dynamic_attr_8616(profile, "stack_like", ())
            and not _dynamic_attr_8616(profile, "array_like", ())
            and not _dynamic_attr_8616(profile, "induction_like", ())
        ):
            return "stack"
        return _simple_hint_kind_8616(profile, base_key)

    return _impl()


@cython.ccall
def _structured_hint_kinds_8616(profile: object) -> object:
    """Map structured induction/stride evidence to object-hint kinds."""
    evidence: object
    structured_kinds: set[str] = set()
    induction_evidence = _dynamic_attr_8616(profile, "induction_evidence", ())
    stride_evidence = _dynamic_attr_8616(profile, "stride_evidence", ())
    for evidence in tuple(induction_evidence) + tuple(stride_evidence):
        kind = _dynamic_attr_8616(evidence, "kind", None)
        if kind == "member_like":
            structured_kinds.add("member")
        elif kind == "array_like":
            structured_kinds.add("array")
        elif kind == "induction_like":
            structured_kinds.add("induction")
    return structured_kinds


@cython.ccall
def _simple_hint_kind_8616(profile: object, base_key: BaseKey) -> object:
    """Resolve the single simple hint kind, or the stack fallback."""
    simple_kinds: set[str] = set()
    if _dynamic_attr_8616(profile, "member_like", ()):
        simple_kinds.add("member")
    if _dynamic_attr_8616(profile, "array_like", ()):
        simple_kinds.add("array")
    if _dynamic_attr_8616(profile, "induction_like", ()):
        simple_kinds.add("induction")
    if len(simple_kinds) == 1:
        return next(iter(simple_kinds))
    if simple_kinds:
        return None
    if base_key and base_key[0] == "stack" and _dynamic_attr_8616(profile, "stack_like", ()):
        return "stack"
    return None


@cython.ccall
def _build_stable_access_object_hints(
    traits: TraitCache,
    *,
    build_access_trait_evidence_profiles: BuildAccessTraitEvidenceProfiles,
) -> object:
    kind: object
    base_key: object
    profile: object
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


@cython.ccall
def _stable_access_object_hint_for_key(
    hints: object,
    base_key: object,
) -> AccessTraitObjectHint | None:
    hint: object
    if base_key is None:
        return None
    hint = hints.get(base_key)
    if hint is not None:
        return hint
    if len(base_key) == 4 and base_key[0] == "stack":
        return hints.get(base_key[:3])
    return None


@cython.ccall
def _has_stable_access_object_hints(
    codegen: object,
    *,
    build_access_trait_evidence_profiles: BuildAccessTraitEvidenceProfiles,
) -> cython.bint:
    """Return whether codegen has any stable access-object hints available."""
    cfunc: object
    project: object
    traits: object
    cfunc = _dynamic_attr_8616(codegen, "cfunc", None)
    if cfunc is None:
        return False
    project = _dynamic_attr_8616(codegen, "project", None)
    if project is None:
        return False
    cache = _dynamic_attr_8616(project, "_inertia_access_traits", None)
    if not isinstance(cache, dict):
        return False
    traits = cache.get(_dynamic_attr_8616(cfunc, "addr", None))
    if not isinstance(traits, dict):
        return False
    return bool(
        _build_stable_access_object_hints(
            traits,
            build_access_trait_evidence_profiles=build_access_trait_evidence_profiles,
        )
    )
