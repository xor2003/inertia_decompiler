"""Register proven C global declarations for 16-bit lowering.

Layer: Types/Lowering.
Responsibility: merge already-proven global storage declarations for emitted C.
Consumes alias, widening, and typed facts; it merges already-proven storage
identity into declarations without creating new storage evidence.
Do not recover semantics from COD, source, assembly, or rendered C text.
Postprocess and CLI may consume declarations, but proof belongs here.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from ..codegen_metadata import (
    GlobalDeclarationArrayExtent8616,
    GlobalDeclarationArrayLength8616,
)
from .segment_register_state import is_runtime_segment_state_symbol_8616


class GlobalDeclarationCodegen8616(Protocol):
    """Dynamic codegen metadata slot used by proven global declaration lowering."""

    _inertia_global_declaration_specs_8616: tuple[
        tuple[str, str, GlobalDeclarationArrayLength8616], ...
    ]
    _inertia_strong_global_declaration_specs_8616: tuple[
        tuple[str, str, GlobalDeclarationArrayLength8616], ...
    ]


class GlobalDeclarationCType8616(Enum):
    """Canonical C declaration type for one proven global storage width."""

    SIGNED_LONG = "long"
    UNSIGNED_CHAR = "unsigned char"
    UNSIGNED_SHORT = "unsigned short"
    UNSIGNED_LONG = "unsigned long"

    @property
    def c_name(self) -> str:
        """Return the C spelling used in emitted declarations."""
        return self.value

    @property
    def width(self) -> int:
        """Return the byte width represented by this declaration type."""
        return _GLOBAL_CTYPE_WIDTHS_8616[self]


@dataclass(frozen=True, slots=True)
class NamedAggregateDeclarationCType8616:
    """Two lifecycle spellings of one proven named aggregate declaration.

    Before angr's function type store is available, a global may need an
    inline definition. Once the same type is registered, declarations must use
    its typedef name so codegen does not emit a duplicate struct definition.
    """

    type_name: str
    inline_definition: str
    registered: bool

    @property
    def c_name(self) -> str:
        """Return the currently valid C spelling for the aggregate."""
        if self.registered:
            return " ".join(self.type_name.split())
        return " ".join(self.inline_definition.split())

    def merge_with_serialized(self, old_ctype: str) -> str | None:
        """Merge an earlier serialized view of this exact aggregate.

        Return ``None`` when the earlier declaration is unrelated, leaving the
        generic declaration precedence rules responsible for that case.
        """
        old_name = " ".join(old_ctype.split())
        type_name = " ".join(self.type_name.split())
        inline_definition = " ".join(self.inline_definition.split())
        if old_name not in {type_name, inline_definition}:
            return None
        if self.registered or old_name == type_name:
            return type_name
        return inline_definition


_GLOBAL_CTYPE_WIDTHS_8616: dict[GlobalDeclarationCType8616, int] = {
    GlobalDeclarationCType8616.SIGNED_LONG: 4,
    GlobalDeclarationCType8616.UNSIGNED_CHAR: 1,
    GlobalDeclarationCType8616.UNSIGNED_SHORT: 2,
    GlobalDeclarationCType8616.UNSIGNED_LONG: 4,
}


def ctype_for_global_width_8616(width: int) -> GlobalDeclarationCType8616:
    """Return the canonical declaration type for a proven global width."""
    if int(width) == 1:
        return GlobalDeclarationCType8616.UNSIGNED_CHAR
    if int(width) == 4:
        return GlobalDeclarationCType8616.UNSIGNED_LONG
    return GlobalDeclarationCType8616.UNSIGNED_SHORT


def initialize_global_declaration_specs_8616(codegen: object) -> None:
    """Initialize the owned declaration metadata contract on an angr codegen."""
    typed_codegen = cast(GlobalDeclarationCodegen8616, codegen)
    try:
        typed_codegen._inertia_global_declaration_specs_8616  # noqa: B018
    except AttributeError:
        typed_codegen._inertia_global_declaration_specs_8616 = ()


def _merge_spec_8616(
    ctype: GlobalDeclarationCType8616 | NamedAggregateDeclarationCType8616 | str,
    ctype_name: str,
    name: str,
    normalized_len: GlobalDeclarationArrayLength8616,
    spec: object,
) -> tuple[tuple[str, str, GlobalDeclarationArrayLength8616], bool]:
    """Return the stored tuple for one prior spec and whether it merged."""
    old_ctype, old_name, old_len = cast(tuple[object, object, object], spec)
    old_ctype_name = " ".join(cast(str, old_ctype).split())
    old_name_s = cast(str, old_name)
    old_array_len = _normalize_global_array_len_8616(old_len)
    if old_name_s != name:
        return (old_ctype_name, old_name_s, old_array_len), False
    aggregate_merge = (
        ctype.merge_with_serialized(old_ctype_name)
        if isinstance(ctype, NamedAggregateDeclarationCType8616)
        else None
    )
    if (
        isinstance(ctype, NamedAggregateDeclarationCType8616)
        and aggregate_merge is None
        and not _ctype_is_struct_8616(old_ctype_name)
        and not _ctype_is_pointer_8616(old_ctype_name)
    ):
        chosen_ctype = ctype_name
    else:
        chosen_ctype = aggregate_merge or _choose_global_ctype_8616(old_ctype_name, ctype_name)
    if _scalar_global_covers_existing_array_8616(
        old_ctype_name,
        old_array_len,
        ctype_name,
        normalized_len,
    ):
        chosen_len = None
    else:
        chosen_len = merge_global_array_extents_8616(old_array_len, normalized_len)
    return (chosen_ctype, name, chosen_len), True


def record_global_declaration_spec_8616(
    codegen: object,
    *,
    ctype: GlobalDeclarationCType8616 | NamedAggregateDeclarationCType8616 | str,
    name: str,
    array_len: GlobalDeclarationArrayLength8616,
) -> None:
    """Record one proven global declaration, merging duplicate storage identities.

    Multiple lowering paths may see the same global through different evidence
    views, e.g. direct `g_work+10` and indexed `g_work[si]`. The emitted C must
    contain one declaration for that semantic global, with the widest proven
    extent.
    """
    if (
        not isinstance(name, str)
        or re.fullmatch(r"[A-Za-z_]\w*", name) is None
        or is_runtime_segment_state_symbol_8616(name)
    ):
        return
    typed_codegen = cast(GlobalDeclarationCodegen8616, codegen)
    initialize_global_declaration_specs_8616(codegen)
    if isinstance(ctype, (GlobalDeclarationCType8616, NamedAggregateDeclarationCType8616)):
        ctype_name = ctype.c_name
    else:
        ctype_name = " ".join(str(ctype).split())
    if not ctype_name:
        return
    normalized_len = _normalize_global_array_len_8616(array_len)
    try:
        raw_specs = typed_codegen._inertia_global_declaration_specs_8616
    except AttributeError:
        raw_specs = ()
    specs = tuple(cast(Iterable[object], raw_specs or ()))
    merged: list[tuple[str, str, GlobalDeclarationArrayLength8616]] = []
    replaced = False
    for spec in specs:
        if not isinstance(spec, (list, tuple)) or len(spec) != 3:
            continue
        old_ctype, old_name, _old_len = spec
        if not isinstance(old_ctype, str) or not isinstance(old_name, str):
            continue
        entry, merged_here = _merge_spec_8616(
            ctype, ctype_name, name, normalized_len, spec
        )
        merged.append(entry)
        replaced = replaced or merged_here
    if not replaced:
        merged.append((ctype_name, name, normalized_len))
    typed_codegen._inertia_global_declaration_specs_8616 = tuple(dict.fromkeys(merged))


def replace_global_declaration_spec_from_stronger_typed_evidence_8616(
    codegen: object,
    *,
    ctype: GlobalDeclarationCType8616 | NamedAggregateDeclarationCType8616 | str,
    name: str,
    array_len: GlobalDeclarationArrayLength8616,
) -> None:
    """Replace one weaker declaration after typed evidence upgrades its identity.

    The caller must already have proven storage identity and type compatibility.
    This function selects by owned storage name only and never infers semantics
    from the serialized C type spelling being replaced.
    """
    if (
        not isinstance(name, str)
        or re.fullmatch(r"[A-Za-z_]\w*", name) is None
        or is_runtime_segment_state_symbol_8616(name)
    ):
        return
    typed_codegen = cast(GlobalDeclarationCodegen8616, codegen)
    initialize_global_declaration_specs_8616(codegen)
    try:
        raw_specs = typed_codegen._inertia_global_declaration_specs_8616
    except AttributeError:
        raw_specs = ()
    retained = tuple(
        (old_ctype, old_name, old_len)
        for old_ctype, old_name, old_len in raw_specs
        if old_name != name
    )
    normalized_len = _normalize_global_array_len_8616(array_len)
    ctype_name = " ".join(ctype.split()) if isinstance(ctype, str) else ctype.c_name
    typed_codegen._inertia_global_declaration_specs_8616 = (
        *retained,
        (ctype_name, name, normalized_len),
    )
    _record_strong_global_declaration_spec_8616(
        typed_codegen,
        ctype=ctype_name,
        name=name,
        array_len=normalized_len,
    )


def _record_strong_global_declaration_spec_8616(
    codegen: GlobalDeclarationCodegen8616,
    *,
    ctype: str,
    name: str,
    array_len: GlobalDeclarationArrayLength8616,
) -> None:
    """Persist one typed replacement across later alias reconciliation."""
    try:
        raw_specs = codegen._inertia_strong_global_declaration_specs_8616
    except AttributeError:
        raw_specs = ()
    retained = tuple(
        (old_ctype, old_name, old_len)
        for old_ctype, old_name, old_len in raw_specs
        if old_name != name
    )
    codegen._inertia_strong_global_declaration_specs_8616 = (
        *retained,
        (ctype, name, array_len),
    )


def reconcile_strong_global_declaration_specs_8616(codegen: object) -> bool:
    """Replay authoritative typed declarations after weaker alias metadata."""
    typed_codegen = cast(GlobalDeclarationCodegen8616, codegen)
    initialize_global_declaration_specs_8616(codegen)
    try:
        raw_specs = typed_codegen._inertia_strong_global_declaration_specs_8616
    except AttributeError:
        return False
    strong_specs = tuple(
        (ctype, name, _normalize_global_array_len_8616(array_len))
        for ctype, name, array_len in raw_specs
        if isinstance(ctype, str)
        and bool(ctype)
        and isinstance(name, str)
        and bool(name)
    )
    before = typed_codegen._inertia_global_declaration_specs_8616
    strong_names = {name for _ctype, name, _array_len in strong_specs}
    retained = tuple(spec for spec in before if spec[1] not in strong_names)
    typed_codegen._inertia_global_declaration_specs_8616 = tuple(
        dict.fromkeys((*retained, *strong_specs))
    )
    return before != typed_codegen._inertia_global_declaration_specs_8616


def record_scalar_global_declaration_spec_8616(
    codegen: object,
    *,
    ctype: GlobalDeclarationCType8616 | str,
    name: str,
) -> None:
    """Record a proven scalar global and discard an equal-width one-element view.

    A direct scalar load used as a value is stronger shape evidence than an
    earlier compatibility declaration inferred from one addressed element.
    Wider arrays and differently sized declarations remain untouched because
    they may represent distinct aggregate evidence.
    """
    typed_codegen = cast(GlobalDeclarationCodegen8616, codegen)
    initialize_global_declaration_specs_8616(codegen)
    ctype_name = ctype.c_name if isinstance(ctype, GlobalDeclarationCType8616) else " ".join(str(ctype).split())
    try:
        specs = tuple(cast(Iterable[object], typed_codegen._inertia_global_declaration_specs_8616 or ()))
    except AttributeError:
        specs = ()
    filtered: list[tuple[str, str, GlobalDeclarationArrayLength8616]] = []
    for spec in specs:
        if not isinstance(spec, (list, tuple)) or len(spec) != 3:
            continue
        old_ctype, old_name, old_len = spec
        if not isinstance(old_ctype, str) or not isinstance(old_name, str):
            continue
        old_ctype_name = " ".join(old_ctype.split())
        old_array_len = _normalize_global_array_len_8616(old_len)
        if (
            old_name == name
            and old_array_len == 1
            and _ctype_width_8616(old_ctype_name) == _ctype_width_8616(ctype_name)
        ):
            continue
        filtered.append((old_ctype_name, old_name, old_array_len))
    typed_codegen._inertia_global_declaration_specs_8616 = tuple(filtered)
    record_global_declaration_spec_8616(codegen, ctype=ctype, name=name, array_len=None)


def _normalize_global_array_len_8616(value: object) -> GlobalDeclarationArrayLength8616:
    """Normalize one owned array extent without inventing a numeric bound."""
    if value is GlobalDeclarationArrayExtent8616.UNKNOWN:
        return value
    return int(value) if isinstance(value, int) and value > 0 else None


def merge_global_array_extents_8616(
    left: GlobalDeclarationArrayLength8616,
    right: GlobalDeclarationArrayLength8616,
) -> GlobalDeclarationArrayLength8616:
    """Choose the widest proven array extent for one merged global name."""
    if isinstance(left, int) and isinstance(right, int):
        return max(left, right)
    if isinstance(left, int):
        return left
    if isinstance(right, int):
        return right
    if left is GlobalDeclarationArrayExtent8616.UNKNOWN or right is GlobalDeclarationArrayExtent8616.UNKNOWN:
        return GlobalDeclarationArrayExtent8616.UNKNOWN
    if left is None:
        return right
    return left


def _scalar_global_covers_existing_array_8616(
    left_ctype: str,
    left_len: GlobalDeclarationArrayLength8616,
    right_ctype: str,
    right_len: GlobalDeclarationArrayLength8616,
) -> bool:
    """Return whether a scalar declaration exactly covers an existing array."""
    left_width = _ctype_width_8616(left_ctype)
    right_width = _ctype_width_8616(right_ctype)
    if left_len is None and left_width >= 4:
        return _array_byte_extent_8616(right_ctype, right_len) == left_width
    if right_len is None and right_width >= 4:
        return _array_byte_extent_8616(left_ctype, left_len) == right_width
    return False


def _array_byte_extent_8616(
    ctype: str,
    array_len: GlobalDeclarationArrayLength8616,
) -> int | None:
    """Return the byte extent for a declared array, when it is array-shaped."""
    if not isinstance(array_len, int):
        return None
    return _ctype_width_8616(ctype) * array_len


def _choose_global_ctype_8616(left: str, right: str) -> str:
    """Choose the declaration type preserving the most structured proven view."""
    if _ctype_is_pointer_8616(right) and not _ctype_is_pointer_8616(left):
        return right
    if _ctype_is_pointer_8616(left) and not _ctype_is_pointer_8616(right):
        return left
    if _ctype_is_struct_8616(right) and not _ctype_is_struct_8616(left):
        return right
    if _ctype_is_struct_8616(left) and not _ctype_is_struct_8616(right):
        return left
    left_width = _ctype_width_8616(left)
    right_width = _ctype_width_8616(right)
    if right_width > left_width:
        return right
    return left


def _ctype_is_struct_8616(ctype: str) -> bool:
    """Return whether a declaration type names a proven object/field aggregate."""
    return " ".join(ctype.split()).startswith("struct ")


def _ctype_is_pointer_8616(ctype: str) -> bool:
    """Return whether a declaration type is pointer-shaped C syntax."""
    return "*" in " ".join(ctype.split())


def _ctype_width_8616(ctype: str) -> int:
    """Return the storage width represented by a scalar or known aggregate type."""
    ctype = " ".join(ctype.split())
    if ctype in {"unsigned char", "signed char", "char", "uint8_t", "int8_t"}:
        return 1
    if ctype in {"unsigned long", "long", "uint32_t", "int32_t"}:
        return 4
    return 2
