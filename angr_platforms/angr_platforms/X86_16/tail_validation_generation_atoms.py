"""Normalize mutable validation inputs into exact in-process atoms.

Layer: Tail validation.
Responsibility: build deterministic, cycle-aware atoms for one validation-input
generation request without retaining state across requests.
Dynamic attribute access is limited to the third-party angr/codegen boundary.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum

__all__ = [
    "ValidationGenerationAtom8616",
    "ValidationGenerationAtomBuilder8616",
    "build_validation_generation_atom_8616",
]

type ValidationGenerationAtom8616 = (
    bool
    | int
    | str
    | tuple[ValidationGenerationAtom8616, ...]
    | None
)

_THIRD_PARTY_SEMANTIC_FIELDS_8616 = (
    "addr",
    "args",
    "base",
    "bits",
    "category",
    "ident",
    "label",
    "length",
    "name",
    "offset",
    "pts_to",
    "region",
    "registers",
    "returnty",
    "signed",
    "size",
    "variable",
    "variable_type",
)


def _qualified_type_name_8616(value: object) -> str:
    """Return a stable qualified type label for one generation atom."""
    value_type = type(value)
    return f"{value_type.__module__}.{value_type.__qualname__}"


@dataclass(slots=True)
class ValidationGenerationAtomBuilder8616:
    """Build exact atoms while reusing only proven cycle-free subgraphs."""

    _active: set[int] = field(default_factory=set, init=False)
    _memo: dict[int, tuple[object, ValidationGenerationAtom8616]] = field(
        default_factory=dict,
        init=False,
    )

    def atom(self, value: object) -> ValidationGenerationAtom8616:
        """Normalize one value within this request-local shared-object graph."""
        atom, _ = self._atom_with_cacheability(value)
        return atom

    def dynamic_field_atom(
        self,
        owner: object,
        field_name: str,
    ) -> ValidationGenerationAtom8616:
        """Read one dynamic angr/codegen field and normalize its value."""
        atom, _ = self._dynamic_field_atom_with_cacheability(owner, field_name)
        return atom

    def _dynamic_field_atom_with_cacheability(
        self,
        owner: object,
        field_name: str,
    ) -> tuple[ValidationGenerationAtom8616, bool]:
        """Return one field atom and whether it is independent of ancestry."""
        try:
            value = getattr(owner, field_name)
        except AttributeError:
            return ("missing", field_name), True
        return self._atom_with_cacheability(value)

    def _atom_with_cacheability(
        self,
        value: object,
    ) -> tuple[ValidationGenerationAtom8616, bool]:
        """Return an atom plus proof that no ancestor cycle shaped it."""
        if value is None or isinstance(value, bool | int | str):
            return value, True
        if isinstance(value, Enum):
            enum_value, cacheable = self._atom_with_cacheability(value.value)
            return (
                "enum",
                _qualified_type_name_8616(value),
                enum_value,
            ), cacheable

        identity = id(value)
        cached = self._memo.get(identity)
        if cached is not None and cached[0] is value:
            return cached[1], True
        if identity in self._active:
            return ("cycle", _qualified_type_name_8616(value), identity), False

        self._active.add(identity)
        try:
            atom, cacheable = self._uncached_atom(value)
        finally:
            self._active.remove(identity)
        if cacheable:
            self._memo[identity] = (value, atom)
        return atom, cacheable

    def _dataclass_atom(
        self,
        value: object,
    ) -> tuple[ValidationGenerationAtom8616, bool]:
        """Normalize one dataclass instance field-by-field."""
        field_atoms: list[ValidationGenerationAtom8616] = []
        cacheable = True
        for dataclass_field in fields(value):
            field_atom, field_cacheable = (
                self._dynamic_field_atom_with_cacheability(
                    value,
                    dataclass_field.name,
                )
            )
            field_atoms.append((dataclass_field.name, field_atom))
            cacheable = cacheable and field_cacheable
        return (
            "dataclass",
            _qualified_type_name_8616(value),
            tuple(field_atoms),
        ), cacheable

    def _mapping_atom(
        self,
        value: Mapping[object, object],
    ) -> tuple[ValidationGenerationAtom8616, bool]:
        """Normalize one mapping with order-independent item atoms."""
        mapping_items: list[ValidationGenerationAtom8616] = []
        cacheable = True
        for key, item in value.items():
            key_atom, key_cacheable = self._atom_with_cacheability(key)
            item_atom, item_cacheable = self._atom_with_cacheability(item)
            mapping_items.append((key_atom, item_atom))
            cacheable = cacheable and key_cacheable and item_cacheable
        return (
            "mapping",
            _qualified_type_name_8616(value),
            tuple(sorted(mapping_items, key=repr)),
        ), cacheable

    def _set_atom(
        self,
        value: Set[object],
    ) -> tuple[ValidationGenerationAtom8616, bool]:
        """Normalize one set with order-independent item atoms."""
        set_items: list[ValidationGenerationAtom8616] = []
        cacheable = True
        for item in value:
            item_atom, item_cacheable = self._atom_with_cacheability(item)
            set_items.append(item_atom)
            cacheable = cacheable and item_cacheable
        return (
            "set",
            _qualified_type_name_8616(value),
            tuple(sorted(set_items, key=repr)),
        ), cacheable

    def _sequence_atom(
        self,
        value: Sequence[object],
    ) -> tuple[ValidationGenerationAtom8616, bool]:
        """Normalize one ordered sequence item-by-item."""
        sequence_items: list[ValidationGenerationAtom8616] = []
        cacheable = True
        for item in value:
            item_atom, item_cacheable = self._atom_with_cacheability(item)
            sequence_items.append(item_atom)
            cacheable = cacheable and item_cacheable
        return (
            "sequence",
            _qualified_type_name_8616(value),
            tuple(sequence_items),
        ), cacheable

    def _uncached_atom(
        self,
        value: object,
    ) -> tuple[ValidationGenerationAtom8616, bool]:
        """Normalize one non-active, non-memoized compound value."""
        if is_dataclass(value) and not isinstance(value, type):
            return self._dataclass_atom(value)
        if isinstance(value, Mapping):
            return self._mapping_atom(value)
        if isinstance(value, Set) and not isinstance(value, str | bytes | bytearray):
            return self._set_atom(value)
        if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
            return self._sequence_atom(value)

        semantic_fields: list[ValidationGenerationAtom8616] = []
        cacheable = True
        for field_name in _THIRD_PARTY_SEMANTIC_FIELDS_8616:
            try:
                field_value = getattr(value, field_name)
            except (AttributeError, TypeError, ValueError):
                continue
            field_atom, field_cacheable = self._atom_with_cacheability(field_value)
            semantic_fields.append((field_name, field_atom))
            cacheable = cacheable and field_cacheable
        if semantic_fields:
            return (
                "surface",
                _qualified_type_name_8616(value),
                tuple(semantic_fields),
            ), cacheable
        return ("opaque", _qualified_type_name_8616(value), id(value)), True


def build_validation_generation_atom_8616(
    value: object,
) -> ValidationGenerationAtom8616:
    """Build one exact atom with request-local cycle-safe memoization."""
    return ValidationGenerationAtomBuilder8616().atom(value)
