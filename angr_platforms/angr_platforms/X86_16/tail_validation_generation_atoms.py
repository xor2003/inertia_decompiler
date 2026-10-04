"""Normalize mutable validation inputs into exact in-process atoms.

Layer: Tail validation.
Responsibility: build deterministic, cycle-aware atoms and compare their exact
values without expanding shared paths or retaining state across requests.
Dynamic attribute access is limited to the third-party angr/codegen boundary.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from _typeshed import DataclassInstance

__all__ = [
    "ValidationGenerationAtom8616",
    "ValidationGenerationAtomBuilder8616",
    "build_validation_generation_atom_8616",
    "validation_generation_atoms_equal_8616",
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


def _ordered_item_atoms_8616(
    items: list[ValidationGenerationAtom8616],
) -> tuple[ValidationGenerationAtom8616, ...]:
    """Return item atoms in repr order without repr work for trivial sizes.

    Sorting zero or one item is already order-exact, so expanding shared-DAG
    repr keys is skipped there; two or more items keep the existing repr
    ordering byte-for-byte.
    """
    if len(items) <= 1:
        return tuple(items)
    return tuple(sorted(items, key=repr))


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
        dataclass_value: DataclassInstance = cast("DataclassInstance", value)
        for dataclass_field in fields(dataclass_value):
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
            _ordered_item_atoms_8616(mapping_items),
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
            _ordered_item_atoms_8616(set_items),
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


def _atoms_have_builtin_value_semantics_8616(
    left: ValidationGenerationAtom8616,
    right: ValidationGenerationAtom8616,
) -> bool:
    """Prove plain immutable values before suppressing repeated comparisons.

    The builder can retain int/str subclasses. Their custom equality may have
    observable effects, so isinstance is insufficient proof of pure native
    equality. Inspect each exact tuple once without invoking user methods.
    """
    pending: list[ValidationGenerationAtom8616] = [left, right]
    seen: set[int] = set()
    while pending:
        node = pending.pop()
        node_type = type(node)
        if node_type is tuple:
            identity = id(node)
            if identity in seen:
                continue
            seen.add(identity)
            pending.extend(cast(tuple[ValidationGenerationAtom8616, ...], node))
        else:
            native_scalar = (
                node is None or node_type is bool or node_type is int or node_type is str
            )
            if not native_scalar:
                return False
    return True


def validation_generation_atoms_equal_8616(
    left: ValidationGenerationAtom8616,
    right: ValidationGenerationAtom8616,
) -> bool:
    """Return ``left == right`` while walking each shared tuple pair once.

    Atoms are immutable scalar/tuple DAGs built bottom-up, so a tuple node
    can never contain itself. The worklist and seen identity pairs live only
    for this call: the call frame pins both immutable
    roots for the comparison's whole lifetime, which transitively keeps every
    descendant tuple alive, so a memoized identity pair can never be reused
    by a different node while it is recorded. Each unique shared subtree
    pair is therefore compared once instead of once per root path.

    Value semantics are exactly ``tuple.__eq__``: every scalar and tuple
    position is compared, ``True`` still equals ``1``, and literal cycle
    markers — including their recorded object ids — must match position for
    position. Positional work is scheduled once per unique tuple pair and
    must all pass; a seen pair never substitutes proof of an unexamined
    child. An explicit worklist preserves builder-supported depth without
    adding recursive Python frames. Scalar/tuple subclasses without proven
    native value semantics retain native comparison, including their custom
    methods and exceptions. Nothing persists across calls.
    """
    if not isinstance(left, tuple) or not isinstance(right, tuple):
        return left == right
    if not _atoms_have_builtin_value_semantics_8616(left, right):
        return left == right
    pending: list[tuple[ValidationGenerationAtom8616, ValidationGenerationAtom8616]] = [
        (left, right)
    ]
    seen_pairs: set[tuple[int, int]] = set()
    while pending:
        left_node, right_node = pending.pop()
        # Like tuple equality, identical contained values need no value call.
        if left_node is right_node:
            continue
        if isinstance(left_node, tuple) and isinstance(right_node, tuple):
            if len(left_node) != len(right_node):
                return False
            pair = (id(left_node), id(right_node))
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            # Reverse scheduling keeps value comparisons in positional order.
            pending.extend(zip(reversed(left_node), reversed(right_node), strict=True))
        else:
            # Tuple comparison uses equality, not independently overloaded !=.
            values_equal = left_node == right_node
            if not values_equal:
                return False
    return True
