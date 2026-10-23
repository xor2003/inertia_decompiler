"""Normalize mutable validation inputs into exact in-process atoms.

Layer: Tail validation.
Responsibility: build deterministic, cycle-aware atoms and compare their exact
values without expanding shared paths or retaining state across requests.
Dynamic attribute access is limited to the third-party angr/codegen boundary.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence, Set
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum, EnumType
from itertools import pairwise
from types import GetSetDescriptorType
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


_SCALAR_LEAF_TYPES_8616 = (bool, int, str)
_CONTEXT_REFERENCE_LIMIT_8616: int = 4096


def _qualified_type_name_8616(value_type: type[object]) -> str:
    """Return a stable qualified type label for one exact type."""
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


def _standard_enum_repr_8616(value: object) -> bool:
    """Recognize native scalar enum repr without executing an attribute hook.

    Enum's standard repr reads its class, name, and value. Require plain
    instance fields, ordinary class lookup, and the exact builtin value repr;
    descriptors or user formatting keep the original repr-sort path.
    """
    value_type = type(value)
    if type(value_type) is not EnumType:
        return False
    methods: dict[str, object] = {}
    for base in value_type.__mro__:
        namespace = vars(base)
        if any(name in namespace for name in ("_name_", "_value_", "__class__")) and base is not object:
            return False
        if "__dict__" in namespace and type(namespace["__dict__"]) is not GetSetDescriptorType:
            return False
        for key in ("__repr__", "__getattribute__", "_value_repr_"):
            if key not in methods and key in namespace:
                methods[key] = namespace[key]
    if methods.get("__repr__") is not Enum.__repr__ or methods.get("__getattribute__") is not object.__getattribute__:
        return False
    fields = object.__getattribute__(value, "__dict__")
    name, scalar = fields.get("_name_"), fields.get("_value_")
    scalar_type = type(scalar)
    if type(name) is not str or (scalar_type is not str and scalar_type is not int):
        return False
    return methods.get("_value_repr_") is scalar_type.__repr__


def _pure_mapping_atoms_8616(items: list[ValidationGenerationAtom8616]) -> bool:
    """Require pure builtin repr without expanding repeated tuple descendants."""
    pending = list(items)
    seen: set[int] = set()
    while pending:
        item = pending.pop()
        item_type = type(item)
        if item is None or item_type is bool or item_type is int or item_type is str:
            continue
        if _standard_enum_repr_8616(item):
            continue
        if item_type is not tuple:
            return False
        if id(item) not in seen:
            seen.add(id(item))
            pending.extend(cast("tuple[ValidationGenerationAtom8616, ...]", item))
    return True


def _ordered_mapping_atoms_8616(
    items: list[ValidationGenerationAtom8616],
) -> tuple[ValidationGenerationAtom8616, ...]:
    """Sort by exact disjoint repr prefixes, retaining native fallback otherwise.

    A mapping pair begins with its key repr and a comma delimiter. Distinct,
    non-overlapping prefixes decide order without rendering potentially huge
    shared value DAGs. Custom scalar repr keeps its original call order/count.
    """
    if len(items) <= 1 or not _pure_mapping_atoms_8616(items):
        return _ordered_item_atoms_8616(items)
    prefixes: list[tuple[str, ValidationGenerationAtom8616]] = []
    for item in items:
        if type(item) is not tuple or len(item) != 2:
            return _ordered_item_atoms_8616(items)
        prefixes.append(("(" + repr(item[0]) + ", ", item))
    prefixes.sort(key=lambda pair: pair[0])
    if any(right[0].startswith(left[0]) for left, right in pairwise(prefixes)):
        return _ordered_item_atoms_8616(items)
    return tuple(item for _prefix, item in prefixes)


@dataclass(slots=True)
class ValidationGenerationAtomBuilder8616:
    """Build exact atoms with bounded reuse of ancestry-dependent subgraphs.

    Exact builtin containers dispatch by identity so arbitrary metaclass
    ``__hash__``/``__eq__`` is never invoked, and bound-method locals only
    cut attribute lookups: no state is retained across generation requests,
    so mutations between builds are still observed exactly as before.
    """

    _active: dict[int, object] = field(default_factory=dict, init=False)
    _context_memo: dict[
        int,
        dict[frozenset[int], tuple[object, ValidationGenerationAtom8616, tuple[object, ...]]],
    ] = field(default_factory=dict, init=False)
    _context_references: int = field(default=0, init=False)
    _memo: dict[int, tuple[object, ValidationGenerationAtom8616]] = field(
        default_factory=dict,
        init=False,
    )

    def atom(self, value: object) -> ValidationGenerationAtom8616:
        """Normalize one value within this request-local shared-object graph."""
        self._begin_root()
        atom, _ = self._atom_with_cacheability(value)
        return atom

    def dynamic_field_atom(
        self,
        owner: object,
        field_name: str,
    ) -> ValidationGenerationAtom8616:
        """Read one dynamic angr/codegen field and normalize its value."""
        self._begin_root()
        atom, _ = self._dynamic_field_atom_with_cacheability(owner, field_name)
        return atom

    def _begin_root(self) -> None:
        """Discard cyclic snapshots between roots, where inputs can mutate."""
        if not self._active:
            self._context_memo.clear()
            self._context_references = 0

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
        if value is None:
            return value, True
        value_type = type(value)
        # Exact scalar types first; the isinstance fallback keeps subclass
        # leaves (including IntEnum) on the identical leaf branch as before.
        if value_type is bool or value_type is int or value_type is str:
            return cast("ValidationGenerationAtom8616", value), True
        if isinstance(value, _SCALAR_LEAF_TYPES_8616):
            return value, True
        if isinstance(value, Enum):
            enum_value, cacheable = self._atom_with_cacheability(value.value)
            return (
                "enum",
                _qualified_type_name_8616(value_type),
                enum_value,
            ), cacheable

        identity = id(value)
        cached = self._memo.get(identity)
        if cached is not None and cached[0] is value:
            return cached[1], True
        if identity in self._active:
            return ("cycle", _qualified_type_name_8616(value_type), identity), False

        contexts = self._context_memo.get(identity)
        if contexts is not None:
            context_atom = contexts.get(frozenset(self._active))
            if context_atom is not None and context_atom[0] is value:
                return context_atom[1], False

        self._active[identity] = value
        try:
            atom, cacheable = self._uncached_atom(value)
        finally:
            del self._active[identity]
        if cacheable:
            self._memo[identity] = (value, atom)
        else:
            self._remember_context_atom(value, atom)
        return atom, cacheable

    def _remember_context_atom(
        self, value: object, atom: ValidationGenerationAtom8616,
    ) -> None:
        """Reuse cycles only under identical ancestors within a fixed memory cap.

        Existing path-sensitive cycle markers depend on the active identity set.
        Retain those ancestors to prevent identity reuse within a root walk.
        Charge both the root and every ancestor against the cap. Discard a
        saturated batch before admitting newer contexts, so early cold graphs
        cannot disable all sharing for the remainder of the current root.
        Eviction only causes recomputation; it never broadens a reuse key.
        """
        references = len(self._active) + 1
        if references > _CONTEXT_REFERENCE_LIMIT_8616:
            return
        if self._context_references + references > _CONTEXT_REFERENCE_LIMIT_8616:
            self._context_memo.clear()
            self._context_references = 0
        self._context_memo.setdefault(id(value), {})[frozenset(self._active)] = (
            value, atom, tuple(self._active.values()),
        )
        self._context_references += references

    def _dataclass_atom(
        self,
        value: object,
    ) -> tuple[ValidationGenerationAtom8616, bool]:
        """Normalize one dataclass instance field-by-field."""
        field_atoms: list[ValidationGenerationAtom8616] = []
        cacheable = True
        atom_with_cacheability = self._atom_with_cacheability
        dataclass_value: DataclassInstance = cast("DataclassInstance", value)
        for dataclass_field in fields(dataclass_value):
            field_name = dataclass_field.name
            try:
                field_value = getattr(value, field_name)
            except AttributeError:
                field_atoms.append((field_name, ("missing", field_name)))
                continue
            field_atom, field_cacheable = atom_with_cacheability(field_value)
            field_atoms.append((field_name, field_atom))
            cacheable = cacheable and field_cacheable
        return (
            "dataclass",
            _qualified_type_name_8616(type(value)),
            tuple(field_atoms),
        ), cacheable

    def _mapping_atom(
        self,
        value: Mapping[object, object],
    ) -> tuple[ValidationGenerationAtom8616, bool]:
        """Normalize one mapping with order-independent item atoms."""
        mapping_items: list[ValidationGenerationAtom8616] = []
        cacheable = True
        atom_with_cacheability = self._atom_with_cacheability
        for key, item in value.items():
            key_atom, key_cacheable = atom_with_cacheability(key)
            item_atom, item_cacheable = atom_with_cacheability(item)
            mapping_items.append((key_atom, item_atom))
            cacheable = cacheable and key_cacheable and item_cacheable
        return (
            "mapping",
            _qualified_type_name_8616(type(value)),
            _ordered_mapping_atoms_8616(mapping_items),
        ), cacheable

    def _set_atom(
        self,
        value: Set[object],
    ) -> tuple[ValidationGenerationAtom8616, bool]:
        """Normalize one set with order-independent item atoms."""
        set_items: list[ValidationGenerationAtom8616] = []
        cacheable = True
        atom_with_cacheability = self._atom_with_cacheability
        for item in value:
            item_atom, item_cacheable = atom_with_cacheability(item)
            set_items.append(item_atom)
            cacheable = cacheable and item_cacheable
        return (
            "set",
            _qualified_type_name_8616(type(value)),
            _ordered_item_atoms_8616(set_items),
        ), cacheable

    def _sequence_atom(
        self,
        value: Sequence[object],
    ) -> tuple[ValidationGenerationAtom8616, bool]:
        """Normalize one ordered sequence item-by-item."""
        sequence_items: list[ValidationGenerationAtom8616] = []
        cacheable = True
        atom_with_cacheability = self._atom_with_cacheability
        for item in value:
            item_atom, item_cacheable = atom_with_cacheability(item)
            sequence_items.append(item_atom)
            cacheable = cacheable and item_cacheable
        return (
            "sequence",
            _qualified_type_name_8616(type(value)),
            tuple(sequence_items),
        ), cacheable

    def _uncached_atom(
        self,
        value: object,
    ) -> tuple[ValidationGenerationAtom8616, bool]:
        """Normalize one non-active, non-memoized compound value."""
        value_type = type(value)
        # Exact builtin containers are never dataclass instances, so identity
        # dispatch reproduces the general branch order below without adding
        # a frame per nesting level and without invoking arbitrary metaclass
        # __hash__/__eq__ on the value's class.
        container_atom = _EXACT_CONTAINER_ATOMS_8616.get(id(value_type))
        if container_atom is not None:
            return container_atom(self, value)
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
        atom_with_cacheability = self._atom_with_cacheability
        for field_name in _THIRD_PARTY_SEMANTIC_FIELDS_8616:
            try:
                field_value = getattr(value, field_name)
            except (AttributeError, TypeError, ValueError):
                continue
            field_atom, field_cacheable = atom_with_cacheability(field_value)
            semantic_fields.append((field_name, field_atom))
            cacheable = cacheable and field_cacheable
        if semantic_fields:
            return (
                "surface",
                _qualified_type_name_8616(value_type),
                tuple(semantic_fields),
            ), cacheable
        return ("opaque", _qualified_type_name_8616(value_type), id(value)), True


_ContainerAtomMethod8616 = Callable[
    [ValidationGenerationAtomBuilder8616, object],
    tuple[ValidationGenerationAtom8616, bool],
]


# Strongly retain the builtin container types so their ids are stable and
# can never be reused by another class for the table's whole lifetime.
_EXACT_CONTAINER_TYPES_8616 = (dict, list, tuple, set, frozenset)

# Exact builtin containers are never dataclass instances, so they reach the
# same branch as the general isinstance order inside ``_uncached_atom``.
# The table is keyed by ``id`` of the strongly retained builtin types, so
# lookup hashes an int and never invokes arbitrary metaclass
# ``__hash__``/``__eq__`` on the value's class; an unhashable or
# equality-poisoned class misses the table and falls through to the same
# isinstance order as before. The single cast records that the table only
# ever pairs a builtin with its matching container handler.
_EXACT_CONTAINER_ATOMS_8616 = cast(
    "dict[int, _ContainerAtomMethod8616]",
    {
        id(dict): ValidationGenerationAtomBuilder8616._mapping_atom,
        id(list): ValidationGenerationAtomBuilder8616._sequence_atom,
        id(tuple): ValidationGenerationAtomBuilder8616._sequence_atom,
        id(set): ValidationGenerationAtomBuilder8616._set_atom,
        id(frozenset): ValidationGenerationAtomBuilder8616._set_atom,
    },
)


def build_validation_generation_atom_8616(
    value: object,
) -> ValidationGenerationAtom8616:
    """Build one exact atom with request-local cycle-safe memoization."""
    return ValidationGenerationAtomBuilder8616().atom(value)


class _PureAtomComparison8616(Enum):
    """Known pure result, or a request to preserve native user-method dispatch."""

    EQUAL = "equal"
    DIFFERENT = "different"
    NATIVE_REQUIRED = "native_required"


def _queue_tuple_comparisons_8616(
    pending: list[tuple[ValidationGenerationAtom8616, ValidationGenerationAtom8616] | None],
    left: tuple[ValidationGenerationAtom8616, ...],
    right: tuple[ValidationGenerationAtom8616, ...],
) -> None:
    """Schedule common-prefix comparisons before checking unequal lengths.

    None is a work-item marker for unequal lengths, never an atom pair.
    A custom equality method in the common prefix must precede this mismatch.
    """
    if len(left) != len(right):
        pending.append(None)
    count = min(len(left), len(right))
    for index in range(count - 1, -1, -1):
        pending.append((left[index], right[index]))


def _compare_pure_generation_atoms_8616(left: ValidationGenerationAtom8616, right: ValidationGenerationAtom8616) -> _PureAtomComparison8616:
    """Compare native-pure prefixes without ever invoking a custom method.

    Exact builtin scalars have side-effect-free equality. Identical contained
    objects need no method call, including enum singletons. Unknown comparison
    requests native fallback before any custom method has executed, preserving
    its order and side effects. Positional work follows native left-to-right
    order; a known mismatch can stop before later custom comparisons.

    Each tuple pair is visited once. Immutable bottom-up atom DAGs cannot
    contain themselves, and both roots pin every descendant throughout this
    call, preventing identity reuse. No comparison state survives the call.
    """
    pending: list[tuple[ValidationGenerationAtom8616, ValidationGenerationAtom8616] | None] = [(left, right)]
    seen: set[tuple[int, int]] = set()
    while pending:
        pair = pending.pop()
        # A length mismatch follows the common prefix in native tuple order.
        if pair is None:
            return _PureAtomComparison8616.DIFFERENT
        left_node, right_node = pair
        if left_node is right_node:
            continue
        left_type, right_type = type(left_node), type(right_node)
        if left_type is tuple and right_type is tuple:
            identity = (id(left_node), id(right_node))
            if identity in seen:
                continue
            seen.add(identity)
            _queue_tuple_comparisons_8616(
                pending,
                cast("tuple[ValidationGenerationAtom8616, ...]", left_node),
                cast("tuple[ValidationGenerationAtom8616, ...]", right_node),
            )
            continue
        left_native = left_node is None or left_type is bool or left_type is int or left_type is str
        right_native = right_node is None or right_type is bool or right_type is int or right_type is str
        if not left_native or not right_native:
            return _PureAtomComparison8616.NATIVE_REQUIRED
        values_equal = left_node == right_node
        if not values_equal:
            return _PureAtomComparison8616.DIFFERENT
    return _PureAtomComparison8616.EQUAL


def validation_generation_atoms_equal_8616(left: ValidationGenerationAtom8616, right: ValidationGenerationAtom8616) -> bool:
    """Keep root protocols and fall back before custom equality has executed."""
    if type(left) is not tuple or type(right) is not tuple:
        return left == right
    result = _compare_pure_generation_atoms_8616(left, right)
    if result is _PureAtomComparison8616.NATIVE_REQUIRED:
        return left == right
    return result is _PureAtomComparison8616.EQUAL
