# cython: language_level=3, infer_types=True
"""Bind stable stack accesses to named local variable identities.

Layer: Types/Lowering.
Responsibility: owns stack variable binding contracts after alias proof.
Consumes alias, widening, and typed facts to create stack variable bindings
only when SS/BP stack stability has been proven.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from inertia.ir.core import AddressStatus, IRAddress, IRValue, MemSpace, SegmentOrigin
import dataclasses
import operator

__all__ = [
    "STACK_SLOT_BINDING_TAG_8616",
    "StackAnnotationSpec8616",
    "StackBaseBpBiasEvidence8616",
    "StackVariableBinding",
    "build_stack_variable_bindings_8616",
    "select_normalized_stack_argument_annotation_spec_8616",
    "select_stack_annotation_spec_8616",
    "stable_ss_address_to_ir_value_8616",
    "stable_ss_offset_to_ir_address_8616",
    "stable_stack_binding_tags_8616",
    "stack_binding_from_tags_8616",
    "stack_binding_inherits_containing_name_8616",
]

STACK_SLOT_BINDING_TAG_8616: str = "inertia_stack_slot_binding_8616"


@dataclasses.dataclass(frozen=True, )
class StackAnnotationSpec8616:
    """An inert source/debug name and type hint for one proven stack object."""

    name: object
    type_spec: object | None


@dataclasses.dataclass(frozen=True, )
class StackBaseBpBiasEvidence8616:
    """Evidence snapshot for rebasing angr's entry-SP placeholder to BP."""

    statement_root: object
    stack_base_displacements: object
    known_bp_offsets: object
    inferred_bias: int | None

    def matches(
        self,
        statement_root: object,
        stack_base_displacements: object,
        known_bp_offsets: object,
    ) -> cython.bint:
        """Return whether this snapshot still describes the current C/evidence state."""
        return (
            self.statement_root is statement_root
            and operator.eq(self.stack_base_displacements, stack_base_displacements)
            and operator.eq(self.known_bp_offsets, frozenset(known_bp_offsets))
        )


class StackVariableBinding:
    """A stable binding from a stack access to a local variable identity.

    This represents: ``[ss:bp-N]`` → local variable ``v_N``.

    Bindings are only created when the alias model has proven stability:
    - The segment is proven STABLE SS
    - The offset is a constant BP-offset
    - No cross-segment ambiguity exists
    """

    __slots__ = ("bp_offset", "is_stable", "size", "var_name")

    def __init__(self, bp_offset: cython.longlong, size: cython.longlong, *, var_name: object = None, is_stable: cython.bint = True) -> None:
        """Create a proven stack binding for one SS:BP-relative slot."""
        self.bp_offset = bp_offset
        self.size = size
        self.var_name = var_name or f"var_{abs(bp_offset):x}"
        self.is_stable = is_stable

    def __repr__(self) -> str:
        """Return a debugging representation of the stack binding."""
        return (
            "StackVariableBinding("
            f"bp_offset={self.bp_offset}, size={self.size}, "
            f"var_name={self.var_name!r}, stable={self.is_stable})"
        )

    def to_dict(self) -> dict[str, object]:
        """Return a stable diagnostic representation for reports and tests."""
        return {
            "bp_offset": self.bp_offset,
            "size": self.size,
            "var_name": self.var_name,
            "is_stable": self.is_stable,
        }

    def contains_offset(self, bp_offset: cython.longlong) -> cython.bint:
        """Return whether this binding owns the byte at ``bp_offset``."""
        return self.bp_offset <= bp_offset < self.bp_offset + self.size

    def contains_access(self, bp_offset: cython.longlong, size: cython.longlong) -> cython.bint:
        """Return whether a positive-width access is fully inside this binding."""
        return size > 0 and self.size > 0 and self.bp_offset <= bp_offset and bp_offset + size <= self.bp_offset + self.size


@cython.ccall
def stable_stack_binding_tags_8616(binding: StackVariableBinding) -> dict[str, object]:
    """Return C-AST tags carrying one alias-proven stack-slot identity."""
    if not binding.is_stable:
        raise ValueError("exact stack-slot provenance requires a stable binding")
    return {STACK_SLOT_BINDING_TAG_8616: binding}


@cython.ccall
def stack_binding_from_tags_8616(tags: object) -> StackVariableBinding | None:
    """Read exact stack-slot provenance from a dynamic C-AST tag mapping."""
    binding: object
    if not isinstance(tags, Mapping):
        return None
    binding = tags.get(STACK_SLOT_BINDING_TAG_8616)
    return binding if isinstance(binding, StackVariableBinding) and binding.is_stable else None


@cython.ccall
def _coerce_stack_annotation_spec_8616(value: object) -> StackAnnotationSpec8616 | None:
    """Normalize one metadata value without deriving storage semantics from it."""
    name: object
    name_value: object
    type_spec: object
    if isinstance(value, str):
        return StackAnnotationSpec8616(name=value or None, type_spec=None)
    if not isinstance(value, Mapping):
        return None
    name_value = value.get("name")
    name = name_value if isinstance(name_value, str) and name_value else None
    type_spec = value.get("type")
    if name is None and type_spec is None:
        return None
    return StackAnnotationSpec8616(name=name, type_spec=type_spec)


def select_stack_annotation_spec_8616(
    binding: StackVariableBinding,
    *,
    stack_specs: Mapping[object, object],
    candidate_offsets: Iterable[cython.longlong],
    known_bindings: Iterable[StackVariableBinding],
) -> StackAnnotationSpec8616 | None:
    """Select metadata for a proven stack object without renaming interior views.

    Exact storage offsets win. A biased/legacy fallback may name a binding only
    when its candidate offset is not the base of another proven binding that
    contains the current binding's first byte. This keeps metadata inert:
    `[bp-2]` cannot borrow the name of a four-byte object rooted at `[bp-4]`.
    """
    spec: object
    candidate_offset: object
    bindings = tuple(known_bindings)
    seen_offsets: set[cython.longlong] = set()
    for candidate_offset in candidate_offsets:
        if candidate_offset in seen_offsets:
            continue
        seen_offsets.add(candidate_offset)
        if operator.ne(candidate_offset, binding.bp_offset) and any(
            operator.eq(owner.bp_offset, candidate_offset)
            and operator.ne(owner.bp_offset, binding.bp_offset)
            and owner.contains_offset(binding.bp_offset)
            for owner in iter(bindings)
        ):
            continue
        spec = _coerce_stack_annotation_spec_8616(stack_specs.get(candidate_offset))
        if spec is not None:
            return spec
    return None


@cython.ccall
def select_normalized_stack_argument_annotation_spec_8616(
    binding: StackVariableBinding,
    *,
    stack_specs: Mapping[object, object],
    return_address_size: cython.longlong = 2,
) -> StackAnnotationSpec8616 | None:
    """Select one argument label after its normalized coordinate map is proven.

    Normalized metadata omits the near return-address word. Once the caller has
    proven that coordinate contract, one architectural ``BP`` displacement has
    exactly one metadata key; generic containing-object fallback must not run.
    """
    if binding.bp_offset <= return_address_size or return_address_size <= 0:
        return None
    return _coerce_stack_annotation_spec_8616(stack_specs.get(binding.bp_offset - return_address_size))


def stack_binding_inherits_containing_name_8616(
    binding: StackVariableBinding,
    *,
    current_name: object,
    known_bindings: Iterable[StackVariableBinding],
) -> cython.bint:
    """Return whether an interior view copied its containing object's name."""
    if not current_name:
        return False
    return any(
        operator.ne(owner.bp_offset, binding.bp_offset)
        and owner.contains_offset(binding.bp_offset)
        and operator.eq(owner.var_name, current_name)
        for owner in iter(known_bindings)
    )


def build_stack_variable_bindings_8616(
    addresses: object,  # (offset, size) pairs
    *,
    preferred_names: object = None,
) -> object:
    """Build stable local variable bindings from a sorted list of stack offsets.

    Args:
        addresses: Sorted list of (bp_offset, size) pairs (negative offsets for locals)
        preferred_names: Optional mapping of offset → preferred variable name

    Returns:
        Sorted list of StackVariableBinding objects

    Adjacent offsets with matching segment origin are NOT blindly folded;
    binding stability requires alias proof which is the caller's responsibility.
    """
    var_name: object
    offset: object
    size: object
    bindings: list[StackVariableBinding] = []
    for offset, size in addresses:
        var_name = None
        if preferred_names is not None:
            var_name = preferred_names.get(offset)
        binding = StackVariableBinding(offset, size, var_name=var_name)
        bindings.append(binding)
    return sorted(bindings, key=lambda b: b.bp_offset)


@cython.ccall
def stable_ss_address_to_ir_value_8616(offset: cython.longlong, size: cython.longlong) -> IRValue:
    """Convert a stable SS/Bp offset into an IRValue.

    This preserves segment identity and stability status.
    """
    return IRValue(
        space=MemSpace.SS,
        name="bp",
        offset=offset,
        size=size,
    )


@cython.ccall
def stable_ss_offset_to_ir_address_8616(offset: cython.longlong, size: cython.longlong) -> IRAddress:
    """Convert a stable SS/Bp offset into an IRAddress with proven stability."""
    return IRAddress(
        space=MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )
