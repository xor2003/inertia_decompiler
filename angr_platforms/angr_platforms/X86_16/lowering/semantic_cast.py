"""Render casts whose conversion is part of proven machine semantics.

Layer: Types/Lowering.
Responsibility: distinguish required width/signedness conversions from angr's
optional cosmetic casts so generated C preserves binary value semantics.
Byte conversions use explicit signedness; plain C char is target-dependent,
and native SimTypeChar's unnamed representation loses its signed flag.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeChar, SimTypeInt, SimTypeLong, SimTypeLongLong, SimTypeShort
from angr.sim_variable import SimVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616


class CSemanticCast8616(
    structured_c.CTypeCast,  # type: ignore[misc]  # dynamic angr codegen base
):
    """Structured-C cast that remains visible when cosmetic casts are hidden."""

    def c_repr_chunks(
        self,
        indent: int = 0,
        asexpr: bool = False,
    ) -> Iterator[tuple[str, object]]:
        """Render the required C conversion independently of ``show_casts``."""
        del indent, asexpr
        if self.collapsed:
            yield "...", self
            return
        parenthesis = structured_c.CClosingObject("(")
        yield "(", parenthesis
        destination = self.dst_type
        if isinstance(destination, SimTypeChar) and isinstance(destination.signed, bool):
            type_name = "signed char" if destination.signed else "unsigned char"
        else:
            type_name = destination.c_repr(name=None)
        yield type_name, destination
        yield ")", parenthesis
        wrap_expression = isinstance(self.expr, structured_c.CBinaryOp)
        if wrap_expression:
            yield "(", parenthesis
        yield from structured_c.CExpression._try_c_repr_chunks(self.expr)
        if wrap_expression:
            yield ")", parenthesis


class RequiredAssignmentCastReconcileStatus8616(StrEnum):
    """Typed outcome for evidence-backed assignment-cast reconciliation."""

    NOT_REQUIRED = "not_required"
    ALREADY_PRESENT = "already_present"
    NO_MATCH = "no_match"
    AMBIGUOUS = "ambiguous"
    APPLIED = "applied"


class _DeclarationTypeSurface8616(Protocol):
    """Native C-function declaration inventory consumed without name recovery."""

    arg_list: list[structured_c.CVariable]
    unified_local_vars: dict[SimVariable, set[tuple[structured_c.CVariable, SimType]]]


def _declared_variable_type_8616(expression: structured_c.CVariable) -> SimType | None:
    """Use a unique emitted declaration type for the exact variable identity."""
    try:
        cfunc = cast(_DeclarationTypeSurface8616 | None, expression.codegen.cfunc)
    except AttributeError:
        return expression.variable_type
    if cfunc is None:
        return expression.variable_type
    identity = expression.unified_variable or expression.variable
    try:
        arguments = cfunc.arg_list
        locals_ = cfunc.unified_local_vars
    except AttributeError:
        return expression.variable_type
    argument_types = {
        argument.variable_type
        for argument in arguments
        if isinstance(argument, structured_c.CVariable)
        and (argument.unified_variable or argument.variable) == identity
    }
    entries = locals_.get(identity, ())
    types = argument_types or {type_ for _, type_ in entries}
    return next(iter(types)) if len(types) == 1 else None


def is_identity_semantic_variable_cast_8616(node: CSemanticCast8616) -> bool:
    """Prove a same-width cast is redundant against its current variable type.

    Declaration refinement can leave a cast's source metadata behind. Only
    explicit integer widths and matching current/destination signedness prove
    identity; names, historical source signedness and missing types do not.
    """
    if not isinstance(node.expr, structured_c.CVariable):
        return False
    integer_types = (SimTypeChar, SimTypeShort, SimTypeInt, SimTypeLong, SimTypeLongLong)
    source = node.src_type
    destination = node.dst_type
    current = _declared_variable_type_8616(node.expr)
    if (
        not isinstance(source, integer_types)
        or not isinstance(destination, integer_types)
        or not isinstance(current, integer_types)
    ):
        return False
    try:
        source_size = source.size
        return bool(
            isinstance(source_size, int)
            and source_size > 0
            and source_size == destination.size == current.size
            and isinstance(current.signed, bool)
            and current.signed is destination.signed
        )
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class RequiredAssignmentCastReconcileResult8616:
    """Closed evidence result for one required assignment cast."""

    status: RequiredAssignmentCastReconcileStatus8616
    assignment_count: int
    destination_count: int
    candidate_count: int

    @property
    def changed(self) -> bool:
        """Return whether the required cast was applied."""
        return self.status is RequiredAssignmentCastReconcileStatus8616.APPLIED


def reconcile_required_assignment_cast_8616(
    root: object,
    expected: structured_c.CAssignment,
    *,
    same_destination: Callable[[object, object], bool],
    same_source: Callable[[object, object], bool],
) -> RequiredAssignmentCastReconcileResult8616:
    """Restore one evidence-backed cast onto a unique stale assignment."""
    expected_rhs = expected.rhs
    if not isinstance(expected_rhs, CSemanticCast8616):
        return RequiredAssignmentCastReconcileResult8616(
            RequiredAssignmentCastReconcileStatus8616.NOT_REQUIRED,
            0,
            0,
            0,
        )
    assignments = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, structured_c.CAssignment)
    )
    destinations = tuple(
        node for node in assignments if same_destination(node.lhs, expected.lhs)
    )
    already_present = tuple(
        node
        for node in destinations
        if isinstance(node.rhs, CSemanticCast8616)
        and node.rhs.dst_type == expected_rhs.dst_type
        and same_source(node.rhs.expr, expected_rhs.expr)
    )
    if len(already_present) == 1:
        return RequiredAssignmentCastReconcileResult8616(
            RequiredAssignmentCastReconcileStatus8616.ALREADY_PRESENT,
            len(assignments),
            len(destinations),
            1,
        )
    if len(already_present) > 1:
        return RequiredAssignmentCastReconcileResult8616(
            RequiredAssignmentCastReconcileStatus8616.AMBIGUOUS,
            len(assignments),
            len(destinations),
            len(already_present),
        )
    candidates = tuple(
        node
        for node in destinations
        if not isinstance(node.rhs, CSemanticCast8616)
        and same_source(node.rhs, expected_rhs.expr)
    )
    if not candidates:
        return RequiredAssignmentCastReconcileResult8616(
            RequiredAssignmentCastReconcileStatus8616.NO_MATCH,
            len(assignments),
            len(destinations),
            0,
        )
    if len(candidates) != 1:
        return RequiredAssignmentCastReconcileResult8616(
            RequiredAssignmentCastReconcileStatus8616.AMBIGUOUS,
            len(assignments),
            len(destinations),
            len(candidates),
        )
    candidates[0].rhs = expected_rhs
    return RequiredAssignmentCastReconcileResult8616(
        RequiredAssignmentCastReconcileStatus8616.APPLIED,
        len(assignments),
        len(destinations),
        1,
    )
