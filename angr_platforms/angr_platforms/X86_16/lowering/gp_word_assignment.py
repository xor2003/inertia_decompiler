"""Render proven partial GP writes through coherent word lvalues.

Layer: Types/Lowering.
Responsibility: preserve the canonical full-lane assignment for all semantic
consumers while projecting its proven low-word write into the shared runtime
ABI. No upper bits are deleted and no independent word state is introduced.
The current AST is checked on every rendering; stale shapes and effectful
values retain their explicit assignment. No rendered-C recovery occurs here.
"""

from __future__ import annotations

from collections.abc import Iterator

from angr.analyses.decompiler.structured_codegen import c as c
from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeNum
from angr.sim_variable import SimTemporaryVariable

from .gp_word_runtime import GP_WORD_RUNTIME_LANES_8616, GPRegisterRuntimeABI8616, gp_runtime_abi_8616
from .terminal_return_expressions import _safe_scalar_expression_8616


def _word_projection(assignment: c.CAssignment) -> tuple[str, c.CExpression] | None:
    """Require the current exact partial-write identity and pure value tree."""
    # The register owner calls our factory after constructing its canonical
    # effect. Import here to avoid a module-initialization cycle with that owner.
    from .gp_register_state import runtime_gp_expression_view_8616

    if not isinstance(assignment.lhs, c.CVariable):
        return None
    target = runtime_gp_expression_view_8616(assignment.lhs)
    if target is None or target.width != 4:
        return None
    rhs = assignment.rhs
    if not isinstance(rhs, c.CBinaryOp) or rhs.op != "Or":
        return None
    preserved, inserted = rhs.lhs, rhs.rhs
    if not _exact_mask(preserved, 0xffff0000) or not _exact_mask(inserted, 0xffff):
        return None
    # The view classifier strips casts, but a narrowing cast here destroys
    # upper bits. Preservation requires the direct full-register value.
    if not isinstance(preserved.lhs, c.CVariable):
        return None
    if runtime_gp_expression_view_8616(preserved.lhs) != target:
        return None
    value = inserted.lhs
    if not isinstance(value, c.CExpression) or not _pure_word_value(value):
        return None
    lane = next((lane for lane in GP_WORD_RUNTIME_LANES_8616 if lane.full_register == target.parent_name), None)
    return (lane.word_symbol, value) if lane is not None else None


def _pure_word_value(value: c.CExpression) -> bool:
    """Permit an integer temporary read without substituting its definition.

    Return recovery requires resolved provenance; this projection only changes
    the destination lvalue. The same direct scalar read is evaluated once, so
    an integer temporary need not be inlined or reconstructed to preserve it.
    """
    if (
        isinstance(value, c.CVariable)
        and isinstance(value.variable, SimTemporaryVariable)
        and isinstance(value.type, (SimTypeChar, SimTypeInt, SimTypeNum))
    ):
        return True
    return bool(_safe_scalar_expression_8616(value))


def _exact_mask(expression: object, mask: int) -> bool:
    """Recognize only the register owner's explicit bit-preservation operator."""
    return (
        isinstance(expression, c.CBinaryOp) and expression.op == "And"
        and isinstance(expression.rhs, c.CConstant) and expression.rhs.value == mask
    )


class CGPWordAssignment8616(c.CAssignment):  # type: ignore[misc]  # dynamic angr codegen base
    """One canonical assignment, with no cached or separately mutable value AST."""

    __slots__ = ()

    def c_repr_chunks(self, indent: int = 0, asexpr: bool = False) -> Iterator[tuple[str, object]]:
        """Render a word lvalue only while its ABI and exact proof still hold."""
        projection = (
            _word_projection(self)
            if gp_runtime_abi_8616(self.codegen) is GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS else None
        )
        # An assignment used as an expression has the full merged value, not
        # just the new word. Only statement projection is equivalent.
        if projection is None or asexpr:
            yield from super().c_repr_chunks(indent=indent, asexpr=asexpr)
            return
        word_symbol, value = projection
        yield self.indent_str(indent=indent), None
        yield word_symbol, self.lhs
        yield " = ", self
        yield from c.CExpression._try_c_repr_chunks(value)
        yield ";\n", self


def project_gp_word_assignment_8616(assignment: c.CAssignment) -> c.CAssignment:
    """Attach a word projection without mutating or hiding the canonical effect."""
    if gp_runtime_abi_8616(assignment.codegen) is not GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS:
        return assignment
    if _word_projection(assignment) is None:
        return assignment
    return CGPWordAssignment8616(
        assignment.lhs, assignment.rhs, codegen=assignment.codegen, tags=assignment.tags,
    )
