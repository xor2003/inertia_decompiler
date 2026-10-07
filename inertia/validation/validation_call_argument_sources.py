"""Validate exact stack dependencies of materialized call arguments.

Layer: Tail validation.
Responsibility: compare binary-proven one-push argument source dependencies
with the final structured C argument without mutating or repairing the AST.

Consumes alias, widening, and typed facts through callsite summaries. Do not
recover semantics from COD, source, assembly, or rendered C text.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CTypeCast, CVariable
from angr.sim_variable import SimStackVariable

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.stack_function_coordinates import final_c_function_machine_bp_offset_8616
from inertia.semantics.callsite_summary import CallsitePushSourceKind8616, CallsiteSummary8616

from .validation_stack_projection import validated_stack_projection_fact_8616


class CallArgumentSourceIssueKind8616(StrEnum):
    """Typed final-call source dependency failures."""

    STACK_DEPENDENCY_MISMATCH = "stack-dependency-mismatch"


@dataclass(frozen=True, order=True, slots=True)
class CallArgumentSourceDependencyFact8616:
    """One exact binary-to-C stack dependency comparison."""

    argument_index: int
    expected_stack_offsets: tuple[int, ...]
    actual_stack_offsets: tuple[int, ...]

    @property
    def materialized(self) -> bool:
        """Return whether every proven source dependency survives in C."""
        return set(self.expected_stack_offsets).issubset(self.actual_stack_offsets)


@dataclass(frozen=True, order=True, slots=True)
class CallArgumentSourceIssue8616:
    """One final call argument that lost a binary-proven stack dependency."""

    kind: CallArgumentSourceIssueKind8616
    callsite_addr: int
    target_addr: int
    argument_index: int
    expected_stack_offsets: tuple[int, ...]
    actual_stack_offsets: tuple[int, ...]

    def token(self) -> str:
        """Return a deterministic failure token for tail-validation reports."""
        expected = _stack_offsets_token_8616(self.expected_stack_offsets)
        actual = _stack_offsets_token_8616(self.actual_stack_offsets)
        return (
            f"call-argument-source:{self.kind}:callsite={self.callsite_addr:#x}:"
            f"target={self.target_addr:#x}:arg={self.argument_index}:"
            f"expected-bp={expected}:actual-bp={actual}"
        )


def _stack_offsets_token_8616(offsets: tuple[int, ...]) -> str:
    """Render sorted BP-relative offsets for a stable issue token."""
    return ",".join(f"{offset:+#x}" for offset in offsets) if offsets else "none"


def _stack_offsets_from_push_source_8616(source: object) -> tuple[int, ...]:
    """Collect exact BP-relative leaves from one structured push source."""
    offsets: set[int] = set()

    def visit(value: object) -> None:
        if not isinstance(value, (tuple, list)):
            return
        if (
            len(value) >= 2
            and value[0]
            in {
                CallsitePushSourceKind8616.BP_VALUE.value,
                CallsitePushSourceKind8616.BP_ADDRESS.value,
                CallsitePushSourceKind8616.BP_INDEX_ADDRESS.value,
            }
            and isinstance(value[1], int)
        ):
            offsets.add(value[1])
        children = value[1:] if value and isinstance(value[0], str) else value
        for child in children:
            visit(child)

    visit(source)
    return tuple(sorted(offsets))


def _stack_offsets_from_c_argument_8616(
    codegen: object,
    argument: object,
) -> tuple[int, ...]:
    """Collect direct BP-relative storage identities from a final C argument."""
    projected_offset = _stack_byte_projection_offset_8616(codegen, argument)
    if projected_offset is not None:
        return (projected_offset,)

    offsets: set[int] = set()
    for node in _iter_c_nodes_deep_8616(argument):
        if not isinstance(node, CVariable):
            continue
        variable = node.variable
        if isinstance(variable, SimStackVariable) and variable.base == "bp":
            bp_offset = final_c_function_machine_bp_offset_8616(codegen, variable)
            if isinstance(bp_offset, int):
                offsets.add(bp_offset)
    return tuple(sorted(offsets))


def _stack_byte_projection_offset_8616(
    codegen: object,
    argument: object,
) -> int | None:
    """Return the exact BP view selected by typed evidence or a right shift."""
    projection = validated_stack_projection_fact_8616(argument)
    if projection is not None:
        return int(projection.view_offset)
    while isinstance(argument, CTypeCast):
        argument = argument.expr
    if not isinstance(argument, CBinaryOp) or argument.op != "Shr":
        return None
    shift = argument.rhs
    if not isinstance(shift, CConstant) or not isinstance(shift.value, int):
        return None
    if shift.value < 0 or shift.value % 8 != 0:
        return None

    source = argument.lhs
    while isinstance(source, CTypeCast):
        source = source.expr
    if not isinstance(source, CVariable):
        return None
    variable = source.variable
    byte_index = shift.value // 8
    if (
        not isinstance(variable, SimStackVariable)
        or variable.base != "bp"
        or not isinstance(variable.offset, int)
        or not isinstance(variable.size, int)
        or byte_index >= variable.size
    ):
        return None
    bp_offset = final_c_function_machine_bp_offset_8616(codegen, variable)
    return bp_offset + byte_index if isinstance(bp_offset, int) else None


def call_argument_source_stack_dependencies_8616(
    summary: CallsiteSummary8616,
) -> tuple[tuple[int, ...], ...] | None:
    """Return C-order stack dependencies for an exact one-push interface."""
    sources = summary.push_arg_sources
    widths = summary.arg_widths
    if (
        not isinstance(summary.arg_count, int)
        or summary.arg_count <= 0
        or summary.arg_count != len(sources)
        or len(widths) != len(sources)
        or any(source is None for source in sources)
    ):
        return None
    return tuple(
        _stack_offsets_from_push_source_8616(source)
        for source in reversed(sources)
    )


def call_argument_source_dependency_facts_8616(
    codegen: object,
    summary: CallsiteSummary8616,
    arguments: tuple[object, ...],
) -> tuple[CallArgumentSourceDependencyFact8616, ...]:
    """Compare every classified source dependency with final C arguments."""
    dependencies = call_argument_source_stack_dependencies_8616(summary)
    if dependencies is None or len(arguments) != len(dependencies):
        return ()
    return tuple(
        CallArgumentSourceDependencyFact8616(
            argument_index=index,
            expected_stack_offsets=expected,
            actual_stack_offsets=_stack_offsets_from_c_argument_8616(codegen, arguments[index]),
        )
        for index, expected in enumerate(dependencies)
        if expected
    )


__all__ = [
    "CallArgumentSourceDependencyFact8616",
    "CallArgumentSourceIssue8616",
    "CallArgumentSourceIssueKind8616",
    "call_argument_source_dependency_facts_8616",
    "call_argument_source_stack_dependencies_8616",
]
