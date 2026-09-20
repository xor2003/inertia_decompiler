"""Preserve defined register values while publishing architectural writes.

Layer: Types/Lowering.
Responsibility: retain exact C register identities before mutable runtime-state
projection. Consume existing typed definitions; never recover from names,
assembly, source sidecars, or rendered C. Ambiguous ordering refuses early.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Callable, MutableMapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CStatements, CVariable
from angr.sim_type import SimType
from angr.sim_variable import SimTemporaryVariable, SimVariable

from ..c_ast_utils import _iter_c_node_occurrences_8616, _iter_c_nodes_deep_8616, _replace_c_children_8616
from ..pipeline.errors import PipelineHardError
from .stack_value_projection import project_pointer_storage_value_8616
from .terminal_return_expressions import contains_effectful_call_8616

type RegisterIdentity8616 = tuple[int, int, str | None, int | None]
type RegisterClassifier8616 = Callable[[object], tuple[RegisterIdentity8616, str] | None]
_CAPTURE_TAG: str = "inertia_gp_version_capture_8616"
_POINTER_WORD_BYTES: int = 2


class _VariableManager8616(Protocol):
    """Type publication boundary of the angr variable manager."""

    def set_variable_type(self, variable: SimVariable, type_: SimType) -> None:
        """Publish a captured local's existing type."""


class _Function8616(Protocol):
    """Function storage and declaration surfaces required for capture."""

    addr: int
    statements: object
    variables_in_use: MutableMapping[SimVariable, CVariable]
    variable_manager: _VariableManager8616

    def refresh(self) -> None:
        """Rebuild declarations from the published storage inventory."""


class _Codegen8616(Protocol):
    """Owned capture counters attached at the codegen boundary."""

    cfunc: _Function8616
    _inertia_gp_register_version_capture_stats_8616: GPVersionCaptureStats8616


@dataclass(frozen=True, slots=True)
class GPVersionCaptureStats8616:
    """Closed census of exact register definitions requiring value storage."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class _CapturePlan8616:
    """One uniquely defined version and its dominating statement group."""

    identity: RegisterIdentity8616
    assignment: CAssignment
    group: CStatements
    source: CVariable


def _reference_count(root: object, identity: RegisterIdentity8616, classify: RegisterClassifier8616) -> int:
    """Count occurrences rather than shared-node identities."""
    return sum(
        fact is not None and fact[0] == identity
        for node in _iter_c_node_occurrences_8616(root)
        for fact in (classify(node),)
    )


def _capture_plan(
    root: object, assignment: CAssignment, identity: RegisterIdentity8616,
    classify: RegisterClassifier8616,
) -> _CapturePlan8616 | None:
    """Require every read to follow the unique definition in its own group."""
    total = _reference_count(root, identity, classify)
    if total <= 1:
        return None
    owners = tuple(
        group for group in _iter_c_nodes_deep_8616(root) if isinstance(group, CStatements)
        and any(statement is assignment for statement in group.statements)
    )
    if len(owners) != 1:
        raise PipelineHardError(f"GP version capture: identity={identity!r}: ambiguous definition owner")
    group = owners[0]
    # A definition can dominate its own branch/loop body without dominating
    # the function. Count against the whole function to reject escaping reads.
    scopes = (node for node in _iter_c_nodes_deep_8616(root) if isinstance(node, CStatements))
    dominating = next((scope for scope in scopes if _dominates_reads(scope, assignment, identity, classify, total)), None)
    if dominating is None:
        raise PipelineHardError(f"GP version capture: identity={identity!r}: definition does not dominate every read")
    if not _outlives_register_value(dominating, assignment, identity, classify):
        return None
    return _CapturePlan8616(identity, assignment, group, cast(CVariable, assignment.lhs))


def _may_overwrite_lane(statement: object, parent: str, classify: RegisterClassifier8616) -> bool:
    """Keep unknown destinations conservative; distinguish known register lanes."""
    for node in _iter_c_nodes_deep_8616(statement):
        if isinstance(node, CAssignment):
            destination = classify(node.lhs)
            if destination is None or destination[1] == parent:
                return True
    return False


def _outlives_register_value(
    scope: CStatements, assignment: CAssignment, identity: RegisterIdentity8616,
    classify: RegisterClassifier8616,
) -> bool:
    """Capture only when a use can follow an overwrite or an effectful call.

    Pure generated memory helpers do not clobber registers. A compound statement
    can revisit reads on a backedge, so a nested overwrite is conservative even
    if its first read precedes the write. No assignments or effects are removed.
    """
    source = classify(assignment.lhs)
    assert source is not None
    linear = _linear_sequence(scope)
    position = next(index for index, node in enumerate(linear) if node is assignment)
    clobbered = False
    for statement in linear[position + 1:]:
        clobbered |= contains_effectful_call_8616(statement)
        overwrite = _may_overwrite_lane(statement, source[1], classify)
        nested_overwrite = overwrite and not isinstance(statement, CAssignment)
        if _reference_count(statement, identity, classify) and (clobbered or nested_overwrite):
            return True
        clobbered |= overwrite
    return False


def _dominates_reads(
    scope: CStatements, assignment: CAssignment, identity: RegisterIdentity8616,
    classify: RegisterClassifier8616, total: int,
) -> bool:
    """Prove all reads follow a definition without crossing a control boundary."""
    linear = _linear_sequence(scope)
    positions = tuple(index for index, statement in enumerate(linear) if statement is assignment)
    if len(positions) != 1:
        return False
    later_reads = sum(_reference_count(statement, identity, classify) for statement in linear[positions[0] + 1:])
    return total == later_reads + 1


def _linear_sequence(root: object) -> tuple[object, ...]:
    """Flatten grouping only; never enter a conditional or loop body."""
    if isinstance(root, CStatements):
        return tuple(child for statement in root.statements for child in _linear_sequence(statement))
    return (root,)


def _plans(
    root: object, state_names: frozenset[str], classify: RegisterClassifier8616,
) -> tuple[_CapturePlan8616, ...]:
    """Select distinct defined versions sharing an architectural state lane."""
    definitions: dict[RegisterIdentity8616, list[CAssignment]] = {}
    parents: dict[RegisterIdentity8616, str] = {}
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CAssignment):
            continue
        fact = classify(node.lhs)
        if fact is not None and fact[1] in state_names:
            definitions.setdefault(fact[0], []).append(node)
            parents[fact[0]] = fact[1]
    selected: list[_CapturePlan8616] = []
    for identity, assignments in definitions.items():
        shares_lane = any(key != identity and parent == parents[identity] for key, parent in parents.items())
        if len(assignments) != 1 or not shares_lane:
            continue
        plan = _capture_plan(root, assignments[0], identity, classify)
        if plan is not None:
            selected.append(plan)
    return tuple(selected)


def capture_gp_register_versions_8616(
    codegen: object, state_names: frozenset[str], classify: RegisterClassifier8616,
) -> bool:
    """Keep local values and publish each original register write exactly once."""
    boundary = cast(_Codegen8616, codegen)
    function = boundary.cfunc
    root = function.statements
    try:
        plans = _plans(root, state_names, classify)
    except PipelineHardError as error:
        boundary._inertia_gp_register_version_capture_stats_8616 = GPVersionCaptureStats8616(1, 1, 0, 0, 1)
        raise PipelineHardError(f"GP version capture function={function.addr:#x}: {error}") from error
    existing = sum(
        isinstance(node, CAssignment) and node.tags.get(_CAPTURE_TAG) is True
        for node in _iter_c_nodes_deep_8616(root)
    )
    if not plans:
        boundary._inertia_gp_register_version_capture_stats_8616 = GPVersionCaptureStats8616(
            existing, existing, existing, existing, 0,
        )
        return False
    used_ids = {
        node.variable.tmp_id for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CVariable) and isinstance(node.variable, SimTemporaryVariable)
    }
    used_ids.update(variable.tmp_id for variable in function.variables_in_use if isinstance(variable, SimTemporaryVariable))
    next_id = max(used_ids, default=-1) + 1
    for plan in plans:
        temporary = SimTemporaryVariable(next_id, plan.source.variable.size)
        next_id += 1
        value = CVariable(temporary, variable_type=plan.source.variable_type, codegen=codegen)
        # A scalar register snapshot stores guest offset bits, not a host C
        # pointer. Reuse the architectural-write owner's exact projection.
        projected = project_pointer_storage_value_8616(
            codegen, plan.assignment.rhs, max(plan.source.variable.size, _POINTER_WORD_BYTES),
        )
        assert projected is not None
        plan.assignment.rhs = projected

        def replace_version(node: object, plan: _CapturePlan8616 = plan, value: CVariable = value) -> object:
            """Replace only the selected full identity, including its definition."""
            fact = classify(node)
            return value if fact is not None and fact[0] == plan.identity else node

        _replace_c_children_8616(root, replace_version)
        # Evaluate the RHS once into the local, then publish that exact value.
        publication = CAssignment(plan.source, value, codegen=codegen, tags=dict(plan.assignment.tags))
        plan.assignment.tags[_CAPTURE_TAG] = True
        position = next(index for index, statement in enumerate(plan.group.statements) if statement is plan.assignment)
        plan.group.statements = [*plan.group.statements[:position + 1], publication, *plan.group.statements[position + 1:]]
        function.variables_in_use[temporary] = value
        function.variable_manager.set_variable_type(temporary, plan.source.variable_type)
    function.refresh()
    count = existing + len(plans)
    boundary._inertia_gp_register_version_capture_stats_8616 = GPVersionCaptureStats8616(count, count, count, count, 0)
    return True
