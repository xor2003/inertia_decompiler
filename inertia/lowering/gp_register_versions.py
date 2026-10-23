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
from dataclasses import dataclass, field
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CDirtyExpression,
    CExpression,
    CStatements,
    CVariable,
)
from angr.sim_type import SimType, SimTypeChar, SimTypeLong, SimTypeShort
from angr.sim_variable import SimTemporaryVariable, SimVariable
from archinfo import Arch

from inertia.lowering.c_ast_utils import (
    _iter_c_node_occurrences_8616,
    _iter_c_nodes_deep_8616,
    _replace_c_children_8616,
)
from inertia.pipeline.errors import PipelineHardError

from .stack_value_projection import project_pointer_storage_value_8616
from .terminal_return_expressions import contains_effectful_call_8616

type RegisterIdentity8616 = tuple[int, int, int | str | None, int | None]
type RegisterClassifier8616 = Callable[[object], tuple[RegisterIdentity8616, str] | None]
_CAPTURE_TAG: str = "inertia_gp_version_capture_8616"
_POINTER_WORD_BYTES: int = 2
_STATEMENT_CENSUS_OCCURRENCE_MULTIPLIER: int = 2


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


class _Project8616(Protocol):
    """Architecture used to bind machine-width capture types."""

    arch: Arch


class _Codegen8616(Protocol):
    """Owned capture counters attached at the codegen boundary."""

    cfunc: _Function8616
    project: _Project8616
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
    source: CVariable | CDirtyExpression


def _occurrence_histogram(
    root: object, classify: RegisterClassifier8616,
) -> dict[RegisterIdentity8616, int]:
    """Count classify-positive identities across every AST edge occurrence."""
    counts: dict[RegisterIdentity8616, int] = {}
    for node in _iter_c_node_occurrences_8616(root):
        fact = classify(node)
        if fact is not None:
            counts[fact[0]] = counts.get(fact[0], 0) + 1
    return counts


@dataclass(slots=True)
class _CaptureScan8616:
    """Bounded per-invocation census shared across candidate plans.

    One lazy whole-root occurrence histogram replaces a full re-scan per
    candidate identity. Per-statement histograms, owner groups, and effect
    checks are memoized by node identity for this single planning pass only;
    the tree is not mutated until every plan is selected, so each memoized
    answer stays exact. Retained histogram entries are bounded by the root's
    register occurrences, including repeated uses of an identity. This admits
    disjoint statement censuses without thrashing while overlapping nested
    scopes cannot accumulate quadratic storage.
    Nothing persists across capture invocations. The classifier must be a
    read-only projection of the unchanged tree during planning.
    """

    root: object
    classify: RegisterClassifier8616
    groups: tuple[CStatements, ...]
    _occurrences: dict[RegisterIdentity8616, int] | None = None
    _owners: dict[int, list[CStatements]] | None = None
    _statement_occurrences: dict[int, tuple[object, dict[RegisterIdentity8616, int]]] = field(
        default_factory=dict,
    )
    _statement_identity_entries: int = 0
    _statement_identity_limit: int = 0
    _effectful: dict[int, tuple[object, bool]] = field(default_factory=dict)
    _overwrites: dict[tuple[int, str], tuple[object, bool]] = field(default_factory=dict)

    def total(self, identity: RegisterIdentity8616) -> int:
        """Return the whole-root occurrence count, building the census once."""
        if self._occurrences is None:
            self._occurrences = _occurrence_histogram(self.root, self.classify)
            self._statement_identity_limit = (
                _STATEMENT_CENSUS_OCCURRENCE_MULTIPLIER * sum(self._occurrences.values())
            )
        return self._occurrences.get(identity, 0)

    def owner_groups(self, assignment: CAssignment) -> tuple[CStatements, ...]:
        """Return deep-ordered statement groups directly listing the assignment."""
        if self._owners is None:
            owners: dict[int, list[CStatements]] = {}
            for group in self.groups:
                seen: set[int] = set()
                for statement in group.statements:
                    marker = id(statement)
                    if marker in seen or not isinstance(statement, CAssignment):
                        continue
                    seen.add(marker)
                    owners.setdefault(marker, []).append(group)
            self._owners = owners
        return tuple(self._owners.get(id(assignment), ()))

    def statement_reads(self, statement: object, identity: RegisterIdentity8616) -> int:
        """Count a subtree with bounded temporary reuse of overlapping censuses."""
        marker = id(statement)
        cached = self._statement_occurrences.get(marker)
        if cached is None or cached[0] is not statement:
            cached = (statement, _occurrence_histogram(statement, self.classify))
            self.total(identity)
            assert self._occurrences is not None
            limit = self._statement_identity_limit
            entries = len(cached[1])
            if self._statement_identity_entries + entries > limit:
                self._statement_occurrences.clear()
                self._statement_identity_entries = 0
            if entries <= limit:
                self._statement_occurrences[marker] = cached
                self._statement_identity_entries += entries
        return cached[1].get(identity, 0)

    def clobbers(self, statement: object) -> bool:
        """Return whether the subtree holds an effectful call, memoized per node."""
        marker = id(statement)
        cached = self._effectful.get(marker)
        if cached is None or cached[0] is not statement:
            cached = (statement, contains_effectful_call_8616(statement))
            self._effectful[marker] = cached
        return cached[1]

    def overwrites(self, statement: object, parent: str) -> bool:
        """Return whether the subtree may write the lane, memoized per node."""
        key = (id(statement), parent)
        cached = self._overwrites.get(key)
        if cached is None or cached[0] is not statement:
            cached = (statement, _may_overwrite_lane(statement, parent, self.classify))
            self._overwrites[key] = cached
        return cached[1]


def _capture_plan(
    scan: _CaptureScan8616, assignment: CAssignment, identity: RegisterIdentity8616,
) -> _CapturePlan8616 | None:
    """Require every read to follow the unique definition in its own group."""
    total = scan.total(identity)
    if total <= 1:
        return None
    owners = scan.owner_groups(assignment)
    if len(owners) != 1:
        raise PipelineHardError(f"GP version capture: identity={identity!r}: ambiguous definition owner")
    group = owners[0]
    # A definition can dominate its own branch/loop body without dominating
    # the function. Count against the whole function to reject escaping reads.
    dominating = next(
        (scope for scope in scan.groups if _dominates_reads(scan, scope, assignment, identity, total)),
        None,
    )
    if dominating is None:
        raise PipelineHardError(f"GP version capture: identity={identity!r}: definition does not dominate every read")
    if not isinstance(assignment.lhs, CDirtyExpression) and not _outlives_register_value(
        scan, dominating, assignment, identity,
    ):
        return None
    return _CapturePlan8616(identity, assignment, group, cast(CVariable | CDirtyExpression, assignment.lhs))


def _may_overwrite_lane(statement: object, parent: str, classify: RegisterClassifier8616) -> bool:
    """Keep unknown destinations conservative; distinguish known register lanes."""
    for node in _iter_c_nodes_deep_8616(statement):
        if isinstance(node, CAssignment):
            destination = classify(node.lhs)
            if destination is None or destination[1] == parent:
                return True
    return False


def _outlives_register_value(
    scan: _CaptureScan8616, scope: CStatements, assignment: CAssignment,
    identity: RegisterIdentity8616,
) -> bool:
    """Capture only when a use can follow an overwrite or an effectful call.

    Pure generated memory helpers do not clobber registers. A compound statement
    can revisit reads on a backedge, so a nested overwrite is conservative even
    if its first read precedes the write. No assignments or effects are removed.
    """
    source = scan.classify(assignment.lhs)
    assert source is not None
    linear = _linear_sequence(scope)
    position = next(index for index, node in enumerate(linear) if node is assignment)
    clobbered = False
    for statement in linear[position + 1:]:
        clobbered |= scan.clobbers(statement)
        overwrite = scan.overwrites(statement, source[1])
        nested_overwrite = overwrite and not isinstance(statement, CAssignment)
        if scan.statement_reads(statement, identity) and (clobbered or nested_overwrite):
            return True
        clobbered |= overwrite
    return False


def _dominates_reads(
    scan: _CaptureScan8616, scope: CStatements, assignment: CAssignment,
    identity: RegisterIdentity8616, total: int,
) -> bool:
    """Prove all reads follow a definition without crossing a control boundary."""
    linear = _linear_sequence(scope)
    positions = tuple(index for index, statement in enumerate(linear) if statement is assignment)
    if len(positions) != 1:
        return False
    later_reads = sum(scan.statement_reads(statement, identity) for statement in linear[positions[0] + 1:])
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
    groups: list[CStatements] = []
    for node in _iter_c_nodes_deep_8616(root):
        if isinstance(node, CStatements):
            groups.append(node)
        if not isinstance(node, CAssignment):
            continue
        fact = classify(node.lhs)
        if fact is not None and fact[1] in state_names:
            definitions.setdefault(fact[0], []).append(node)
            parents[fact[0]] = fact[1]
    scan = _CaptureScan8616(root, classify, tuple(groups))
    selected: list[_CapturePlan8616] = []
    for identity, assignments in definitions.items():
        shares_lane = any(key != identity and parent == parents[identity] for key, parent in parents.items())
        if len(assignments) != 1:
            continue
        if not shares_lane and not isinstance(assignments[0].lhs, CDirtyExpression):
            continue
        plan = _capture_plan(scan, assignments[0], identity)
        if plan is not None:
            selected.append(plan)
    return tuple(selected)



def _capture_storage_type_8616(plan: _CapturePlan8616, codegen: _Codegen8616) -> SimType:
    """Consume a typed C variable or the exact machine width of a dirty SSA value."""
    if isinstance(plan.source, CVariable):
        return plan.source.variable_type
    types: dict[int, SimType] = {
        1: SimTypeChar(False), 2: SimTypeShort(False), 4: SimTypeLong(False),
    }
    size = plan.identity[1]
    if size not in types:
        raise PipelineHardError(f"GP version capture: unsupported register width {size}")
    return types[size].with_arch(codegen.project.arch)


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
    replacements: dict[RegisterIdentity8616, CVariable] = {}
    publications: list[tuple[_CapturePlan8616, CAssignment]] = []

    def replace_version(node: object) -> object:
        """Project selected full identities without merging architectural lanes."""
        fact = classify(node)
        return replacements.get(fact[0], node) if fact is not None else node

    for plan in plans:
        capture_type = _capture_storage_type_8616(plan, boundary)
        temporary = SimTemporaryVariable(next_id, plan.identity[1])
        next_id += 1
        value = CVariable(temporary, variable_type=capture_type, codegen=codegen)
        # A scalar register snapshot stores guest offset bits, not a host C
        # pointer. Reuse the architectural-write owner's exact projection.
        # Earlier captures must already be visible to this RHS's type query.
        # Visit only this expression now; replace the complete function once
        # after every plan is prepared, before adding architectural publications.
        rhs = cast(CExpression, replace_version(plan.assignment.rhs))
        _replace_c_children_8616(rhs, replace_version)
        projected = project_pointer_storage_value_8616(
            codegen, rhs, max(plan.identity[1], _POINTER_WORD_BYTES),
        )
        assert projected is not None
        plan.assignment.rhs = projected

        replacements[plan.identity] = value
        # Evaluate the RHS once into the local, then publish that exact value.
        publication = CAssignment(plan.source, value, codegen=codegen, tags=dict(plan.assignment.tags))
        plan.assignment.tags[_CAPTURE_TAG] = True
        publications.append((plan, publication))
        function.variables_in_use[temporary] = value
        function.variable_manager.set_variable_type(temporary, capture_type)
    _replace_c_children_8616(root, replace_version)
    for plan, publication in publications:
        position = next(index for index, statement in enumerate(plan.group.statements) if statement is plan.assignment)
        plan.group.statements = [*plan.group.statements[:position + 1], publication, *plan.group.statements[position + 1:]]
    function.refresh()
    count = existing + len(plans)
    boundary._inertia_gp_register_version_capture_stats_8616 = GPVersionCaptureStats8616(count, count, count, count, 0)
    return True
