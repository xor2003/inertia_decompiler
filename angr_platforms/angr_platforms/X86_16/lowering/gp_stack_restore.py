"""Materialize Alias-proven 16-bit GP saves and restores.

Layer: Types/Lowering.
Responsibility: consume exact stack-byte provenance and bind the structured
PUSH stores and POP register write to one coherent architectural GP lane.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

Dynamic boundary: angr structured-C nodes and codegen attachments expose
version-dependent child containers and tags.
"""

from __future__ import annotations

import copy
import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable

from ..alias.segment_stack_restore import (
    SegmentStackRestoreArtifact8616,
    SegmentStackRestoreFact8616,
    SegmentStackRestoreVerdict8616,
)
from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from ..pipeline.errors import PipelineHardError
from .gp_constant_restore import ConstantRestorePublication8616, publish_constant_gp_restore_8616
from .gp_register_state import runtime_gp_state_expr_8616
from .gp_stack_local_reload import has_materialized_gp_local_reload_8616
from .gp_stack_local_return import has_materialized_gp_local_return_8616
from .gp_stack_restore_identity import (
    has_materialized_gp_stack_bytes_8616,
    matches_gp_restore_stack_bytes_8616,
)
from .segment_access_policy import instruction_addrs_from_node_8616

__all__ = [
    "GPStackRestoreLoweringStats8616",
    "materialize_gp_stack_restores_8616",
]

_GP_STACK_SAVE_ANCHOR_TAG_8616 = "inertia_x86_16_gp_stack_save_anchor"


class _ArchRegisters8616(Protocol):
    """Third-party architecture register map used for physical identity."""

    registers: Mapping[str, tuple[int, int]]


class _Project8616(Protocol):
    """Project boundary required for exact register shapes."""

    arch: _ArchRegisters8616


class _CFunction8616(Protocol):
    """Structured function surface consumed by this lowering owner."""

    addr: int
    statements: object
    unified_local_vars: dict[object, object]
    variables_in_use: dict[object, object]


class _CodegenBoundary8616(Protocol):
    """Owned attachments and third-party fields used by this pass."""

    cfunc: _CFunction8616 | None
    project: _Project8616 | None
    _inertia_stack_register_restore_artifact_8616: SegmentStackRestoreArtifact8616
    _inertia_gp_stack_restore_lowering_stats_8616: GPStackRestoreLoweringStats8616
    _inertia_gp_stack_restore_materialized_pairs_8616: frozenset[tuple[int, int, str]]
    _inertia_gp_stack_restore_snapshots_8616: tuple[structured_c.CVariable, ...]


@dataclass(frozen=True, slots=True)
class GPStackRestoreLoweringStats8616:
    """Closed evidence census for exact GP stack save/restore lowering."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closed(self) -> bool:
        """Return whether every classified fact reached a terminal lane."""
        return bool(
            self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count == self.materialized_count + self.failure_count
        )


def _statement_containers_8616(root: object) -> tuple[structured_c.CStatements, ...]:
    """Return deterministic structured statement containers under one root."""
    return tuple(
        {
            id(node): node
            for node in (root, *_iter_c_nodes_deep_8616(root))
            if isinstance(node, structured_c.CStatements)
        }.values()
    )


def _snapshot_insertion_point_8616(
    containers: tuple[structured_c.CStatements, ...],
    save_addr: int,
    restore_addr: int,
    restore_register: str,
) -> tuple[structured_c.CStatements, int] | None:
    """Find the unique earliest structured statement following a proven save."""
    anchor_identity = (save_addr, restore_addr, restore_register)
    anchored: list[tuple[structured_c.CStatements, int]] = []
    for container in containers:
        anchored_indices = tuple(
            index
            for index, statement in enumerate(container.statements)
            if isinstance(getattr(statement, "tags", None), dict)
            and statement.tags.get(_GP_STACK_SAVE_ANCHOR_TAG_8616) == anchor_identity
        )
        if anchored_indices:
            anchored.append((container, min(anchored_indices)))
    unique_anchors = {(id(container), index) for container, index in anchored}
    if len(unique_anchors) == 1:
        return anchored[0]
    if unique_anchors:
        return None

    candidates: list[tuple[int, int, int, structured_c.CStatements, int]] = []
    for container in containers:
        container_addrs = tuple(
            instruction_addrs_from_node_8616(statement)
            for statement in container.statements
        )
        following_indices: list[tuple[int, int]] = []
        for index, statement in enumerate(container.statements):
            if not isinstance(
                statement,
                (
                    structured_c.CAssignment,
                    structured_c.CFunctionCall,
                    structured_c.CReturn,
                ),
            ):
                continue
            statement_addrs = container_addrs[index]
            if not statement_addrs or min(statement_addrs) <= save_addr:
                continue
            following = tuple(
                address
                for address in statement_addrs
                if save_addr < address <= restore_addr
            )
            if following:
                following_indices.append((min(following), index))
        if following_indices:
            earliest_addr = min(address for address, _index in following_indices)
            insertion_index = min(
                index for address, index in following_indices if address == earliest_addr
            )
            candidates.append(
                (
                    earliest_addr,
                    len(container.statements),
                    len(set().union(*container_addrs)),
                    container,
                    insertion_index,
                )
            )
    if not candidates:
        return None
    best_score = min(candidate[:3] for candidate in candidates)
    owners = tuple(candidate for candidate in candidates if candidate[:3] == best_score)
    unique = {(id(container), index) for _addr, _span, _size, container, index in owners}
    if len(unique) != 1:
        return None
    _addr, _size, _span, container, index = owners[0]
    return container, index


def _snapshot_variable_8616(
    fact: SegmentStackRestoreFact8616,
    containers: tuple[structured_c.CStatements, ...],
    *,
    codegen: object,
    project: _Project8616,
    function_addr: int,
) -> structured_c.CVariable:
    """Build an unpublished snapshot for the Alias-proven save range."""
    offset = min(fact.stack_offsets)
    exemplars = tuple(
        node
        for container in containers
        for node in _iter_c_nodes_deep_8616(container)
        if isinstance(node, structured_c.CVariable)
        and isinstance(node.variable, SimStackVariable)
        and node.variable.offset == offset
    )
    exact_exemplar = next(
        (node for node in exemplars if node.variable.size == 2),
        None,
    )
    naming_exemplar = exact_exemplar or next(iter(exemplars), None)
    if exact_exemplar is not None:
        variable = exact_exemplar.variable
    else:
        base = naming_exemplar.variable.base if naming_exemplar is not None else "bp"
        # This local is a materialized value snapshot, not an unresolved SP
        # address placeholder inherited from its byte-sized backing view.
        name = f"gp_saved_{fact.saved_register}_{fact.saved_instruction_addr:x}"
        variable = SimStackVariable(
            offset,
            2,
            base=base,
            name=name,
            region=function_addr,
        )
    value_type = SimTypeShort(False).with_arch(project.arch)
    unified_variable = (
        exact_exemplar.unified_variable
        if exact_exemplar is not None
        else None
    )
    cvar = structured_c.CVariable(
        variable,
        unified_variable=unified_variable,
        variable_type=value_type,
        codegen=codegen,
    )
    return cvar


def _materialize_fact_8616(
    fact: SegmentStackRestoreFact8616,
    containers: tuple[structured_c.CStatements, ...],
    *,
    codegen: object,
    project: _Project8616,
    function_addr: int,
) -> bool:
    """Materialize one wide stack snapshot and consume its POP recomposition."""
    if fact.saved_instruction_addr is None or fact.saved_register is None:
        return False
    insertion = _snapshot_insertion_point_8616(
        containers,
        fact.saved_instruction_addr,
        fact.restore_instruction_addr,
        fact.restore_register,
    )
    if fact.constant_value is not None:
        source = structured_c.CConstant(fact.constant_value, SimTypeShort(False).with_arch(project.arch), codegen=codegen)
    else:
        source = runtime_gp_state_expr_8616(fact.saved_register, codegen=codegen, function_addr=function_addr)
    if insertion is None or source is None:
        if os.environ.get("INERTIA_DEBUG_GP_STACK_RESTORE"):
            logging.getLogger(__name__).warning(
                "[gp-stack-restore-refusal] save=%#x restore=%#x insertion=%s source=%s statement_addrs=%s",
                fact.saved_instruction_addr,
                fact.restore_instruction_addr,
                insertion,
                source,
                tuple(
                    tuple(sorted(instruction_addrs_from_node_8616(statement)))
                    for container in containers
                    for statement in container.statements
                ),
            )
        return False
    snapshot = _snapshot_variable_8616(
        fact,
        containers,
        codegen=codegen,
        project=project,
        function_addr=function_addr,
    )
    replacement_count = 0

    def replace_restore(node: object) -> object:
        """Replace the syntax projection only inside the proven POP owner."""
        nonlocal replacement_count
        # Dynamic angr C-AST boundary: tags are the durable typed identity
        # carried through later structured-tree cloning and simplification.
        node_tags = getattr(node, "tags", None)
        restore_identity = (
            fact.saved_instruction_addr,
            fact.restore_instruction_addr,
            fact.restore_register,
        )
        if (
            isinstance(node, structured_c.CVariable)
            and isinstance(node_tags, dict)
            and node_tags.get("inertia_x86_16_gp_stack_restore") == restore_identity
        ):
            replacement_count += 1
            return node
        if not matches_gp_restore_stack_bytes_8616(codegen, node, fact):
            return node
        replacement_count += 1
        replacement = copy.copy(snapshot)
        replacement.tags = {
            **(dict(node_tags) if isinstance(node_tags, dict) else {}),
            "ins_addr": fact.restore_instruction_addr,
            "inertia_x86_16_gp_stack_restore": restore_identity,
        }
        return replacement

    for container in containers:
        for statement in tuple(container.statements):
            # Compound statements aggregate descendant tags, not ownership.
            # Their leaf statements are visited through their own containers.
            if not isinstance(statement, (
                structured_c.CAssignment, structured_c.CReturn,
                structured_c.CFunctionCall, structured_c.CExpressionStatement,
            )):
                continue
            if fact.restore_instruction_addr not in instruction_addrs_from_node_8616(statement):
                continue
            _replace_c_children_8616(statement, replace_restore)
    if replacement_count < 1:
        if os.environ.get("INERTIA_DEBUG_GP_STACK_RESTORE"):
            byte_offsets = tuple(
                (
                    sorted(instruction_addrs_from_node_8616(statement)),
                    tuple(
                        (node.variable.base, node.variable.offset, node.variable.size)
                        for node in _iter_c_nodes_deep_8616(statement)
                        if isinstance(node, structured_c.CVariable)
                        and isinstance(node.variable, SimStackVariable)
                    ),
                )
                for container in containers
                for statement in tuple(container.statements)
                if isinstance(statement, (structured_c.CAssignment, structured_c.CReturn))
                and fact.restore_instruction_addr in instruction_addrs_from_node_8616(statement)
            )
            logging.getLogger(__name__).warning(
                "[gp-stack-restore-refusal] restore=%#x replacement_count=%d "
                "expected_offsets=%r observed_byte_offsets=%r",
                fact.restore_instruction_addr,
                replacement_count,
                fact.stack_offsets,
                byte_offsets,
            )
        return False
    target, index = insertion
    assignment = structured_c.CAssignment(
        copy.copy(snapshot),
        source,
        codegen=codegen,
        tags={
            "ins_addr": fact.saved_instruction_addr,
            "inertia_x86_16_gp_stack_save": (
                fact.saved_instruction_addr,
                fact.restore_instruction_addr,
                fact.restore_register,
            ),
        },
    )
    anchor_identity = (
        fact.saved_instruction_addr,
        fact.restore_instruction_addr,
        fact.restore_register,
    )
    for statement in target.statements[index:]:
        addresses = instruction_addrs_from_node_8616(statement)
        if not any(
            fact.saved_instruction_addr < address < fact.restore_instruction_addr
            for address in addresses
        ):
            continue
        statement_tags = getattr(statement, "tags", None)
        statement.tags = {
            **(dict(statement_tags) if isinstance(statement_tags, dict) else {}),
            _GP_STACK_SAVE_ANCHOR_TAG_8616: anchor_identity,
        }
    if os.environ.get("INERTIA_DEBUG_GP_STACK_RESTORE"):
        logging.getLogger(__name__).warning(
            "[gp-stack-restore-placement] save=%#x restore=%#x index=%d statements=%r",
            fact.saved_instruction_addr,
            fact.restore_instruction_addr,
            index,
            tuple(
                (
                    type(statement).__name__,
                    tuple(sorted(instruction_addrs_from_node_8616(statement))),
                )
                for statement in target.statements
            ),
        )
    target.statements.insert(index, assignment)
    # A refused restore must not replace declarations for existing stack locals.
    cfunc = cast(_CodegenBoundary8616, codegen).cfunc
    if cfunc is not None:
        cfunc.unified_local_vars[snapshot.variable] = {(snapshot, snapshot.type)}
        cfunc.variables_in_use[snapshot.variable] = snapshot
    return True


def materialize_gp_stack_restores_8616(codegen: object) -> bool:
    """Materialize every Alias-proven 16-bit GP stack restoration fact."""
    boundary = cast(_CodegenBoundary8616, codegen)
    empty = GPStackRestoreLoweringStats8616(0, 0, 0, 0, 0)
    try:
        artifact = boundary._inertia_stack_register_restore_artifact_8616
    except AttributeError:
        boundary._inertia_gp_stack_restore_lowering_stats_8616 = empty
        return False
    cfunc = boundary.cfunc
    project = boundary.project
    if (
        not isinstance(artifact, SegmentStackRestoreArtifact8616)
        or cfunc is None
        or project is None
    ):
        boundary._inertia_gp_stack_restore_lowering_stats_8616 = empty
        return False
    facts = tuple(
        fact
        for fact in artifact.facts
        if fact.verdict is SegmentStackRestoreVerdict8616.PROVEN
    )
    containers = _statement_containers_8616(cfunc.statements)
    live_assignments = tuple(
        statement
        for container in containers
        for statement in container.statements
        if isinstance(statement, structured_c.CAssignment)
        and isinstance(statement.tags, dict)
        and isinstance(statement.tags.get("inertia_x86_16_gp_stack_save"), tuple)
    )
    completed_pairs = {
        statement.tags["inertia_x86_16_gp_stack_save"]
        for statement in live_assignments
    }
    snapshots = [
        statement.lhs
        for statement in live_assignments
        if isinstance(statement.lhs, structured_c.CVariable)
    ]
    newly_materialized = 0
    for fact in facts:
        assert fact.saved_instruction_addr is not None
        key = (
            fact.saved_instruction_addr,
            fact.restore_instruction_addr,
            fact.restore_register,
        )
        if key in completed_pairs:
            continue
        constant_publication = publish_constant_gp_restore_8616(codegen, containers, fact, cfunc.addr)
        if constant_publication is not ConstantRestorePublication8616.REFUSED:
            completed_pairs.add(key)
            newly_materialized += constant_publication is ConstantRestorePublication8616.INSERTED
            continue
        if (has_materialized_gp_stack_bytes_8616(codegen, containers, fact)
                or has_materialized_gp_local_reload_8616(codegen, containers, fact)
                or has_materialized_gp_local_return_8616(codegen, containers, fact)):
            completed_pairs.add(key)
            continue
        if _materialize_fact_8616(
            fact,
            containers,
            codegen=codegen,
            project=project,
            function_addr=cfunc.addr,
        ):
            snapshot_offset = min(fact.stack_offsets)
            snapshots.extend(
                node
                for container in containers
                for statement in container.statements
                if isinstance(statement, structured_c.CAssignment)
                and isinstance(statement.tags, dict)
                and statement.tags.get("inertia_x86_16_gp_stack_save")
                == (
                    fact.saved_instruction_addr,
                    fact.restore_instruction_addr,
                    fact.restore_register,
                )
                for node in (statement.lhs,)
                if isinstance(node, structured_c.CVariable)
                and isinstance(node.variable, SimStackVariable)
                and node.variable.offset == snapshot_offset
            )
            completed_pairs.add(key)
            newly_materialized += 1
    materialized = sum(
        fact.saved_instruction_addr is not None
        and (
            fact.saved_instruction_addr,
            fact.restore_instruction_addr,
            fact.restore_register,
        )
        in completed_pairs
        for fact in facts
    )
    boundary._inertia_gp_stack_restore_materialized_pairs_8616 = frozenset(completed_pairs)
    boundary._inertia_gp_stack_restore_snapshots_8616 = tuple(
        {id(snapshot): snapshot for snapshot in snapshots}.values()
    )
    stats = GPStackRestoreLoweringStats8616(
        raw_fact_count=len(facts),
        normalized_fact_count=len(facts),
        classified_fact_count=len(facts),
        materialized_count=materialized,
        failure_count=len(facts) - materialized,
    )
    boundary._inertia_gp_stack_restore_lowering_stats_8616 = stats
    if os.environ.get("INERTIA_DEBUG_GP_STACK_RESTORE"):
        logging.getLogger(__name__).warning(
            "[gp-stack-restore-lowering] function=%#x stats=%s root=%#x containers=%d live_assignments=%d newly_materialized=%d",
            cfunc.addr,
            stats,
            id(cfunc.statements),
            len(containers),
            len(live_assignments),
            newly_materialized,
        )
    if facts and materialized == 0:
        raise PipelineHardError(
            "GP stack-restore facts were classified but none materialized",
            layer="stack_lowering",
            function_addr=cfunc.addr,
            details={
                "restore_obligations": tuple(
                    (fact.restore_instruction_addr, fact.restore_register, fact.stack_offsets) for fact in facts
                ),
                "raw_fact_count": stats.raw_fact_count,
                "normalized_fact_count": stats.normalized_fact_count,
                "classified_fact_count": stats.classified_fact_count,
                "materialized_count": stats.materialized_count,
                "failure_count": stats.failure_count,
            },
        )
    return newly_materialized > 0
