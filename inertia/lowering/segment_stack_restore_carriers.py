# cython: language_level=3, infer_types=True
"""Consume alias-proven segment save/restore stack carriers.

Layer: Types/Lowering.
Responsibility: remove structured stack bookkeeping only when Alias proves an
exact segment-register save and restore pair and both structured roles survive.
Preflight precedes mutation; incomplete or overlapping refused pairs stay intact.
Pair presence alone does not prove runtime register-state preservation.
Consumes alias facts. Do not infer pairs from opcodes, assembly, or C text.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.

Dynamic boundary: third-party angr C-AST statements and codegen attachments
expose version-dependent tags and child containers.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort

from inertia.alias.segment_stack_restore import (
    SegmentStackRestoreArtifact8616,
    SegmentStackRestoreFact8616,
    SegmentStackRestoreVerdict8616,
)
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.structured_tags import copy_structured_tags_8616
import dataclasses
import operator
import builtins

__all__ = [
    "SegmentStackRestoreCarrierStats8616",
    "prune_proven_segment_stack_restore_carriers_8616",
]

_PairKey8616 = tuple[int, int, str]


class SegmentRestoreCarrierRefusal8616(StrEnum):
    """Reason an optional pair optimization must leave the AST unchanged."""

    INCOMPLETE_PAIR = "incomplete_pair"
    SHARED_REFUSED_CARRIER = "shared_refused_carrier"
    RUNTIME_STATE_RESTORE = "runtime_state_restore"


class _SegmentStackRestoreCodegen8616(Protocol):
    """Owned fields consumed and published at the dynamic codegen boundary."""

    cfunc: _SegmentStackRestoreCFunction8616
    _inertia_segment_stack_restore_artifact: SegmentStackRestoreArtifact8616
    _inertia_segment_stack_restore_carrier_pairs_8616: object
    _inertia_segment_stack_restore_carrier_stats_8616: SegmentStackRestoreCarrierStats8616


class _SegmentStackRestoreCFunction8616(Protocol):
    """Owned C-function surface needed by the carrier consumer."""

    statements: object


@dataclasses.dataclass(frozen=True, )
class SegmentStackRestoreCarrierStats8616:
    """Closed accounting for proven restore facts and removed AST carriers."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    already_materialized_count: cython.longlong
    failure_count: cython.longlong
    removed_assignment_count: cython.longlong
    replaced_assignment_count: cython.longlong = 0
    refusals: tuple[tuple[_PairKey8616, SegmentRestoreCarrierRefusal8616], ...] = ()

    @property
    def refused_pair_count(self) -> cython.longlong:
        """Return pairs retained because their structured evidence is incomplete."""
        return len(self.refusals)

    @property
    def closed(self) -> cython.bint:
        """Return whether every proven pair reached one terminal lane."""
        return bool(
            operator.eq(self.raw_fact_count, self.normalized_fact_count + self.failure_count)
            and operator.eq(self.normalized_fact_count, self.classified_fact_count + self.refused_pair_count)
            and operator.eq(self.classified_fact_count, self.materialized_count + self.already_materialized_count)
        )


@cython.ccall
def _statement_instruction_addr_8616(statement: object) -> int | None:
    """Return one exact structured assignment instruction address."""
    instruction_addr: object
    tags: object
    tags = copy_structured_tags_8616(getattr(statement, "tags", None))
    if tags is not None:
        instruction_addr = tags.get("ins_addr")
        if isinstance(instruction_addr, int):
            return instruction_addr
    instruction_addr = getattr(statement, "ins_addr", None)
    return instruction_addr if isinstance(instruction_addr, int) else None


@cython.ccall
def _fact_key_8616(fact: SegmentStackRestoreFact8616) -> object:
    """Return one exact proven save/restore pair identity."""
    if (
        fact.verdict is not SegmentStackRestoreVerdict8616.PROVEN
        or not isinstance(fact.saved_instruction_addr, int)
    ):
        return None
    return fact.saved_instruction_addr, fact.restore_instruction_addr, fact.restore_register


def _statement_lists_8616(root: object) -> tuple[list[object], ...]:
    """Collect mutable statement lists using the shared child schema once."""
    candidate: object
    lists = [root] if isinstance(root, list) else []
    roots = tuple(root) if isinstance(root, list) else (root,)
    seen: set[cython.longlong] = set()
    for candidate in roots:
        lists.extend(
            node.statements
            for node in builtins.iter(_iter_c_nodes_deep_8616(candidate, seen))
            if isinstance(node, structured_c.CStatements) and isinstance(node.statements, list)
        )
    return tuple(lists)


@cython.ccall
def _pair_refusals_8616(
    pending_pairs: object,
    statement_lists: object,
) -> object:
    """Refuse absent roles and every pair sharing a refused instruction carrier."""
    present = {
        _statement_instruction_addr_8616(statement)
        for statements in iter(statement_lists)
        for statement in iter(statements)
        if isinstance(statement, structured_c.CAssignment)
    }
    refused = {
        key: (
            SegmentRestoreCarrierRefusal8616.INCOMPLETE_PAIR
            if key[0] not in present or key[1] not in present
            else SegmentRestoreCarrierRefusal8616.RUNTIME_STATE_RESTORE
        )
        for key, fact in builtins.iter(pending_pairs.items())
        if key[0] not in present or key[1] not in present or fact.constant_value is None
    }
    while True:
        protected_addresses = {address for key in iter(refused) for address in iter(key[:2])}
        overlapping = {
            key: SegmentRestoreCarrierRefusal8616.SHARED_REFUSED_CARRIER
            for key in iter(pending_pairs)
            if key not in refused and protected_addresses.intersection(key[:2])
        }
        if not overlapping:
            return refused
        refused.update(overlapping)


def prune_proven_segment_stack_restore_carriers_8616(project, codegen: object) -> cython.bint:
    """Remove exact structured carriers for alias-proven segment restores."""
    prior_pairs: object
    fact: object
    key: object
    statements: object
    del project
    boundary = cast(_SegmentStackRestoreCodegen8616, codegen)
    try:
        artifact = boundary._inertia_segment_stack_restore_artifact
        root = boundary.cfunc.statements
    except AttributeError:
        return False
    if not isinstance(artifact, SegmentStackRestoreArtifact8616):
        return False

    facts_by_key = {
        key: fact
        for fact in iter(artifact.facts)
        if (key := _fact_key_8616(fact)) is not None
    }
    prior_pairs = getattr(
        boundary, "_inertia_segment_stack_restore_carrier_pairs_8616", frozenset()
    )
    typed_prior_pairs: object = (
        prior_pairs if isinstance(prior_pairs, frozenset) else frozenset()
    )
    completed_pairs = set(typed_prior_pairs)
    pending_pairs = {key: fact for key, fact in builtins.iter(facts_by_key.items()) if key not in completed_pairs}
    statement_lists = _statement_lists_8616(root)
    refusals = _pair_refusals_8616(pending_pairs, statement_lists)
    pending_pairs = {key: fact for key, fact in builtins.iter(pending_pairs.items()) if key not in refusals}
    address_roles: dict[cython.longlong, set[tuple[tuple[cython.longlong, cython.longlong, str], str]]] = {}
    for key, fact in pending_pairs.items():
        assert fact.saved_instruction_addr is not None
        address_roles.setdefault(fact.saved_instruction_addr, set()).add((key, "save"))
        address_roles.setdefault(fact.restore_instruction_addr, set()).add((key, "restore"))

    observed_roles: dict[tuple[cython.longlong, cython.longlong, str], set[str]] = {}
    removed_assignment_count = 0
    replaced_assignment_count = 0

    def rewrite_statement_list(statements: object) -> None:
        """Commit preflighted replacements while retaining every refused carrier."""
        instruction_addr: object
        key: object
        role: object
        statement: object
        nonlocal removed_assignment_count, replaced_assignment_count
        kept: list[object] = []
        for statement in statements:
            instruction_addr = _statement_instruction_addr_8616(statement)
            roles = address_roles.get(instruction_addr, ()) if instruction_addr is not None else ()
            if isinstance(statement, structured_c.CAssignment) and roles:
                constant_restores = tuple(
                    (key, pending_pairs[key])
                    for key, role in iter(roles)
                    if role == "restore" and pending_pairs[key].constant_value is not None
                )
                if len(constant_restores) == 1:
                    key, fact = constant_restores[0]
                    replacement = structured_c.CAssignment(
                        statement.lhs,
                        structured_c.CConstant(
                            fact.constant_value,
                            SimTypeShort(False),
                            codegen=codegen,
                        ),
                        codegen=codegen,
                        tags=copy_structured_tags_8616(getattr(statement, "tags", None)),
                    )
                    kept.append(replacement)
                    observed_roles.setdefault(key, set()).add("restore")
                    replaced_assignment_count += 1
                    continue
                for key, role in roles:
                    observed_roles.setdefault(key, set()).add(role)
                removed_assignment_count += 1
                continue
            kept.append(statement)
        statements[:] = kept
    for statements in statement_lists:
        rewrite_statement_list(statements)

    materialized_pairs = {
        key for key, roles in builtins.iter(observed_roles.items()) if roles == {"save", "restore"}
    }
    completed_pairs.update(materialized_pairs)
    boundary._inertia_segment_stack_restore_carrier_pairs_8616 = frozenset(completed_pairs)
    stats = SegmentStackRestoreCarrierStats8616(
        raw_fact_count=len(facts_by_key),
        normalized_fact_count=len(facts_by_key),
        classified_fact_count=len(facts_by_key) - len(refusals),
        materialized_count=len(materialized_pairs),
        already_materialized_count=len(set(facts_by_key) & set(typed_prior_pairs)),
        failure_count=0,
        removed_assignment_count=removed_assignment_count,
        replaced_assignment_count=replaced_assignment_count,
        refusals=tuple(sorted(tuple(refusals.items()))),
    )
    boundary._inertia_segment_stack_restore_carrier_stats_8616 = stats
    return removed_assignment_count > 0 or replaced_assignment_count > 0
