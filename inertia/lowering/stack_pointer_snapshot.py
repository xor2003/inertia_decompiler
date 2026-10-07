"""Materialize saved BP-argument pointer versions in structured C.

Layer: Types/Lowering.
Responsibility: join exact near-pointer instruction facts to segmented C access
nodes and preserve the pre-update pointer value carried by a register. Matching
uses typed storage identity, width, and instruction provenance; absent or
ambiguous evidence must remain unmodified. Consumes alias, widening, and typed
facts. Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import contextlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from archinfo import Arch

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616

from .near_pointer_argument import NearPointerArgumentFact8616

_SNAPSHOT_TAG_8616 = "inertia_x86_16_stack_pointer_snapshot"
_SOURCE_INSTRUCTION_ADDRS_TAG_8616 = "inertia_source_instruction_addrs"
_HELPER_WIDTHS_8616 = {"SEG_U8": 1, "SEG_U16": 2, "SEG_U32": 4}


class _ProjectBoundary8616(Protocol):
    """Typed view of the project fields needed to type constants."""

    arch: Arch


class _CodegenBoundary8616(Protocol):
    """Typed view of the structured-codegen fields used here."""

    project: _ProjectBoundary8616


class StackPointerSnapshotStatus8616(StrEnum):
    """Typed outcomes for one saved stack-pointer version materialization."""

    NO_FACT = "no_fact"
    MATERIALIZED = "materialized"
    ALREADY_MATERIALIZED = "already_materialized"
    AMBIGUOUS_FACT = "ambiguous_fact"
    STACK_SLOT_NOT_PRESENT = "stack_slot_not_present"


@dataclass(frozen=True, slots=True)
class StackPointerSnapshotResult8616:
    """Result of applying exact saved-value evidence to one address expression."""

    expression: object
    status: StackPointerSnapshotStatus8616
    matched_facts: tuple[NearPointerArgumentFact8616, ...] = ()


@dataclass(frozen=True, slots=True)
class StackPointerSnapshotStats8616:
    """Closed evidence counters for saved stack-pointer versions."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


class StackPointerSnapshotMaterializationError8616(RuntimeError):
    """Raised when classified saved-value evidence reaches no C expression."""


def _stack_offsets_in_expression_8616(expression: object) -> frozenset[int]:
    """Return explicit BP stack offsets used by one structured C expression."""
    offsets: set[int] = set()
    for node in _iter_c_nodes_deep_8616(expression):
        if isinstance(node, structured_c.CVariable) and isinstance(node.variable, SimStackVariable):
            offsets.add(int(node.variable.offset))
    return frozenset(offsets)


def _snapshot_fact_key_8616(fact: NearPointerArgumentFact8616) -> tuple[int, int, int, int]:
    """Return the stable C-AST marker for one saved-value fact."""
    return (
        fact.stack_offset,
        fact.carrier_load_ins_addr,
        fact.dereference_ins_addr,
        fact.source_version_delta,
    )


def _runtime_helper_width_8616(node: object) -> int | None:
    """Return the width of one typed segmented helper call."""
    if not isinstance(node, structured_c.CFunctionCall) or not isinstance(node.callee_target, str):
        return None
    return _HELPER_WIDTHS_8616.get(node.callee_target.upper())


def _runtime_helper_candidates_8616(
    root: object,
) -> dict[tuple[int, int], list[structured_c.CFunctionCall]]:
    """Group untagged helper accesses by exact stack identity and width."""
    candidates: dict[tuple[int, int], list[structured_c.CFunctionCall]] = {}
    for node in _iter_c_nodes_deep_8616(root):
        width = _runtime_helper_width_8616(node)
        if width is None or not isinstance(node, structured_c.CFunctionCall) or len(node.args) < 2:
            continue
        offsets = _stack_offsets_in_expression_8616(node.args[1])
        if len(offsets) != 1:
            continue
        key = (next(iter(offsets)), width)
        candidates.setdefault(key, []).append(node)
    return candidates


@dataclass(slots=True)
class StackPointerSnapshotTracker8616:
    """Track and enforce saved stack-pointer materialization for one function."""

    facts: tuple[NearPointerArgumentFact8616, ...]
    classified_facts: set[NearPointerArgumentFact8616] = field(default_factory=set)
    materialized_facts: set[NearPointerArgumentFact8616] = field(default_factory=set)
    failed_facts: set[NearPointerArgumentFact8616] = field(default_factory=set)
    bound_facts_by_node_id: dict[int, NearPointerArgumentFact8616] = field(default_factory=dict)

    def bind_unique_untagged_helpers(self, root: object) -> None:
        """Attach provenance only for one-to-one binary-fact/AST-helper joins."""
        facts_by_key: dict[tuple[int, int], list[NearPointerArgumentFact8616]] = {}
        for fact in self.facts:
            if fact.source_version_delta == 0:
                continue
            facts_by_key.setdefault((fact.stack_offset, fact.access_width_bytes), []).append(fact)
        for key, candidates in _runtime_helper_candidates_8616(root).items():
            facts = facts_by_key.get(key, [])
            if len(facts) != 1 or len(candidates) != 1:
                continue
            fact = facts[0]
            candidate = candidates[0]
            self.bound_facts_by_node_id[id(candidate)] = fact
            if _SOURCE_INSTRUCTION_ADDRS_TAG_8616 not in candidate.tags:
                candidate.tags = {
                    **candidate.tags,
                    _SOURCE_INSTRUCTION_ADDRS_TAG_8616: (fact.dereference_ins_addr,),
                }

    def materialize(
        self,
        expression: object,
        *,
        source_instruction_addrs: frozenset[int],
        provenance_node: object | None,
        codegen: object | None,
    ) -> object:
        """Apply and account for an exact saved-value fact at one dereference."""
        bound_fact = self.bound_facts_by_node_id.get(id(provenance_node)) if provenance_node is not None else None
        result = materialize_stack_pointer_snapshot_8616(
            expression,
            facts=(bound_fact,) if bound_fact is not None else self.facts,
            source_instruction_addrs=(
                frozenset({bound_fact.dereference_ins_addr})
                if bound_fact is not None and not source_instruction_addrs
                else source_instruction_addrs
            ),
            codegen=codegen,
        )
        if not result.matched_facts:
            return result.expression
        self.classified_facts.update(result.matched_facts)
        if result.status in {
            StackPointerSnapshotStatus8616.MATERIALIZED,
            StackPointerSnapshotStatus8616.ALREADY_MATERIALIZED,
        }:
            self.materialized_facts.update(result.matched_facts)
        else:
            self.failed_facts.update(result.matched_facts)
        return result.expression

    def materialize_indexed_access(
        self,
        access: structured_c.CIndexedVariable,
        *,
        source_instruction_addrs: frozenset[int],
        codegen: object | None,
    ) -> object:
        """Apply a saved pointer version to one typed pointer index."""
        matching = tuple(
            fact
            for fact in self.facts
            if fact.source_version_delta != 0
            and fact.dereference_ins_addr in source_instruction_addrs
        )
        if not matching:
            return access
        self.classified_facts.update(matching)
        if len(matching) != 1:
            self.failed_facts.update(matching)
            return access
        fact = matching[0]
        if access.tags.get(_SNAPSHOT_TAG_8616) == _snapshot_fact_key_8616(fact):
            self.materialized_facts.add(fact)
            return access
        if fact.stack_offset not in _stack_offsets_in_expression_8616(access.variable):
            self.failed_facts.add(fact)
            return access
        width = fact.access_width_bytes
        if width <= 0 or fact.source_version_delta % width:
            self.failed_facts.add(fact)
            return access
        element_delta = fact.source_version_delta // width
        value_type = _unsigned_short_type_8616(codegen)
        adjusted_index = structured_c.CBinaryOp(
            "Sub" if element_delta > 0 else "Add",
            access.index,
            structured_c.CConstant(abs(element_delta), value_type, codegen=codegen),
            codegen=codegen,
        )
        adjusted = structured_c.CIndexedVariable(
            access.variable,
            adjusted_index,
            variable_type=access.type,
            codegen=codegen,
            tags={**access.tags, _SNAPSHOT_TAG_8616: _snapshot_fact_key_8616(fact)},
        )
        self.materialized_facts.add(fact)
        return adjusted

    @property
    def stats(self) -> StackPointerSnapshotStats8616:
        """Return closed counters for this function's versioned pointer facts."""
        versioned = {fact for fact in self.facts if fact.source_version_delta != 0}
        return StackPointerSnapshotStats8616(
            raw_fact_count=len(versioned),
            normalized_fact_count=len(versioned),
            classified_fact_count=len(self.classified_facts),
            materialized_count=len(self.materialized_facts),
            failure_count=len(self.failed_facts - self.materialized_facts),
        )

    def assert_closed(self) -> None:
        """Fail when classified snapshot evidence was never materialized."""
        stats = self.stats
        if stats.classified_fact_count > 0 and stats.materialized_count == 0:
            raise StackPointerSnapshotMaterializationError8616(
                "classified saved stack-pointer evidence reached no C expression"
            )


def _unsigned_short_type_8616(codegen: object | None) -> SimTypeShort:
    """Return an architecture-bound unsigned short for pointer deltas."""
    value_type = SimTypeShort(False)
    if codegen is not None:
        with contextlib.suppress(AttributeError):
            value_type = value_type.with_arch(cast(_CodegenBoundary8616, codegen).project.arch)
    return value_type


def materialize_stack_pointer_snapshot_8616(
    expression: object,
    *,
    facts: Sequence[NearPointerArgumentFact8616],
    source_instruction_addrs: frozenset[int],
    codegen: object | None,
) -> StackPointerSnapshotResult8616:
    """Rebind one current stack argument expression to its saved binary version."""
    matching = tuple(
        fact
        for fact in facts
        if fact.source_version_delta != 0 and fact.dereference_ins_addr in source_instruction_addrs
    )
    if not matching:
        return StackPointerSnapshotResult8616(expression, StackPointerSnapshotStatus8616.NO_FACT)
    if len(matching) != 1:
        return StackPointerSnapshotResult8616(
            expression,
            StackPointerSnapshotStatus8616.AMBIGUOUS_FACT,
            matching,
        )
    fact = matching[0]
    if isinstance(expression, structured_c.CBinaryOp) and expression.tags.get(_SNAPSHOT_TAG_8616) == _snapshot_fact_key_8616(fact):
        return StackPointerSnapshotResult8616(
            expression,
            StackPointerSnapshotStatus8616.ALREADY_MATERIALIZED,
            matching,
        )
    if fact.stack_offset not in _stack_offsets_in_expression_8616(expression):
        return StackPointerSnapshotResult8616(
            expression,
            StackPointerSnapshotStatus8616.STACK_SLOT_NOT_PRESENT,
            matching,
        )
    delta = fact.source_version_delta
    constant = structured_c.CConstant(abs(delta), _unsigned_short_type_8616(codegen), codegen=codegen)
    adjusted = structured_c.CBinaryOp(
        "Sub" if delta > 0 else "Add",
        expression,
        constant,
        codegen=codegen,
        tags={_SNAPSHOT_TAG_8616: _snapshot_fact_key_8616(fact)},
    )
    return StackPointerSnapshotResult8616(
        adjusted,
        StackPointerSnapshotStatus8616.MATERIALIZED,
        matching,
    )
