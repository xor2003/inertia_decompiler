"""Collect complete project global-source evidence once.

Layer: Types/Lowering.
Responsibility: normalize the complete discovered call-target census, classify
callee pointer parameters at their existing binary functions, and derive the
layout-bound global-source artifact. CLI supplies boundaries but owns no fact.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from inertia.lowering.analysis_helpers import collect_neighbor_call_targets
from inertia.widening.global_object_layout import GlobalObjectLayoutEvidence8616

from .callee_global_object_sources import (
    GlobalObjectSourceEvidence8616,
    collect_project_global_object_source_evidence_8616,
)
from .callee_pointer_contracts import (
    callee_pointer_argument_evidence_by_addr_8616,
)
from .callee_pointer_evidence import (
    apply_callee_pointer_argument_evidence_at_address_8616,
)
from .global_object_program_requirement import (
    GLOBAL_OBJECT_PROGRAM_CALL_TARGET_KINDS_8616,
)

__all__ = [
    "ProjectGlobalObjectSourceCollection8616",
    "collect_complete_project_global_object_sources_8616",
]


class _FunctionManager8616(Protocol):
    """Third-party exact function lookup used at the collection boundary."""

    def function(self, *, addr: int, create: bool = False) -> object | None:
        """Return one existing function without inventing a boundary."""


class _KnowledgeBase8616(Protocol):
    """Third-party knowledge base used for exact callee lookup."""

    functions: _FunctionManager8616


class _Project8616(Protocol):
    """Third-party project surface required by project source collection."""

    kb: _KnowledgeBase8616


@dataclass(frozen=True, slots=True)
class ProjectGlobalObjectSourceCollection8616:
    """Closed call-target census and its derived project source artifact."""

    call_target_addrs: tuple[int, ...]
    source_evidence: GlobalObjectSourceEvidence8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    def validate(self) -> None:
        """Reject an open target census or incoherent source dependency."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        if any(count < 0 for count in counts):
            raise ValueError("project source collection counters must be nonnegative")
        if self.call_target_addrs != tuple(sorted(set(self.call_target_addrs))):
            raise ValueError("project source call targets are not canonical")
        if self.raw_fact_count < self.normalized_fact_count:
            raise ValueError("project source normalization expands call evidence")
        if self.normalized_fact_count != len(self.call_target_addrs):
            raise ValueError("project source normalized count disagrees with targets")
        if self.classified_fact_count != self.materialized_count:
            raise ValueError("project source pointer classification is not materialized")
        if self.normalized_fact_count != self.classified_fact_count + self.failure_count:
            raise ValueError("project source target accounting does not close")
        self.source_evidence.validate()
        if self.source_evidence.scope_addr is not None:
            raise ValueError("complete project source evidence has a local scope")
        proven_targets = tuple(
            target_addr
            for target_addr in self.call_target_addrs
            if target_addr in self.source_evidence.pointer_target_addrs
        )
        if proven_targets != self.source_evidence.pointer_target_addrs:
            raise ValueError("project source pointer targets escape the call census")
        if len(proven_targets) != self.classified_fact_count:
            raise ValueError("project source pointer target count disagrees with census")


def collect_complete_project_global_object_sources_8616(
    project: object,
    functions: Sequence[object],
    layout_evidence: GlobalObjectLayoutEvidence8616,
) -> ProjectGlobalObjectSourceCollection8616:
    """Collect layout-bound source evidence from one complete function catalog."""
    if not layout_evidence.closed:
        raise ValueError("project source collection requires closed Widening layout")
    call_targets = tuple(
        target.target_addr
        for function in functions
        for target in collect_neighbor_call_targets(function)
        if target.kind in GLOBAL_OBJECT_PROGRAM_CALL_TARGET_KINDS_8616
    )
    retained = callee_pointer_argument_evidence_by_addr_8616(project)
    prior_only_targets = set(retained) - set(call_targets)
    target_addrs = tuple(sorted(set(call_targets) | prior_only_targets))
    raw_fact_count = len(call_targets) + len(prior_only_targets)
    classified_targets: set[int] = {
        target_addr
        for target_addr, evidence in retained.items()
        if target_addr in target_addrs and evidence.closes_classification
    }
    manager = cast(_Project8616, project).kb.functions
    for target_addr in target_addrs:
        if target_addr in retained:
            continue
        function = manager.function(addr=target_addr, create=False)
        if function is None:
            continue
        if apply_callee_pointer_argument_evidence_at_address_8616(
            project,
            function,
            target_addr,
        ):
            classified_targets.add(target_addr)
    source_evidence = collect_project_global_object_source_evidence_8616(
        project,
        layout_evidence,
    )
    result = ProjectGlobalObjectSourceCollection8616(
        call_target_addrs=target_addrs,
        source_evidence=source_evidence,
        raw_fact_count=raw_fact_count,
        normalized_fact_count=len(target_addrs),
        classified_fact_count=len(classified_targets),
        materialized_count=len(classified_targets),
        failure_count=len(target_addrs) - len(classified_targets),
    )
    result.validate()
    return result
