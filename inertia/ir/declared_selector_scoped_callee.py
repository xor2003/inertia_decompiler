"""Layer: IR.
Responsibility: retain invocation-bound callee proofs during selector induction.

Only unresolved native callees demand the existing scoped collection route.
The original records remain conditional and are never published as summaries.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import cast

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DirectCallTargetResolver8616,
)
from inertia.semantics.direct_near_call_target_binding import DirectNearCallTargetBinding8616

from .entry_domain_call_preservation import (
    EntryDomainCallPreservation8616,
    Real16InvocationSource8616,
    _exact_boundary_for_8616,
    _premise_target_resolver_8616,
    collect_entry_domain_call_preservations_8616,
)
from .real16_invocation_domain import (
    DeclaredFunctionEntryLink8616,
    Real16CallChainLink8616,
    Real16CallInvocation8616,
    Real16InvocationDomain8616,
)
from .segment_call_preservation import SegmentCallPreservationResult8616


def _invocation_facts(invocation: Real16CallInvocation8616 | None, seen: set[int]) -> object:
    """Detach exact callsite use and its recursively retained premise."""
    if invocation is None or id(invocation) in seen:
        return id(invocation)
    seen.add(id(invocation))
    return (id(invocation), invocation.callsite_addr, invocation.target_addr,
            id(invocation.project), id(invocation.block), _scope_facts(invocation.premise, seen))


def _binding_facts(binding: DirectNearCallTargetBinding8616 | None, seen: set[int]) -> object:
    """Detach native target theorem fields without invoking its validator."""
    if binding is None or id(binding) in seen:
        return id(binding)
    seen.add(id(binding))
    return (id(binding), binding.callsite_addr, binding.target_addr, binding.verdict,
            binding.failure, deepcopy(binding.stats), deepcopy(binding.shape),
            _invocation_facts(binding.invocation, seen), id(binding.selector_binding))


def _proof_facts(proof: object, seen: set[int]) -> object:
    """Snapshot supported prior proofs; unsupported authority fails closed."""
    from .declared_selector_call_preservation import _callee_facts_8616, _coverage_facts_8616, _index_facts_8616

    if proof is None or id(proof) in seen:
        return id(proof)
    if type(proof) is EntryDomainCallPreservation8616:
        return _record_facts(proof, seen)
    if type(proof) is SegmentCallPreservationResult8616:
        seen.add(id(proof))
        visited = seen
        return (id(proof), _coverage_facts_8616(proof.caller), _callee_facts_8616(proof.callee, seen),
                _index_facts_8616(proof.index), proof.callsite_addr, proof.failure,
                proof.raw_fact_count, proof.normalized_fact_count, proof.classified_fact_count,
                proof.materialized_count, proof.failure_count,
                _invocation_facts(proof.invocation, visited), _scope_facts(proof.invocation_scope, visited))
    return object()


def _scope_facts(scope: Real16InvocationDomain8616 | None, seen: set[int]) -> object:
    """Detach explicit invocation fields without calling diagnostic/proof methods."""
    if scope is None or id(scope) in seen:
        return id(scope)
    seen.add(id(scope))
    chain = scope.chain
    chain_facts: object = id(chain)
    if type(chain) is DeclaredFunctionEntryLink8616:
        chain_facts = (id(chain), id(chain.artifact), id(chain.boundary), deepcopy(chain.admission))
    elif type(chain) is Real16CallChainLink8616:
        chain_facts = (id(chain), _scope_facts(chain.parent, seen),
                       id(chain.callsite_index), id(chain.callsite), id(chain.callsite_artifact),
                       id(chain.callsite_boundary), deepcopy(chain.call_state),
                       id(chain.callee_artifact), id(chain.callee_boundary),
                       _binding_facts(chain.entry_binding, seen), _proof_facts(chain.edge, seen))
    return (id(scope), id(scope.project), id(scope.coverage), id(scope.boot), id(scope.boot_recompute),
            scope.callsite_addr, scope.entry_segment, scope.entry_offset, scope.stack_segment,
            scope.stack_offset, scope.load_segment, scope.source_sha256,
            scope.minimum_selector, scope.maximum_selector, scope.kind, scope.path_block_addrs,
            scope.fetched_range_count, scope.checked_store_count, scope.failure,
            scope.raw_fact_count, scope.normalized_fact_count, scope.classified_fact_count,
            scope.materialized_count, scope.failure_count, chain_facts,
            tuple(_proof_facts(record, seen) for record in scope.call_preservations),
            tuple(_proof_facts(record, seen) for record in scope.entry_call_preservations),
            deepcopy((scope.assumptions, scope.callsite_call_state, scope.callsite_memory,
                      scope.declared_services, scope.service_consumptions,
                      scope.refusal_site, scope.infeasible_edges)))


def _entry_facts(entry: DecodedDirectCallsite8616 | None) -> object:
    """Detach a possibly equal but distinct decoded entry without native handles."""
    from .declared_selector_call_preservation import _native_entry_facts_8616

    if entry is None:
        return None
    return (id(entry), entry.caller_start, id(entry.instructions), entry.instruction_index,
            entry.callsite_addr, entry.target_addr, id(entry.entry_identity), entry.is_far,
            _native_entry_facts_8616(entry))


def _record_facts(
    record: EntryDomainCallPreservation8616, seen: set[int],
) -> object:
    """Detach retained proof fields before callbacks may mutate both aliases."""
    from .declared_selector_call_preservation import _callee_facts_8616, _index_facts_8616

    if id(record) in seen:
        return id(record)
    seen.add(id(record))
    callee = record.callee
    return (id(record), id(record.artifact), id(record.block), id(record.instruction),
            id(record.boundary), _entry_facts(record.entry), id(record.selector_binding), _scope_facts(record.required_scope, seen),
            record.callsite_addr, record.target_addr, record.failure,
            record.raw_fact_count, record.normalized_fact_count, record.classified_fact_count,
            record.materialized_count, record.failure_count, _index_facts_8616(record.index),
            _binding_facts(record.binding, seen),
            None if callee is None else (_callee_facts_8616(callee, seen), _scope_facts(callee.state.invocation_scope, seen)))


def scoped_selector_record_facts_8616(record: EntryDomainCallPreservation8616) -> object:
    """Snapshot one complete proof graph once per fresh public operation."""
    return _record_facts(record, set())


def scoped_selector_records_facts_8616(
    records: tuple[EntryDomainCallPreservation8616, ...],
) -> tuple[object, ...]:
    """Snapshot the entire retained batch with shared-node identity references."""
    seen: set[int] = set()
    return tuple(_record_facts(record, seen) for record in records)


def scoped_selector_records_current_8616(
    records: tuple[EntryDomainCallPreservation8616, ...],
) -> bool:
    """Reauthenticate each exact caller premise and conditional callee closure."""
    before = scoped_selector_records_facts_8616(records)
    for record in records:
        if record.required_scope is None or not record.complete_for(record.required_scope):
            return False
    return before == scoped_selector_records_facts_8616(records)


@dataclass(slots=True)
class ScopedSelectorCollection8616:
    """One operation-local batch of missing-boundary callsite demands."""

    project: object
    source: Real16InvocationSource8616
    root: DeclaredFunctionEntryLink8616 | None
    records: tuple[EntryDomainCallPreservation8616, ...] = ()
    attempted: bool = False
    facts: tuple[object, ...] = field(default=())

    def collect(self) -> None:
        """Demand missing native boundaries once under existing shared budgets."""
        if self.attempted or self.root is None:
            return
        self.attempted = True
        root = self.root
        calls = {row.addr for block in root.artifact.blocks for row in block.instrs if row.op == "CALL"}
        selected = frozenset(row.callsite_addr for rows in self.source.callsite_index._entries_by_normalized_target.values() for row in rows
                             if row.caller_start == root.artifact.function_addr
                             and row.callsite_addr in calls
                             and _exact_boundary_for_8616(self.project, row.target_addr) is None)
        if not selected:
            return
        records = collect_entry_domain_call_preservations_8616(
            self.project, root.artifact, root.boundary,
            direct_target_resolver=cast(DirectCallTargetResolver8616, _premise_target_resolver_8616(self.project)),
            selected_callsites=selected,
        )
        accepted = []
        for record in records:
            required = record.required_scope
            if record.artifact is not root.artifact or required is None:
                continue
            if (type(required.chain) is not DeclaredFunctionEntryLink8616
                    or required.chain.admission is not root.admission
                    or required.chain.artifact is not root.artifact
                    or required.chain.boundary is not root.boundary):
                continue
            if record.complete_for(required):
                accepted.append(record)
        self.records = tuple(accepted)
        self.facts = scoped_selector_records_facts_8616(self.records)

    def record(self, head: int, callsite: int) -> EntryDomainCallPreservation8616 | None:
        """Select one original call record without merging sibling invocations."""
        return next((record for record in self.records if record.artifact.function_addr == head
                     and record.callsite_addr == callsite), None)


def scoped_selector_facts_work_8616(facts: object) -> int:
    """Count detached tuple and mapping entries walked by a pure seal."""
    if isinstance(facts, (tuple, list)):
        return 1 + sum(scoped_selector_facts_work_8616(item) for item in facts)
    if isinstance(facts, dict):
        return 1 + sum(scoped_selector_facts_work_8616(item) for item in facts.values())
    return 1
