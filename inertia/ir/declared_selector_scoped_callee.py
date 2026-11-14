# cython: language_level=3, infer_types=True
"""Layer: IR.
Responsibility: retain invocation-bound callee proofs during selector induction.

Unresolved native callees demand the existing scoped collection route, including
the earlier CALL proofs needed to reach those demands.
The original records remain conditional and are never published as summaries.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""
from __future__ import annotations
import typing
import cython

from copy import deepcopy
from dataclasses import dataclass, field
from typing import cast

from inertia.frontend.x86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DirectCallTargetResolver8616,
)
from inertia.semantics.direct_near_call_target_binding import DirectNearCallTargetBinding8616

from .core import IRFunctionArtifact
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
    _dangerous_block_addrs_8616,
)
from .segment_call_preservation import SegmentCallPreservationResult8616
import dataclasses
import operator
import builtins


@cython.ccall
def _invocation_facts(invocation: object, seen: object) -> object:
    """Detach exact callsite use and its recursively retained premise."""
    if invocation is None or id(invocation) in seen:
        return id(invocation)
    seen.add(id(invocation))
    return (id(invocation), invocation.callsite_addr, invocation.target_addr,
            id(invocation.project), id(invocation.block), _scope_facts(invocation.premise, seen))


@cython.ccall
def _binding_facts(binding: object, seen: object) -> object:
    """Detach native target theorem fields without invoking its validator."""
    if binding is None or id(binding) in seen:
        return id(binding)
    seen.add(id(binding))
    return (id(binding), binding.callsite_addr, binding.target_addr, binding.verdict,
            binding.failure, deepcopy(binding.stats), deepcopy(binding.shape),
            _invocation_facts(binding.invocation, seen), id(binding.selector_binding))


@cython.ccall
def _shared_index_facts(index: DecodedDirectCallsiteIndex8616, seen: object) -> object:
    """Snapshot each retained native index once within this fresh proof graph.

    Later references retain identity, so replacing an index remains visible.
    The first reference detaches every mutable map and native coordinate; each
    new snapshot has a fresh visited set and therefore sees later mutations.
    """
    from .declared_selector_call_preservation import _index_facts_8616

    if id(index) in seen:
        return id(index)
    seen.add(id(index))
    return id(index), _index_facts_8616(index)


@cython.ccall
def _proof_facts(proof: object, seen: object) -> object:
    """Snapshot supported prior proofs; unsupported authority fails closed."""
    from .declared_selector_call_preservation import _callee_facts_8616, _coverage_facts_8616

    if proof is None or id(proof) in seen:
        return id(proof)
    if type(proof) is EntryDomainCallPreservation8616:
        return _record_facts(proof, seen)
    if type(proof) is SegmentCallPreservationResult8616:
        prior = cast("SegmentCallPreservationResult8616", proof)
        seen.add(id(prior))
        visited = seen
        return (id(prior), _coverage_facts_8616(prior.caller), _callee_facts_8616(prior.callee, seen),
                _shared_index_facts(prior.index, seen), prior.callsite_addr, prior.failure,
                prior.raw_fact_count, prior.normalized_fact_count, prior.classified_fact_count,
                prior.materialized_count, prior.failure_count,
                _invocation_facts(prior.invocation, visited), _scope_facts(prior.invocation_scope, visited))
    return object()


def _scope_facts(scope: object, seen: object) -> object:
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
            tuple(_proof_facts(record, seen) for record in iter(scope.call_preservations)),
            tuple(_proof_facts(record, seen) for record in iter(scope.entry_call_preservations)),
            deepcopy((scope.assumptions, scope.callsite_call_state, scope.callsite_memory,
                      scope.declared_services, scope.service_consumptions,
                      scope.refusal_site, scope.infeasible_edges)))


@cython.ccall
def _entry_facts(entry: object) -> object:
    """Detach a possibly equal but distinct decoded entry without native handles."""
    from .declared_selector_call_preservation import _native_entry_facts_8616

    if entry is None:
        return None
    return (id(entry), entry.caller_start, id(entry.instructions), entry.instruction_index,
            entry.callsite_addr, entry.target_addr, id(entry.entry_identity), entry.is_far,
            _native_entry_facts_8616(entry))


@cython.ccall
def _record_facts(
    record: EntryDomainCallPreservation8616, seen: object,
) -> object:
    """Detach retained proof fields before callbacks may mutate both aliases."""
    callee: object
    from .declared_selector_call_preservation import _callee_facts_8616

    if id(record) in seen:
        return id(record)
    seen.add(id(record))
    callee = record.callee
    return (id(record), id(record.artifact), id(record.block), id(record.instruction),
            id(record.boundary), _entry_facts(record.entry), id(record.selector_binding), _scope_facts(record.required_scope, seen),
            record.callsite_addr, record.target_addr, record.failure,
            record.raw_fact_count, record.normalized_fact_count, record.classified_fact_count,
            record.materialized_count, record.failure_count, _shared_index_facts(record.index, seen),
            _binding_facts(record.binding, seen),
            None if callee is None else (_callee_facts_8616(callee, seen), _scope_facts(callee.state.invocation_scope, seen)))


@cython.ccall
def scoped_selector_record_facts_8616(record: EntryDomainCallPreservation8616) -> object:
    """Snapshot one complete proof graph once per fresh public operation."""
    return _record_facts(record, set())


def scoped_selector_records_facts_8616(
    records: object,
) -> tuple[object, ...]:
    """Snapshot the entire retained batch with shared-node identity references."""
    seen: set[cython.longlong] = set()
    return tuple(_record_facts(record, seen) for record in iter(records))


@cython.ccall
def scoped_selector_records_current_8616(
    records: object,
    *, before: object = None,
) -> cython.bint:
    """Freshly authenticate all closures and compare their detached graph.

    An enclosing synchronous seal may supply its earlier snapshot. It is only
    a mutation guard: every record still reauthenticates, and the ending graph
    is always read freshly. No admission or snapshot is retained for replay.
    """
    record: object
    if before is None:
        before = scoped_selector_records_facts_8616(records)
    for record in records:
        if record.required_scope is None or not record.complete_for(record.required_scope):
            return False
    return operator.eq(before, scoped_selector_records_facts_8616(records))


@cython.ccall
def _prerequisite_callsites_8616(
    artifact: IRFunctionArtifact, selected: object,
) -> frozenset[cython.longlong]:
    """Include the canonical census prefixes needed to prove selected CALLs.

    This selects proof requests only; it grants no coverage or call effects.
    Instruction order bounds the terminal block, so a later CALL in that
    block is not demanded merely because an earlier callee lacks a boundary.
    """
    block: object
    instruction: object
    target: object
    target_block: object
    required = set(selected)
    for target_block in artifact.blocks:
        for target in target_block.instrs:
            if target.op != "CALL" or target.addr not in selected:
                continue
            prefix = _dangerous_block_addrs_8616(artifact, target_block)
            for block in artifact.blocks:
                if block.addr not in prefix:
                    continue
                for instruction in block.instrs:
                    if instruction.op == "CALL" and type(instruction.addr) is int:
                        required.add(instruction.addr)
                    if block is target_block and instruction is target:
                        break
    return frozenset(required)


@cython.dataclasses.dataclass()
class ScopedSelectorCollection8616:
    """One operation-local batch of missing-boundary callsite demands."""

    project: object
    source: Real16InvocationSource8616
    root: DeclaredFunctionEntryLink8616 | None
    records: tuple[EntryDomainCallPreservation8616, ...] = ()
    attempted: cython.bint = False
    facts: object = field(default=())

    def collect(self) -> None:
        """Demand missing boundaries and their CALL prerequisites under shared budgets."""
        required: object
        record: object
        if self.attempted or self.root is None:
            return
        self.attempted = True
        root = self.root
        calls = {row.addr for block in iter(root.artifact.blocks) for row in iter(block.instrs) if row.op == "CALL"}
        selected = frozenset(row.callsite_addr for rows in builtins.iter(self.source.callsite_index._entries_by_normalized_target.values()) for row in iter(rows)
                             if operator.eq(row.caller_start, root.artifact.function_addr)
                             and row.callsite_addr in calls
                             and _exact_boundary_for_8616(self.project, row.target_addr) is None)
        if not selected:
            return
        selected = _prerequisite_callsites_8616(root.artifact, selected)
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

    def record(self, head: cython.longlong, callsite: cython.longlong) -> EntryDomainCallPreservation8616 | None:
        """Select one original call record without merging sibling invocations."""
        return next((record for record in iter(self.records) if operator.eq(record.artifact.function_addr, head)
                     and operator.eq(record.callsite_addr, callsite)), None)


def scoped_selector_facts_work_8616(facts: object) -> cython.longlong:
    """Count detached tuple and mapping entries walked by a pure seal."""
    if isinstance(facts, (tuple, list)):
        return 1 + sum(scoped_selector_facts_work_8616(item) for item in iter(facts))
    if isinstance(facts, dict):
        return 1 + sum(scoped_selector_facts_work_8616(item) for item in builtins.iter(facts.values()))
    return 1
