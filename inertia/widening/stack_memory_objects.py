# cython: language_level=3, infer_types=True
"""Widen Alias-proved nested stack byte views into canonical objects.

Layer: Widening.
Responsibility: resolve each composed stack overlap component to one unique
containing storage range, or emit one typed refusal for the whole component.
Consumes alias-proven storage identity; do not infer C types or materialize locals.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations
import typing
import cython

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Protocol, cast

from inertia.alias.alias_model_impl import AliasStorageFacts
from inertia.alias.stack_memory_ssa_contracts import (
    StackMemoryAliasFactKind8616,
    StackMemorySSAAliasAccess8616,
    StackMemorySSAAliasArtifact8616,
    StackMemorySSAAliasFact8616,
)
from inertia.ir.core import IRAddress
from inertia.ir.ssa_memory_contracts import (
    SSACallStackEffectSite8616,
    SSAMemoryAccessKind8616,
    SSAMemoryOverlapRelation8616,
)
from inertia.pipeline.errors import PipelineHardError

from .stack_memory_objects_contracts import (
    StackMemoryObjectWideningArtifact8616,
    StackMemoryObjectWideningCandidate8616,
    StackMemoryObjectWideningRefusal8616,
    StackMemoryObjectWideningRefusalKind8616,
    StackMemoryObjectWideningStats8616,
)
import dataclasses
import operator
import builtins

_RangeKey8616 = typing.TypeAliasType("_RangeKey8616", tuple[str, tuple[str, ...], int, int])


class _CodegenBoundary8616(Protocol):
    """Owned artifacts carried across the dynamic angr codegen boundary."""
    _inertia_stack_memory_ssa_alias_artifact: object
    _inertia_stack_memory_object_widening_artifact: StackMemoryObjectWideningArtifact8616


@dataclasses.dataclass(frozen=True, )
class _RangeEvidence8616:
    """Alias storage and source records for one unversioned stack range."""
    address: IRAddress
    storages: object
    accesses: object
    facts: object

    @property
    def storage(self) -> AliasStorageFacts | None:
        """Return the unique storage identity, or ``None`` on disagreement."""
        if not self.storages:
            return None
        first = self.storages[0]
        return first if all(storage == first for storage in iter(self.storages[1:])) else None


@cython.ccall
def _range_key_8616(address: IRAddress) -> _RangeKey8616:
    """Return deterministic unversioned segmented range identity."""
    return (address.space.value, address.base, address.offset, address.size)


def _composed_accesses_8616(source: StackMemorySSAAliasArtifact8616) -> object:
    """Return raw composed views plus separately proven logical owners."""
    return source.accesses + tuple(item.alias_access for item in iter(source.logical_accesses))


@cython.ccall
def _contains_range_8616(owner: IRAddress, member: IRAddress) -> cython.bint:
    """Return whether one exact segmented range fully contains another."""
    return (
        owner.space is member.space
        and operator.eq(owner.base, member.base)
        and owner.offset <= member.offset
        and member.offset + member.size <= owner.offset + owner.size
    )


def _connected_components_8616(
    adjacency: object,
    composed_keys: object,
) -> tuple[frozenset[_RangeKey8616], ...]:
    """Return overlap components that contain at least one composed access."""
    key: object
    remaining = set(adjacency)
    components: list[frozenset[_RangeKey8616]] = []
    while remaining:
        root = min(remaining)
        pending = [root]
        component: set[_RangeKey8616] = set()
        while pending:
            key = pending.pop()
            if key in component:
                continue
            component.add(key)
            pending.extend(sorted(tuple(adjacency.get(key, ())), reverse=True))
        remaining.difference_update(component)
        if component & composed_keys:
            components.append(frozenset(component))
    components.extend(frozenset((key,)) for key in builtins.iter(sorted(composed_keys - set(adjacency))))
    return tuple(sorted(components, key=lambda item: min(item)))


@cython.ccall
def _range_evidence_8616(
    source: StackMemorySSAAliasArtifact8616,
) -> dict[_RangeKey8616, _RangeEvidence8616]:
    """Collect every range's Alias storage and source records."""
    access: object
    address: object
    fact: object
    item: object
    overlap: object
    storage: object
    addresses: dict[_RangeKey8616, IRAddress] = {}
    storages: object = defaultdict(list)
    accesses: object = defaultdict(list)
    facts: object = defaultdict(list)
    for access in _composed_accesses_8616(source):
        key = _range_key_8616(access.source.address)
        addresses[key] = replace(access.source.address, version=None)
        storages[key].append(access.storage)
        accesses[key].append(access)
        for item in access.slices:
            slice_key = _range_key_8616(item.source.address)
            addresses[slice_key] = replace(item.source.address, version=None)
            storages[slice_key].append(item.storage)
    for fact in source.facts:
        key = _range_key_8616(fact.address)
        addresses[key] = replace(fact.address, version=None)
        storages[key].append(fact.storage)
        facts[key].append(fact)
    for overlap in source.overlaps:
        for address, storage in (
            (overlap.source.left, overlap.left_storage),
            (overlap.source.right, overlap.right_storage),
        ):
            key = _range_key_8616(address)
            addresses[key] = replace(address, version=None)
            storages[key].append(storage)
    return {
        key: _RangeEvidence8616(
            address=addresses[key],
            storages=tuple(storages[key]),
            accesses=tuple(accesses[key]),
            facts=tuple(facts[key]),
        )
        for key in builtins.iter(sorted(addresses))
    }


def _component_refusal_8616(
    kind: StackMemoryObjectWideningRefusalKind8616,
    detail: object,
    component: Iterable[_RangeKey8616],
    evidence: object,
) -> StackMemoryObjectWideningRefusal8616:
    """Build one deterministic refusal covering an entire component."""
    addresses = tuple(sorted((evidence[key].address for key in iter(component)), key=_range_key_8616))
    return StackMemoryObjectWideningRefusal8616(kind, detail, addresses)


def _candidate_for_component_8616(
    component: object,
    evidence: object,
    *,
    has_partial_overlap: cython.bint,
    call_effects: object,
) -> StackMemoryObjectWideningCandidate8616 | StackMemoryObjectWideningRefusal8616:
    """Resolve one component to its unique containing Alias object or typed refusal."""
    owner_storage: object
    version: object
    owners = [
        key
        for key in builtins.iter(sorted(component))
        if all(_contains_range_8616(evidence[key].address, evidence[member].address) for member in iter(component))
    ]
    if len(owners) != 1:
        refusal_kinds = StackMemoryObjectWideningRefusalKind8616
        if has_partial_overlap:
            return _component_refusal_8616(
                refusal_kinds.PARTIAL_OVERLAP, "partial overlap lacks one containing Alias range", component, evidence
            )
        return _component_refusal_8616(
            refusal_kinds.MISSING_UNIQUE_OWNER, "overlap component has no unique containing range", component, evidence
        )
    owner = evidence[owners[0]]
    owner_storage = owner.storage
    if not owner.accesses:
        return _component_refusal_8616(
            StackMemoryObjectWideningRefusalKind8616.OWNER_NOT_COMPOSED_ACCESS,
            "containing range is not an Alias-proved composed access",
            component,
            evidence,
        )
    if owner_storage is None or any(
        member.storage is None
        or (operator.ne(member.address, owner.address) and not owner_storage.contains(member.storage))
        for member in iter((evidence[key] for key in iter(component)))
    ):
        return _component_refusal_8616(
            StackMemoryObjectWideningRefusalKind8616.INCONSISTENT_STORAGE,
            "nested ranges do not share one containing Alias storage identity",
            component,
            evidence,
        )
    source_accesses = tuple(
        sorted(
            (access for key in iter(component) for access in iter(evidence[key].accesses)),
            key=lambda access: (access.source.block_addr, access.source.instr_index, _range_key_8616(access.source.address)),
        )
    )
    source_facts = tuple(
        sorted(
            (fact for key in iter(component) for fact in iter(evidence[key].facts)),
            key=lambda fact: (fact.block_addr, -1 if fact.instr_index is None else fact.instr_index, fact.kind.value),
        )
    )
    versions = {
        version
        for access in iter(source_accesses)
        for item in iter(access.slices)
        if (version := item.source.address.version) is not None
    }
    versions.update(
        version
        for fact in iter(source_facts)
        for version in iter((fact.address.version, ) + tuple(fact.incoming_versions))
        if version is not None
    )
    fact_kinds = {fact.kind for fact in iter(source_facts)}
    fact_kinds.update(
        StackMemoryAliasFactKind8616.STORE
        if access.source.kind is SSAMemoryAccessKind8616.STORE
        else StackMemoryAliasFactKind8616.LOAD
        for access in iter(source_accesses)
    )
    return StackMemoryObjectWideningCandidate8616(
        address=owner.address,
        storage=owner_storage,
        covered_addresses=tuple(
            sorted((evidence[key].address for key in iter(component)), key=_range_key_8616)
        ),
        source_accesses=source_accesses,
        source_facts=source_facts,
        versions=tuple(sorted(versions)),
        fact_kinds=tuple(sorted(fact_kinds, key=lambda kind: kind.value)),
        call_effects=call_effects,
    )


def build_x86_16_stack_memory_object_widening_artifact(
    source: StackMemorySSAAliasArtifact8616,
) -> StackMemoryObjectWideningArtifact8616:
    """Resolve Alias-composed stack views without guessing object identity."""
    access: object
    component: object
    item: object
    overlap: object
    if not source.complete:
        raise PipelineHardError(
            "stack-memory object Widening received incomplete Alias evidence",
            layer="widening",
        )
    evidence = _range_evidence_8616(source)
    composed_accesses = _composed_accesses_8616(source)
    composed_keys = {_range_key_8616(access.source.address) for access in iter(composed_accesses)}
    adjacency: object = defaultdict(set)
    partial_pairs: set[frozenset[_RangeKey8616]] = set()
    for overlap in source.overlaps:
        left = _range_key_8616(overlap.source.left)
        right = _range_key_8616(overlap.source.right)
        adjacency[left].add(right)
        adjacency[right].add(left)
        if overlap.source.relation is SSAMemoryOverlapRelation8616.PARTIAL:
            partial_pairs.add(frozenset((left, right)))
    for access in composed_accesses:
        owner = _range_key_8616(access.source.address)
        for item in access.slices:
            slice_key = _range_key_8616(item.source.address)
            if slice_key == owner:
                continue
            adjacency[owner].add(slice_key)
            adjacency[slice_key].add(owner)
    candidates: list[StackMemoryObjectWideningCandidate8616] = []
    refusals = [
        StackMemoryObjectWideningRefusal8616(StackMemoryObjectWideningRefusalKind8616.SOURCE_LOGICAL_ALIAS_REFUSAL, refusal.detail, tuple(()) if refusal.source is None else tuple((refusal.source.address,)), refusal)
        for refusal in iter(source.logical_refusals)
    ]
    components = _connected_components_8616(adjacency, composed_keys)
    for component in components:
        if len(component) == 1:
            refusals.append(
                _component_refusal_8616(
                    StackMemoryObjectWideningRefusalKind8616.ORPHAN_COMPOSED_ACCESS,
                    "composed access has no Alias overlap evidence for its internal byte boundary",
                    component,
                    evidence,
                )
            )
            continue
        outcome = _candidate_for_component_8616(
            component,
            evidence,
            has_partial_overlap=any(pair <= component for pair in iter(partial_pairs)),
            call_effects=source.call_effects,
        )
        if isinstance(outcome, StackMemoryObjectWideningCandidate8616):
            candidates.append(outcome)
        else:
            refusals.append(outcome)
    stats = StackMemoryObjectWideningStats8616(
        raw_fact_count=len(components) + len(source.logical_refusals),
        normalized_fact_count=len(candidates),
        classified_fact_count=len(candidates),
        materialized_count=len(candidates),
        failure_count=len(refusals),
    )
    return StackMemoryObjectWideningArtifact8616(
        function_addr=source.function_addr,
        source_alias=source,
        candidates=tuple(candidates),
        refusals=tuple(refusals),
        stats=stats,
    )


@cython.ccall
def apply_x86_16_stack_memory_object_widening_8616(
    _project: object,
    codegen: object,
) -> cython.bint:
    """Attach composed stack-object Widening after the exact Alias artifact."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        source = boundary._inertia_stack_memory_ssa_alias_artifact
    except AttributeError:
        return False
    if not isinstance(source, StackMemorySSAAliasArtifact8616):
        return False
    try:
        existing = boundary._inertia_stack_memory_object_widening_artifact
    except AttributeError:
        existing = None
    if isinstance(existing, StackMemoryObjectWideningArtifact8616) and existing.source_alias is source:
        if not existing.complete:
            raise PipelineHardError(
                "cached stack-memory object Widening evidence is incomplete",
                layer="widening",
                details=existing.to_dict(),
            )
        return False
    artifact = build_x86_16_stack_memory_object_widening_artifact(source)
    boundary._inertia_stack_memory_object_widening_artifact = artifact
    if not artifact.complete:
        raise PipelineHardError(
            "stack-memory object Widening evidence accounting is incomplete",
            layer="widening",
            details=artifact.to_dict(),
        )
    return False

__all__ = ["apply_x86_16_stack_memory_object_widening_8616", "build_x86_16_stack_memory_object_widening_artifact"]
