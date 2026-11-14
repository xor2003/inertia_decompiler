# cython: language_level=3, infer_types=True
"""Resolve and publish SCC-aware interprocedural storage contracts.

Layer: Types/Lowering.
Responsibility: propagate concrete direct output seeds through deferred recursive
return pass-throughs, resolve complete function joins to a deterministic fixed
point, and produce one atomic publication payload. This module does not infer
signatures, mutate codegen, or synthesize missing SSA return reads.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: signature guessing or partial publication.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass, field

from inertia.pipeline.errors import PipelineHardError

from .interprocedural_storage_contracts import (
    FunctionStorageResolution8616,
    FunctionStorageTrials8616,
    ProgramStorageResolution8616,
    StorageSlotContract8616,
    StorageTrialStats8616,
)
from .interprocedural_storage_function_solver import (
    FunctionStorageTrialJoin8616,
    join_function_storage_trials_8616,
    resolve_joined_function_storage_trials_8616,
)
from .interprocedural_storage_return_discard import discarded_return_census_proves_empty_8616
import dataclasses
import operator
import builtins

__all__ = ["resolve_program_storage_trials_8616"]

_OutputSeed8616 = typing.TypeAliasType("_OutputSeed8616", tuple[StorageSlotContract8616, ...])


@dataclasses.dataclass(frozen=True, )
class _SCCOutputState8616:
    """One immutable fixed-point state for direct and propagated outputs."""

    direct_outputs: object
    passthrough_outputs: object

    def direct_for(self, function_addr: cython.longlong) -> _OutputSeed8616 | None:
        """Return the concrete direct seed for one SCC member."""
        return next(
            (outputs for address, outputs in iter(self.direct_outputs) if address == function_addr),
            None,
        )

    def passthrough_for(self, function_addr: cython.longlong) -> _OutputSeed8616 | None:
        """Return the seed propagated through all of one member's deferred facts."""
        return next(
            (
                outputs
                for address, outputs in iter(self.passthrough_outputs)
                if address == function_addr
            ),
            None,
        )


@cython.ccall
def _caller_callee_graph_8616(
    trials_by_addr: object,
) -> object:
    """Build internal caller-to-callee edges for tracked functions only."""
    callee_addr: object
    callsite: object
    trials: object
    graph: dict[cython.longlong, set[cython.longlong]] = {address: set() for address in iter(trials_by_addr)}
    for callee_addr, trials in trials_by_addr.items():
        for callsite in trials.callsites:
            if callsite.caller_addr in graph:
                graph[callsite.caller_addr].add(callee_addr)
    return graph


@cython.dataclasses.dataclass()
class _TarjanState8616:
    """Mutable Tarjan traversal state over the deterministic call graph."""

    graph: object
    index: cython.longlong = 0
    indices: object = field(default_factory=dict)
    lowlinks: object = field(default_factory=dict)
    stack: object = field(default_factory=list)
    on_stack: object = field(default_factory=set)
    components: object = field(default_factory=list)

    @cython.ccall
    def visit(self, node: cython.longlong) -> None:
        """Visit one node and emit its component after all descendants."""
        member: object
        target: object
        self.indices[node] = self.index
        self.lowlinks[node] = self.index
        self.index += 1
        self.stack.append(node)
        self.on_stack.add(node)
        for target in sorted(self.graph[node]):
            if target not in self.indices:
                self.visit(target)
                self.lowlinks[node] = min(self.lowlinks[node], self.lowlinks[target])
            elif target in self.on_stack:
                self.lowlinks[node] = min(self.lowlinks[node], self.indices[target])
        if operator.ne(self.lowlinks[node], self.indices[node]):
            return
        component: list[cython.longlong] = []
        while True:
            member = self.stack.pop()
            self.on_stack.remove(member)
            component.append(member)
            if operator.eq(member, node):
                break
        self.components.append(tuple(sorted(component)))


def _deterministic_sccs_8616(
    trials_by_addr: object,
) -> tuple[tuple[cython.longlong, ...], ...]:
    """Return deterministic Tarjan SCCs for internal caller-to-callee edges."""
    node: object
    graph = _caller_callee_graph_8616(trials_by_addr)
    state = _TarjanState8616(graph)
    for node in sorted(graph):
        if node not in state.indices:
            state.visit(node)
    return tuple(sorted(state.components, key=lambda item: item[0]))


@cython.ccall
def _direct_output_seed_8616(
    joined: FunctionStorageTrialJoin8616, scc: object,
) -> _OutputSeed8616 | None:
    """Add empty seeds only from a closed independent discarded-result census."""
    seed: object
    seed = joined.direct_output_seed
    if seed is not None or joined.failures:
        return seed
    return () if discarded_return_census_proves_empty_8616(joined.trials, frozenset(scc)) else None


def _next_scc_output_state_8616(
    scc: object,
    joined_by_addr: object,
    previous: object,
) -> _SCCOutputState8616:
    """Advance direct seeds through exact recursive pass-through relations once."""
    function_addr: object
    direct_outputs = tuple(
        (function_addr, _direct_output_seed_8616(joined_by_addr[function_addr], scc))
        for function_addr in iter(scc)
    )
    passthrough_outputs: list[tuple[cython.longlong, _OutputSeed8616 | None]] = []
    for function_addr in scc:
        joined = joined_by_addr[function_addr]
        outputs = None
        if joined.passthroughs and previous is not None:
            outputs = previous.direct_for(function_addr)
        passthrough_outputs.append((function_addr, outputs))
    return _SCCOutputState8616(
        direct_outputs=direct_outputs,
        passthrough_outputs=tuple(passthrough_outputs),
    )


@cython.ccall
def _resolve_scc_output_state_8616(
    scc: object,
    joined_by_addr: object,
) -> tuple[_SCCOutputState8616, cython.longlong]:
    """Reach a bounded deterministic output/pass-through fixed point."""
    previous: object
    previous = None
    for iteration in range(1, len(scc) + 4):
        current = _next_scc_output_state_8616(scc, joined_by_addr, previous)
        if previous is not None and operator.eq(current, previous):
            return current, iteration
        previous = current
    raise PipelineHardError(
        "interprocedural storage outputs did not reach a fixed point",
        layer="types/lowering",
        details=scc,
    )


def _sum_stats_8616(
    resolutions: Iterable[FunctionStorageResolution8616],
) -> StorageTrialStats8616:
    """Accumulate mandatory evidence counters across function resolutions."""
    items = tuple(resolutions)
    return StorageTrialStats8616(
        raw_fact_count=sum(item.stats.raw_fact_count for item in iter(items)),
        normalized_fact_count=sum(item.stats.normalized_fact_count for item in iter(items)),
        classified_fact_count=sum(item.stats.classified_fact_count for item in iter(items)),
        materialized_count=sum(item.stats.materialized_count for item in iter(items)),
        failure_count=sum(item.stats.failure_count for item in iter(items)),
    )


def resolve_program_storage_trials_8616(
    function_trials: Iterable[FunctionStorageTrials8616],
) -> ProgramStorageResolution8616:
    """Resolve all SCCs to a deterministic fixed point without partial mutation."""
    address: object
    scc: object
    supplied = tuple(function_trials)
    trials_by_addr = {item.function_addr: item for item in iter(supplied)}
    if operator.ne(len(trials_by_addr), len(supplied)):
        raise PipelineHardError("duplicate function storage trials", layer="types/lowering")
    joined_by_addr = {
        address: join_function_storage_trials_8616(trials)
        for address, trials in builtins.iter(trials_by_addr.items())
    }
    sccs = _deterministic_sccs_8616(trials_by_addr)
    resolved: dict[cython.longlong, FunctionStorageResolution8616] = {}
    iterations_by_scc: list[cython.longlong] = []
    for scc in sccs:
        output_state, iterations = _resolve_scc_output_state_8616(scc, joined_by_addr)
        iterations_by_scc.append(iterations)
        for address in scc:
            resolution = resolve_joined_function_storage_trials_8616(
                joined_by_addr[address],
                output_state.passthrough_for(address),
                recursive_callers=frozenset(scc),
            )
            resolved[address] = resolution
    ordered = tuple(resolved[address] for address in builtins.iter(sorted(resolved)))
    return ProgramStorageResolution8616(
        function_trials=tuple(trials_by_addr[address] for address in builtins.iter(sorted(trials_by_addr))),
        resolutions=ordered,
        sccs=sccs,
        iterations_by_scc=tuple(iterations_by_scc),
        stats=_sum_stats_8616(ordered),
    )
