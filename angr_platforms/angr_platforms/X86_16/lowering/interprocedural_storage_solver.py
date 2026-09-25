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

from collections.abc import Iterable
from dataclasses import dataclass, field

from ..pipeline.errors import PipelineHardError
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

__all__ = ["resolve_program_storage_trials_8616"]

type _OutputSeed8616 = tuple[StorageSlotContract8616, ...]


@dataclass(frozen=True, slots=True)
class _SCCOutputState8616:
    """One immutable fixed-point state for direct and propagated outputs."""

    direct_outputs: tuple[tuple[int, _OutputSeed8616 | None], ...]
    passthrough_outputs: tuple[tuple[int, _OutputSeed8616 | None], ...]

    def direct_for(self, function_addr: int) -> _OutputSeed8616 | None:
        """Return the concrete direct seed for one SCC member."""
        return next(
            (outputs for address, outputs in self.direct_outputs if address == function_addr),
            None,
        )

    def passthrough_for(self, function_addr: int) -> _OutputSeed8616 | None:
        """Return the seed propagated through all of one member's deferred facts."""
        return next(
            (
                outputs
                for address, outputs in self.passthrough_outputs
                if address == function_addr
            ),
            None,
        )


def _caller_callee_graph_8616(
    trials_by_addr: dict[int, FunctionStorageTrials8616],
) -> dict[int, set[int]]:
    """Build internal caller-to-callee edges for tracked functions only."""
    graph: dict[int, set[int]] = {address: set() for address in trials_by_addr}
    for callee_addr, trials in trials_by_addr.items():
        for callsite in trials.callsites:
            if callsite.caller_addr in graph:
                graph[callsite.caller_addr].add(callee_addr)
    return graph


@dataclass(slots=True)
class _TarjanState8616:
    """Mutable Tarjan traversal state over the deterministic call graph."""

    graph: dict[int, set[int]]
    index: int = 0
    indices: dict[int, int] = field(default_factory=dict)
    lowlinks: dict[int, int] = field(default_factory=dict)
    stack: list[int] = field(default_factory=list)
    on_stack: set[int] = field(default_factory=set)
    components: list[tuple[int, ...]] = field(default_factory=list)

    def visit(self, node: int) -> None:
        """Visit one node and emit its component after all descendants."""
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
        if self.lowlinks[node] != self.indices[node]:
            return
        component: list[int] = []
        while True:
            member = self.stack.pop()
            self.on_stack.remove(member)
            component.append(member)
            if member == node:
                break
        self.components.append(tuple(sorted(component)))


def _deterministic_sccs_8616(
    trials_by_addr: dict[int, FunctionStorageTrials8616],
) -> tuple[tuple[int, ...], ...]:
    """Return deterministic Tarjan SCCs for internal caller-to-callee edges."""
    graph = _caller_callee_graph_8616(trials_by_addr)
    state = _TarjanState8616(graph)
    for node in sorted(graph):
        if node not in state.indices:
            state.visit(node)
    return tuple(sorted(state.components, key=lambda item: item[0]))


def _direct_output_seed_8616(
    joined: FunctionStorageTrialJoin8616, scc: tuple[int, ...],
) -> _OutputSeed8616 | None:
    """Add empty seeds only from a closed independent discarded-result census."""
    seed: _OutputSeed8616 | None = joined.direct_output_seed
    if seed is not None or joined.failures:
        return seed
    return () if discarded_return_census_proves_empty_8616(joined.trials, frozenset(scc)) else None


def _next_scc_output_state_8616(
    scc: tuple[int, ...],
    joined_by_addr: dict[int, FunctionStorageTrialJoin8616],
    previous: _SCCOutputState8616 | None,
) -> _SCCOutputState8616:
    """Advance direct seeds through exact recursive pass-through relations once."""
    direct_outputs = tuple(
        (function_addr, _direct_output_seed_8616(joined_by_addr[function_addr], scc))
        for function_addr in scc
    )
    passthrough_outputs: list[tuple[int, _OutputSeed8616 | None]] = []
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


def _resolve_scc_output_state_8616(
    scc: tuple[int, ...],
    joined_by_addr: dict[int, FunctionStorageTrialJoin8616],
) -> tuple[_SCCOutputState8616, int]:
    """Reach a bounded deterministic output/pass-through fixed point."""
    previous: _SCCOutputState8616 | None = None
    for iteration in range(1, len(scc) + 4):
        current = _next_scc_output_state_8616(scc, joined_by_addr, previous)
        if previous is not None and current == previous:
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
        raw_fact_count=sum(item.stats.raw_fact_count for item in items),
        normalized_fact_count=sum(item.stats.normalized_fact_count for item in items),
        classified_fact_count=sum(item.stats.classified_fact_count for item in items),
        materialized_count=sum(item.stats.materialized_count for item in items),
        failure_count=sum(item.stats.failure_count for item in items),
    )


def resolve_program_storage_trials_8616(
    function_trials: Iterable[FunctionStorageTrials8616],
) -> ProgramStorageResolution8616:
    """Resolve all SCCs to a deterministic fixed point without partial mutation."""
    supplied = tuple(function_trials)
    trials_by_addr = {item.function_addr: item for item in supplied}
    if len(trials_by_addr) != len(supplied):
        raise PipelineHardError("duplicate function storage trials", layer="types/lowering")
    joined_by_addr = {
        address: join_function_storage_trials_8616(trials)
        for address, trials in trials_by_addr.items()
    }
    sccs = _deterministic_sccs_8616(trials_by_addr)
    resolved: dict[int, FunctionStorageResolution8616] = {}
    iterations_by_scc: list[int] = []
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
    ordered = tuple(resolved[address] for address in sorted(resolved))
    return ProgramStorageResolution8616(
        function_trials=tuple(trials_by_addr[address] for address in sorted(trials_by_addr)),
        resolutions=ordered,
        sccs=sccs,
        iterations_by_scc=tuple(iterations_by_scc),
        stats=_sum_stats_8616(ordered),
    )
