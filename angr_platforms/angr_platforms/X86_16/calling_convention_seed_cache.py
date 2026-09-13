"""Snapshot consumed calling-convention dependencies for in-process reuse.

Layer: Analysis/calling-convention coordination.
Responsibility: invalidate seeding when local CFG/prototype state, observed
result use, or an inspected callee contract changes. No semantic recovery.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from typing import Protocol, cast

from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeFunction

from .annotations import ANNOTATION_KEY
from .call_target_identity import resolve_x86_16_call_target_function_8616
from .callsite_summary import CallerReturnUseVerdict8616
from .lowering.return_type_evidence import proven_function_result_observation_8616


class _Node8616(Protocol):
    """Third-party CFG node identity used by terminal path proofs."""

    addr: int
    size: int | None


class _Graph8616(Protocol):
    """Third-party CFG adjacency consumed by terminal path proofs."""

    nodes: Iterable[_Node8616]

    def successors(self, node: _Node8616) -> Iterable[_Node8616]:
        """Return successors of one exact CFG node."""


class _Function8616(Protocol):
    """Optional third-party function fields read at the cache boundary."""

    addr: int
    block_addrs_set: Iterable[int]
    graph: _Graph8616
    prototype: SimTypeFunction | None
    is_prototype_guessed: bool
    prototype_source: PrototypeSource
    info: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class FunctionSeedState8616:
    """Detached local inputs; prototype copies detect in-place type changes."""

    address: int | None
    blocks: tuple[int, ...]
    graph: tuple[tuple[int, int | None, tuple[int, ...]], ...] | None
    prototype: SimTypeFunction | None
    guessed: bool
    source: PrototypeSource | None
    annotated_prototype: SimTypeFunction | None


@dataclass(frozen=True, slots=True)
class CalleeSeedDependency8616:
    """One inspected target, including a missing or refused callee contract."""

    target_addr: int
    state: FunctionSeedState8616 | None


@dataclass(frozen=True, slots=True)
class CallingConventionSeedRevision8616:
    """Local inputs and exact terminal-callee dependencies for one seed result."""

    project_identity: int
    local: FunctionSeedState8616
    observation: CallerReturnUseVerdict8616 | None
    callees: tuple[CalleeSeedDependency8616, ...]


def _prototype_snapshot(prototype: object) -> SimTypeFunction | None:
    """Copy mutable type facts without copying the immutable architecture."""
    if not isinstance(prototype, SimTypeFunction):
        return None
    return deepcopy(prototype, {id(prototype._arch): prototype._arch})


def _graph_snapshot(function: _Function8616) -> tuple[tuple[int, int | None, tuple[int, ...]], ...] | None:
    """Snapshot the exact graph fields consumed by terminal-return traversal."""
    try:
        graph = function.graph
        return tuple(sorted(
            (node.addr, node.size, tuple(sorted(successor.addr for successor in graph.successors(node))))
            for node in graph.nodes
        ))
    except (AttributeError, TypeError):
        return None


def _function_state(function: object) -> FunctionSeedState8616:
    """Read optional angr fields without relying on mutable prototype identity."""
    boundary = cast(_Function8616, function)
    try:
        address = boundary.addr
    except AttributeError:
        address = None
    try:
        blocks = tuple(sorted(boundary.block_addrs_set))
    except AttributeError:
        blocks = ()
    try:
        prototype = _prototype_snapshot(boundary.prototype)
    except AttributeError:
        prototype = None
    try:
        guessed = boundary.is_prototype_guessed
    except AttributeError:
        guessed = True
    try:
        source = boundary.prototype_source
    except AttributeError:
        source = None
    try:
        annotations = boundary.info.get(ANNOTATION_KEY)
    except AttributeError:
        annotations = None
    annotated = _prototype_snapshot(annotations.get("prototype")) if isinstance(annotations, Mapping) else None
    return FunctionSeedState8616(address, blocks, _graph_snapshot(boundary), prototype, guessed, source, annotated)


def calling_convention_seed_revision_8616(
    project: object | None,
    function: object,
    inspected_targets: tuple[int, ...],
) -> CallingConventionSeedRevision8616:
    """Refresh only the local facts and callees consumed by the previous seed."""
    local = _function_state(function)
    observation = (
        proven_function_result_observation_8616(project, local.address)
        if project is not None and local.address is not None else None
    )
    callees: list[CalleeSeedDependency8616] = []
    for target in inspected_targets:
        callee = resolve_x86_16_call_target_function_8616(project, target) if project is not None else None
        callees.append(CalleeSeedDependency8616(target, _function_state(callee) if callee is not None else None))
    return CallingConventionSeedRevision8616(id(project), local, observation, tuple(callees))
