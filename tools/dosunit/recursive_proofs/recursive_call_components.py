"""Deterministic strongly-connected-component contracts for recursive calls.

Layer: dosunit recursive-call staging (m5).

Responsibility: own the shared typed finite call-graph model, its complete
admission checks, and the deterministic strongly-connected-component (SCC)
partition that a future joint recursive transition solver will consume. This
module classifies structure only: discovering that functions share a recursive
component is an admission proposal, never a proof of equality, and it
discharges no proof obligation. A component grants no PROVED status and no
callee is conditionally bootstrapped; every vertex and edge is retained, edge
endpoints that are not declared vertices refuse closed, and corrupted or
over-budget input refuses with a typed reason. Both the partition walk and the
dependency ordering are iterative so deep graphs cannot hit Python's
recursion limit.
"""

from __future__ import annotations

import heapq
import time
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

REPORT_SCHEMA: str = "dosunit.recursive_components.v1"


class EdgeRole(StrEnum):
    """Position of a call edge relative to the component partition."""

    INTRA_COMPONENT = "intra_component"
    INTER_COMPONENT = "inter_component"


class ComponentRefusalReason(StrEnum):
    """Typed stable reason a call graph was refused for component analysis."""

    VERTEX_ID_INVALID = "vertex_id_invalid"
    DUPLICATE_VERTEX = "duplicate_vertex"
    DUPLICATE_EDGE = "duplicate_edge"
    EDGE_ENDPOINT_MISSING = "edge_endpoint_missing"
    GRAPH_LIMIT_EXCEEDED = "graph_limit_exceeded"
    ANALYSIS_BUDGET_EXCEEDED = "analysis_budget_exceeded"
    ANALYSIS_DEADLINE_EXCEEDED = "analysis_deadline_exceeded"
    INCONSISTENT_PARTITION = "inconsistent_partition"


class RecursiveCallRefusal(Exception):
    """Fail-closed admission or analysis refusal carrying a typed reason."""

    def __init__(self, reason: ComponentRefusalReason, detail: Mapping[str, Any] | None = None) -> None:
        """Retain the explicit admission invariant or budget that failed."""
        super().__init__(reason.value)
        self.reason = reason
        self.detail = dict(detail or {})


@dataclass(frozen=True, order=True)
class FunctionId:
    """Stable binary-derived identity of one call-graph vertex."""

    value: str

    def __post_init__(self) -> None:
        """Reject identifiers that cannot stably name a function vertex."""
        if type(self.value) is not str or not self.value:
            raise ValueError("function id requires a non-empty string")

    def __str__(self) -> str:
        """Return the raw stable identifier for diagnostics."""
        return self.value


@dataclass(frozen=True, order=True)
class CallEdge:
    """One resolved direct call from ``caller`` to ``callee``."""

    caller: FunctionId
    callee: FunctionId

    def __post_init__(self) -> None:
        """Reject edges whose endpoints are not typed function identities."""
        if not isinstance(self.caller, FunctionId) or not isinstance(self.callee, FunctionId):
            raise ValueError("call edge endpoints must be FunctionId values")


@dataclass(frozen=True)
class CallGraph:
    """Complete finite directed call graph; every edge endpoint is declared.

    ``vertices`` and ``edges`` are canonical (sorted, unique) when built
    through :func:`build_call_graph`; direct construction still enforces the
    completeness invariant that no edge may reference an undeclared vertex.
    """

    vertices: tuple[FunctionId, ...]
    edges: tuple[CallEdge, ...]

    def __post_init__(self) -> None:
        """Enforce uniqueness and call-graph completeness or refuse closed."""
        if len(set(self.vertices)) != len(self.vertices):
            raise RecursiveCallRefusal(ComponentRefusalReason.DUPLICATE_VERTEX)
        if len(set(self.edges)) != len(self.edges):
            raise RecursiveCallRefusal(ComponentRefusalReason.DUPLICATE_EDGE)
        declared = set(self.vertices)
        missing = sorted({endpoint for edge in self.edges for endpoint in (edge.caller, edge.callee)} - declared)
        if missing:
            raise RecursiveCallRefusal(
                ComponentRefusalReason.EDGE_ENDPOINT_MISSING,
                {"missing_endpoints": [str(vertex) for vertex in missing[:16]]},
            )


@dataclass(frozen=True)
class ComponentLimits:
    """Analysis resource bounds; exceeding any of them refuses.

    ``deadline_ms < 0`` disables the wall-clock deadline, ``deadline_ms == 0``
    refuses at the first accounted step, and a positive value bounds the
    analysis by that many milliseconds. ``max_steps`` bounds total iterative
    vertex/edge processing regardless of wall time.
    """

    max_vertices: int = 65_536
    max_edges: int = 262_144
    max_steps: int = 4_194_304
    deadline_ms: int = -1

    def __post_init__(self) -> None:
        """Reject limits that cannot describe a finite bounded analysis."""
        if any(type(value) is not int or value <= 0 for value in (self.max_vertices, self.max_edges, self.max_steps)):
            raise ValueError("component limits must be positive integers")
        if type(self.deadline_ms) is not int:
            raise ValueError("deadline must be an integer millisecond budget")


@dataclass(frozen=True)
class CallComponent:
    """One SCC of the call graph; ``recursive`` is structural, never proof.

    ``order`` is a callee-first dependency index: for every inter-component
    edge caller -> callee, ``callee``'s component has a strictly smaller
    ``order`` than ``caller``'s component.
    """

    key: str
    order: int
    members: tuple[FunctionId, ...]
    recursive: bool
    self_loop_members: tuple[FunctionId, ...]
    intra_edges: tuple[CallEdge, ...]


@dataclass(frozen=True)
class ClassifiedEdge:
    """One retained call edge with its exact component classification."""

    edge: CallEdge
    role: EdgeRole
    caller_component: str
    callee_component: str

    def __post_init__(self) -> None:
        """Enforce coherence between the role and the endpoint components."""
        if self.role is EdgeRole.INTRA_COMPONENT and self.caller_component != self.callee_component:
            raise ValueError("intra-component edge must share one component")
        if self.role is EdgeRole.INTER_COMPONENT and self.caller_component == self.callee_component:
            raise ValueError("inter-component edge must cross components")


@dataclass(frozen=True)
class ComponentCounters:
    """Closed evidence counters for one complete component analysis."""

    vertex_count: int = 0
    edge_count: int = 0
    component_count: int = 0
    recursive_component_count: int = 0
    recursive_vertex_count: int = 0
    self_loop_edge_count: int = 0
    intra_edge_count: int = 0
    inter_edge_count: int = 0
    steps: int = 0

    def __post_init__(self) -> None:
        """Reject counters that cannot describe a closed partition."""
        values = (
            self.vertex_count,
            self.edge_count,
            self.component_count,
            self.recursive_component_count,
            self.recursive_vertex_count,
            self.self_loop_edge_count,
            self.intra_edge_count,
            self.inter_edge_count,
            self.steps,
        )
        if any(type(count) is not int or count < 0 for count in values):
            raise ValueError("component counters must be non-negative integers")
        if self.intra_edge_count + self.inter_edge_count != self.edge_count:
            raise ValueError("classified edges must cover every retained edge")
        if (self.vertex_count == 0) != (self.component_count == 0):
            raise ValueError("non-empty graphs must yield components")
        if not (self.recursive_component_count <= self.component_count <= self.vertex_count or self.vertex_count == 0):
            raise ValueError("component counts cannot exceed retained vertices")
        if self.self_loop_edge_count > self.intra_edge_count:
            raise ValueError("self loops are a subset of intra-component edges")
        if self.recursive_vertex_count > self.vertex_count:
            raise ValueError("recursive members are a subset of vertices")


@dataclass(frozen=True)
class ComponentAnalysis:
    """Complete deterministic SCC partition of a call graph.

    Grouping is a proposal only: it names which functions must be discharged
    jointly, but assigns no proof status and proves no equality.
    ``membership`` maps every vertex to its component key.
    """

    graph: CallGraph
    components: tuple[CallComponent, ...]
    edges: tuple[ClassifiedEdge, ...]
    counters: ComponentCounters
    membership: Mapping[FunctionId, str] = field(default_factory=dict)

    def component_key_of(self, vertex: FunctionId) -> str | None:
        """Return the component key owning ``vertex``, or ``None`` if absent."""
        return self.membership.get(vertex)


@dataclass
class _Budget:
    """Mutable step/deadline accounting for one bounded analysis run."""

    limits: ComponentLimits
    deadline: float
    steps: int = 0

    @classmethod
    def start(cls, limits: ComponentLimits) -> _Budget:
        """Open a budget; ``deadline_ms < 0`` means no wall-clock bound."""
        deadline = -1.0
        if limits.deadline_ms >= 0:
            deadline = time.monotonic() + limits.deadline_ms / 1000.0
        return cls(limits=limits, deadline=deadline)

    def bump(self, count: int = 1) -> None:
        """Charge accounted work; refuse on step budget or deadline."""
        self.steps += count
        if self.steps > self.limits.max_steps:
            raise RecursiveCallRefusal(
                ComponentRefusalReason.ANALYSIS_BUDGET_EXCEEDED,
                {"counter": "steps", "limit": self.limits.max_steps},
            )
        if self.deadline >= 0.0 and time.monotonic() > self.deadline:
            raise RecursiveCallRefusal(
                ComponentRefusalReason.ANALYSIS_DEADLINE_EXCEEDED,
                {"counter": "deadline"},
            )


def _function_id(value: FunctionId | str) -> FunctionId:
    """Adapt a boundary string or pass through a typed identifier."""
    return value if isinstance(value, FunctionId) else FunctionId(value)


def _check_graph_size(vertex_count: int, edge_count: int, limits: ComponentLimits) -> None:
    """Enforce admission limits even when callers construct the graph directly."""
    for counter, count, limit in (
        ("vertices", vertex_count, limits.max_vertices),
        ("edges", edge_count, limits.max_edges),
    ):
        if count > limit:
            raise RecursiveCallRefusal(
                ComponentRefusalReason.GRAPH_LIMIT_EXCEEDED,
                {"counter": counter, "count": count, "limit": limit},
            )


def _bounded_items[T](items: Iterable[T], limit: int, counter: str, budget: _Budget) -> list[T]:
    """Stop consuming at the first excess item instead of materializing a stream."""
    retained: list[T] = []
    for item in items:
        budget.bump()
        if len(retained) >= limit:
            raise RecursiveCallRefusal(
                ComponentRefusalReason.GRAPH_LIMIT_EXCEEDED,
                {"counter": counter, "count": len(retained) + 1, "limit": limit},
            )
        retained.append(item)
    return retained


def build_call_graph(
    vertices: Iterable[FunctionId | str], edges: Iterable[CallEdge], *,
    limits: ComponentLimits | None = None,
) -> CallGraph:
    """Admit one complete graph with bounded input consumption and total work."""
    active = limits if limits is not None else ComponentLimits()
    return _build_call_graph(vertices, edges, _Budget.start(active))


def _build_call_graph(
    vertices: Iterable[FunctionId | str], edges: Iterable[CallEdge], budget: _Budget,
) -> CallGraph:
    """Build a canonical complete call graph or refuse with a typed reason.

    Refuses duplicate vertices, duplicate edges, undeclared edge endpoints
    (missing call targets) and input sizes beyond ``limits``. Every declared
    vertex and edge is retained; nothing is dropped or inferred.
    """
    active = budget.limits
    vertex_list = [_function_id(vertex) for vertex in _bounded_items(vertices, active.max_vertices, "vertices", budget)]
    edge_list = _bounded_items(edges, active.max_edges, "edges", budget)
    for edge in edge_list:
        if not isinstance(edge, CallEdge):
            raise ValueError("call graph edges must be CallEdge values")
    _check_graph_size(len(vertex_list), len(edge_list), active)
    if len(set(vertex_list)) != len(vertex_list):
        raise RecursiveCallRefusal(ComponentRefusalReason.DUPLICATE_VERTEX, {"count": len(vertex_list)})
    if len(set(edge_list)) != len(edge_list):
        raise RecursiveCallRefusal(ComponentRefusalReason.DUPLICATE_EDGE, {"count": len(edge_list)})
    graph = CallGraph(vertices=tuple(sorted(vertex_list)), edges=tuple(sorted(edge_list)))
    budget.bump(0)
    return graph


def _first_unindexed(
    node: FunctionId,
    successors: Iterator[FunctionId],
    index_of: dict[FunctionId, int],
    lowlink: dict[FunctionId, int],
    on_stack: set[FunctionId],
    budget: _Budget,
) -> FunctionId | None:
    """Scan successors until the first unindexed one; fold indexed lowlinks."""
    for successor in successors:
        budget.bump()
        if successor not in index_of:
            return successor
        if successor in on_stack and index_of[successor] < lowlink[node]:
            lowlink[node] = index_of[successor]
    return None


def _finish_node(
    work: list[tuple[FunctionId, Iterator[FunctionId]]],
    node: FunctionId,
    index_of: dict[FunctionId, int],
    lowlink: dict[FunctionId, int],
    on_stack: set[FunctionId],
    stack: list[FunctionId],
    components: list[tuple[FunctionId, ...]],
) -> None:
    """Pop a finished node, emit its SCC when it is a root, update its parent."""
    work.pop()
    if lowlink[node] == index_of[node]:
        members: list[FunctionId] = []
        while True:
            member = stack.pop()
            on_stack.discard(member)
            members.append(member)
            if member == node:
                break
        components.append(tuple(sorted(members)))
    if work:
        parent = work[-1][0]
        if lowlink[node] < lowlink[parent]:
            lowlink[parent] = lowlink[node]


def _tarjan_components(
    vertices: tuple[FunctionId, ...],
    callees: Mapping[FunctionId, tuple[FunctionId, ...]],
    budget: _Budget,
) -> list[tuple[FunctionId, ...]]:
    """Iterative Tarjan SCC partition over sorted vertices and adjacency."""
    index_of: dict[FunctionId, int] = {}
    lowlink: dict[FunctionId, int] = {}
    on_stack: set[FunctionId] = set()
    stack: list[FunctionId] = []
    components: list[tuple[FunctionId, ...]] = []
    for root in vertices:
        if root in index_of:
            continue
        work: list[tuple[FunctionId, Iterator[FunctionId]]] = [(root, iter(callees[root]))]
        while work:
            node, successors = work[-1]
            if node not in index_of:
                budget.bump()
                index_of[node] = lowlink[node] = len(index_of)
                stack.append(node)
                on_stack.add(node)
            pending = _first_unindexed(node, successors, index_of, lowlink, on_stack, budget)
            if pending is not None:
                work.append((pending, iter(callees[pending])))
                continue
            _finish_node(work, node, index_of, lowlink, on_stack, stack, components)
    return components


def _component_key(members: tuple[FunctionId, ...]) -> str:
    """Stable component key derived from its smallest member identifier."""
    return f"scc:{members[0].value}"


def _order_components(
    components: list[tuple[FunctionId, ...]],
    graph: CallGraph,
    budget: _Budget,
) -> list[int]:
    """Callee-first topological order of the condensation DAG via Kahn.

    For each inter-component call caller -> callee, the callee's component is
    assigned the smaller order index. Ties break on the component key, and a
    condensation that cannot be fully ordered is an internal contradiction and
    refuses as ``INCONSISTENT_PARTITION``.
    """
    owner: dict[FunctionId, int] = {}
    for position, members in enumerate(components):
        for member in members:
            owner[member] = position
    enables: dict[int, set[int]] = {position: set() for position in range(len(components))}
    indegree: dict[int, int] = dict.fromkeys(range(len(components)), 0)
    for edge in graph.edges:
        budget.bump()
        caller_at = owner[edge.caller]
        callee_at = owner[edge.callee]
        if caller_at == callee_at or caller_at in enables[callee_at]:
            continue
        enables[callee_at].add(caller_at)
        indegree[caller_at] += 1
    ready: list[tuple[str, int]] = [
        (_component_key(components[position]), position)
        for position in range(len(components))
        if indegree[position] == 0
    ]
    heapq.heapify(ready)
    order = [-1] * len(components)
    placed = 0
    while ready:
        _, position = heapq.heappop(ready)
        order[position] = placed
        placed += 1
        for dependent in sorted(enables[position]):
            budget.bump()
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                heapq.heappush(ready, (_component_key(components[dependent]), dependent))
    if placed != len(components):
        raise RecursiveCallRefusal(
            ComponentRefusalReason.INCONSISTENT_PARTITION,
            {"placed": placed, "components": len(components)},
        )
    return order


def discover_components(
    graph: CallGraph, *, limits: ComponentLimits | None = None,
) -> ComponentAnalysis:
    """Analyze one admitted graph, independently enforcing the caller's bounds."""
    active = limits if limits is not None else ComponentLimits()
    return _discover_components(graph, _Budget.start(active))


def _discover_components(graph: CallGraph, budget: _Budget) -> ComponentAnalysis:
    """Partition a complete call graph into deterministic ordered SCCs.

    The result retains every vertex and edge, marks each edge intra- or
    inter-component, and orders components callees before callers. The
    partition is an admission proposal only; it proves nothing by itself.
    """
    active = budget.limits
    _check_graph_size(len(graph.vertices), len(graph.edges), active)
    callees: dict[FunctionId, list[FunctionId]] = {vertex: [] for vertex in graph.vertices}
    for edge in graph.edges:
        budget.bump()
        callees[edge.caller].append(edge.callee)
    adjacency = {vertex: tuple(sorted(targets)) for vertex, targets in callees.items()}
    raw_components = _tarjan_components(graph.vertices, adjacency, budget)
    owner: dict[FunctionId, int] = {}
    for position, members in enumerate(raw_components):
        for member in members:
            if member in owner:
                raise RecursiveCallRefusal(
                    ComponentRefusalReason.INCONSISTENT_PARTITION,
                    {"member": str(member)},
                )
            owner[member] = position
    if set(owner) != set(graph.vertices):
        raise RecursiveCallRefusal(
            ComponentRefusalReason.INCONSISTENT_PARTITION,
            {"vertices": len(graph.vertices), "partitioned": len(owner)},
        )
    order = _order_components(raw_components, graph, budget)
    self_loops: dict[int, list[FunctionId]] = {position: [] for position in range(len(raw_components))}
    intra: dict[int, list[CallEdge]] = {position: [] for position in range(len(raw_components))}
    classified: list[ClassifiedEdge] = []
    for edge in graph.edges:
        caller_at = owner[edge.caller]
        callee_at = owner[edge.callee]
        if caller_at == callee_at:
            role = EdgeRole.INTRA_COMPONENT
            intra[caller_at].append(edge)
            if edge.caller == edge.callee:
                self_loops[caller_at].append(edge.caller)
        else:
            role = EdgeRole.INTER_COMPONENT
        classified.append(
            ClassifiedEdge(
                edge=edge,
                role=role,
                caller_component=_component_key(raw_components[caller_at]),
                callee_component=_component_key(raw_components[callee_at]),
            )
        )
    components = tuple(
        sorted(
            (
                CallComponent(
                    key=_component_key(members),
                    order=order[position],
                    members=members,
                    recursive=len(members) > 1 or bool(self_loops[position]),
                    self_loop_members=tuple(sorted(self_loops[position])),
                    intra_edges=tuple(sorted(intra[position])),
                )
                for position, members in enumerate(raw_components)
            ),
            key=lambda component: component.order,
        )
    )
    budget.bump(0)
    counters = ComponentCounters(
        vertex_count=len(graph.vertices),
        edge_count=len(graph.edges),
        component_count=len(components),
        recursive_component_count=sum(1 for component in components if component.recursive),
        recursive_vertex_count=sum(len(component.members) for component in components if component.recursive),
        self_loop_edge_count=sum(len(loops) for loops in self_loops.values()),
        intra_edge_count=sum(len(edges) for edges in intra.values()),
        inter_edge_count=sum(1 for edge in classified if edge.role is EdgeRole.INTER_COMPONENT),
        steps=budget.steps,
    )
    return ComponentAnalysis(
        graph=graph,
        components=components,
        edges=tuple(sorted(classified, key=lambda row: row.edge)),
        counters=counters,
        membership={member: _component_key(raw_components[owner[member]]) for member in graph.vertices},
    )


def analyze_call_graph(
    vertices: Iterable[FunctionId | str],
    edges: Iterable[CallEdge],
    *,
    limits: ComponentLimits | None = None,
) -> ComponentAnalysis:
    """Build a complete call graph and partition it in one bounded step."""
    active = limits if limits is not None else ComponentLimits()
    budget = _Budget.start(active)
    graph = _build_call_graph(vertices, edges, budget)
    return _discover_components(graph, budget)
