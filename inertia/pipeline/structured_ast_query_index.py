"""Index read-only structured-C query keys for one mutation request.

Layer: Pipeline governance.
Responsibility: build typed, request-owned acceleration indexes over a current
third-party angr C-AST without deriving semantic facts or surviving mutations.
Callers must discard or explicitly update an index after they mutate its root.
Owns runtime ordering, invariant checks, hard failures, and final emission gates.
Do not recover semantic facts or perform IR, alias, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.structured_tags import copy_structured_tags_8616

__all__ = [
    "StructuredAstQueryIndex8616",
    "StructuredAstQuerySession8616",
    "StructuredAstQuerySessionStats8616",
    "TaggedAssignmentAddressIndex8616",
    "TaggedAssignmentAddressQueryStats8616",
]


@dataclass(frozen=True, slots=True)
class StructuredAstQueryIndex8616:
    """Nodes and identities from one immutable structured-C query request."""

    root: object
    nodes: tuple[object, ...]
    node_ids: frozenset[int]
    statement_blocks: tuple[structured_c.CStatements, ...]
    assignments: tuple[structured_c.CAssignment, ...]
    calls: tuple[structured_c.CFunctionCall, ...]
    variables: tuple[structured_c.CVariable, ...]

    @classmethod
    def build(cls, root: object) -> StructuredAstQueryIndex8616:
        """Traverse ``root`` once and retain deterministic walker order."""
        nodes = tuple(_iter_c_nodes_deep_8616(root))
        return cls(
            root=root,
            nodes=nodes,
            node_ids=frozenset(id(node) for node in nodes),
            statement_blocks=tuple(
                node for node in nodes if isinstance(node, structured_c.CStatements)
            ),
            assignments=tuple(
                node for node in nodes if isinstance(node, structured_c.CAssignment)
            ),
            calls=tuple(
                node for node in nodes if isinstance(node, structured_c.CFunctionCall)
            ),
            variables=tuple(
                node for node in nodes if isinstance(node, structured_c.CVariable)
            ),
        )

    def contains(self, node: object) -> bool:
        """Return whether ``node`` occurs by identity in this request."""
        return id(node) in self.node_ids

    def require_root(self, root: object) -> None:
        """Reject reuse of this request index for a different AST root."""
        if self.root is not root:
            raise ValueError("structured AST query index belongs to a different root")


@dataclass(frozen=True, slots=True)
class StructuredAstQuerySessionStats8616:
    """Closed accounting for one mutation-aware AST query session."""

    request_count: int
    build_count: int
    hit_count: int
    invalidation_count: int

    @property
    def closed(self) -> bool:
        """Return whether every request built or reused exactly one index."""
        return bool(
            self.request_count == self.build_count + self.hit_count
            and min(
                self.request_count,
                self.build_count,
                self.hit_count,
                self.invalidation_count,
            )
            >= 0
        )


@dataclass(slots=True)
class StructuredAstQuerySession8616:
    """Reuse one query index until its caller reports an AST mutation."""

    root: object
    _index: StructuredAstQueryIndex8616 | None = None
    _request_count: int = 0
    _build_count: int = 0
    _hit_count: int = 0
    _invalidation_count: int = 0

    def current(self) -> StructuredAstQueryIndex8616:
        """Return the current index, rebuilding only after invalidation."""
        self._request_count += 1
        if self._index is None:
            self._index = StructuredAstQueryIndex8616.build(self.root)
            self._build_count += 1
        else:
            self._hit_count += 1
        return self._index

    def record_mutation(self, changed: bool) -> bool:
        """Invalidate cached projections and return the reported mutation state."""
        if changed:
            self._index = None
            self._invalidation_count += 1
        return changed

    def stats(self) -> StructuredAstQuerySessionStats8616:
        """Return immutable closed accounting for this request session."""
        result = StructuredAstQuerySessionStats8616(
            request_count=self._request_count,
            build_count=self._build_count,
            hit_count=self._hit_count,
            invalidation_count=self._invalidation_count,
        )
        if not result.closed:
            raise ValueError("structured AST query session accounting is not closed")
        return result


@dataclass(frozen=True, slots=True)
class TaggedAssignmentAddressQueryStats8616:
    """Closed accounting for exact-address prefilter queries."""

    query_count: int
    hit_count: int
    miss_count: int
    record_count: int

    def __post_init__(self) -> None:
        """Reject incomplete query accounting at the owning boundary."""
        if self.query_count != self.hit_count + self.miss_count:
            raise ValueError("tagged-assignment query accounting is not closed")
        if min(self.query_count, self.hit_count, self.miss_count, self.record_count) < 0:
            raise ValueError("tagged-assignment query counters must be non-negative")


@dataclass(slots=True)
class TaggedAssignmentAddressIndex8616:
    """Instruction addresses carried by assignments in one current C-AST."""

    addresses: set[int]
    tagged_assignments: tuple[
        tuple[structured_c.CAssignment, frozenset[int]], ...
    ] = ()
    complete: bool = True
    query_count: int = 0
    hit_count: int = 0
    miss_count: int = 0
    record_count: int = 0

    @classmethod
    def build(cls, root: object) -> TaggedAssignmentAddressIndex8616:
        """Build one request-owned index from exact structured assignment tags."""
        return cls.from_query_index(StructuredAstQueryIndex8616.build(root))

    @classmethod
    def from_query_index(
        cls,
        query_index: StructuredAstQueryIndex8616,
    ) -> TaggedAssignmentAddressIndex8616:
        """Project exact assignment tags from one current AST query index."""
        addresses: set[int] = set()
        tagged_assignments: list[
            tuple[structured_c.CAssignment, frozenset[int]]
        ] = []
        for node in query_index.assignments:
            tags = copy_structured_tags_8616(node.tags)
            if tags is None:
                continue
            assignment_addresses: set[int] = set()
            for name in ("ins_addr", "inertia_relocated_from_ins_addr"):
                address = tags.get(name)
                if isinstance(address, int):
                    addresses.add(address)
                    assignment_addresses.add(address)
            if assignment_addresses:
                tagged_assignments.append((node, frozenset(assignment_addresses)))
        return cls(addresses, tuple(tagged_assignments))

    def intersects(self, candidate_addresses: frozenset[int]) -> bool:
        """Return whether any exact candidate address has a tagged assignment."""
        self.query_count += 1
        intersects = not self.addresses.isdisjoint(candidate_addresses)
        if intersects:
            self.hit_count += 1
        else:
            self.miss_count += 1
        return intersects

    def candidate_assignments(
        self,
        candidate_addresses: frozenset[int],
    ) -> tuple[structured_c.CAssignment, ...] | None:
        """Return exact tagged candidates, or ``None`` after an unindexed mutation."""
        self.query_count += 1
        if not self.complete:
            self.hit_count += 1
            return None
        candidates = tuple(
            assignment
            for assignment, assignment_addresses in self.tagged_assignments
            if not assignment_addresses.isdisjoint(candidate_addresses)
        )
        if candidates:
            self.hit_count += 1
        else:
            self.miss_count += 1
        return candidates

    def record(self, candidate_addresses: frozenset[int]) -> None:
        """Mark an inserted assignment as an unindexed mutation for later queries."""
        self.addresses.update(candidate_addresses)
        self.complete = False
        self.record_count += 1

    def stats(self) -> TaggedAssignmentAddressQueryStats8616:
        """Return immutable closed accounting for the current request."""
        return TaggedAssignmentAddressQueryStats8616(
            query_count=self.query_count,
            hit_count=self.hit_count,
            miss_count=self.miss_count,
            record_count=self.record_count,
        )
