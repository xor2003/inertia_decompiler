"""Index structured-C assignments for one immutable query generation.

Layer: Pipeline governance.
Responsibility: project caller-supplied structural assignment identities from
one current structured-AST query index and return typed lookup verdicts.
This module does not derive alias, type, stack, or other semantic evidence.
Callers must discard the index when the owning AST generation is accepted as
mutated; ambiguous identities are always refused.
Owns runtime ordering, invariant checks, hard failures, and final emission gates.
Do not recover semantic facts or perform IR, alias, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum

from .structured_ast_query_index import StructuredAstQueryIndex8616

__all__ = [
    "StructuredAssignmentIdentityIndex8616",
    "StructuredAssignmentIdentityKey8616",
    "StructuredAssignmentIdentityKind8616",
    "StructuredAssignmentLookupResult8616",
    "StructuredAssignmentLookupStats8616",
    "StructuredAssignmentLookupVerdict8616",
]


class StructuredAssignmentIdentityKind8616(StrEnum):
    """Structural identity kinds supplied by a typed pipeline consumer."""

    VARIABLE_OBJECT = "variable_object"
    CVARIABLE_NAME = "cvariable_name"
    VIRTUAL_NAME = "virtual_name"
    REGISTER = "register"


@dataclass(frozen=True, slots=True)
class StructuredAssignmentIdentityKey8616:
    """One explicit structural key for an assignment left-hand side."""

    kind: StructuredAssignmentIdentityKind8616
    identity: int | str
    width: int | None = None

    def __post_init__(self) -> None:
        """Reject malformed identities before they enter the projection."""
        if self.kind is StructuredAssignmentIdentityKind8616.REGISTER:
            if not isinstance(self.identity, int) or not isinstance(self.width, int):
                raise ValueError("register assignment identity requires integer offset and width")
            if self.width <= 0:
                raise ValueError("register assignment width must be positive")
            return
        if self.width is not None:
            raise ValueError("only register assignment identities carry a width")
        if self.kind is StructuredAssignmentIdentityKind8616.VARIABLE_OBJECT:
            if not isinstance(self.identity, int):
                raise ValueError("variable-object assignment identity must be an integer")
            return
        if not isinstance(self.identity, str) or not self.identity:
            raise ValueError("named assignment identity must be a non-empty string")


class StructuredAssignmentLookupVerdict8616(StrEnum):
    """Typed result classes for exact assignment projection queries."""

    MISSING = "missing"
    UNIQUE = "unique"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True, slots=True)
class StructuredAssignmentLookupResult8616:
    """Result of one exact assignment identity lookup."""

    verdict: StructuredAssignmentLookupVerdict8616
    rhs: object | None
    match_count: int

    def __post_init__(self) -> None:
        """Keep verdict, payload, and accounting coherent."""
        if self.verdict is StructuredAssignmentLookupVerdict8616.MISSING:
            valid = self.match_count == 0 and self.rhs is None
        elif self.verdict is StructuredAssignmentLookupVerdict8616.UNIQUE:
            valid = self.match_count == 1
        else:
            valid = self.match_count > 1 and self.rhs is None
        if not valid:
            raise ValueError("assignment lookup result is internally inconsistent")


@dataclass(frozen=True, slots=True)
class StructuredAssignmentLookupStats8616:
    """Closed accounting for one assignment projection generation."""

    build_count: int
    assignment_count: int
    indexed_assignment_count: int
    key_count: int
    query_count: int
    missing_count: int
    unique_count: int
    ambiguous_count: int

    def __post_init__(self) -> None:
        """Reject incomplete or negative projection accounting."""
        counters = (
            self.build_count,
            self.assignment_count,
            self.indexed_assignment_count,
            self.key_count,
            self.query_count,
            self.missing_count,
            self.unique_count,
            self.ambiguous_count,
        )
        if min(counters) < 0:
            raise ValueError("assignment projection counters must be non-negative")
        if self.build_count != 1:
            raise ValueError("one assignment projection must have exactly one build")
        if self.indexed_assignment_count > self.assignment_count:
            raise ValueError("indexed assignment count exceeds the source census")
        if self.query_count != self.missing_count + self.unique_count + self.ambiguous_count:
            raise ValueError("assignment projection query accounting is not closed")


@dataclass(frozen=True, slots=True)
class _StructuredAssignmentRecord8616:
    """Immutable assignment payload retained for one query generation."""

    assignment_identity: int
    rhs: object | None


@dataclass(slots=True)
class StructuredAssignmentIdentityIndex8616:
    """Deterministic assignment projection over one structured-AST census."""

    root: object
    _records_by_key: Mapping[
        StructuredAssignmentIdentityKey8616,
        tuple[_StructuredAssignmentRecord8616, ...],
    ]
    assignment_count: int
    indexed_assignment_count: int
    query_count: int = 0
    missing_count: int = 0
    unique_count: int = 0
    ambiguous_count: int = 0

    @classmethod
    def build(
        cls,
        query_index: StructuredAstQueryIndex8616,
        key_extractor: Callable[
            [object],
            Iterable[StructuredAssignmentIdentityKey8616],
        ],
    ) -> StructuredAssignmentIdentityIndex8616:
        """Build one projection from the query index's assignment census."""
        records_by_key: dict[
            StructuredAssignmentIdentityKey8616,
            list[_StructuredAssignmentRecord8616],
        ] = {}
        indexed_assignment_count = 0
        for assignment in query_index.assignments:
            keys = tuple(dict.fromkeys(key_extractor(assignment.lhs)))
            if not keys:
                continue
            indexed_assignment_count += 1
            record = _StructuredAssignmentRecord8616(id(assignment), assignment.rhs)
            for key in keys:
                records_by_key.setdefault(key, []).append(record)
        return cls(
            root=query_index.root,
            _records_by_key={key: tuple(records) for key, records in records_by_key.items()},
            assignment_count=len(query_index.assignments),
            indexed_assignment_count=indexed_assignment_count,
        )

    def require_root(self, root: object) -> None:
        """Reject reuse for a different structured-AST generation root."""
        if self.root is not root:
            raise ValueError("assignment projection belongs to a different AST root")

    def lookup(
        self,
        keys: Iterable[StructuredAssignmentIdentityKey8616],
    ) -> StructuredAssignmentLookupResult8616:
        """Return missing, unique, or fail-closed ambiguous for exact keys."""
        self.query_count += 1
        matches: dict[int, _StructuredAssignmentRecord8616] = {}
        for key in dict.fromkeys(keys):
            for record in self._records_by_key.get(key, ()):
                matches.setdefault(record.assignment_identity, record)
        if not matches:
            self.missing_count += 1
            return StructuredAssignmentLookupResult8616(
                StructuredAssignmentLookupVerdict8616.MISSING,
                None,
                0,
            )
        if len(matches) == 1:
            self.unique_count += 1
            record = next(iter(matches.values()))
            return StructuredAssignmentLookupResult8616(
                StructuredAssignmentLookupVerdict8616.UNIQUE,
                record.rhs,
                1,
            )
        self.ambiguous_count += 1
        return StructuredAssignmentLookupResult8616(
            StructuredAssignmentLookupVerdict8616.AMBIGUOUS,
            None,
            len(matches),
        )

    def stats(self) -> StructuredAssignmentLookupStats8616:
        """Return immutable closed accounting for this projection."""
        return StructuredAssignmentLookupStats8616(
            build_count=1,
            assignment_count=self.assignment_count,
            indexed_assignment_count=self.indexed_assignment_count,
            key_count=len(self._records_by_key),
            query_count=self.query_count,
            missing_count=self.missing_count,
            unique_count=self.unique_count,
            ambiguous_count=self.ambiguous_count,
        )
