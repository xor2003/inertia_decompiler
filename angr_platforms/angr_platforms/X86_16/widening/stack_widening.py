"""Stack and storage widening proofs built from alias facts.

Layer: Widening.
Responsibility: owns stack and storage widening proofs after alias recovery.
Consumes alias-proven storage identity before deciding whether adjacent stack
or register slices may become one semantic value.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ..alias.alias_model import (
    AliasStorageFacts,
    _merge_storage_domains,
    _StorageDomainSignature,
    _StorageView,
)
from ..alias_domains import DomainKey, register_pair_name
from ..alias_state import AliasState
from ..semantics.alias_query import (
    _storage_domain_for_expr,
    can_join_alias_storage,
    contains_alias_storage,
    describe_alias_storage,
    same_alias_storage_domain,
)
from .register_widening import RegisterWideningCandidate, can_join_adjacent_register_slices


@dataclass(frozen=True)
class WideningCandidate:
    """Alias-described storage slice that may participate in a widening join."""

    domain: _StorageDomainSignature
    view: _StorageView
    expr: object

    def is_joinable_with(self, other: WideningCandidate) -> bool:
        """Return whether this candidate's domain and view can join another."""
        return bool(self.domain.can_join(other.domain) and self.view.can_join(other.view))

    @classmethod
    def from_expr(cls, expr: object) -> WideningCandidate:
        """Build a candidate from an expression with concrete alias storage."""
        domain = _storage_domain_for_expr(expr)
        if domain.view is None:
            raise ValueError("cannot build widening candidate without a concrete storage view")
        return cls(domain, domain.view, expr)


@dataclass(frozen=True)
class WideningProof:
    """Result of proving whether two adjacent storage slices may be widened."""

    ok: bool
    reason: str
    left: AliasStorageFacts
    right: AliasStorageFacts
    merged_domain: _StorageDomainSignature | None = None
    register_pair: str | None = None
    left_version: int | None = None
    right_version: int | None = None

    def is_safe(self) -> bool:
        """Return whether this proof allows widening."""
        return self.ok


@dataclass(frozen=True)
class StorageSubviewProof:
    """Proof that one stack expression is a proper contained storage view."""

    ok: bool
    reason: str
    container: AliasStorageFacts
    subview: AliasStorageFacts
    relative_bit_offset: int | None = None

    def is_safe(self) -> bool:
        """Return whether this proof allows contained-view materialization."""
        return self.ok


@dataclass(frozen=True)
class StorageJoinAnalysis:
    """Convenience view over a widening proof for layer-boundary consumers."""

    proof: WideningProof

    @property
    def ok(self) -> bool:
        """Whether the underlying proof allows widening."""
        return self.proof.ok

    @property
    def reason(self) -> str:
        """Short deterministic reason for the proof result."""
        return self.proof.reason

    @property
    def left(self) -> AliasStorageFacts:
        """Alias facts for the low/left slice."""
        return self.proof.left

    @property
    def right(self) -> AliasStorageFacts:
        """Alias facts for the high/right slice."""
        return self.proof.right

    @property
    def merged_domain(self) -> _StorageDomainSignature | None:
        """Merged storage domain when proof succeeded."""
        return self.proof.merged_domain

    def same_domain(self) -> bool:
        """Return whether both slices describe the same storage domain."""
        return bool(self.left.same_domain(self.right))

    def compatible_view(self) -> bool:
        """Return whether both slices have join-compatible storage views."""
        return bool(self.left.compatible_view(self.right))

    def needs_synthesis(self) -> bool:
        """Return whether either side lacks concrete storage evidence."""
        return bool(self.left.needs_synthesis() or self.right.needs_synthesis())


@dataclass(frozen=True)
class WideningPipelineSpec:
    """Documented widening pipeline step and its owning helper functions."""

    name: str
    purpose: str
    helpers: tuple[str, ...]


def _register_version_for_expr(expr: object, state: AliasState | None) -> int | None:
    if state is None:
        return None
    facts = describe_alias_storage(expr)
    if facts.identity is None:
        return None
    kind, name = facts.identity
    if kind != "register" or not isinstance(name, str):
        return None
    pair_name = register_pair_name(name)
    if pair_name is None:
        return None
    version = state.version_of(DomainKey("reg", pair_name.upper()))
    return version if isinstance(version, int) else None


def _adjacent_refusal_8616(
    reason: str,
    low_facts: AliasStorageFacts,
    high_facts: AliasStorageFacts,
    low_version: int | None,
    high_version: int | None,
) -> WideningProof:
    """Build a refused widening proof carrying the version evidence."""
    return WideningProof(
        False,
        reason,
        low_facts,
        high_facts,
        left_version=low_version,
        right_version=high_version,
    )


def _shared_register_value_8616(
    low_facts: AliasStorageFacts,
    high_facts: AliasStorageFacts,
) -> str | None:
    """Return the register name both slice identities agree on."""
    if low_facts.identity is None or high_facts.identity is None:
        return None
    low_kind, low_value = low_facts.identity
    high_kind, high_value = high_facts.identity
    if (
        low_kind == high_kind == "register"
        and low_value == high_value
        and isinstance(low_value, str)
    ):
        return low_value
    return None


def _register_pair_identity_8616(
    low_facts: AliasStorageFacts,
    high_facts: AliasStorageFacts,
) -> str | None:
    """Return the shared register when both slices order as a named pair."""
    low_value = _shared_register_value_8616(low_facts, high_facts)
    if low_value is None:
        return None
    low_view = low_facts.domain.view
    high_view = high_facts.domain.view
    if (
        low_view is not None
        and high_view is not None
        and low_view.bit_offset < high_view.bit_offset
    ):
        return low_value
    return None


def _register_version_verdict_8616(
    register_pair: str | None,
    low_facts: AliasStorageFacts,
    high_facts: AliasStorageFacts,
    low_version: int | None,
    high_version: int | None,
) -> WideningProof | None:
    """Check pair/version evidence when an alias state is supplied."""
    if register_pair is None:
        return _adjacent_refusal_8616(
            "register_pair_mismatch", low_facts, high_facts, low_version, high_version,
        )
    if low_version is None or high_version is None:
        return _adjacent_refusal_8616(
            "missing_version_evidence", low_facts, high_facts, low_version, high_version,
        )
    if low_version != high_version:
        return _adjacent_refusal_8616(
            "version_mismatch", low_facts, high_facts, low_version, high_version,
        )
    return None


def _prove_adjacent_slices_8616(
    low_expr: object,
    high_expr: object,
    alias_state: AliasState | None,
    version_resolver: Callable[[object, AliasState | None], int | None],
) -> WideningProof:
    """Run the adjacent-slice proof ladder over alias storage facts."""
    low_facts = describe_alias_storage(low_expr)
    high_facts = describe_alias_storage(high_expr)
    register_pair = _register_pair_identity_8616(low_facts, high_facts)
    low_version = version_resolver(low_expr, alias_state)
    high_version = version_resolver(high_expr, alias_state)

    if low_facts.needs_synthesis() or high_facts.needs_synthesis():
        return _adjacent_refusal_8616(
            "needs_synthesis", low_facts, high_facts, low_version, high_version,
        )
    if not same_alias_storage_domain(low_expr, high_expr):
        return _adjacent_refusal_8616(
            "domain_mismatch", low_facts, high_facts, low_version, high_version,
        )
    if not can_join_alias_storage(low_expr, high_expr):
        return _adjacent_refusal_8616(
            "view_mismatch", low_facts, high_facts, low_version, high_version,
        )
    if alias_state is not None and (
        low_facts.identity is not None
        and high_facts.identity is not None
        and low_facts.identity[0] == "register"
        and high_facts.identity[0] == "register"
    ):
        verdict = _register_version_verdict_8616(
            register_pair, low_facts, high_facts, low_version, high_version,
        )
        if verdict is not None:
            return verdict

    merged_domain = _merge_storage_domains(_storage_domain_for_expr(low_expr), _storage_domain_for_expr(high_expr))
    return WideningProof(
        True,
        "ok",
        low_facts,
        high_facts,
        merged_domain=merged_domain,
        register_pair=register_pair,
        left_version=low_version,
        right_version=high_version,
    )


def prove_adjacent_storage_slices(
    low_expr: object,
    high_expr: object,
    *,
    alias_state: AliasState | None = None,
    register_version_for_expr: Callable[[object, AliasState | None], int | None] | None = None,
) -> WideningProof:
    """Prove whether two adjacent slices can be joined by the widening layer."""
    return _prove_adjacent_slices_8616(
        low_expr,
        high_expr,
        alias_state,
        register_version_for_expr or _register_version_for_expr,
    )


def prove_contained_stack_subview(
    container_expr: object,
    subview_expr: object,
    *,
    expected_bit_offset: int | None = None,
) -> StorageSubviewProof:
    """Prove that a narrower stack expression is contained by a wider one."""
    container = describe_alias_storage(container_expr)
    subview = describe_alias_storage(subview_expr)
    if container.needs_synthesis() or subview.needs_synthesis():
        return StorageSubviewProof(False, "needs_synthesis", container, subview)
    if container.identity is None or subview.identity is None:
        return StorageSubviewProof(False, "missing_identity", container, subview)
    if container.identity[0] != "stack" or subview.identity[0] != "stack":
        return StorageSubviewProof(False, "not_stack_storage", container, subview)
    container_view = container.domain.view
    subview_view = subview.domain.view
    if container_view is None or subview_view is None:
        return StorageSubviewProof(False, "missing_view", container, subview)
    if container_view.bit_width is None or subview_view.bit_width is None:
        return StorageSubviewProof(False, "unknown_width", container, subview)
    if container_view.bit_width <= subview_view.bit_width:
        return StorageSubviewProof(False, "not_proper_subview", container, subview)
    if not contains_alias_storage(container_expr, subview_expr):
        return StorageSubviewProof(False, "storage_mismatch", container, subview)
    relative_bit_offset = subview_view.bit_offset - container_view.bit_offset
    if expected_bit_offset is not None and relative_bit_offset != expected_bit_offset:
        return StorageSubviewProof(
            False,
            "bit_offset_mismatch",
            container,
            subview,
            relative_bit_offset=relative_bit_offset,
        )
    return StorageSubviewProof(
        True,
        "ok",
        container,
        subview,
        relative_bit_offset=relative_bit_offset,
    )


def analyze_adjacent_storage_slices(
    low_expr: object, high_expr: object, *, alias_state: AliasState | None = None
) -> StorageJoinAnalysis:
    """Return a convenience analysis object for adjacent storage slices."""
    return StorageJoinAnalysis(prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state))


def collect_widening_candidates(exprs: Iterable[object]) -> list[WideningCandidate]:
    """Collect expressions that have concrete widening candidate evidence."""
    candidates: list[WideningCandidate] = []
    for expr in exprs:
        try:
            candidates.append(WideningCandidate.from_expr(expr))
        except ValueError:
            continue
    return candidates


def describe_widening_candidates(exprs: Iterable[object]) -> tuple[dict[str, object], ...]:
    """Return deterministic descriptions of joinable widening candidates."""
    descriptions: list[dict[str, object]] = []
    for candidate in collect_widening_candidates(exprs):
        descriptions.append(
            {
                "domain": str(candidate.domain),
                "view": {
                    "bit_offset": candidate.view.bit_offset,
                    "bit_width": candidate.view.bit_width,
                },
            }
        )
    return tuple(descriptions)


WIDENING_PIPELINE: tuple[WideningPipelineSpec, ...] = (
    WideningPipelineSpec(
        name="candidate_extraction",
        purpose="Collect joinable storage candidates before proof or rewrite decisions.",
        helpers=("collect_widening_candidates", "describe_widening_candidates", "analyze_adjacent_storage_slices"),
    ),
    WideningPipelineSpec(
        name="compatibility_proof",
        purpose="Prove adjacent joins or contained projections are safe before widening proceeds.",
        helpers=("prove_adjacent_storage_slices", "prove_contained_stack_subview"),
    ),
    WideningPipelineSpec(
        name="join_decision",
        purpose="Gate widening on alias facts, compatible views, and version safety.",
        helpers=("can_join_adjacent_storage_slices", "merge_storage_slice_domains"),
    ),
)


def describe_x86_16_widening_pipeline() -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """Describe the widening pipeline order for architecture checks and tests."""
    return tuple((spec.name, spec.purpose, spec.helpers) for spec in WIDENING_PIPELINE)


def can_join_adjacent_storage_slices(
    low_expr: object, high_expr: object, *, alias_state: AliasState | None = None
) -> bool:
    """Return whether adjacent storage slices are proven safe to join."""

    def _impl() -> bool:
        proof = prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
        if not proof.ok:
            return False
        try:
            low_candidate = RegisterWideningCandidate.from_expr(low_expr)
            high_candidate = RegisterWideningCandidate.from_expr(high_expr)
        except ValueError:
            low_candidate = None
            high_candidate = None
        if low_candidate is not None and high_candidate is not None:
            if alias_state is None:
                return bool(low_candidate.is_joinable_with(high_candidate))
            return bool(can_join_adjacent_register_slices(low_expr, high_expr, alias_state=alias_state, proof=proof))

        try:
            low_storage_candidate = WideningCandidate.from_expr(low_expr)
            high_storage_candidate = WideningCandidate.from_expr(high_expr)
        except ValueError:
            return False
        if low_storage_candidate.domain.is_unknown() or high_storage_candidate.domain.is_unknown():
            return False
        if low_storage_candidate.domain.is_mixed() or high_storage_candidate.domain.is_mixed():
            return False
        return low_storage_candidate.is_joinable_with(high_storage_candidate)

    return _impl()


def merge_storage_slice_domains(
    low_expr: object, high_expr: object, *, alias_state: AliasState | None = None
) -> _StorageDomainSignature:
    """Return the merged storage domain for proven adjacent slices."""
    proof = prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
    if not proof.ok or proof.merged_domain is None:
        return _StorageDomainSignature("mixed")
    return proof.merged_domain


__all__ = [
    "WIDENING_PIPELINE",
    "RegisterWideningCandidate",
    "StorageJoinAnalysis",
    "StorageSubviewProof",
    "WideningCandidate",
    "WideningPipelineSpec",
    "WideningProof",
    "_StorageDomainSignature",
    "analyze_adjacent_storage_slices",
    "can_join_adjacent_register_slices",
    "can_join_adjacent_storage_slices",
    "collect_widening_candidates",
    "describe_widening_candidates",
    "describe_x86_16_widening_pipeline",
    "merge_storage_slice_domains",
    "prove_adjacent_storage_slices",
    "prove_contained_stack_subview",
]
