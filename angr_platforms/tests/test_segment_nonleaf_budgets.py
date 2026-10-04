"""Parent controls for consistent root accounting and bounded census allocation."""

from dataclasses import replace

import pytest
from segment_nonleaf_test_helpers import _Chain, call_preservation


@pytest.mark.parametrize("budget", (1, 2))
def test_constructor_and_revalidation_share_root_budget(monkeypatch: pytest.MonkeyPatch, budget: int) -> None:
    """Construction cannot report acceptance that immediately fails revalidation."""
    chain = _Chain()
    closure = chain.mid_closure()
    traversal = call_preservation.SegmentCallDependencyTraversal8616
    monkeypatch.setattr(call_preservation, "SegmentCallDependencyTraversal8616",
                        lambda: traversal(remaining_proofs=budget))
    proof = chain.root_proof(closure)
    expected = budget == 2
    assert (proof.failure is None) is expected
    assert proof.complete is expected
    assert proof.materialized_count == int(expected)
    assert proof.failure_count == int(not expected)


@pytest.mark.parametrize("field", ("census", "proofs"))
def test_oversized_census_is_refused_by_resource_guard(field: str) -> None:
    """Oversized retained tuples refuse before building per-call lookup tables."""
    chain = _Chain()
    closure = chain.mid_closure()
    if field == "census":
        closure = replace(closure, callsite_addrs=tuple(range(257)))
    else:
        state = replace(closure.state, call_preservations=(chain.mid_leaf_proof,) * 257)
        closure = replace(closure, state=state)
    proof = chain.root_proof(closure)
    assert proof.failure is call_preservation.SegmentCallPreservationFailure8616.DEPENDENCY_BUDGET_EXHAUSTED
    assert not proof.complete


@pytest.mark.parametrize("field", ("coverage", "state"))
def test_malformed_leaf_closure_is_refused_before_dereference(field: str) -> None:
    """The retained-field guard also covers a leaf with no dependency census."""
    chain = _Chain()
    closure = replace(chain.leaf_closure, **{field: None})
    proof = call_preservation.prove_segment_call_preservation_8616(
        chain.cov_mid, closure, chain.index, 0x2000,
    )
    assert proof.failure is call_preservation.SegmentCallPreservationFailure8616.DEPENDENCY_STALE
    assert not proof.complete
