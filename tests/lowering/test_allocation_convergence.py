"""Unit coverage for the Lowering-owned allocation convergence policy."""

from __future__ import annotations

from inertia.lowering.allocation_convergence import (
    AllocationCensus,
    AllocationConvergenceSession,
    AllocationDecisionKind,
    AllocationFingerprintRefusal,
    AllocationInputFingerprint,
    NativeVariableKey,
)


def _fp(tag: int, *, graph: bool = True) -> AllocationInputFingerprint:
    """Minimal typed fingerprint whose evidence varies with ``tag``."""
    return AllocationInputFingerprint(
        function_addr=0x1000,
        argument_variables=(NativeVariableKey("stack", f"v{tag}", tag, 2, None),),
        argument_vvars=(),
        vvar_to_vvar=(),
        type_hints=(),
        manual_types=(),
        stack_items=(),
        prototype=None,
        calling_convention=None,
        entry_node=None,
        graph_nodes=((0x1000, 0, ((tag,),)),) if graph else (),
        graph_edges=() if not graph else (((0x1000, 0), (0x1000, 0), ()),),
    )


def test_census_invariants() -> None:
    assert AllocationCensus().validate() == ()
    assert AllocationCensus(attempts=1, published=2).validate() != ()
    assert AllocationCensus(attempts=1, failures=2).validate() != ()
    assert AllocationCensus(skipped=-1).validate() != ()


def test_first_entry_must_run() -> None:
    session = AllocationConvergenceSession(max_rounds=1)
    assert session.decide(_fp(1), bound=True).kind is AllocationDecisionKind.RUN


def test_unchanged_bound_input_skips() -> None:
    session = AllocationConvergenceSession(max_rounds=1)
    session.begin_transaction(_fp(1))
    session.record_published(_fp(1), _fp(1), "handle-a")
    assert session.decide(_fp(1), bound=True).kind is AllocationDecisionKind.SKIP
    session.record_skip()
    assert session.census().skipped == 1


def test_unbound_surfaces_must_rerun() -> None:
    """A new clinic generation (new variable_map/graph) cannot reuse."""
    session = AllocationConvergenceSession(max_rounds=1)
    session.begin_transaction(_fp(1))
    session.record_published(_fp(1), _fp(1), "handle-a")
    assert session.decide(_fp(1), bound=False).kind is AllocationDecisionKind.RUN


def test_accepted_output_reentry_skips() -> None:
    """Same clinic re-entering after its own run presents the output surface."""
    session = AllocationConvergenceSession(max_rounds=1)
    session.begin_transaction(_fp(1))
    session.record_published(_fp(1), _fp(9), "handle-a")
    assert session.decide(_fp(9), bound=True).kind is AllocationDecisionKind.SKIP


def test_midrun_revision_iterates_then_exhausts() -> None:
    """Distinct evidence revisions inside one transaction consume the budget."""
    session = AllocationConvergenceSession(max_rounds=1)
    session.begin_transaction(_fp(1))
    assert session.record_revision_round(_fp(2).evidence_only()).kind is (
        AllocationDecisionKind.RUN
    )
    assert session.record_revision_round(_fp(3).evidence_only()).kind is (
        AllocationDecisionKind.EXHAUSTED
    )


def test_midrun_revision_cycle() -> None:
    """Evidence oscillating inside one transaction is a cycle refusal."""
    session = AllocationConvergenceSession(max_rounds=4)
    session.begin_transaction(_fp(1))
    assert session.record_revision_round(_fp(2).evidence_only()).kind is AllocationDecisionKind.RUN
    assert session.record_revision_round(_fp(1).evidence_only()).kind is (
        AllocationDecisionKind.CYCLE
    )


def test_lifetime_revisions_are_not_cycles() -> None:
    """A -> B -> A across completed transactions is a legitimate edit."""
    session = AllocationConvergenceSession(max_rounds=1)
    for tag in (1, 2, 1, 2):
        assert session.decide(_fp(tag), bound=False).kind is AllocationDecisionKind.RUN
        session.begin_transaction(_fp(tag))
        session.record_published(_fp(tag), _fp(tag), "h")


def test_failure_does_not_publish() -> None:
    session = AllocationConvergenceSession(max_rounds=1)
    session.begin_transaction(_fp(1))
    session.record_published(_fp(1), _fp(1), "h")
    session.decide(_fp(2), bound=True)
    session.begin_transaction(_fp(2))
    session.record_failure(_fp(2))
    assert session.census().failures == 1
    assert session.accepted_fingerprint == _fp(1)


def test_fingerprint_refusal_is_typed() -> None:
    assert issubclass(AllocationFingerprintRefusal, Exception)


def test_completed_stage_decisions_have_closed_evidence_counts() -> None:
    """Publication, reuse and refusal all occupy one explicit outcome slot."""
    census = AllocationCensus(attempts=3, published=2, failures=1, skipped=4, refused=5)
    assert census.raw_fact_count == census.normalized_fact_count == census.classified_fact_count == 12
    assert census.materialized_count == 6
    assert census.failure_count == 6
    assert census.validate() == ()
    assert AllocationCensus(attempts=1).validate() != ()
