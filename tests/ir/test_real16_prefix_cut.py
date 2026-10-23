"""Structural-only CALL-cut admissions and corrupted controls."""

from dataclasses import replace
from time import monotonic

import pytest

pytestmark = pytest.mark.decompiler

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRRefusal
from inertia.ir.real16_prefix_cut import (
    PrefixCallRow8616,
    PrefixCutBudget8616,
    PrefixCutFailure8616,
    admit_prefix_cut_8616,
)


def graph(edges=((2,), (3,), ())):
    blocks = tuple(IRBlock(i + 1, (IRInstr("CALL", None, (), addr=10 + i),),
                           successor_addrs=targets) for i, targets in enumerate(edges))
    return IRFunctionArtifact(1, blocks)


def row(artifact, block_index=0, index=0):
    block = artifact.blocks[block_index]
    return PrefixCallRow8616(artifact, block, index, block.instrs[index])


def admit(artifact, prior=None, later=None, **kwargs):
    boundary = ExactFunctionRangeBoundary8616(
        object(), artifact.function_addr, 100, frozenset(block.addr for block in artifact.blocks),
        frozenset(), tuple((block.addr, target) for block in artifact.blocks
                          for target in block.successor_addrs),
    )
    if kwargs.pop("incomplete", False):
        boundary = replace(boundary, successor_edges=())
    if kwargs.pop("duplicate_boundary", False):
        boundary = replace(boundary, successor_edges=boundary.successor_edges * 2)
    return admit_prefix_cut_8616(
        artifact, boundary, prior or row(artifact), later or row(artifact, len(artifact.blocks) - 1),
        budget=kwargs.pop("budget", PrefixCutBudget8616(1000, monotonic() + 10)),
        **kwargs,
    )


@pytest.mark.parametrize("edges", [((2,), ()), ((2,), (3,), ())])
def test_two_and_three_calls(edges):
    artifact = graph(edges)
    result = admit(artifact)
    assert result.complete
    assert result.witness.artifact is artifact
    assert result.witness.prior.row is artifact.blocks[0].instrs[0]
    assert result.work_units > 0
    assert result.stats.materialized_count == 1


def test_closed_cut_reuses_the_collected_block_census():
    """The CFG owner must consume the fresh census, not traverse the artifact again."""
    visits = []

    class CountedBlocks(tuple):
        def __iter__(self):
            visits.append(1)
            return super().__iter__()

    artifact = graph()
    boundary = ExactFunctionRangeBoundary8616(
        object(), 1, 100, frozenset((1, 2, 3)), frozenset(), ((1, 2), (2, 3)))
    prior, later = row(artifact), row(artifact, 2)
    object.__setattr__(artifact, 'blocks', CountedBlocks(artifact.blocks))
    result = admit_prefix_cut_8616(
        artifact, boundary, prior, later, budget=PrefixCutBudget8616(1000, float('inf')))
    assert result.complete
    assert len(visits) == 1


@pytest.mark.parametrize('edges', [((2,), ()), ((2, 3), (3,), ())])
def test_extension_advice_tracks_metered_structural_work(edges):
    """Selection advice must remain a lower bound on actual admitted work."""
    from types import SimpleNamespace

    from inertia.ir.real16_invocation_domain import _prefix_structural_extension_lower_8616
    from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

    artifact = graph(edges)
    boundary = ExactFunctionRangeBoundary8616(
        object(), 1, 100, frozenset(block.addr for block in artifact.blocks), frozenset(),
        tuple((block.addr, target) for block in artifact.blocks for target in block.successor_addrs))
    ctx = SimpleNamespace(work_units=0, accounted_work_units=0, work_limit=20000, deadline=float('inf'))
    with segment_call_dependency_traversal_scope_8616():
        lower = _prefix_structural_extension_lower_8616(ctx, artifact, boundary)
    result = admit_prefix_cut_8616(artifact, boundary, row(artifact), row(artifact, len(edges)-1),
                                 budget=PrefixCutBudget8616(1000, float('inf')))
    assert result.complete
    assert lower is not None and 0 < lower <= result.work_units


def test_same_block_order():
    artifact = IRFunctionArtifact(1, (IRBlock(1, (
        IRInstr("CALL", None, (), addr=10), IRInstr("CALL", None, (), addr=11))),))
    assert admit(artifact, row(artifact), row(artifact, index=1)).complete
    assert admit(artifact, row(artifact, index=1), row(artifact)).failure is PrefixCutFailure8616.ORDER


@pytest.mark.parametrize("reject_at,visited", [(1, 0), (32, 1), (1000, 3)])
def test_unprofitable_extension_advice_stops_counting(reject_at, visited):
    """Once rejection is certain, do not spend the proof budget refining advice."""
    from types import SimpleNamespace

    from inertia.ir.real16_invocation_domain import _prefix_structural_extension_lower_8616
    from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

    artifact = graph()
    boundary = ExactFunctionRangeBoundary8616(
        object(), 1, 100, frozenset((1, 2, 3)), frozenset(), ((1, 2), (2, 3)))
    ctx = SimpleNamespace(work_units=0, accounted_work_units=0, work_limit=20000, deadline=float("inf"))
    with segment_call_dependency_traversal_scope_8616():
        lower = _prefix_structural_extension_lower_8616(ctx, artifact, boundary, reject_at=reject_at)
    assert lower is not None
    assert ctx.work_units == visited
    assert (lower >= reject_at) == (visited < len(artifact.blocks))


@pytest.mark.parametrize("edges,failure", [
    (( (2, 3), (3,), ()), PrefixCutFailure8616.BYPASS),
    (( (2,), (3,), (1,)), PrefixCutFailure8616.CYCLE),
    (( (2,), (99,), ()), PrefixCutFailure8616.MISSING_EDGE),
    (( (2, 2), (3,), ()), PrefixCutFailure8616.DUPLICATE_EDGE),
])
def test_graph_corruption(edges, failure):
    artifact = graph(edges)
    prior = row(artifact, 1) if failure is PrefixCutFailure8616.BYPASS else row(artifact)
    result = admit(artifact, prior=prior)
    assert not result.complete
    assert result.witness is None
    assert result.failure is failure
    assert result.stats.failure_count == 1
    assert result.stats.classified_fact_count == result.stats.materialized_count + result.stats.failure_count


def test_identity_is_not_equality():
    artifact = graph()
    forged = replace(row(artifact), row=replace(artifact.blocks[0].instrs[0]))
    assert admit(artifact, prior=forged).failure is PrefixCutFailure8616.IDENTITY
    foreign = replace(row(artifact), artifact=replace(artifact))
    assert admit(artifact, prior=foreign).failure is PrefixCutFailure8616.IDENTITY


@pytest.mark.parametrize("mutation,failure", [
    ("call", PrefixCutFailure8616.DUPLICATE_CALL),
    ("block", PrefixCutFailure8616.DUPLICATE_BLOCK),
    ("malformed", PrefixCutFailure8616.MALFORMED_ROW),
    ("refusal", PrefixCutFailure8616.INCOMPLETE_CFG),
])
def test_ambiguous_or_incomplete(mutation, failure):
    artifact = graph()
    blocks = list(artifact.blocks)
    if mutation == "call":
        blocks[1] = replace(blocks[1], instrs=blocks[0].instrs)
    elif mutation == "block":
        blocks.append(blocks[0])
    elif mutation == "malformed":
        blocks[1] = replace(blocks[1], instrs=(IRInstr("CALL", None, (), addr=None),))
    else:
        blocks[1] = replace(blocks[1], refusals=(IRRefusal("unknown", "incomplete"),))
    artifact = replace(artifact, blocks=tuple(blocks))
    assert admit(artifact).failure is failure


def test_explicit_completeness_required():
    assert admit(graph(), incomplete=True).failure is PrefixCutFailure8616.INCOMPLETE_CFG


def test_duplicate_native_boundary_edges():
    assert admit(graph(), duplicate_boundary=True).failure is PrefixCutFailure8616.DUPLICATE_EDGE


def test_exhaustion_at_each_work_boundary():
    artifact = graph()
    complete = admit(artifact)
    for limit in range(complete.work_units):
        budget = PrefixCutBudget8616(limit, monotonic() + 10)
        result = admit(artifact, budget=budget)
        assert result.failure is PrefixCutFailure8616.WORK
        assert result.witness is None
        assert budget.work_units <= limit


def test_branch_join_before_cut():
    artifact = graph(((2, 3), (4,), (4,), (5,), ()))
    assert admit(artifact, prior=row(artifact, 3)).complete


@pytest.mark.parametrize("op", ["RET", "JMP", "CJMP"])
def test_control_before_selected_call(op):
    artifact = IRFunctionArtifact(1, (IRBlock(1, (
        IRInstr("CALL", None, (), addr=10), IRInstr(op, None, (), addr=11),
        IRInstr("CALL", None, (), addr=12))),))
    result = admit(artifact, row(artifact), row(artifact, index=2))
    assert result.failure is PrefixCutFailure8616.MALFORMED_ROW
    assert result.witness is None


def test_missing_entry_is_typed_refusal():
    artifact = replace(graph(), function_addr=99)
    assert admit(artifact).failure is PrefixCutFailure8616.INCOMPLETE_CFG


@pytest.mark.parametrize("budget,failure", [
    (PrefixCutBudget8616(0, float("inf")), PrefixCutFailure8616.WORK),
    (PrefixCutBudget8616(1000, 0), PrefixCutFailure8616.DEADLINE),
])
def test_exhausted_budget(budget, failure):
    result = admit(graph(), budget=budget)
    assert result.failure is failure
    assert result.witness is None
    assert budget.work_units <= budget.max_work_units


def absorbing(artifact, **kwargs):
    from inertia.ir.real16_prefix_cut import PrefixCutExtent8616

    return admit(artifact, extent=PrefixCutExtent8616.BEFORE_LATER_CALL, **kwargs)


def test_absorbing_future_refusal_keeps_original_artifact():
    artifact = graph(((2, 4), (3,), (5,), (), (5,)))
    blocks = list(artifact.blocks)
    blocks[3] = replace(blocks[3], instrs=(IRInstr("RET", None, (), addr=13),))
    refusal = IRRefusal("unknown", "future control unresolved")
    blocks[4] = replace(blocks[4], refusals=(refusal,))
    artifact = replace(artifact, blocks=tuple(blocks))
    assert admit(artifact, later=row(artifact, 2)).failure is PrefixCutFailure8616.INCOMPLETE_CFG
    result = absorbing(artifact, later=row(artifact, 2))
    assert result.complete
    assert result.witness.region == frozenset((1, 2, 3, 4))
    assert result.witness.artifact is artifact
    assert artifact.blocks[4].refusals == (refusal,)


def test_absorbing_pre_cut_refusal():
    artifact = graph()
    artifact = replace(artifact, blocks=(artifact.blocks[0], replace(
        artifact.blocks[1], refusals=(IRRefusal("unknown", "before cut"),)), artifact.blocks[2]))
    assert absorbing(artifact).failure is PrefixCutFailure8616.INCOMPLETE_CFG


@pytest.mark.parametrize("edges,prior,failure", [
    (((2, 3), (3,), ()), 1, PrefixCutFailure8616.BYPASS),
    (((2,), (1, 3), ()), 0, PrefixCutFailure8616.CYCLE),
])
def test_absorbing_before_cut_graph_refusals(edges, prior, failure):
    artifact = graph(edges)
    assert absorbing(artifact, prior=row(artifact, prior)).failure is failure


def test_absorbing_global_call_ambiguity_and_terminal_geometry():
    artifact = graph()
    blocks = list(artifact.blocks)
    blocks[-1] = replace(blocks[-1], instrs=(*blocks[-1].instrs, IRInstr("NOP", None, (), addr=12)))
    assert absorbing(replace(artifact, blocks=tuple(blocks))).failure is PrefixCutFailure8616.MALFORMED_ROW
    artifact = graph(((2,), (3,), ()))
    blocks = list(artifact.blocks)
    blocks[-1] = replace(blocks[-1], instrs=blocks[0].instrs)
    artifact = replace(artifact, blocks=tuple(blocks))
    assert absorbing(artifact, later=row(artifact, 1)).failure is PrefixCutFailure8616.DUPLICATE_CALL


def test_absorbing_region_does_not_authorize_future_execution():
    artifact = graph(((2,), (3,), (1,)))
    result = absorbing(artifact, later=row(artifact, 1))
    assert result.complete
    assert result.witness.region == frozenset((1, 2))
    assert not frozenset((1, 2, 3)).issubset(result.witness.region)
    assert admit(artifact, later=row(artifact, 1)).failure is PrefixCutFailure8616.CYCLE


def test_absorbing_exhaustion_and_foreign_row():
    artifact = graph(((2,), (3,), (3,)))
    complete = absorbing(artifact, later=row(artifact, 1))
    assert complete.complete
    for limit in range(complete.work_units):
        result = absorbing(artifact, later=row(artifact, 1), budget=PrefixCutBudget8616(limit, float("inf")))
        assert result.failure is PrefixCutFailure8616.WORK
        assert result.witness is None
    result = absorbing(artifact, later=row(artifact, 1), budget=PrefixCutBudget8616(1000, 0))
    assert result.failure is PrefixCutFailure8616.DEADLINE
    forged = replace(row(artifact, 1), row=replace(artifact.blocks[1].instrs[0]))
    assert absorbing(artifact, later=forged).failure is PrefixCutFailure8616.IDENTITY


@pytest.mark.parametrize("op", ["RET", "JMP", "CJMP"])
def test_absorbing_early_control_before_selected_row(op):
    artifact = graph()
    block = replace(artifact.blocks[1], instrs=(IRInstr(op, None, (), addr=11), *artifact.blocks[1].instrs))
    artifact = replace(artifact, blocks=(artifact.blocks[0], block, artifact.blocks[2]))
    assert absorbing(artifact).failure is PrefixCutFailure8616.MALFORMED_ROW


@pytest.mark.parametrize("extent", [None, "before_later_call", object()])
def test_foreign_extent_cannot_skip_full_refusals(extent):
    artifact = graph()
    artifact = replace(artifact, blocks=(*artifact.blocks[:-1], replace(
        artifact.blocks[-1], refusals=(IRRefusal("unknown", "pending"),))))
    assert admit(artifact, extent=extent).failure is PrefixCutFailure8616.IDENTITY


def test_executor_rejects_future_reentry_scope_before_callbacks(monkeypatch):
    """Absorbing structure alone cannot authorize the executor's future cone."""
    from types import SimpleNamespace

    from inertia.ir import real16_invocation_domain as owner

    artifact = graph(((2,), (3,), (1,)))
    boundary = ExactFunctionRangeBoundary8616(
        object(), 1, 100, frozenset((1, 2, 3)), frozenset(), ((1, 2), (2, 3), (3, 1)),
    )
    prior = row(artifact)
    terminal = SimpleNamespace(block=prior.block, index=prior.index, instruction=prior.row)
    data = SimpleNamespace(context=SimpleNamespace(prefix_consumed=False, prefix_terminal_call=terminal))
    ctx = SimpleNamespace(callsite_addr=11, stop_block_addr=2, work_units=0,
                          deadline=monotonic() + 10, edge_feasibility=SimpleNamespace(
                              live_blocks=frozenset((1, 2, 3))))
    # Isolate the scope guard with synthetic private inputs; this grants no
    # CURRENT/native authority and never reaches the execution machinery.
    monkeypatch.setattr(owner, "_prefix_extension_inputs_8616", lambda *args: True)
    monkeypatch.setattr(owner, "_prefix_work_allowance_8616", lambda *args: 10000)
    monkeypatch.setattr(owner, "_census_resource_failure_8616", lambda *args: None)
    monkeypatch.setattr(owner, "_prefix_suffix_scope_8616", lambda *args: frozenset((2, 3)))

    def forbidden(*args):
        pytest.fail("future scope reached callback authentication or execution")

    monkeypatch.setattr(owner, "_prefix_calls_current_8616", forbidden)
    monkeypatch.setattr(owner, "_execute_prefix_extension_8616", forbidden)
    assert owner._try_prefix_extension_8616(ctx, artifact, boundary, None, data) is False
    assert not data.context.prefix_consumed
    assert ctx.work_units > 0
