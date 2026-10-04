"""Bounded call-chain preservation and dependency-refusal contracts.

Layer: Tests.
Responsibility: verify complete bound dependencies and linear validation work.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import angr_platforms.X86_16.ir.segment_call_preservation as call_preservation
import angr_platforms.X86_16.ir.segment_effect_closure as effect_closure
from angr_platforms.X86_16.ir import (
    build_x86_16_segment_state_artifact,
)
from segment_nonleaf_test_helpers import (
    _as_complete,
    _call,
    _Chain,
    _coverage,
    _EvidenceCalls,
    _index,
    _mov_seg,
    _ret,
    _single_block_artifact,
)


def test_leaf_call_preservation_unchanged() -> None:
    """Leaf callees keep the same verdict under both staged variants."""
    chain = _Chain()
    proof = chain.mid_leaf_proof
    assert proof.complete
    assert (proof.raw_fact_count, proof.normalized_fact_count, proof.classified_fact_count,
            proof.materialized_count, proof.failure_count) == (1, 1, 1, 1, 0)
    assert "ds" in proof.preserved_registers
    assert "es" not in proof.preserved_registers


def test_fully_proved_chain_admitted() -> None:
    """A non-leaf callee is admitted when every chain callsite is bound."""
    chain = _Chain()
    proof = chain.root_proof()
    assert proof.failure is None
    assert proof.complete
    assert (proof.materialized_count, proof.failure_count) == (1, 0)
    preserved = proof.preserved_registers
    assert "ds" in preserved and "ss" in preserved and "cs" in preserved
    assert "es" not in preserved
    assert proof.complete


def test_child_mutation_loses_affected_preservation() -> None:
    """A deeper segment write removes that identity from the whole chain."""
    chain = _Chain(leaf_writes=(
        _mov_seg("es", 0xB800, 0x3000),
        _mov_seg("ds", 0x1234, 0x3003),
    ))
    proof = chain.root_proof()
    assert proof.complete
    preserved = proof.preserved_registers
    assert "ds" not in preserved and "es" not in preserved
    assert "ss" in preserved and "cs" in preserved


def test_missing_dependency_proof_refuses() -> None:
    """A recorded callee callsite with no bound proof is a typed refusal."""
    chain = _Chain()
    state = build_x86_16_segment_state_artifact(chain.mid)
    mid_closure = chain.mid_closure_with_state(state)
    proof = chain.root_proof(mid_closure)
    assert not proof.complete
    assert proof.failure is call_preservation.SegmentCallPreservationFailure8616.DEPENDENCY_MISSING
    assert (proof.materialized_count, proof.failure_count) == (0, 1)


def test_duplicate_dependency_proof_refuses() -> None:
    """Two bound proofs for one callsite are ambiguous, not a pass."""
    chain = _Chain()
    mid_closure = chain.mid_closure(proofs=(chain.mid_leaf_proof, chain.mid_leaf_proof))
    proof = chain.root_proof(mid_closure)
    assert not proof.complete
    assert proof.failure is call_preservation.SegmentCallPreservationFailure8616.DEPENDENCY_AMBIGUOUS


def test_foreign_artifact_dependency_is_stale() -> None:
    """A bound proof issued for another caller artifact cannot be reused."""
    chain = _Chain()
    other = _single_block_artifact(0x4000, (_call(0x3000, 0x4000), _ret(0x4003)))
    cov_other = _coverage(chain.project, other)
    index = _index((0x1000, 0x1000, 0x2000), (0x2000, 0x2000, 0x3000), (0x4000, 0x4000, 0x3000))
    foreign = call_preservation.prove_segment_call_preservation_8616(cov_other, chain.leaf_closure, index, 0x4000)
    assert foreign.complete
    state = build_x86_16_segment_state_artifact(chain.mid, call_preservations=(chain.mid_leaf_proof,))
    fabricated = replace(state, call_preservations=(foreign,))
    proof = chain.root_proof(chain.mid_closure_with_state(fabricated))
    assert not proof.complete
    assert proof.failure is call_preservation.SegmentCallPreservationFailure8616.DEPENDENCY_STALE


def test_off_census_dependency_is_stale() -> None:
    """A proof bound to the artifact but outside the call census is stale."""
    chain = _Chain()
    displaced = replace(chain.mid_leaf_proof, callsite_addr=0x2FFE)
    state = build_x86_16_segment_state_artifact(chain.mid, call_preservations=(chain.mid_leaf_proof,))
    fabricated = replace(state, call_preservations=(displaced,))
    proof = chain.root_proof(chain.mid_closure_with_state(fabricated))
    assert not proof.complete
    assert proof.failure is call_preservation.SegmentCallPreservationFailure8616.DEPENDENCY_STALE


def test_cross_project_dependency_refuses() -> None:
    """A bound proof whose callee closure lives in another project refuses."""
    chain = _Chain()
    foreign_project = SimpleNamespace()
    leaf2 = _single_block_artifact(0x3000, (_mov_seg("es", 0xB800, 0x3000), _ret(0x3008)))
    cov_leaf2 = _coverage(foreign_project, leaf2)
    closure_leaf2 = effect_closure.prove_segment_effect_closure_8616(
        cov_leaf2, build_x86_16_segment_state_artifact(leaf2),
    )
    cross = call_preservation.prove_segment_call_preservation_8616(
        chain.cov_mid, closure_leaf2, chain.index, 0x2000,
    )
    state = build_x86_16_segment_state_artifact(chain.mid, call_preservations=(chain.mid_leaf_proof,))
    fabricated = replace(state, call_preservations=(cross,))
    proof = chain.root_proof(chain.mid_closure_with_state(fabricated))
    assert not proof.complete
    assert proof.failure is call_preservation.SegmentCallPreservationFailure8616.PROJECT_MISMATCH


def test_dependency_cycle_refuses_without_recursion_error() -> None:
    """Mutually referential callee evidence is a typed cycle refusal."""
    project = SimpleNamespace()
    caller = _single_block_artifact(0x9000, (_call(0x5000, 0x9000), _ret(0x9003)))
    gee = _single_block_artifact(0x5000, (_call(0x6000, 0x5000), _ret(0x5003)))
    eff = _single_block_artifact(0x6000, (_call(0x5000, 0x6000), _ret(0x6003)))
    cov_root = _coverage(project, caller)
    cov_g = _coverage(project, gee)
    cov_f = _coverage(project, eff)
    cycle_index = _index(
        (0x9000, 0x9000, 0x5000), (0x5000, 0x5000, 0x6000), (0x6000, 0x6000, 0x5000),
    )
    g_state0 = build_x86_16_segment_state_artifact(gee)
    f_state0 = build_x86_16_segment_state_artifact(eff)
    g_closure0 = effect_closure.prove_segment_effect_closure_8616(cov_g, g_state0)
    f_closure0 = effect_closure.prove_segment_effect_closure_8616(cov_f, f_state0)
    p_gf = _as_complete(call_preservation.prove_segment_call_preservation_8616(cov_g, f_closure0, cycle_index, 0x5000))
    p_fg = _as_complete(call_preservation.prove_segment_call_preservation_8616(cov_f, g_closure0, cycle_index, 0x6000))
    g_state = replace(g_state0, call_preservations=(p_gf,))
    f_state = replace(f_state0, call_preservations=(p_fg,))
    g_closure = replace(g_closure0, state=g_state)
    f_closure = replace(f_closure0, state=f_state)
    object.__setattr__(p_gf, "callee", f_closure)
    object.__setattr__(p_fg, "callee", g_closure)
    proof = call_preservation.prove_segment_call_preservation_8616(cov_root, g_closure, cycle_index, 0x9000)
    assert not proof.complete
    assert proof.failure is call_preservation.SegmentCallPreservationFailure8616.DEPENDENCY_CYCLE


def test_dependency_budget_exhaustion_refuses() -> None:
    """Chains beyond the explicit depth budget refuse instead of recursing."""
    project = SimpleNamespace()
    depth = 20
    addrs = [0x7000 + 0x100 * i for i in range(depth + 1)]
    artifacts = [
        _single_block_artifact(addr, (_call(addrs[i + 1], addr), _ret(addr + 3)))
        for i, addr in enumerate(addrs[:-1])
    ]
    artifacts.append(_single_block_artifact(addrs[-1], (_ret(addrs[-1]),)))
    coverages = [_coverage(project, artifact) for artifact in artifacts]
    index = _index(*(
        (addrs[i], addrs[i], addrs[i + 1]) for i in range(depth)
    ))
    closure = effect_closure.prove_segment_effect_closure_8616(
        coverages[-1], build_x86_16_segment_state_artifact(artifacts[-1]),
    )
    for i in range(depth - 1, -1, -1):
        proof = _as_complete(call_preservation.prove_segment_call_preservation_8616(
            coverages[i], closure, index, addrs[i],
        ))
        state = replace(
            build_x86_16_segment_state_artifact(artifacts[i]),
            call_preservations=(proof,),
        )
        closure = replace(
            closure, coverage=coverages[i], state=state, callsite_addrs=(addrs[i],),
        )
    top = call_preservation.prove_segment_call_preservation_8616(coverages[0], closure, index, addrs[0])
    assert not top.complete
    assert top.failure is not None and top.failure.value == "dependency_budget_exhausted"


def test_shared_callee_dag_still_admitted() -> None:
    """A shared callee reached through two chain paths is admitted once."""
    project = SimpleNamespace()
    leaf = _single_block_artifact(0x3000, (_mov_seg("es", 0xB800, 0x3000), _ret(0x3008)))
    mid_a = _single_block_artifact(0x2100, (_call(0x3000, 0x2100), _ret(0x2103)))
    mid_b = _single_block_artifact(0x2200, (_call(0x3000, 0x2200), _ret(0x2203)))
    hub = _single_block_artifact(0x2300, (_call(0x2100, 0x2300), _call(0x2200, 0x2303), _ret(0x2306)))
    root = _single_block_artifact(0xF000, (_call(0x2300, 0xF000), _ret(0xF003)))
    cov_leaf = _coverage(project, leaf)
    cov_a = _coverage(project, mid_a)
    cov_b = _coverage(project, mid_b)
    cov_hub = _coverage(project, hub)
    cov_root = _coverage(project, root)
    index = _index(
        (0xF000, 0xF000, 0x2300), (0x2100, 0x2100, 0x3000),
        (0x2200, 0x2200, 0x3000), (0x2300, 0x2300, 0x2100), (0x2300, 0x2303, 0x2200),
    )
    leaf_closure = effect_closure.prove_segment_effect_closure_8616(
        cov_leaf, build_x86_16_segment_state_artifact(leaf),
    )
    p_a = call_preservation.prove_segment_call_preservation_8616(cov_a, leaf_closure, index, 0x2100)
    p_b = call_preservation.prove_segment_call_preservation_8616(cov_b, leaf_closure, index, 0x2200)
    closure_a = effect_closure.prove_segment_effect_closure_8616(
        cov_a, build_x86_16_segment_state_artifact(mid_a, call_preservations=(p_a,)),
    )
    closure_b = effect_closure.prove_segment_effect_closure_8616(
        cov_b, build_x86_16_segment_state_artifact(mid_b, call_preservations=(p_b,)),
    )
    p_hub_a = call_preservation.prove_segment_call_preservation_8616(cov_hub, closure_a, index, 0x2300)
    p_hub_b = call_preservation.prove_segment_call_preservation_8616(cov_hub, closure_b, index, 0x2303)
    state_hub = build_x86_16_segment_state_artifact(hub, call_preservations=(p_hub_a, p_hub_b))
    closure_hub = effect_closure.prove_segment_effect_closure_8616(cov_hub, state_hub)
    proof = call_preservation.prove_segment_call_preservation_8616(cov_root, closure_hub, index, 0xF000)
    assert proof.complete
    assert "es" not in proof.preserved_registers
    assert "ds" in proof.preserved_registers


def test_unresolved_inner_target_refuses() -> None:
    """An inner proof whose callsite lacks an index entry stays refused."""
    chain = _Chain()
    foreign_index = _index((0x9999, 0x2000, 0x3000))
    unproven = call_preservation.prove_segment_call_preservation_8616(
        chain.cov_mid, chain.leaf_closure, foreign_index, 0x2000,
    )
    assert not unproven.complete
    state = build_x86_16_segment_state_artifact(chain.mid, call_preservations=(chain.mid_leaf_proof,))
    fabricated = replace(state, call_preservations=(unproven,))
    proof = call_preservation.prove_segment_call_preservation_8616(
        chain.cov_root, chain.mid_closure_with_state(fabricated), chain.index, 0x1000,
    )
    assert not proof.complete
    assert proof.failure is call_preservation.SegmentCallPreservationFailure8616.CALLSITE_UNPROVEN


def test_forged_empty_census_cannot_bypass_dependency_check() -> None:
    """A shrunken stored callsite census is caught by artifact revalidation."""
    chain = _Chain()
    forged = replace(chain.mid_closure(), callsite_addrs=())
    proof = chain.root_proof(forged)
    assert not proof.complete
    assert proof.failure is not None and proof.failure.value == "coverage_incomplete"


def test_dependency_evaluations_bounded_on_linear_chain() -> None:
    """One prove pass evaluates each callee closure's local evidence once."""
    chain = _Chain()
    mid_closure = chain.mid_closure()
    with _EvidenceCalls() as calls:
        proof = chain.root_proof(mid_closure)
    assert proof.complete
    assert calls.count == 2


def test_dependency_evaluations_bounded_on_shared_dag() -> None:
    """A shared leaf reached through two parents is validated once per edge."""
    project = SimpleNamespace()
    leaf = _single_block_artifact(0x3000, (_mov_seg("es", 0xB800, 0x3000), _ret(0x3008)))
    mid_a = _single_block_artifact(0x2100, (_call(0x3000, 0x2100), _ret(0x2103)))
    mid_b = _single_block_artifact(0x2200, (_call(0x3000, 0x2200), _ret(0x2203)))
    hub = _single_block_artifact(0x2300, (_call(0x2100, 0x2300), _call(0x2200, 0x2303), _ret(0x2306)))
    root = _single_block_artifact(0xF000, (_call(0x2300, 0xF000), _ret(0xF003)))
    cov_leaf = _coverage(project, leaf)
    cov_a = _coverage(project, mid_a)
    cov_b = _coverage(project, mid_b)
    cov_hub = _coverage(project, hub)
    cov_root = _coverage(project, root)
    index = _index(
        (0xF000, 0xF000, 0x2300), (0x2100, 0x2100, 0x3000),
        (0x2200, 0x2200, 0x3000), (0x2300, 0x2300, 0x2100), (0x2300, 0x2303, 0x2200),
    )
    leaf_closure = effect_closure.prove_segment_effect_closure_8616(
        cov_leaf, build_x86_16_segment_state_artifact(leaf),
    )
    p_a = call_preservation.prove_segment_call_preservation_8616(cov_a, leaf_closure, index, 0x2100)
    p_b = call_preservation.prove_segment_call_preservation_8616(cov_b, leaf_closure, index, 0x2200)
    closure_a = effect_closure.prove_segment_effect_closure_8616(
        cov_a, build_x86_16_segment_state_artifact(mid_a, call_preservations=(p_a,)),
    )
    closure_b = effect_closure.prove_segment_effect_closure_8616(
        cov_b, build_x86_16_segment_state_artifact(mid_b, call_preservations=(p_b,)),
    )
    p_hub_a = call_preservation.prove_segment_call_preservation_8616(cov_hub, closure_a, index, 0x2300)
    p_hub_b = call_preservation.prove_segment_call_preservation_8616(cov_hub, closure_b, index, 0x2303)
    closure_hub = effect_closure.prove_segment_effect_closure_8616(
        cov_hub,
        build_x86_16_segment_state_artifact(hub, call_preservations=(p_hub_a, p_hub_b)),
    )
    with _EvidenceCalls() as calls:
        proof = call_preservation.prove_segment_call_preservation_8616(cov_root, closure_hub, index, 0xF000)
    assert proof.complete
    assert calls.count == 5
