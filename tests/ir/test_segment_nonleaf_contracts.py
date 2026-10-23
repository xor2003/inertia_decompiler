"""Bounded call-chain preservation and dependency-refusal contracts.

Layer: Tests.
Responsibility: verify complete bound dependencies and linear validation work.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import inertia.ir.segment_call_preservation as call_preservation
import inertia.ir.segment_effect_closure as effect_closure
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir import (
    IRFunctionArtifact,
    IRInstr,
    build_x86_16_segment_state_artifact,
)
from inertia.ir.function_ir_registry import publish_function_ir_artifact_8616
from inertia.ir.ir_boundary_cfg import (
    IRBoundaryCoverageResult8616,
    prove_ir_boundary_coverage_8616,
)
from tests.fixtures.segment_nonleaf_test_helpers import (
    _as_complete,
    _call,
    _Chain,
    _EvidenceCalls,
    _index,
    _mov_seg,
    _ret,
    _single_block_artifact,
)

_BLOCK_CODE = bytes.fromhex("8cd8e8fb0f8ec0c3")  # mov ax,ds; call +0xffb; mov es,ax; ret


def _project_8616() -> SimpleNamespace:
    """Mint a mock project carrying the bound-block authentication surface.

    Bound-block coverage authentication requires a real architecture, live
    loader bytes equal to the retained decoded bytes, and decoded blocks on
    the boundary; the mock supplies exactly that surface.
    """
    spans: dict[int, bytes] = {}

    def _load(addr: int, size: int) -> bytes:
        for base, code in spans.items():
            if base <= addr and addr + size <= base + len(code):
                return code[addr - base: addr - base + size]
        return b""

    return SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(memory=SimpleNamespace(load=_load)),
        _inertia_test_native_spans_8616=spans,
    )


def _decoded_block_8616(addr: int) -> SimpleNamespace:
    """Mint one retained decoded block over the shared clean bytes."""
    extents = ((addr + 0, 2), (addr + 2, 3), (addr + 5, 2), (addr + 7, 1))
    return SimpleNamespace(
        addr=addr, size=len(_BLOCK_CODE), bytes=_BLOCK_CODE,
        capstone=SimpleNamespace(insns=tuple(
            SimpleNamespace(address=head, size=size) for head, size in extents)),
    )


def _coverage(
    project: SimpleNamespace, artifact: IRFunctionArtifact,
) -> IRBoundaryCoverageResult8616:
    """Publish and prove boundary coverage over retained decoded blocks."""
    publish_function_ir_artifact_8616(project, artifact)
    spans = project._inertia_test_native_spans_8616
    blocks = tuple(
        _decoded_block_8616(block.addr) for block in artifact.blocks
    )
    for block in artifact.blocks:
        spans[block.addr] = _BLOCK_CODE
    boundary = ExactFunctionRangeBoundary8616(
        project,
        artifact.function_addr,
        0x10,
        frozenset(block.addr for block in artifact.blocks),
        frozenset(instr.addr for block in artifact.blocks for instr in block.instrs),
        (),
        blocks=blocks,
    )
    return prove_ir_boundary_coverage_8616(project, boundary, artifact)


class _BoundChain(_Chain):
    """The proved caller->mid->leaf chain over the bound native surface."""

    def __init__(
        self,
        leaf_writes: tuple[IRInstr, ...] = (_mov_seg("es", 0xB800, 0x3000),),
    ) -> None:
        """Build the same chain against a minted bound-block project."""
        self.project = _project_8616()
        self.leaf = _single_block_artifact(0x3000, (*leaf_writes, _ret(0x3008)))
        self.mid = _single_block_artifact(0x2000, (_call(0x3000, 0x2000), _ret(0x2003)))
        self.root = _single_block_artifact(0x1000, (_call(0x2000, 0x1000), _ret(0x1003)))
        self.cov_leaf = _coverage(self.project, self.leaf)
        self.cov_mid = _coverage(self.project, self.mid)
        self.cov_root = _coverage(self.project, self.root)
        self.index = _index((0x1000, 0x1000, 0x2000), (0x2000, 0x2000, 0x3000))
        self.leaf_closure = effect_closure.prove_segment_effect_closure_8616(
            self.cov_leaf, build_x86_16_segment_state_artifact(self.leaf),
        )
        self.mid_leaf_proof = call_preservation.prove_segment_call_preservation_8616(
            self.cov_mid, self.leaf_closure, self.index, 0x2000,
        )


def test_leaf_call_preservation_unchanged() -> None:
    """Leaf callees keep the same verdict under both staged variants."""
    chain = _BoundChain()
    proof = chain.mid_leaf_proof
    assert proof.complete
    assert (proof.raw_fact_count, proof.normalized_fact_count, proof.classified_fact_count,
            proof.materialized_count, proof.failure_count) == (1, 1, 1, 1, 0)
    assert "ds" in proof.preserved_registers
    assert "es" not in proof.preserved_registers


def test_fully_proved_chain_admitted() -> None:
    """A non-leaf callee is admitted when every chain callsite is bound."""
    chain = _BoundChain()
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
    chain = _BoundChain(leaf_writes=(
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
    chain = _BoundChain()
    state = build_x86_16_segment_state_artifact(chain.mid)
    mid_closure = chain.mid_closure_with_state(state)
    proof = chain.root_proof(mid_closure)
    assert not proof.complete
    assert proof.failure is call_preservation.SegmentCallPreservationFailure8616.DEPENDENCY_MISSING
    assert (proof.materialized_count, proof.failure_count) == (0, 1)


def test_duplicate_dependency_proof_refuses() -> None:
    """Two bound proofs for one callsite are ambiguous, not a pass."""
    chain = _BoundChain()
    mid_closure = chain.mid_closure(proofs=(chain.mid_leaf_proof, chain.mid_leaf_proof))
    proof = chain.root_proof(mid_closure)
    assert not proof.complete
    assert proof.failure is call_preservation.SegmentCallPreservationFailure8616.DEPENDENCY_AMBIGUOUS


def test_foreign_artifact_dependency_is_stale() -> None:
    """A bound proof issued for another caller artifact cannot be reused."""
    chain = _BoundChain()
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
    chain = _BoundChain()
    displaced = replace(chain.mid_leaf_proof, callsite_addr=0x2FFE)
    state = build_x86_16_segment_state_artifact(chain.mid, call_preservations=(chain.mid_leaf_proof,))
    fabricated = replace(state, call_preservations=(displaced,))
    proof = chain.root_proof(chain.mid_closure_with_state(fabricated))
    assert not proof.complete
    assert proof.failure is call_preservation.SegmentCallPreservationFailure8616.DEPENDENCY_STALE


def test_cross_project_dependency_refuses() -> None:
    """A bound proof whose callee closure lives in another project refuses."""
    chain = _BoundChain()
    foreign_project = _project_8616()
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
    project = _project_8616()
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
    project = _project_8616()
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
    project = _project_8616()
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
    chain = _BoundChain()
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
    chain = _BoundChain()
    forged = replace(chain.mid_closure(), callsite_addrs=())
    proof = chain.root_proof(forged)
    assert not proof.complete
    assert proof.failure is not None and proof.failure.value == "coverage_incomplete"


def test_dependency_evaluations_bounded_on_linear_chain() -> None:
    """One prove pass evaluates each callee closure's local evidence once."""
    chain = _BoundChain()
    mid_closure = chain.mid_closure()
    with _EvidenceCalls() as calls:
        proof = chain.root_proof(mid_closure)
    assert proof.complete
    assert calls.count == 2


def test_dependency_evaluations_bounded_on_shared_dag() -> None:
    """A shared leaf reached through two parents is validated once per edge."""
    project = _project_8616()
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
