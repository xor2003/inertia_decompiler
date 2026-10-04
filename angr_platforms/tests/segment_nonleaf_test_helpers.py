"""Typed fixture construction and counters for call-dependency proof controls.

Layer: Tests.
Responsibility: construct registered evidence and measure bounded validation.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import angr_platforms.X86_16.ir.segment_call_preservation as call_preservation
import angr_platforms.X86_16.ir.segment_effect_closure as effect_closure
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsite8616,
    DecodedDirectCallsiteIndex8616,
    DecodedDirectCallsiteIndexStats8616,
)
from angr_platforms.X86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from angr_platforms.X86_16.ir import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    build_x86_16_segment_state_artifact,
)
from angr_platforms.X86_16.ir.function_ir_registry import publish_function_ir_artifact_8616
from angr_platforms.X86_16.ir.ir_boundary_cfg import IRBoundaryCoverageResult8616, prove_ir_boundary_coverage_8616
from angr_platforms.X86_16.ir.segment_call_preservation import SegmentCallPreservationResult8616 as PreservationResult
from angr_platforms.X86_16.ir.segment_effect_closure import SegmentEffectClosureFailure8616
from angr_platforms.X86_16.ir.segment_effect_closure import SegmentEffectClosureResult8616 as ClosureResult
from angr_platforms.X86_16.ir.segment_state import SegmentStateArtifact


def _mov_seg(register: str, const: int, addr: int) -> IRInstr:
    """Build one constant segment-register write instruction."""
    return IRInstr(
        "MOV",
        IRValue(MemSpace.REG, name=register, size=2),
        (IRValue(MemSpace.CONST, const=const, size=2),),
        addr=addr,
    )


def _call(target: int, site: int) -> IRInstr:
    """Build one CONST-target near CALL instruction."""
    return IRInstr("CALL", None, (IRValue(MemSpace.CONST, const=target, size=2),), addr=site)


def _ret(addr: int) -> IRInstr:
    """Build one RET terminator."""
    return IRInstr("RET", None, (), addr=addr)


def _single_block_artifact(addr: int, instrs: tuple[IRInstr, ...]) -> IRFunctionArtifact:
    """Build a one-block function artifact ending in RET."""
    return IRFunctionArtifact(addr, (IRBlock(addr, instrs=instrs),))


def _coverage(
    project: SimpleNamespace, artifact: IRFunctionArtifact,
) -> IRBoundaryCoverageResult8616:
    """Publish and prove boundary coverage for one artifact."""
    publish_function_ir_artifact_8616(project, artifact)
    boundary = ExactFunctionRangeBoundary8616(
        project,
        artifact.function_addr,
        0x10,
        frozenset(block.addr for block in artifact.blocks),
        frozenset(instr.addr for block in artifact.blocks for instr in block.instrs),
        (),
    )
    return prove_ir_boundary_coverage_8616(project, boundary, artifact)


def _index(*entries: tuple[int, int, int]) -> DecodedDirectCallsiteIndex8616:
    """Build a closed decoded index from (caller_start, site, target) rows."""
    by_target: dict[int, list[DecodedDirectCallsite8616]] = {}
    for caller_start, site, target in entries:
        entry = DecodedDirectCallsite8616(
            caller_start, (SimpleNamespace(address=site),), 0, site, target,
        )
        by_target.setdefault(target, []).append(entry)
    count = len(entries)
    return DecodedDirectCallsiteIndex8616(
        {target: tuple(items) for target, items in by_target.items()},
        DecodedDirectCallsiteIndexStats8616(count, count, count, count, 0),
    )


def _as_complete(proof: PreservationResult) -> PreservationResult:
    """Fabricate a closed-accounting result for cyclic/budget-only fixtures.

    Revalidation always recomputes live evidence, so relaxing only the stored
    fields cannot launder a verdict; it only lets traversal reach the cycle
    or budget edge being tested.
    """
    return replace(
        proof, failure=None,
        classified_fact_count=1, materialized_count=1, failure_count=0,
    )


class _Chain:
    """Bottom-up proved caller -> mid -> leaf fixture for the typed module."""

    def __init__(
        self, leaf_writes: tuple[IRInstr, ...] = (_mov_seg("es", 0xB800, 0x3000),),
    ) -> None:
        """Build caller/mid/leaf artifacts and prove the mid -> leaf edge."""
        self.project = SimpleNamespace()
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

    def mid_closure(
        self, proofs: tuple[PreservationResult, ...] | None = None,
    ) -> ClosureResult:
        """Build the mid closure over a state carrying the given proofs."""
        if proofs is None:
            proofs = (self.mid_leaf_proof,)
        state = build_x86_16_segment_state_artifact(self.mid, call_preservations=proofs)
        return effect_closure.prove_segment_effect_closure_8616(self.cov_mid, state)

    def mid_closure_with_state(self, state: SegmentStateArtifact) -> ClosureResult:
        """Retain the recorded mid census over a fabricated supplied state."""
        return replace(self.mid_closure(), state=state)

    def root_proof(
        self, mid_closure: ClosureResult | None = None,
    ) -> PreservationResult:
        """Prove root -> mid for the given (or default) mid closure."""
        if mid_closure is None:
            mid_closure = self.mid_closure()
        return call_preservation.prove_segment_call_preservation_8616(
            self.cov_root, mid_closure, self.index, 0x1000,
        )


class _EvidenceCalls:
    """Count real local-closure evidence evaluations in the typed module."""

    def __init__(self) -> None:
        self.count = 0
        self._real = effect_closure._closure_evidence_8616

    def __enter__(self) -> _EvidenceCalls:
        """Count actual local evidence evaluations until scope exit."""
        real = self._real

        def counted(
            coverage: IRBoundaryCoverageResult8616,
            state: SegmentStateArtifact,
        ) -> tuple[SegmentEffectClosureFailure8616 | None, tuple[int, ...], tuple[int, ...]]:
            self.count += 1
            return real(coverage, state)

        effect_closure._closure_evidence_8616 = counted
        return self

    def __exit__(self, *exc: object) -> bool:
        """Restore the evaluator and propagate any test exception."""
        effect_closure._closure_evidence_8616 = self._real
        return False
