"""Native x86 NOP instruction-census regression and refusal controls.

Layer: Tests.
Responsibility: prove a decoded native NOP earns its frontend head through
explicit IMark-bound no-effect evidence, while dropped stores, faults,
unknown encodings, fabricated shapes, and corrupted native bytes still
refuse. Tests import production IR owners directly.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

import angr
import pytest
from angr_platforms.X86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from angr_platforms.X86_16.ir import IRValue, MemSpace
from angr_platforms.X86_16.ir.core import IRFunctionArtifact, IRInstr
from angr_platforms.X86_16.ir.function_ir_registry import publish_function_ir_artifact_8616
from angr_platforms.X86_16.ir.instruction_origin import IRInstructionOrigin8616
from angr_platforms.X86_16.ir.ir_boundary_cfg import (
    IRBoundaryCoverageResult8616,
    prove_ir_boundary_coverage_8616,
)
from angr_platforms.X86_16.ir.scalar_instruction_effects import (
    ScalarInstructionClobber8616,
    ScalarInstructionEffectKind8616,
    scalar_instruction_effect_8616,
)
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from test_segment_call_binding_regression import _CODE_LEAF_RET, _project, _prove

_BASE = 0x1000
# nop; ret
_NOP_RET = bytes.fromhex("90 c3")
# mov ax,0x1234; nop; ret
_NOP_STATEFUL = bytes.fromhex("b8 34 12 90 c3")
# nop; nop; nop; ret
_NOP_MULTI = bytes.fromhex("90 90 90 c3")
# o16-prefixed nop (xchg eax,eax alias); ret
_NOP_PREFIXED = bytes.fromhex("66 90 c3")
# mov [0x1234],ax; nop; ret
_STORE_NOP_RET = bytes.fromhex("a3 34 12 90 c3")
# jmp +2 -> 0x1004; unreachable padding; nop -> 0x1005; jmp $ (self-loop target
# splits the partition, leaving a one-byte block whose only instruction is NOP)
_NOP_TRAILING_BLOCK = bytes.fromhex("eb 02 90 90 90 eb fe")
# hlt; ret — decoded but halting: never a no-effect instruction
_HLT_RET = bytes.fromhex("f4 c3")
# fnop; ret — empty lifted span but not the canonical NOP encoding
_FNOP_RET = bytes.fromhex("d9 d0 c3")
# lock-prefixed nop — #UD on real hardware, never no-effect
_LOCK_NOP_RET = bytes.fromhex("f0 90 c3")
# es:nop; ret — segment-override prefix is unsupported, stays an honest refusal
_SEG_NOP_RET = bytes.fromhex("2e 90 c3")
# pause; ret — f3 90 is the architected PAUSE hint, never the canonical NOP family
_PAUSE_RET = bytes.fromhex("f3 90 c3")


def _built(
    code: bytes,
    start: int,
    end: int,
) -> tuple[
    angr.Project,
    ExactFunctionRangeBoundary8616,
    IRFunctionArtifact,
    IRBoundaryCoverageResult8616,
] | None:
    """Build, publish, and cover one exact boundary; None when it refuses early."""
    project = _project(code, base=_BASE)
    boundary = exact_function_range_boundary_8616(project, start, end)
    if boundary is None:
        return None
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, artifact)
    return (
        project,
        boundary,
        artifact,
        prove_ir_boundary_coverage_8616(project, boundary, artifact),
    )


def _mutated_coverage(
    code: bytes,
    start: int,
    end: int,
    mutate: Callable[[IRFunctionArtifact], IRFunctionArtifact],
) -> IRBoundaryCoverageResult8616 | None:
    """Publish only the mutated artifact on a fresh project, then prove.

    A fresh project per mutation keeps the registry honest: the mutated
    artifact is the single registered IR for the boundary, so the census —
    never an artifact-identity conflict — decides acceptance.
    """
    project = _project(code, base=_BASE)
    boundary = exact_function_range_boundary_8616(project, start, end)
    if boundary is None:
        return None
    artifact = mutate(build_x86_16_ir_function_artifact(project, boundary))
    publish_function_ir_artifact_8616(project, artifact)
    return prove_ir_boundary_coverage_8616(project, boundary, artifact)


def _nop_instrs(artifact: IRFunctionArtifact) -> tuple[IRInstr, ...]:
    """Return every typed no-effect instruction in the artifact."""
    return tuple(
        instr
        for block in artifact.blocks
        for instr in block.instrs
        if instr.op == "NOP"
    )


def _drop_addr_8616(artifact: IRFunctionArtifact, head: int) -> IRFunctionArtifact:
    """Drop every instruction covering one head from its single block."""
    return replace(
        artifact,
        blocks=tuple(
            replace(
                block,
                instrs=tuple(
                    instr for instr in block.instrs if instr.addr != head
                ),
            )
            for block in artifact.blocks
        ),
    )


def _assert_nop_shape(instr: IRInstr, head: int) -> None:
    """Require the census-admitted no-effect shape and mark provenance."""
    assert instr.addr == head
    assert instr.dst is None
    assert instr.args == ()
    assert instr.size == 0
    assert instr.origin is not None
    assert instr.origin.is_instruction_mark
    assert type(instr.origin.statement_index) is int and instr.origin.statement_index >= 0


def test_native_nop_ret_coverage_completes() -> None:
    """One NOP head is covered by explicit no-effect evidence, not dropped."""
    built = _built(_NOP_RET, _BASE, _BASE + 2)
    assert built is not None
    _, boundary, artifact, coverage = built
    assert boundary.reachable_instruction_addrs == frozenset({_BASE, _BASE + 1})
    assert coverage.complete
    nops = _nop_instrs(artifact)
    assert len(nops) == 1
    _assert_nop_shape(nops[0], _BASE)
    effect = scalar_instruction_effect_8616(nops[0])
    assert effect.kind is ScalarInstructionEffectKind8616.NO_REGISTER_WRITE
    assert effect.clobber is ScalarInstructionClobber8616.NONE
    block = artifact.blocks[0]
    assert block.instrs[-1].op == "RET" and block.instrs[-1].addr == _BASE + 1


def test_nop_among_stateful_instructions() -> None:
    """A NOP between real instructions keeps every head and all effects."""
    built = _built(_NOP_STATEFUL, _BASE, _BASE + 5)
    assert built is not None
    _, _, artifact, coverage = built
    assert coverage.complete
    nops = _nop_instrs(artifact)
    assert len(nops) == 1
    _assert_nop_shape(nops[0], _BASE + 3)
    ops = tuple(instr.op for instr in artifact.blocks[0].instrs)
    assert "MOV" in ops and ops[-1] == "RET"
    addrs = {instr.addr for instr in artifact.blocks[0].instrs}
    assert {_BASE, _BASE + 3, _BASE + 4} <= addrs


def test_multiple_nops_each_earn_evidence() -> None:
    """Consecutive empty spans each mint their own source-bound instruction."""
    built = _built(_NOP_MULTI, _BASE, _BASE + 4)
    assert built is not None
    _, _, artifact, coverage = built
    assert coverage.complete
    nops = _nop_instrs(artifact)
    assert tuple(instr.addr for instr in nops) == (_BASE, _BASE + 1, _BASE + 2)
    for index, instr in enumerate(nops):
        _assert_nop_shape(instr, _BASE + index)


def test_trailing_nop_block_fallthrough() -> None:
    """A one-NOP block ending on a boring fallthrough is still covered."""
    built = _built(_NOP_TRAILING_BLOCK, _BASE, _BASE + 7)
    assert built is not None
    _, _, artifact, coverage = built
    assert coverage.complete
    lone = next(block for block in artifact.blocks if block.addr == _BASE + 4)
    assert len(lone.instrs) == 1
    _assert_nop_shape(lone.instrs[0], _BASE + 4)
    assert lone.successor_addrs == (_BASE + 5,)


def test_prefixed_nop_encoding() -> None:
    """A redundant operand-size prefix on the canonical NOP stays covered."""
    built = _built(_NOP_PREFIXED, _BASE, _BASE + 3)
    assert built is not None
    _, _, artifact, coverage = built
    assert coverage.complete
    nops = _nop_instrs(artifact)
    assert len(nops) == 1
    _assert_nop_shape(nops[0], _BASE)


@pytest.mark.parametrize(
    "code",
    [_HLT_RET, _FNOP_RET, _LOCK_NOP_RET, _SEG_NOP_RET, _PAUSE_RET],
    ids=["hlt", "fnop", "lock_nop", "seg_nop", "pause"],
)
def test_unknown_or_faulting_instruction_still_refuses(code: bytes) -> None:
    """Empty spans without canonical-NOP bytes never earn no-effect evidence."""
    built = _built(code, _BASE, _BASE + len(code))
    if built is None:
        return
    _, _, artifact, coverage = built
    assert not coverage.complete
    assert not _nop_instrs(artifact)


def test_dropped_store_instructions_still_refuse() -> None:
    """Removing a stateful instruction's IR cannot be hidden by census."""
    built = _built(_STORE_NOP_RET, _BASE, _BASE + 5)
    assert built is not None
    _, _, artifact, coverage = built
    assert coverage.complete
    block = artifact.blocks[0]
    assert any(instr.op == "STORE" and instr.addr == _BASE for instr in block.instrs)
    refused = _mutated_coverage(
        _STORE_NOP_RET, _BASE, _BASE + 5,
        lambda original: _drop_addr_8616(original, _BASE),
    )
    assert refused is not None and not refused.complete


def test_dropped_nop_evidence_still_refuses() -> None:
    """Deleting the no-effect entry uncovers the head again; nothing else fills it."""
    refused = _mutated_coverage(
        _NOP_RET, _BASE, _BASE + 2,
        lambda original: _drop_addr_8616(original, _BASE),
    )
    assert refused is not None and not refused.complete


def test_fabricated_nop_without_mark_provenance_refuses() -> None:
    """A bare NOP-shaped instruction cannot fabricate coverage of a real head."""
    def forge(artifact: IRFunctionArtifact) -> IRFunctionArtifact:
        forged = IRInstr(op="NOP", dst=None, args=(), size=0, addr=_BASE)
        return replace(
            artifact,
            blocks=tuple(
                replace(block, instrs=(*block.instrs, forged))
                if block.addr == _BASE else block
                for block in artifact.blocks
            ),
        )

    refused = _mutated_coverage(_HLT_RET, _BASE, _BASE + 2, forge)
    assert refused is not None and not refused.complete


def test_mark_provenance_mutation_refuses() -> None:
    """Stripping IMark provenance from no-effect evidence uncovers the head."""
    built = _built(_NOP_RET, _BASE, _BASE + 2)
    assert built is not None
    _, _, artifact, _ = built
    assert _nop_instrs(artifact)

    def alter(mutation: Callable[[IRInstr], IRInstr]) -> IRBoundaryCoverageResult8616:
        def apply(original: IRFunctionArtifact) -> IRFunctionArtifact:
            return replace(
                original,
                blocks=tuple(
                    replace(
                        block,
                        instrs=tuple(
                            mutation(instr) if instr.op == "NOP" and instr.addr == _BASE
                            else instr
                            for instr in block.instrs
                        ),
                    )
                    for block in original.blocks
                ),
            )
        refused = _mutated_coverage(_NOP_RET, _BASE, _BASE + 2, apply)
        assert refused is not None
        return refused

    for mutation in (
        lambda instr: replace(instr, origin=None),
        lambda instr: replace(
            instr, origin=replace(instr.origin, is_instruction_mark=False)
        ),
        # contradictory terminal provenance on a mark-origin claim
        lambda instr: replace(
            instr, origin=replace(instr.origin, is_block_next=True)
        ),
        # contradictory data-flow provenance on a mark-origin claim
        lambda instr: replace(
            instr, origin=replace(instr.origin, address_tmp=4)
        ),
        lambda instr: replace(
            instr, origin=replace(instr.origin, block_next_tmp=9)
        ),
        # statement_index at the next instruction's mark — head mismatch
        lambda instr: replace(
            instr, origin=replace(instr.origin, statement_index=1)
        ),
        # statement_index at a non-IMark statement
        lambda instr: replace(
            instr, origin=replace(instr.origin, statement_index=2)
        ),
        # statement_index beyond the bound statement list
        lambda instr: replace(
            instr, origin=replace(instr.origin, statement_index=1_000_000)
        ),
        # a block address outside the bound block carrying the claim
        lambda instr: replace(
            instr, origin=replace(instr.origin, block_addr=_BASE + 0x100)
        ),
        lambda instr: replace(
            instr, args=(IRValue(MemSpace.CONST, const=0, size=1),)
        ),
        lambda instr: replace(instr, size=1),
    ):
        assert not alter(mutation).complete


def test_forged_mark_cannot_hide_stateful_head() -> None:
    """Mark-shaped provenance on real MOV bytes cannot mint coverage.

    Independent of the parent store control: the forged claim names the real
    IMark index, yet the bound span is nonempty and the bound bytes are not
    the canonical NOP encoding — either bound fact alone must refuse.
    """

    def forge(artifact: IRFunctionArtifact) -> IRFunctionArtifact:
        return replace(
            artifact,
            blocks=tuple(
                replace(
                    block,
                    instrs=(
                        IRInstr(
                            op="NOP", dst=None, args=(), size=0, addr=_BASE,
                            origin=IRInstructionOrigin8616(
                                block_addr=_BASE, statement_index=0,
                                is_instruction_mark=True,
                            ),
                        ),
                        *(instr for instr in block.instrs if instr.addr != _BASE),
                    ),
                )
                if block.addr == _BASE
                else block
                for block in artifact.blocks
            ),
        )

    refused = _mutated_coverage(_NOP_STATEFUL, _BASE, _BASE + 5, forge)
    assert refused is not None and not refused.complete


def test_forged_mark_claim_on_terminal_head_refuses() -> None:
    """A mark-tagged NOP replacing a RET head fails the bound span check."""

    def forge(artifact: IRFunctionArtifact) -> IRFunctionArtifact:
        return replace(
            artifact,
            blocks=tuple(
                replace(
                    block,
                    instrs=tuple(
                        IRInstr(
                            op="NOP", dst=None, args=(), size=0, addr=_BASE + 1,
                            origin=IRInstructionOrigin8616(
                                block_addr=_BASE, statement_index=1,
                                is_instruction_mark=True,
                            ),
                        )
                        if instr.addr == _BASE + 1
                        else instr
                        for instr in block.instrs
                    ),
                )
                for block in artifact.blocks
            ),
        )

    refused = _mutated_coverage(_NOP_RET, _BASE, _BASE + 2, forge)
    assert refused is not None and not refused.complete


def test_forged_nop_claim_in_wrong_block_refuses() -> None:
    """A claim carried by a different IR block cannot bind another block."""

    def forge(artifact: IRFunctionArtifact) -> IRFunctionArtifact:
        forged = IRInstr(
            op="NOP", dst=None, args=(), size=0, addr=_BASE + 4,
            origin=IRInstructionOrigin8616(
                block_addr=_BASE + 4, statement_index=0,
                is_instruction_mark=True,
            ),
        )
        return replace(
            artifact,
            blocks=tuple(
                replace(block, instrs=())
                if block.addr == _BASE + 4
                else (
                    replace(block, instrs=(*block.instrs, forged))
                    if block.addr == _BASE + 5
                    else block
                )
                for block in artifact.blocks
            ),
        )

    refused = _mutated_coverage(_NOP_TRAILING_BLOCK, _BASE, _BASE + 7, forge)
    assert refused is not None and not refused.complete


def test_nop_effect_requires_mark_bound_origin() -> None:
    """The scalar oracle must not honor bare or contradictory NOP claims."""
    bare = IRInstr(op="NOP", dst=None, args=(), size=0, addr=_BASE)
    assert (
        scalar_instruction_effect_8616(bare).kind
        is ScalarInstructionEffectKind8616.UNKNOWN
    )
    unmarked = IRInstr(
        op="NOP", dst=None, args=(), size=0, addr=_BASE,
        origin=IRInstructionOrigin8616(block_addr=_BASE, statement_index=0),
    )
    assert (
        scalar_instruction_effect_8616(unmarked).kind
        is ScalarInstructionEffectKind8616.UNKNOWN
    )
    contradictory = IRInstr(
        op="NOP", dst=None, args=(), size=0, addr=_BASE,
        origin=IRInstructionOrigin8616(
            block_addr=_BASE, statement_index=0,
            is_instruction_mark=True, is_block_next=True,
        ),
    )
    assert (
        scalar_instruction_effect_8616(contradictory).kind
        is ScalarInstructionEffectKind8616.UNKNOWN
    )
    built = _built(_NOP_RET, _BASE, _BASE + 2)
    assert built is not None
    nop = _nop_instrs(built[2])[0]
    assert (
        scalar_instruction_effect_8616(nop).kind
        is ScalarInstructionEffectKind8616.NO_REGISTER_WRITE
    )


def test_native_source_corruption_cannot_pass() -> None:
    """Rewriting the mapped NOP byte to a halting opcode must not keep passing."""
    project = _project(_NOP_RET, base=_BASE)
    project.loader.memory.store(_BASE, b"\xf4")
    boundary = exact_function_range_boundary_8616(project, _BASE, _BASE + 2)
    if boundary is None:
        return
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, artifact)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    assert not coverage.complete


def test_non_nop_caller_callee_pipeline_unchanged() -> None:
    """Ordinary coverage and segment closure over no-NOP code stay identical."""
    project = _project(_CODE_LEAF_RET)
    proof = _prove(project, (_BASE, _BASE + 4), (0x1006, 0x1007), _BASE)
    assert proof.complete
