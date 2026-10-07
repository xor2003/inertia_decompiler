"""Require binary-owned coverage and every-return BP preservation evidence."""

import io
from dataclasses import replace
from types import SimpleNamespace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.function_ir_registry import publish_function_ir_artifact_8616
from inertia.ir.ir_boundary_cfg import (
    IRBoundaryCoverageResult8616,
    prove_ir_boundary_coverage_8616,
)
from inertia.ir.vex_import import build_x86_16_ir_function_artifact

from inertia.alias.bp_preservation import prove_bp_preservation_8616
from inertia.alias.saved_stack_store_window import _site_reaches_8616
from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from tests.alias.test_x86_16_segment_stack_restore import _lift_function
from tests.ir.test_segment_call_binding_regression import (
    _coverage as _bound_binary_coverage_8616,
)
from tests.ir.test_segment_call_binding_regression import _project


def _coverage(artifact: IRFunctionArtifact) -> IRBoundaryCoverageResult8616:
    """Bind a synthetic census-free artifact's instruction and edge census."""
    project = SimpleNamespace()
    publish_function_ir_artifact_8616(project, artifact)
    instruction_addrs: set[int] = set()
    for block in artifact.blocks:
        for instruction in block.instrs:
            assert instruction.addr is not None, "synthetic fixture requires located instructions"
            instruction_addrs.add(instruction.addr)
    boundary = ExactFunctionRangeBoundary8616(
        project, artifact.function_addr, 0x100,
        frozenset(block.addr for block in artifact.blocks),
        frozenset(instruction_addrs),
        tuple((block.addr, target) for block in artifact.blocks for target in block.successor_addrs),
    )
    return prove_ir_boundary_coverage_8616(project, boundary, artifact)


def _binary_coverage(code: bytes) -> IRBoundaryCoverageResult8616:
    """Lift native bytes on the project owning them into bound coverage.

    A no-effect instruction claim is only authenticated against the decoded
    extents, exact bytes, and relifted marks of the project that owns the
    image, so binary fixtures keep their native project and exact boundary.
    """
    return _bound_binary_coverage_8616(_project(code), 0x1000, 0x1000 + len(code))


def _identity_effect(addr: int) -> IRInstr:
    """An explicit register identity effect, never a no-effect source claim."""
    return IRInstr(
        "MOV",
        IRValue(MemSpace.REG, name="ax", size=2),
        (IRValue(MemSpace.REG, name="ax", size=2),),
        size=2,
        addr=addr,
    )


@pytest.mark.parametrize("code,accepted", (
    ("55 89 e5 89 ec 5d c3", True),
    ("55 5d bd 12 34 c3", False),
    ("bd 12 34 c3", False),
    ("55 5d c3", True),
    ("90 55 5d c3", True),
    ("bd 12 34 55 5d c3", False),
    ("90 c3", True),
    ("55 8e d0 5d c3", False),
    ("55 89 e5 c7 46 00 12 34 89 ec 5d c3", False),
    ("66 bd 12 34 56 78 c3", False),
    ("55 89 e3 89 07 5d c3", False),
))
def test_binary_bp_preservation_requires_restoration_at_return(code: str, accepted: bool) -> None:
    """Whole-callee preservation is stronger than observing a POP BP."""
    coverage = _binary_coverage(bytes.fromhex(code))
    assert coverage.complete
    result = prove_bp_preservation_8616(coverage)
    assert result.complete is accepted
    assert result.classified_fact_count == result.materialized_count == int(accepted)
    assert result.failure_count == int(not accepted)
    assert not replace(result, materialized_count=0).complete
    assert not replace(result, coverage=replace(coverage, artifact=replace(coverage.artifact))).complete


@pytest.mark.parametrize("code", (
    "89 07 55 89 e5 5d c3",
    "55 89 e5 5d 89 07 c3",
))
def test_cross_selector_store_outside_saved_bp_lifetime_is_not_a_clobber(code: str) -> None:
    """Only writes that can reach a later saved-byte read need disjointness."""
    proof = prove_bp_preservation_8616(_binary_coverage(bytes.fromhex(code)))
    assert proof.complete


@pytest.mark.parametrize("backedge", (False, True))
def test_saved_byte_lifetime_keeps_instruction_order_and_backedges(backedge: bool) -> None:
    """A later write reaches an earlier restore only through a real CFG cycle."""
    artifact = IRFunctionArtifact(0x1000, (
        IRBlock(0x1000, successor_addrs=(0x1010,)),
        IRBlock(0x1010, successor_addrs=((0x1000,) if backedge else ())),
    ))
    assert _site_reaches_8616(artifact, (0x1000, 2), (0x1000, 1)) is backedge
    assert _site_reaches_8616(artifact, (0x1000, 1), (0x1000, 2))


@pytest.mark.parametrize("clobber", (False, True))
def test_bp_preservation_closes_both_return_paths(clobber: bool) -> None:
    """A single clobbering exit rejects an otherwise preserving branch."""
    write = IRInstr("MOV", IRValue(MemSpace.REG, name="bp", size=2),
                    (IRValue(MemSpace.CONST, const=42, size=2),), size=2, addr=0x1020)
    artifact = IRFunctionArtifact(0x1000, (
        IRBlock(0x1000, instrs=(_identity_effect(0x1000),), successor_addrs=(0x1010, 0x1020)),
        IRBlock(0x1010, instrs=(IRInstr("RET", None, (), addr=0x1010),)),
        IRBlock(0x1020, instrs=((write,) if clobber else ()) + (IRInstr("RET", None, (), addr=0x1021),)),
    ))
    result = prove_bp_preservation_8616(_coverage(artifact))
    assert result.complete is (not clobber)


@pytest.mark.parametrize("terminal", ("CALL", "INT", "MOV"))
def test_unknown_callee_effects_do_not_become_preservation(terminal: str) -> None:
    """Calls, external effects and nonreturning terminal blocks stay refused."""
    head = _identity_effect(0x1000) if terminal == "MOV" else IRInstr(terminal, None, (), addr=0x1000)
    artifact = IRFunctionArtifact(0x1000, (IRBlock(0x1000, instrs=(
        head,
        *((IRInstr("RET", None, (), addr=0x1001),) if terminal != "MOV" else ()),
    )),))
    assert not prove_bp_preservation_8616(_coverage(artifact)).complete


def test_same_instruction_clobber_cannot_borrow_a_restore_fact() -> None:
    """One address identifying a restore does not authorize a second BP write."""
    artifact = _lift_function(bytes.fromhex("55 5d c3"))
    block = artifact.blocks[0]
    clobber = IRInstr("MOV", IRValue(MemSpace.REG, name="bp", size=2),
                      (IRValue(MemSpace.CONST, const=42, size=2),), size=2, addr=0x1001)
    artifact = replace(artifact, blocks=(replace(block, instrs=(*block.instrs[:-1], clobber, block.instrs[-1])),))
    assert not prove_bp_preservation_8616(_coverage(artifact)).complete


@pytest.mark.parametrize("clobber", (False, True))
def test_bp_preservation_propagates_clobber_through_loop(clobber: bool) -> None:
    """A stable loop preserves incoming BP; a backedge clobber reaches its exit."""
    instruction = _identity_effect(0x1010)
    if clobber:
        instruction = IRInstr("MOV", IRValue(MemSpace.REG, name="bp", size=2),
                              (IRValue(MemSpace.CONST, const=42, size=2),), size=2, addr=0x1010)
    artifact = IRFunctionArtifact(0x1000, (
        IRBlock(0x1000, instrs=(_identity_effect(0x1000),), successor_addrs=(0x1010,)),
        IRBlock(0x1010, instrs=(instruction,), successor_addrs=(0x1010, 0x1020)),
        IRBlock(0x1020, instrs=(IRInstr("RET", None, (), addr=0x1020),)),
    ))
    assert prove_bp_preservation_8616(_coverage(artifact)).complete is (not clobber)


def test_binary_loop_proof_requires_complete_real_frontend_census() -> None:
    """Prove an actual framed loop only while its terminal JMP survives import."""
    code = bytes.fromhex("55 89 e5 b9 02 00 49 75 fd eb 00 5d c3")
    project = angr.Project(io.BytesIO(code), main_opts={
        "backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000,
    }, auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1000 + len(code))
    assert boundary is not None
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    publish_function_ir_artifact_8616(project, artifact)
    coverage = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    assert prove_bp_preservation_8616(coverage).complete
    assert any(item.op == "JMP" for block in artifact.blocks for item in block.instrs)
    corrupted = replace(artifact, blocks=tuple(
        replace(block, instrs=tuple(item for item in block.instrs if item.op != "JMP"))
        for block in artifact.blocks
    ))
    assert not prove_bp_preservation_8616(replace(coverage, artifact=corrupted)).complete
