"""Binary-associated contextual input authority and refusal controls."""

import io
from dataclasses import replace

import angr
import pytest
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import IRInstr, IRValue, MemSpace
from inertia.ir.function_ir_registry import publish_function_ir_artifact_8616
from inertia.ir.ir_boundary_cfg import IRBoundaryCoverageResult8616, prove_ir_boundary_coverage_8616
from inertia.ir.logical_constant_word_receipt import prove_logical_constant_word_write_8616
from inertia.ir.logical_memory_contracts import IRMemoryAccessKind8616
from inertia.ir.ssa_function import build_x86_16_function_ssa

from inertia.alias.stack_word_call_binding import (
    StackWordCallBindingFailure8616,
    bind_stack_word_call_window_8616,
)
from inertia.alias.stack_word_call_window import (
    StackWordCallWindowReceipt8616,
    prove_stack_word_call_window_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from tests.fixtures.x86_16_logical_memory_fixtures import lift_ir_artifact


def _fixture(*, omit_frame_lane: bool = False) -> tuple[IRBoundaryCoverageResult8616, StackWordCallWindowReceipt8616]:
    """Use real instruction bytes and independent exact instruction coordinates."""
    code = bytes.fromhex("b8 03 00 50 b8 01 00 50 e8 00 00 c3")
    project = angr.Project(io.BytesIO(code), main_opts={"backend": "blob", "arch": Arch86_16(),
                           "base_addr": 0x1000, "entry_point": 0x1000}, auto_load_libs=False)
    raw = lift_ir_artifact(code)
    if omit_frame_lane:
        block = raw.blocks[0]
        index = next(index for index, item in enumerate(block.instrs)
                     if item.op == "STORE" and item.addr == 0x1008)
        substitute = IRInstr("MOV", IRValue(MemSpace.TMP, name="unused", source_tmp=9999, size=1),
                             (IRValue(MemSpace.CONST, const=0, size=1),), size=1, addr=0x1008)
        raw = replace(raw, blocks=(replace(block, instrs=(*block.instrs[:index], substitute,
                                                         *block.instrs[index + 1:])),))
    publish_function_ir_artifact_8616(project, raw)
    boundary = ExactFunctionRangeBoundary8616(
        project, 0x1000, 11, frozenset({0x1000}),
        frozenset({0x1000, 0x1003, 0x1004, 0x1007, 0x1008}), (),
    )
    coverage = prove_ir_boundary_coverage_8616(project, boundary, raw)
    ssa = build_x86_16_function_ssa(raw)
    assert ssa.logical_memory is not None
    access = next(item for item in ssa.logical_memory.accesses
                  if item.kind is IRMemoryAccessKind8616.WRITE and item.key.insn_addr == 0x1003)
    word = prove_logical_constant_word_write_8616(ssa, access)
    window = prove_stack_word_call_window_8616(raw, word, 0x1008)
    assert coverage.complete and window.complete
    return coverage, window


def test_real_near_call_binds_input_without_proving_callee_load() -> None:
    """Binary transfer and raw envelope earn a contextual entry input only."""
    coverage, window = _fixture()
    proof = bind_stack_word_call_window_8616(coverage, window, 0x100B, 0x100B)
    assert proof.complete
    assert proof.constant == 3 and proof.callee_entry_offsets == (4, 5)
    assert not replace(proof, target_addr=0x100A).complete
    assert not replace(proof, stats=replace(proof.stats, materialized_count=0)).complete
    publish_function_ir_artifact_8616(coverage.boundary.project, replace(coverage.artifact))
    assert not proof.complete


@pytest.mark.parametrize("defect", ("coverage", "foreign_source", "target", "return"))
def test_conflicting_boundary_authority_refuses(defect: str) -> None:
    """An equal-content source or a summary coordinate is not independent proof."""
    coverage, window = _fixture()
    target, returned = 0x100B, 0x100B
    expected = StackWordCallBindingFailure8616.TARGET_UNPROVEN
    if defect == "coverage":
        coverage = replace(coverage, materialized_count=0)
        expected = StackWordCallBindingFailure8616.COVERAGE_UNPROVEN
    elif defect == "foreign_source":
        window = replace(window, source_ir=replace(window.source_ir))
        expected = StackWordCallBindingFailure8616.SOURCE_MISMATCH
    elif defect == "target":
        target += 1
    else:
        returned += 1
    proof = bind_stack_word_call_window_8616(coverage, window, target, returned)
    assert not proof.complete and proof.failure is expected
    assert proof.constant is None and proof.callee_entry_offsets is None
    assert proof.stats.failure_count == 1


def test_instruction_coverage_cannot_replace_missing_return_frame_lane() -> None:
    """Matching machine addresses alone do not prove the physical CALL envelope."""
    coverage, window = _fixture(omit_frame_lane=True)
    proof = bind_stack_word_call_window_8616(coverage, window, 0x100B, 0x100B)
    assert not proof.complete and proof.failure is StackWordCallBindingFailure8616.FRAME_UNPROVEN


@pytest.mark.parametrize("defect", ("offset", "width"))
def test_symbolic_target_proof_retains_native_positive_and_rejects_changed_operand(defect: str) -> None:
    """Native target bytes never justify a different symbolic CALL operand."""
    from inertia.alias.stack_word_call_binding import _target_matches_8616

    coverage, _ = _fixture()
    block = coverage.artifact.blocks[0]
    call = next(instruction for instruction in block.instrs if instruction.op == "CALL")
    operand = call.args[0]
    assert isinstance(operand, IRValue) and operand.space is not MemSpace.CONST
    project = coverage.boundary.project
    assert _target_matches_8616(project, block, call, 0x100B, 0x100B)
    altered = replace(operand, offset=1) if defect == "offset" else replace(operand, size=2)
    assert not _target_matches_8616(project, block, replace(call, args=(altered,)), 0x100B, 0x100B)
