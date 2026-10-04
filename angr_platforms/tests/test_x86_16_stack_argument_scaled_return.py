"""Source-free positive and refusal tests for an exact scaled AX return fact."""

from __future__ import annotations

import io
from dataclasses import replace
from unittest.mock import patch

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import CallsiteMachineFrameKind8616
from angr_platforms.X86_16.compiler_helpers import hook_x86_16_known_compiler_helpers_8616
from angr_platforms.X86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from angr_platforms.X86_16.ir import AddressStatus, IRAddress, IRValue, MemSpace, SegmentOrigin
from angr_platforms.X86_16.ir.scalar_affine_contracts import (
    ScalarAffineExpression8616,
    ScalarAffineTrace8616,
)
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact
from angr_platforms.X86_16.ir.stack_argument_modular_use import (
    prove_stack_argument_modular_return_use_8616,
)
from angr_platforms.X86_16.ir.stack_argument_modular_use_contracts import (
    ModularArgumentUseFailure8616,
    ModularArgumentUseVerdict8616,
    ModularReturnRegister8616,
)
from angr_platforms.X86_16.ir.stack_argument_scaled_return import (
    FarScaledReturnFailure8616,
    ScaledReturnFailure8616,
    ScaledReturnVerdict8616,
    prove_stack_argument_far_scaled_return_8616,
    prove_stack_argument_scaled_return_8616,
)
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.semantics.call_stack_effect_pipeline import (
    build_semantic_function_ssa_8616,
)
from angr_platforms.X86_16.semantics.direct_ret_call_effect import (
    DirectRetCallEffectVerdict8616,
    prove_direct_near_ret_only_effect_8616,
)
from angr_platforms.X86_16.synthetic_call_stub_evidence import record_synthetic_call_stubs_8616

_CODE = bytes.fromhex(
    "55 8b ec 57 56 8b 46 06 d1 e0 03 46 04 e9 00 00 "
    "5e 5f 8b e5 5d c3"
)
_REBASED_WITH_CALL = bytes.fromhex(
    "55 8b ec b8 00 00 e8 c2 04 57 56 8b 46 06 d1 e0 "
    "03 46 04 e9 00 00 5e 5f 8b e5 5d c3"
)
_FAR_WITH_PROBE = bytes.fromhex(
    "55 8b ec b8 00 00 9a 00 08 00 07 57 56 8b 46 0a d1 e0 "
    "03 46 06 8b 56 08 e9 00 00 5e 5f 8b e5 5d cb"
)
_FAR_PROBE = bytes.fromhex(
    "59 5a 8b dc 2b d8 72 0b 3b 1e be 00 72 05 8b e3 52 51 cb"
)
_BASE = IRAddress(
    space=MemSpace.SS, base=("bp",), offset=4, size=2,
    status=AddressStatus.STABLE, segment_origin=SegmentOrigin.PROVEN,
)
_INDEX = replace(_BASE, offset=6)
_FAR_BASE = replace(_BASE, offset=6)
_FAR_INDEX = replace(_BASE, offset=10)


def _semantic_ssa(code: bytes = _CODE) -> tuple[ExactFunctionRangeBoundary8616, SSAFunctionArtifact]:
    project = angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob", "arch": Arch86_16(),
            "base_addr": 0x1000, "entry_point": 0x1000,
        },
        auto_load_libs=False,
        simos="DOS",
    )
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1000 + len(code))
    assert boundary is not None
    _, outputs, ssa = build_semantic_function_ssa_8616(project, boundary)
    assert not outputs.function.refusals
    return boundary, ssa


def _rebased_semantic_ssa(
    *, remove_call: bool = False, remove_shift: bool = False,
    ret_only_helper: bool = True,
) -> tuple[ExactFunctionRangeBoundary8616, SSAFunctionArtifact]:
    """Build the exact rebased machine boundary without external image files."""
    function_bytes = _REBASED_WITH_CALL
    if remove_call:
        function_bytes = function_bytes.replace(bytes.fromhex("e8 c2 04"), b"\x90" * 3)
    if remove_shift:
        function_bytes = function_bytes.replace(bytes.fromhex("d1 e0"), b"\x90" * 2)
    image = bytearray(0x5BE)
    image[0xF1 : 0xF1 + len(function_bytes)] = function_bytes
    image[0x5BC] = 0xC3 if ret_only_helper else 0x90
    image[0x5BD] = 0xC3
    project = angr.Project(
        io.BytesIO(image),
        main_opts={
            "backend": "blob", "arch": Arch86_16(),
            "base_addr": 0x1000, "entry_point": 0x10F1,
        },
        auto_load_libs=False,
        simos="DOS",
    )
    boundary = exact_function_range_boundary_8616(project, 0x10F1, 0x110D)
    assert boundary is not None
    _, outputs, ssa = build_semantic_function_ssa_8616(project, boundary)
    assert not outputs.function.refusals
    return boundary, ssa


def _far_probe_semantic_ssa(
    *, recognizable_helper: bool = True,
    combine_segment: bool = False,
) -> tuple[ExactFunctionRangeBoundary8616, SSAFunctionArtifact]:
    """Lift the actual far-call/RETF return shape with source-free bytes."""
    image = bytearray(0x6800 + len(_FAR_PROBE))
    function_bytes = _FAR_WITH_PROBE
    if combine_segment:
        function_bytes = function_bytes.replace(bytes.fromhex("8b 56 08"), bytes.fromhex("03 56 08"))
    image[0xF1 : 0xF1 + len(function_bytes)] = function_bytes
    probe = bytearray(_FAR_PROBE)
    if not recognizable_helper:
        probe[7] = 0
    image[0x6800 : 0x6800 + len(probe)] = probe
    project = angr.Project(
        io.BytesIO(image),
        main_opts={
            "backend": "blob", "arch": Arch86_16(),
            "base_addr": 0x1000, "entry_point": 0x10F1,
        },
        auto_load_libs=False,
        simos="DOS",
    )
    evidence = hook_x86_16_known_compiler_helpers_8616(project)
    assert len(evidence) == int(recognizable_helper)
    boundary = exact_function_range_boundary_8616(project, 0x10F1, 0x1112)
    assert boundary is not None
    _, outputs, ssa = build_semantic_function_ssa_8616(project, boundary)
    assert not outputs.function.refusals
    return boundary, ssa


def _replace_instruction(
    ssa: SSAFunctionArtifact,
    block_addr: int,
    instr_index: int,
    **changes: object,
) -> SSAFunctionArtifact:
    blocks = []
    for block in ssa.blocks:
        if block.addr != block_addr:
            blocks.append(block)
            continue
        instructions = list(block.instrs)
        instructions[instr_index] = replace(instructions[instr_index], **changes)
        blocks.append(replace(block, instrs=tuple(instructions)))
    return replace(ssa, blocks=tuple(blocks))


def _prove(
    boundary: ExactFunctionRangeBoundary8616,
    ssa: SSAFunctionArtifact,
):
    return prove_stack_argument_scaled_return_8616(boundary, ssa, _BASE, _INDEX)


def test_exact_base_plus_twice_index_is_proven() -> None:
    boundary, ssa = _semantic_ssa()

    result = _prove(boundary, ssa)

    assert result.verdict is ScaledReturnVerdict8616.PROVEN
    assert result.failure is None
    assert result.base_access_key is not None
    assert result.index_access_key is not None
    assert result.base_access_key != result.index_access_key
    assert result.definition_path
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_proven_result_retains_exact_affine_expression() -> None:
    """The proven result publishes the traced modular affine Value itself.

    AX = (base + 2 * index) mod 2**16: the width-2 expression bounds the
    modular wrap, keeps zero additive constant, and binds each term to the
    exact stack word and LOAD site the binary reads.
    """
    boundary, ssa = _semantic_ssa()

    result = _prove(boundary, ssa)

    assert result.complete
    expression = result.offset_expression
    assert isinstance(expression, ScalarAffineExpression8616)
    assert expression.complete
    assert expression.width == 2
    assert expression.constant == 0
    assert expression.root.name == "ax" and expression.root.size == 2
    assert result.definition_path == expression.definition_path
    assert result.base_access_key is not None
    assert result.index_access_key is not None
    load_addrs = {
        site.instr_addr for site in expression.definition_path if site.op == "LOAD"
    }
    assert load_addrs == {
        result.base_access_key.insn_addr,
        result.index_access_key.insn_addr,
    }
    base_terms = [term for term in expression.terms if term.coefficient == 1]
    index_terms = [term for term in expression.terms if term.coefficient == 2]
    assert len(base_terms) == len(index_terms) == 1
    base_term, index_term = base_terms[0], index_terms[0]
    assert isinstance(base_term.source, IRAddress)
    assert isinstance(index_term.source, IRAddress)
    assert base_term.source.offset == _BASE.offset
    assert index_term.source.offset == _INDEX.offset
    assert base_term.value.size == index_term.value.size == 2


def test_missing_or_corrupted_expression_cannot_complete() -> None:
    """A stripped or damaged affine expression can never stay complete."""
    boundary, ssa = _semantic_ssa()
    result = _prove(boundary, ssa)
    expression = result.offset_expression
    assert expression is not None

    corrupted = (
        replace(expression, root=replace(expression.root, name="cx")),
        replace(expression, width=1),
        replace(expression, width=4),
        replace(expression, constant=1),
        replace(expression, definition_path=()),
        replace(
            expression,
            terms=(replace(expression.terms[0], coefficient=3), *expression.terms[1:]),
        ),
        replace(
            expression,
            terms=(
                replace(expression.terms[0], source=expression.terms[1].source),
                *expression.terms[1:],
            ),
        ),
    )
    for bad in (None, *corrupted):
        forged = replace(result, offset_expression=bad)
        assert not forged.complete

    mismatched_path = replace(
        result,
        definition_path=tuple(
            site for site in expression.definition_path if site.op != "LOAD"
        ),
    )
    assert not mismatched_path.complete


def test_scaled_expression_binds_coefficients_to_exact_input_storage() -> None:
    """Retained base/index identities must not accept reversed coefficient roles."""
    boundary, ssa = _semantic_ssa()
    result = _prove(boundary, ssa)
    assert result.matches_storage_inputs(_BASE, _INDEX)
    assert not result.matches_storage_inputs(_INDEX, _BASE)
    assert not result.matches_storage_inputs(replace(_BASE, offset=12), _INDEX)


def test_wrong_scale_refuses() -> None:
    boundary, ssa = _semantic_ssa()
    shift = next(
        (block.addr, index, instruction)
        for block in ssa.blocks
        for index, instruction in enumerate(block.instrs)
        if instruction.op == "Iop_Shl16"
        and len(instruction.args) == 2
        and isinstance(instruction.args[1], IRValue)
        and instruction.args[1].const == 1
    )
    block_addr, instr_index, instruction = shift
    amount = instruction.args[1]
    assert isinstance(amount, IRValue)
    ssa = _replace_instruction(
        ssa, block_addr, instr_index,
        args=(instruction.args[0], replace(amount, const=2)),
    )

    result = _prove(boundary, ssa)

    assert result.verdict is ScaledReturnVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ScaledReturnFailure8616.AFFINE_SHAPE_MISMATCH
    assert result.offset_expression is None


def test_extra_stack_term_refuses() -> None:
    code = _CODE.replace(bytes.fromhex("03 46 04 e9"), bytes.fromhex("03 46 04 03 46 08 e9"))
    boundary, ssa = _semantic_ssa(code)

    result = _prove(boundary, ssa)

    assert result.verdict is ScaledReturnVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ScaledReturnFailure8616.AFFINE_SHAPE_MISMATCH


def test_missing_leaf_sites_refuses_even_with_affine_terms() -> None:
    boundary, ssa = _semantic_ssa()
    from angr_platforms.X86_16.ir.scalar_affine_trace import trace_scalar_affine_expression_8616

    def _without_leaf_sites(*args: object, **kwargs: object) -> ScalarAffineTrace8616:
        original = trace_scalar_affine_expression_8616(*args, **kwargs)
        assert original.expression is not None
        return replace(
            original,
            expression=replace(
                original.expression,
                definition_path=tuple(
                    site for site in original.expression.definition_path if site.op != "LOAD"
                ),
            ),
        )

    with patch(
        "angr_platforms.X86_16.ir.stack_argument_scaled_return.trace_scalar_affine_expression_8616",
        side_effect=_without_leaf_sites,
    ):
        result = _prove(boundary, ssa)

    assert result.verdict is ScaledReturnVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ScaledReturnFailure8616.LEAF_SITE_MISMATCH
    assert result.offset_expression is None


def test_missing_cfg_edge_refuses() -> None:
    boundary, ssa = _semantic_ssa()

    result = _prove(replace(boundary, successor_edges=()), ssa)

    assert result.verdict is ScaledReturnVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ScaledReturnFailure8616.BASE_USE_UNPROVEN
    assert result.upstream_failure is ModularArgumentUseFailure8616.CFG_NOT_CLOSED


def test_missing_call_effect_refuses() -> None:
    boundary, ssa = _semantic_ssa()
    ssa = _replace_instruction(ssa, 0x1000, 0, op="CALL", dst=None, args=())

    result = _prove(boundary, ssa)

    assert result.verdict is ScaledReturnVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ScaledReturnFailure8616.BASE_USE_UNPROVEN
    assert result.upstream_failure is ModularArgumentUseFailure8616.CALL_EFFECT_UNKNOWN


def test_rebased_real_ret_only_call_preserves_bp_and_scaled_return() -> None:
    """A real one-instruction RET body preserves the caller's BP and input."""
    boundary, ssa = _rebased_semantic_ssa()
    assert boundary.successor_edges == ((0x10F1, 0x10FA), (0x10FA, 0x1107))
    assert ssa.predecessor_map[0x10FA] == (0x10F1,)
    assert ssa.predecessor_map[0x1107] == (0x10FA,)
    calls = tuple(
        instruction
        for block in ssa.blocks
        for instruction in block.instrs
        if instruction.op == "CALL"
    )
    assert len(calls) == 1
    assert calls[0].addr == 0x10F7
    assert calls[0].call_stack_effect is not None
    assert calls[0].call_stack_effect.complete
    assert calls[0].call_stack_effect.bp_preserved

    result = _prove(boundary, ssa)

    assert result.verdict is ScaledReturnVerdict8616.PROVEN
    assert result.complete


def test_rebased_nontrivial_call_refuses_without_body_proof() -> None:
    """A NOP/RET helper must not inherit the one-instruction-body proof."""
    boundary, ssa = _rebased_semantic_ssa(ret_only_helper=False)

    result = _prove(boundary, ssa)

    assert result.verdict is ScaledReturnVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ScaledReturnFailure8616.BASE_USE_UNPROVEN
    assert result.upstream_failure is ModularArgumentUseFailure8616.CALL_EFFECT_UNKNOWN


def test_direct_ret_body_proof_refuses_far_frame_and_synthetic_stub() -> None:
    """RET bytes alone cannot turn a far return or placeholder into proof."""
    boundary, _ = _rebased_semantic_ssa()
    target = 0x15BC
    far = prove_direct_near_ret_only_effect_8616(
        boundary.project, 0x10F7, 0x10FA, target, CallsiteMachineFrameKind8616.FAR,
    )
    assert far.verdict is DirectRetCallEffectVerdict8616.UNKNOWN_REFUSE
    record_synthetic_call_stubs_8616(boundary.project, frozenset({target}))
    synthetic = prove_direct_near_ret_only_effect_8616(
        boundary.project, 0x10F7, 0x10FA, target, CallsiteMachineFrameKind8616.NEAR,
    )
    assert synthetic.verdict is DirectRetCallEffectVerdict8616.UNKNOWN_REFUSE


def test_direct_ret_body_proof_refuses_incomplete_stub_registry() -> None:
    """An invalid frontend stub census cannot be treated as real body proof."""
    boundary, _ = _rebased_semantic_ssa()
    target = 0x15BC
    record_synthetic_call_stubs_8616(boundary.project, frozenset({target, -1}))

    result = prove_direct_near_ret_only_effect_8616(
        boundary.project, 0x10F7, 0x10FA, target, CallsiteMachineFrameKind8616.NEAR,
    )

    assert result.verdict is DirectRetCallEffectVerdict8616.UNKNOWN_REFUSE
    assert result.failure_count == 1


def test_direct_ret_body_proof_binds_decoded_call_to_exact_target() -> None:
    """Mapped RET bytes without the matching E8 site never prove effects."""
    boundary, _ = _rebased_semantic_ssa()
    for callsite, return_addr, target in (
        (0x10F8, 0x10FA, 0x15BC),
        (0x10F7, 0x10FB, 0x15BC),
        (0x10F7, 0x10FA, 0x15BD),
    ):
        result = prove_direct_near_ret_only_effect_8616(
            boundary.project, callsite, return_addr, target,
            CallsiteMachineFrameKind8616.NEAR,
        )
        assert result.verdict is DirectRetCallEffectVerdict8616.UNKNOWN_REFUSE
        assert result.materialized_count == 0


def test_rebased_no_call_control_proves_exact_scaled_return() -> None:
    """Removing only the unproven call exposes the otherwise closed proof."""
    boundary, ssa = _rebased_semantic_ssa(remove_call=True)

    result = _prove(boundary, ssa)

    assert result.verdict is ScaledReturnVerdict8616.PROVEN
    assert result.complete
    assert result.return_instruction_addr == 0x110C
    assert result.base_access_key is not None
    assert result.index_access_key is not None
    assert result.base_access_key.insn_addr == 0x1101
    assert result.index_access_key.insn_addr == 0x10FC


def test_rebased_wrong_scale_machine_bytes_refuse() -> None:
    """A changed SHL opcode cannot inherit the valid no-call affine proof."""
    boundary, ssa = _rebased_semantic_ssa(remove_call=True, remove_shift=True)

    result = _prove(boundary, ssa)

    assert result.verdict is ScaledReturnVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ScaledReturnFailure8616.AFFINE_SHAPE_MISMATCH
    assert result.stats.failure_count == 1


def test_far_probe_inline_preserves_bp_for_scaled_ax_return() -> None:
    """Linked far probe has binary-proven local effects, not an unknown call."""
    boundary, ssa = _far_probe_semantic_ssa()
    at_call = tuple(
        instruction for block in ssa.blocks for instruction in block.instrs
        if instruction.addr == 0x10F7
    )
    assert at_call
    assert all(instruction.op != "CALL" for instruction in at_call)
    assert {instruction.dst.name for instruction in at_call if instruction.dst is not None} >= {
        "cx", "dx", "bx",
    }
    assert not any(
        instruction.op == "MOV" and instruction.dst is not None
        and instruction.dst.name == "sp"
        for instruction in at_call
    )

    result = prove_stack_argument_scaled_return_8616(
        boundary, ssa, _FAR_BASE, _FAR_INDEX,
    )

    assert result.verdict is ScaledReturnVerdict8616.PROVEN
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1


def test_far_segment_word_reaches_dx_return_without_signed_use() -> None:
    """Far segment is a separate BP word with a closed DX return path."""
    boundary, ssa = _far_probe_semantic_ssa()
    segment = replace(_BASE, offset=8)

    result = prove_stack_argument_modular_return_use_8616(
        boundary, ssa, segment,
        return_register=ModularReturnRegister8616.DX,
    )

    assert result.verdict is ModularArgumentUseVerdict8616.PROVEN
    assert result.input_access_key is not None
    assert result.input_access_key.insn_addr == 0x1106


def test_far_scaled_return_joins_exact_offset_and_segment() -> None:
    """The linked far shape proves AX offset and independent DX segment."""
    boundary, ssa = _far_probe_semantic_ssa()

    result = prove_stack_argument_far_scaled_return_8616(
        boundary, ssa, _FAR_BASE, replace(_BASE, offset=8), _FAR_INDEX,
    )

    assert result.verdict is ScaledReturnVerdict8616.PROVEN
    assert result.complete
    assert result.segment_access_key is not None
    assert result.segment_access_key.insn_addr == 0x1106
    assert result.offset is not None and result.offset.complete
    assert result.offset.offset_expression is not None
    assert result.offset.return_instruction_addr == result.return_instruction_addr
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1


def test_far_scaled_return_refuses_modified_segment_arithmetic() -> None:
    """DX plus the input segment is not a carried segment identity."""
    boundary, ssa = _far_probe_semantic_ssa(combine_segment=True)

    result = prove_stack_argument_far_scaled_return_8616(
        boundary, ssa, _FAR_BASE, replace(_BASE, offset=8), _FAR_INDEX,
    )

    assert result.verdict is ScaledReturnVerdict8616.UNKNOWN_REFUSE
    assert result.failure is FarScaledReturnFailure8616.SEGMENT_TRACE_UNPROVEN
    assert result.stats.materialized_count == 0


def test_far_scaled_return_refuses_nonadjacent_segment_storage() -> None:
    """A nonadjacent word cannot be the segment half of the input pointer."""
    boundary, ssa = _far_probe_semantic_ssa()

    result = prove_stack_argument_far_scaled_return_8616(
        boundary, ssa, _FAR_BASE, replace(_BASE, offset=12), _FAR_INDEX,
    )

    assert result.verdict is ScaledReturnVerdict8616.UNKNOWN_REFUSE
    assert result.failure is FarScaledReturnFailure8616.INPUT_SHAPE_MISMATCH


def test_far_scaled_return_refuses_late_dx_clobber() -> None:
    """The segment carrier must survive from its read to the far RET."""
    boundary, ssa = _far_probe_semantic_ssa()
    block = next(item for item in ssa.blocks if item.addr == 0x110C)
    instr_index, instruction = next(
        (index, item) for index, item in enumerate(block.instrs)
        if item.dst is not None and item.dst.name == "sp"
    )
    assert instruction.dst is not None
    ssa = _replace_instruction(
        ssa, block.addr, instr_index,
        dst=replace(instruction.dst, name="dx"),
    )

    result = prove_stack_argument_far_scaled_return_8616(
        boundary, ssa, _FAR_BASE, replace(_BASE, offset=8), _FAR_INDEX,
    )

    assert result.verdict is ScaledReturnVerdict8616.UNKNOWN_REFUSE
    assert result.failure is FarScaledReturnFailure8616.SEGMENT_USE_UNPROVEN
    assert result.upstream_failure is ModularArgumentUseFailure8616.RETURN_FLOW_UNKNOWN


def test_far_probe_with_diverted_branch_cannot_prove_scaled_return() -> None:
    """A noncanonical helper remains a CALL with unproven BP preservation."""
    boundary, ssa = _far_probe_semantic_ssa(recognizable_helper=False)
    calls = tuple(
        instruction for block in ssa.blocks for instruction in block.instrs
        if instruction.op == "CALL"
    )
    assert len(calls) == 1
    assert calls[0].addr == 0x10F7

    result = prove_stack_argument_scaled_return_8616(
        boundary, ssa, _FAR_BASE, _FAR_INDEX,
    )

    assert result.verdict is ScaledReturnVerdict8616.UNKNOWN_REFUSE
    assert result.failure is ScaledReturnFailure8616.BASE_USE_UNPROVEN
    assert result.upstream_failure is ModularArgumentUseFailure8616.CALL_EFFECT_UNKNOWN
