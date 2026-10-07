"""Source-free far-return expression binding positive and refusal tests."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.ir import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from inertia.ir.stack_argument_scaled_return import (
    FarScaledReturnFailure8616,
    ScaledReturnVerdict8616,
    prove_stack_argument_far_scaled_return_8616,
)
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.lowering.far_return_expression_binding import (
    FarReturnExpressionBindingFailure8616,
    FarReturnExpressionBindingVerdict8616,
    FarReturnExpressionRole8616,
    FarReturnRepresentationKind8616,
    bind_far_return_expression_8616,
)
from inertia.lowering.stack_variable_coordinates import (
    record_stack_variable_coordinate_projection_8616,
    stack_variable_coordinate_registry_8616,
)
from tests.ir.test_x86_16_stack_argument_scaled_return import _far_probe_semantic_ssa

_BASE = IRAddress(
    space=MemSpace.SS, base=("bp",), offset=6, size=2,
    status=AddressStatus.STABLE, segment_origin=SegmentOrigin.PROVEN,
)
_SEGMENT = replace(_BASE, offset=8)
_INDEX = replace(_BASE, offset=10)


class _StubCodegen:
    """Minimal angr structured-codegen boundary with its current allocator API."""

    def __init__(self, project: object, function_addr: int) -> None:
        self._idx = 0
        self.project = project
        self.cfunc = SimpleNamespace(
            addr=function_addr,
            statements=None,
            variables_in_use={},
        )
        self.cstyle_null_cmp = False

    def next_ident(self, name: str) -> str:
        """Return a stable class display identity."""
        return name

    def next_node_idx(self) -> int:
        """Return one unique C AST node identity."""
        self._idx += 1
        return self._idx


def _case(
    *,
    c_target: str | None = None,
    function_addr: int | None = None,
):
    """Prove the far scaled return on real bytes and expose a stub codegen."""
    boundary, artifact = _far_probe_semantic_ssa()
    project = boundary.project
    if c_target is not None:
        # angr Project is a dynamic third-party boundary for this owned flag.
        cast(Any, project)._inertia_c_target = c_target
    proof = prove_stack_argument_far_scaled_return_8616(
        boundary, artifact, _BASE, _SEGMENT, _INDEX,
    )
    assert proof.complete
    codegen = _StubCodegen(
        project,
        artifact.function_addr if function_addr is None else function_addr,
    )
    return codegen, artifact, proof


def _record_word_arg(
    codegen: object,
    bp_offset: int,
    name: str,
    variable_type: SimType | None = None,
) -> structured_c.CVariable:
    """Project one exact machine-BP word to a canonical C variable."""
    variable = SimStackVariable(
        bp_offset - 6, 2, base="bp", name=name, ident=f"is_{bp_offset:x}",
    )
    cvar = structured_c.CVariable(
        variable,
        variable_type=variable_type if variable_type is not None else SimTypeShort(False),
        codegen=codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=variable,
        cvar=cvar,
        bp_offset=bp_offset,
        entry_sp_offset=bp_offset - 6,
        size=2,
    )
    return cvar


def _record_all_args(codegen: object) -> dict[int, structured_c.CVariable]:
    """Bind canonical word variables at BP+6, BP+8, and BP+10."""
    return {
        6: _record_word_arg(codegen, 6, "arg_base"),
        8: _record_word_arg(codegen, 8, "arg_seg"),
        10: _record_word_arg(codegen, 10, "arg_index"),
    }


def test_far_return_binds_segmented_pointer_expression() -> None:
    codegen, artifact, proof = _case()
    recorded = _record_all_args(codegen)

    result = bind_far_return_expression_8616(codegen, artifact, proof)

    assert result.complete
    assert result.verdict is FarReturnExpressionBindingVerdict8616.BOUND
    assert result.failure is None
    assert result.target == "portable-flat"
    expression = result.expression
    assert isinstance(expression, structured_c.CFunctionCall)
    assert expression.callee_target == "SEG_PTR"
    assert expression.callee_func is None
    segment_arg, offset_arg = expression.args
    assert isinstance(segment_arg, structured_c.CVariable)
    assert segment_arg.variable.name == "arg_seg"
    assert isinstance(offset_arg, structured_c.CTypeCast)
    assert isinstance(offset_arg.dst_type, SimTypeShort)
    assert offset_arg.dst_type.size == 16
    total = offset_arg.expr
    assert isinstance(total, structured_c.CBinaryOp) and total.op == "Add"
    assert isinstance(total.lhs, structured_c.CVariable)
    assert total.lhs.variable.name == "arg_base"
    scaled = total.rhs
    assert isinstance(scaled, structured_c.CBinaryOp) and scaled.op == "Shl"
    assert isinstance(scaled.lhs, structured_c.CVariable)
    assert scaled.lhs.variable.name == "arg_index"
    assert isinstance(scaled.rhs, structured_c.CConstant)
    assert scaled.rhs.value == 1
    by_role = {bound.role: bound for bound in result.bound_inputs}
    assert set(by_role) == set(FarReturnExpressionRole8616)
    assert by_role[FarReturnExpressionRole8616.OFFSET_BASE].storage.offset == 6
    assert by_role[FarReturnExpressionRole8616.SEGMENT].storage.offset == 8
    assert by_role[FarReturnExpressionRole8616.OFFSET_INDEX].storage.offset == 10
    assert proof.offset is not None
    assert (
        by_role[FarReturnExpressionRole8616.OFFSET_BASE].access_key
        == proof.offset.base_access_key
    )
    assert (
        by_role[FarReturnExpressionRole8616.SEGMENT].access_key
        == proof.segment_access_key
    )
    assert (
        by_role[FarReturnExpressionRole8616.OFFSET_INDEX].access_key
        == proof.offset.index_access_key
    )
    assert segment_arg is not recorded[8]
    assert result.stats.raw_fact_count == result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_far_return_binding_is_mutation_free() -> None:
    codegen, artifact, proof = _case()
    _record_all_args(codegen)
    projections = stack_variable_coordinate_registry_8616(codegen).projections

    result = bind_far_return_expression_8616(codegen, artifact, proof)

    assert result.complete
    assert codegen.cfunc.statements is None
    assert stack_variable_coordinate_registry_8616(codegen).projections == projections


def test_far_return_binding_uses_mk_fp_for_msc_dos() -> None:
    codegen, artifact, proof = _case(c_target="msc-dos")
    _record_all_args(codegen)

    result = bind_far_return_expression_8616(codegen, artifact, proof)

    assert result.complete
    assert result.target == "msc-dos"
    expression = result.expression
    assert isinstance(expression, structured_c.CFunctionCall)
    assert expression.callee_target == "MK_FP"


def test_signed_word_inputs_get_unsigned_bitpattern_views_before_scaling() -> None:
    """Negative signed words must not enter a C left shift or segment macro."""
    codegen, artifact, proof = _case()
    for offset, name in ((6, "arg_base"), (8, "arg_seg"), (10, "arg_index")):
        _record_word_arg(codegen, offset, name, SimTypeShort(True))

    result = bind_far_return_expression_8616(codegen, artifact, proof)

    assert result.complete
    expression = result.expression
    assert isinstance(expression, structured_c.CFunctionCall)
    segment_arg, offset_arg = expression.args
    assert isinstance(segment_arg, structured_c.CTypeCast)
    assert isinstance(segment_arg.dst_type, SimTypeShort)
    assert segment_arg.dst_type.signed is False
    assert isinstance(offset_arg, structured_c.CTypeCast)
    total = offset_arg.expr
    assert isinstance(total, structured_c.CBinaryOp)
    assert isinstance(total.lhs, structured_c.CTypeCast)
    assert isinstance(total.lhs.dst_type, SimTypeShort)
    assert total.lhs.dst_type.signed is False
    scaled = total.rhs
    assert isinstance(scaled, structured_c.CBinaryOp)
    assert isinstance(scaled.lhs, structured_c.CTypeCast)
    assert isinstance(scaled.lhs.dst_type, SimTypeShort)
    assert scaled.lhs.dst_type.signed is False


def test_incomplete_proof_refuses_with_upstream_failure() -> None:
    codegen, artifact, proof = _case()
    _record_all_args(codegen)
    broken = replace(
        proof,
        verdict=ScaledReturnVerdict8616.UNKNOWN_REFUSE,
        failure=FarScaledReturnFailure8616.OFFSET_UNPROVEN,
    )
    assert not broken.complete

    result = bind_far_return_expression_8616(codegen, artifact, broken)

    assert not result.complete
    assert result.failure is FarReturnExpressionBindingFailure8616.PROOF_INCOMPLETE
    assert result.upstream_failure is FarScaledReturnFailure8616.OFFSET_UNPROVEN
    assert result.expression is None


def test_codegen_surface_and_function_mismatch_refuse() -> None:
    codegen, artifact, proof = _case(function_addr=0x2000)
    _record_all_args(codegen)

    mismatched = bind_far_return_expression_8616(codegen, artifact, proof)

    assert mismatched.failure is FarReturnExpressionBindingFailure8616.FUNCTION_MISMATCH
    assert (
        mismatched.missing_representation
        is FarReturnRepresentationKind8616.CODEGEN_FUNCTION
    )

    headless = SimpleNamespace(
        project=codegen.project,
        cfunc=None,
        cstyle_null_cmp=False,
    )
    surfaced = bind_far_return_expression_8616(headless, artifact, proof)

    assert (
        surfaced.failure
        is FarReturnExpressionBindingFailure8616.CODEGEN_SURFACE_UNPROVEN
    )


def test_unproven_logical_memory_and_access_key_refuse() -> None:
    codegen, artifact, proof = _case()
    _record_all_args(codegen)

    no_memory = bind_far_return_expression_8616(
        codegen, replace(artifact, logical_memory=None), proof,
    )
    assert (
        no_memory.failure
        is FarReturnExpressionBindingFailure8616.LOGICAL_MEMORY_UNPROVEN
    )

    assert proof.segment_access_key is not None
    foreign_key = replace(proof, segment_access_key=replace(
        proof.segment_access_key, insn_addr=0x9999,
    ))
    missing = bind_far_return_expression_8616(codegen, artifact, foreign_key)

    assert missing.failure is FarReturnExpressionBindingFailure8616.INPUT_ACCESS_UNPROVEN
    assert missing.missing_role is FarReturnExpressionRole8616.SEGMENT


def test_nonadjacent_segment_identity_refuses() -> None:
    codegen, artifact, proof = _case()
    _record_all_args(codegen)
    assert proof.offset is not None
    swapped = replace(proof, segment_access_key=proof.offset.index_access_key)
    assert swapped.complete

    result = bind_far_return_expression_8616(codegen, artifact, swapped)

    assert result.failure is FarReturnExpressionBindingFailure8616.INPUT_STORAGE_MISMATCH
    assert not result.complete


def test_missing_input_projection_refuses_with_role() -> None:
    codegen, artifact, proof = _case()
    _record_word_arg(codegen, 6, "arg_base")
    _record_word_arg(codegen, 8, "arg_seg")

    result = bind_far_return_expression_8616(codegen, artifact, proof)

    assert (
        result.failure
        is FarReturnExpressionBindingFailure8616.INPUT_EXPRESSION_MISSING
    )
    assert (
        result.missing_representation
        is FarReturnRepresentationKind8616.INPUT_STACK_VARIABLE
    )
    assert result.missing_role is FarReturnExpressionRole8616.OFFSET_INDEX


def test_wide_input_variable_refuses_instead_of_rescaling() -> None:
    codegen, artifact, proof = _case()
    _record_word_arg(codegen, 6, "arg_base")
    _record_word_arg(codegen, 8, "arg_seg")
    _record_word_arg(codegen, 10, "arg_index", variable_type=SimTypeLong(False))

    result = bind_far_return_expression_8616(codegen, artifact, proof)

    assert (
        result.failure
        is FarReturnExpressionBindingFailure8616.INPUT_EXPRESSION_MISMATCH
    )
    assert (
        result.missing_representation
        is FarReturnRepresentationKind8616.INPUT_WORD_TYPE
    )
    assert result.missing_role is FarReturnExpressionRole8616.OFFSET_INDEX


def test_unknown_c_target_refuses_without_expression() -> None:
    codegen, artifact, proof = _case(c_target="wasm-flat")
    _record_all_args(codegen)

    result = bind_far_return_expression_8616(codegen, artifact, proof)

    assert result.failure is FarReturnExpressionBindingFailure8616.TARGET_UNKNOWN
    assert (
        result.missing_representation
        is FarReturnRepresentationKind8616.SEGMENTED_POINTER_CONSTRUCTOR
    )
    assert result.expression is None


def test_result_stats_stay_closed_on_refusal() -> None:
    codegen, artifact, proof = _case()
    _record_all_args(codegen)
    broken = replace(
        proof,
        verdict=ScaledReturnVerdict8616.UNKNOWN_REFUSE,
        failure=FarScaledReturnFailure8616.SEGMENT_USE_UNPROVEN,
    )

    result = bind_far_return_expression_8616(codegen, artifact, broken)

    stats = result.stats
    assert stats.raw_fact_count == 1
    assert stats.materialized_count == 0
    assert stats.failure_count == 1
    assert stats.classified_fact_count <= stats.normalized_fact_count <= 1


def test_bound_expression_ignores_caller_dereference_width() -> None:
    """Binding never sizes the pointee from downstream ES:BX access width."""
    codegen, artifact, proof = _case()
    _record_all_args(codegen)

    result = bind_far_return_expression_8616(codegen, artifact, proof)

    assert result.complete
    expression = result.expression
    assert isinstance(expression, structured_c.CFunctionCall)
    # The constructor stays a pointee-free segmented pointer; no typed pointee
    # or dereference node is synthesized from the caller's access width.
    nodes = (expression, *expression.args)
    assert not any(
        isinstance(node, structured_c.CUnaryOp) and node.op == "Dereference"
        for node in nodes
    )
    assert not any(
        isinstance(node, structured_c.CTypeCast)
        and node is not expression.args[1]
        for node in nodes
    )
