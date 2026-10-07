"""Regression tests for deterministic CGoto target validation identity.

Layer: Tests.
Responsibility: prove that independently regenerated CGoto target trees share
one typed validation identity while operand, operator, type, cast, index, and
unknown-target changes stay observable or fail closed — and that unproven
targets refuse equality outright, even for the same live node, after node
release/id reuse, and across summary serialization.
"""

from __future__ import annotations

import gc
import json
import weakref
from types import SimpleNamespace
from typing import cast

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CFunctionCall,
    CGoto,
    CIndexedVariable,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimType, SimTypeFunction, SimTypeInt, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.semantic_cast import CSemanticCast8616

from inertia.validation.tail_validation import (
    X86_16TailValidationSummary,
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    fingerprint_x86_16_tail_validation_boundary,
    x86_16_tail_validation_result_passed,
    x86_16_tail_validation_snapshot_passed,
)
from inertia.validation.validation_control_flow import (
    GotoTargetIdentityIssue8616,
    validate_structured_control_flow_8616,
)
from inertia.validation.validation_goto_target_identity import (
    GotoTargetIdentityReason8616,
    goto_target_boundary_identity_8616,
    goto_target_effect_token_8616,
    goto_target_identity_8616,
)


class _DummyCodegen:
    def __init__(self) -> None:
        self._idx = 0
        self.cfunc: object | None = None
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _project() -> SimpleNamespace:
    return SimpleNamespace(arch=Arch86_16())


def test_foreign_type_metadata_cannot_certify_regenerated_target_equality() -> None:
    """Unknown foreign types refuse equality instead of differing by nonce."""
    class ForeignType:
        def __init__(self, size: int) -> None:
            self.size = size

        def with_arch(self, _arch: object) -> ForeignType:
            return self

    first_codegen, second_codegen = _DummyCodegen(), _DummyCodegen()
    # Cast only at the deliberately malformed third-party type boundary.
    first = CBinaryOp(
        "Add", CConstant(4, cast(SimType, ForeignType(16)), codegen=first_codegen),
        _const(0, first_codegen), codegen=first_codegen,
    )
    second = CBinaryOp(
        "Add", CConstant(4, cast(SimType, ForeignType(32)), codegen=second_codegen),
        _const(0, second_codegen), codegen=second_codegen,
    )
    first_verdict = goto_target_identity_8616(CGoto(first, None, codegen=first_codegen))
    second_verdict = goto_target_identity_8616(CGoto(second, None, codegen=second_codegen))

    assert not first_verdict.complete
    assert not second_verdict.complete
    assert GotoTargetIdentityReason8616.UNSUPPORTED_TYPE in first_verdict.reasons
    assert GotoTargetIdentityReason8616.UNSUPPORTED_TYPE in second_verdict.reasons
    # Unknown identity is deterministic: markers may coincide, but equality is
    # refused through the typed verdict rather than manufactured by an id.
    assert not first_verdict.proves_equal(second_verdict)
    assert not second_verdict.proves_equal(first_verdict)
    first_summary = _summary(first, first_codegen)
    second_summary = _summary(second, second_codegen)
    assert first_summary.unproven_goto_target_identities
    assert second_summary.unproven_goto_target_identities
    comparison = compare_x86_16_tail_validation_summaries(first_summary, second_summary)
    assert comparison["status"] == "failed"
    assert comparison["changed"] is True


def test_bounded_type_traversal_cannot_collapse_distinct_unknown_tails() -> None:
    """Exhausted type traversal refuses both distinct tails without nonces."""
    first_codegen, second_codegen = _DummyCodegen(), _DummyCodegen()
    first_type: SimType = SimTypeShort(False)
    second_type: SimType = SimTypeInt(False)
    for _ in range(12):
        first_type, second_type = SimTypePointer(first_type), SimTypePointer(second_type)
    first = CBinaryOp(
        "Add", CConstant(4, first_type, codegen=first_codegen),
        _const(0, first_codegen), codegen=first_codegen,
    )
    second = CBinaryOp(
        "Add", CConstant(4, second_type, codegen=second_codegen),
        _const(0, second_codegen), codegen=second_codegen,
    )
    first_verdict = goto_target_identity_8616(CGoto(first, None, codegen=first_codegen))
    second_verdict = goto_target_identity_8616(CGoto(second, None, codegen=second_codegen))

    assert not first_verdict.complete
    assert not second_verdict.complete
    assert GotoTargetIdentityReason8616.BOUND_EXCEEDED in first_verdict.reasons
    assert GotoTargetIdentityReason8616.BOUND_EXCEEDED in second_verdict.reasons
    assert not first_verdict.proves_equal(second_verdict)
    # The traversal cutoff truncates both tails at the same depth, so the
    # deterministic markers coincide; refusal — not token inequality — is
    # what prevents false equality.
    first_summary = _summary(first, first_codegen)
    second_summary = _summary(second, second_codegen)
    assert first_summary.unproven_goto_target_identities
    assert second_summary.unproven_goto_target_identities
    comparison = compare_x86_16_tail_validation_summaries(first_summary, second_summary)
    assert comparison["status"] == "failed"
    assert comparison["changed"] is True


def test_call_result_width_stays_observable_in_computed_goto_target() -> None:
    """Matching callee addresses do not erase the target expression's return type."""
    from angr.knowledge_plugins.functions.function import Function

    nodes = []
    for return_type in (SimTypeShort(False), SimTypeInt(False)):
        codegen = _DummyCodegen()
        callee = SimpleNamespace(
            addr=0x1234, name="callee", prototype_libname=None,
            prototype=SimTypeFunction([], return_type).with_arch(codegen.project.arch),
        )
        call = CFunctionCall(
            _const(0x1234, codegen), cast(Function, callee), [], codegen=codegen,
        )
        nodes.append(CGoto(call, None, codegen=codegen))
    assert goto_target_boundary_identity_8616(nodes[0]) != goto_target_boundary_identity_8616(nodes[1])
    assert goto_target_effect_token_8616(nodes[0]) != goto_target_effect_token_8616(nodes[1])


def _codegen(statements, codegen=None):
    codegen = codegen or _DummyCodegen()
    codegen.cfunc = SimpleNamespace(
        addr=0x4010, body=CStatements(statements, addr=0x4010, codegen=codegen)
    )
    return codegen


def _const(value, codegen, sim_type=None):
    return CConstant(value, sim_type or SimTypeShort(False), codegen=codegen)


def _add_target(codegen, value=4, sim_type=None):
    return CBinaryOp(
        "Add",
        _const(0x1000, codegen, sim_type),
        _const(value, codegen, sim_type),
        codegen=codegen,
    )


def _summary(target, codegen, *, target_idx=None):
    _codegen([CGoto(target, target_idx, codegen=codegen)], codegen)
    return collect_x86_16_tail_validation_summary(
        codegen.project, codegen, mode="live_out"
    )


def _summary_effects(target, codegen, *, target_idx=None):
    return tuple(_summary(target, codegen, target_idx=target_idx).control_flow_effects)


def _boundary(target, codegen, *, target_idx=None):
    _codegen([CGoto(target, target_idx, codegen=codegen)], codegen)
    return fingerprint_x86_16_tail_validation_boundary(
        codegen.project, codegen, mode="live_out"
    )


def test_regenerated_identical_target_trees_share_identity() -> None:
    first_codegen, second_codegen = _DummyCodegen(), _DummyCodegen()
    first = _add_target(first_codegen)
    second = _add_target(second_codegen)

    assert goto_target_boundary_identity_8616(
        CGoto(first, None, codegen=first_codegen)
    ) == goto_target_boundary_identity_8616(CGoto(second, None, codegen=second_codegen))
    assert goto_target_effect_token_8616(
        CGoto(first, None, codegen=first_codegen)
    ) == goto_target_effect_token_8616(CGoto(second, None, codegen=second_codegen))


def test_regenerated_identical_targets_share_summary_and_boundary() -> None:
    first_codegen, second_codegen = _DummyCodegen(), _DummyCodegen()
    first = _summary_effects(_add_target(first_codegen), first_codegen)
    first_boundary = _boundary(_add_target(first_codegen), first_codegen)
    second = _summary_effects(_add_target(second_codegen), second_codegen)
    second_boundary = _boundary(_add_target(second_codegen), second_codegen)

    assert first == second
    assert first_boundary == second_boundary
    assert first == (
        "goto:bop:Add("
        "const(4096,SimTypeShort(16,False)),"
        "const(4,SimTypeShort(16,False)),"
        "SimTypeShort(16,False))",
    )


def test_changed_operand_and_operator_remain_observable() -> None:
    codegen = _DummyCodegen()
    base = _summary_effects(_add_target(codegen, 4), codegen)

    changed_operand_codegen = _DummyCodegen()
    changed_operand = _summary_effects(
        _add_target(changed_operand_codegen, 5), changed_operand_codegen
    )
    changed_operator_codegen = _DummyCodegen()
    changed_operator = _summary_effects(
        CBinaryOp(
            "Sub",
            _const(0x1000, changed_operator_codegen),
            _const(4, changed_operator_codegen),
            codegen=changed_operator_codegen,
        ),
        changed_operator_codegen,
    )

    assert base != changed_operand
    assert base != changed_operator


def test_target_idx_identity_is_preserved() -> None:
    codegen = _DummyCodegen()
    plain = _summary_effects(0x1234, codegen)
    indexed_two = _summary_effects(0x1234, codegen, target_idx=2)
    indexed_three = _summary_effects(0x1234, codegen, target_idx=3)

    assert plain == ("goto:4660",)
    assert indexed_two == ("goto:4660:idx=2",)
    assert indexed_three == ("goto:4660:idx=3",)
    assert indexed_two != indexed_three
    assert plain != indexed_two


def test_numeric_and_string_targets_remain_distinct() -> None:
    codegen = _DummyCodegen()
    numeric = _summary_effects(4096, codegen)
    labelled = _summary_effects("LABEL_4096", codegen)

    assert numeric == ("goto:4096",)
    assert labelled == ("goto:'LABEL_4096'",)
    assert numeric != labelled


def test_constant_type_width_and_signedness_stay_observable() -> None:
    short_codegen = _DummyCodegen()
    short = _summary_effects(
        _add_target(short_codegen, sim_type=SimTypeShort(False)), short_codegen
    )
    int_codegen = _DummyCodegen()
    wider = _summary_effects(
        _add_target(int_codegen, sim_type=SimTypeInt(False)), int_codegen
    )
    signed_codegen = _DummyCodegen()
    signed = _summary_effects(
        _add_target(signed_codegen, sim_type=SimTypeShort(True)), signed_codegen
    )

    assert short != wider
    assert short != signed
    assert wider != signed


def test_cast_changes_stay_observable() -> None:
    plain_codegen = _DummyCodegen()
    plain = _summary_effects(_add_target(plain_codegen), plain_codegen)

    cast_codegen = _DummyCodegen()
    cast_target = CTypeCast(
        SimTypeShort(False),
        SimTypeInt(False),
        _add_target(cast_codegen),
        codegen=cast_codegen,
    )
    casted = _summary_effects(cast_target, cast_codegen)

    other_cast_codegen = _DummyCodegen()
    other_cast = CTypeCast(
        SimTypeShort(False),
        SimTypePointer(SimTypeShort(False)),
        _add_target(other_cast_codegen),
        codegen=other_cast_codegen,
    )
    other_casted = _summary_effects(other_cast, other_cast_codegen)

    semantic_codegen = _DummyCodegen()
    semantic_cast = CSemanticCast8616(
        SimTypeShort(False),
        SimTypeInt(False),
        _add_target(semantic_codegen),
        codegen=semantic_codegen,
    )
    semantic_casted = _summary_effects(semantic_cast, semantic_codegen)

    assert plain != casted
    assert casted != other_casted
    assert casted != semantic_casted


def test_variable_and_unary_target_identities() -> None:
    codegen = _DummyCodegen()
    reg_offset, reg_size = _project().arch.registers["ax"]
    variable = CVariable(
        SimRegisterVariable(reg_offset, reg_size, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    unary = CUnaryOp("Reference", variable, codegen=codegen)
    indexed = CIndexedVariable(
        variable, _const(1, codegen), codegen=codegen
    )

    var_token = goto_target_effect_token_8616(CGoto(variable, None, codegen=codegen))
    unary_token = goto_target_effect_token_8616(CGoto(unary, None, codegen=codegen))
    indexed_token = goto_target_effect_token_8616(CGoto(indexed, None, codegen=codegen))

    assert var_token.startswith("goto:var(reg(")
    assert unary_token.startswith("goto:uop:Reference(var(")
    assert indexed_token.startswith("goto:idxv(var(")
    assert len({var_token, unary_token, indexed_token}) == 3


def test_stack_variables_with_distinct_offsets_do_not_merge() -> None:
    codegen = _DummyCodegen()
    first = CVariable(SimStackVariable(-4, 2, base="bp"), codegen=codegen)
    second = CVariable(SimStackVariable(-6, 2, base="bp"), codegen=codegen)

    first_token = goto_target_effect_token_8616(CGoto(first, None, codegen=codegen))
    second_token = goto_target_effect_token_8616(CGoto(second, None, codegen=codegen))

    assert first_token != second_token


def test_unknown_same_class_targets_refuse_equality() -> None:
    """Identical unknown targets share one marker but never certify equality."""
    codegen = _DummyCodegen()
    first_dirty = CDirtyExpression(SimpleNamespace(callee="helper"), codegen=codegen)
    second_dirty = CDirtyExpression(SimpleNamespace(callee="helper"), codegen=codegen)

    first = goto_target_effect_token_8616(CGoto(first_dirty, None, codegen=codegen))
    second = goto_target_effect_token_8616(CGoto(second_dirty, None, codegen=codegen))
    first_verdict = goto_target_identity_8616(CGoto(first_dirty, None, codegen=codegen))
    second_verdict = goto_target_identity_8616(CGoto(second_dirty, None, codegen=codegen))

    assert first == "goto:opaque:unsupported:CDirtyExpression"
    assert second == "goto:opaque:unsupported:CDirtyExpression"
    assert not first_verdict.complete
    assert not second_verdict.complete
    assert first_verdict.reasons == (GotoTargetIdentityReason8616.UNSUPPORTED_NODE,)
    assert not first_verdict.proves_equal(second_verdict)
    assert not second_verdict.proves_equal(first_verdict)


def test_relabelled_result_cannot_discard_unknown_target_failure() -> None:
    """A stable label cannot override retained typed missing-proof evidence."""
    codegen = _DummyCodegen()
    summary = _summary(
        CDirtyExpression(SimpleNamespace(callee="helper"), codegen=codegen), codegen
    )
    comparison = compare_x86_16_tail_validation_summaries(summary, summary)
    assert comparison["semantic_failures"]["control_flow_identity"]
    for status in ("stable", "passed"):
        relabelled = {**comparison, "changed": False, "status": status}
        assert not x86_16_tail_validation_result_passed(relabelled)


def test_relabelled_snapshot_cannot_discard_unknown_target_failure() -> None:
    """Snapshot admission must consume failures after a precision-delta accept."""
    codegen = _DummyCodegen()
    summary = _summary(
        CDirtyExpression(SimpleNamespace(callee="helper"), codegen=codegen), codegen
    )
    comparison = compare_x86_16_tail_validation_summaries(summary, summary)
    assert comparison["semantic_failures"]["control_flow_identity"]
    relabelled = {**comparison, "changed": False, "status": "stable"}
    assert not x86_16_tail_validation_snapshot_passed(
        {"postprocess": relabelled}, expected_stages=("postprocess",)
    )


def test_unknown_identity_refuses_after_node_release() -> None:
    """id() reuse after node collection can never collide unknowns equal."""
    class ReleaseTrackedDirtyExpression(CDirtyExpression):
        __slots__ = ("__weakref__",)

    first_codegen = _DummyCodegen()
    first = ReleaseTrackedDirtyExpression(SimpleNamespace(callee="helper"), codegen=first_codegen)
    released = weakref.ref(first)
    first_summary = _summary(first, first_codegen)
    del first, first_codegen
    gc.collect()
    assert released() is None

    second_codegen = _DummyCodegen()
    second = ReleaseTrackedDirtyExpression(SimpleNamespace(callee="helper2"), codegen=second_codegen)
    second_summary = _summary(second, second_codegen)

    # Even if the second node reused the released id, equal markers never
    # prove equality: the comparison must refuse through typed evidence.
    assert first_summary.unproven_goto_target_identities
    assert second_summary.unproven_goto_target_identities
    comparison = compare_x86_16_tail_validation_summaries(first_summary, second_summary)
    assert comparison["status"] == "failed"
    assert comparison["changed"] is True
    assert comparison["semantic_failures"]["control_flow_identity"]


def test_identical_unknown_before_after_refuses_stable() -> None:
    """Same-shape unknown on both sides must refuse, not report stable."""
    first_codegen, second_codegen = _DummyCodegen(), _DummyCodegen()
    before = _summary(
        CDirtyExpression(SimpleNamespace(callee="helper"), codegen=first_codegen),
        first_codegen,
    )
    after = _summary(
        CDirtyExpression(SimpleNamespace(callee="helper"), codegen=second_codegen),
        second_codegen,
    )

    comparison = compare_x86_16_tail_validation_summaries(before, after)

    assert before.unproven_goto_target_identities == after.unproven_goto_target_identities
    assert before.control_flow_effects == after.control_flow_effects
    assert comparison["status"] == "failed"
    assert comparison["changed"] is True


def test_unproven_identity_refusal_survives_serialization() -> None:
    """A summary rebuilt from its serialized dict keeps the refusal channel."""
    codegen = _DummyCodegen()
    summary = _summary(
        CDirtyExpression(SimpleNamespace(callee="helper"), codegen=codegen), codegen
    )
    assert summary.unproven_goto_target_identities

    restored = X86_16TailValidationSummary(
        **{
            key: tuple(value)
            for key, value in json.loads(json.dumps(summary.as_dict())).items()
        }
    )

    assert restored.unproven_goto_target_identities == summary.unproven_goto_target_identities
    comparison = compare_x86_16_tail_validation_summaries(restored, restored)
    assert comparison["status"] == "failed"
    assert comparison["changed"] is True


def test_unproven_goto_blocks_control_flow_report_passed() -> None:
    """The typed report records classified-but-unmaterialized goto evidence."""
    codegen = _DummyCodegen()
    dirty = CDirtyExpression(SimpleNamespace(callee="helper"), codegen=codegen)
    root = CStatements([CGoto(dirty, None, codegen=codegen)], addr=0x4010, codegen=codegen)

    report = validate_structured_control_flow_8616(root)

    assert report.raw_fact_count >= 1
    assert report.normalized_fact_count >= 1
    assert report.classified_fact_count >= 1
    assert report.materialized_count < report.classified_fact_count
    assert report.failure_count == 1
    assert not report.passed
    issues = tuple(
        issue for issue in report.issues if isinstance(issue, GotoTargetIdentityIssue8616)
    )
    assert len(issues) == 1
    assert issues[0].reasons == (GotoTargetIdentityReason8616.UNSUPPORTED_NODE,)
    assert report.unproven_goto_target_tokens() == (issues[0].token(),)


def test_supported_goto_identity_materializes_cleanly() -> None:
    """A fully supported computed-goto target still passes closed evidence."""
    codegen = _DummyCodegen()
    root = CStatements(
        [CGoto(_add_target(codegen), None, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )

    report = validate_structured_control_flow_8616(root)

    assert report.materialized_count == report.classified_fact_count
    assert not report.unproven_goto_target_tokens()
    assert report.passed


def test_proves_equal_for_regenerated_supported_targets() -> None:
    """Complete verdicts certify equality; mutations stay observable."""
    first_codegen, second_codegen = _DummyCodegen(), _DummyCodegen()
    first = goto_target_identity_8616(CGoto(_add_target(first_codegen), None, codegen=first_codegen))
    second = goto_target_identity_8616(CGoto(_add_target(second_codegen), None, codegen=second_codegen))
    changed = goto_target_identity_8616(
        CGoto(_add_target(second_codegen, value=8), None, codegen=second_codegen)
    )

    assert first.complete and second.complete
    assert first.proves_equal(second)
    assert not first.proves_equal(changed)


def test_cyclic_target_fails_closed() -> None:
    codegen = _DummyCodegen()
    target = _add_target(codegen)
    # Deliberately malformed cyclic AST: identity must fail closed, not hang.
    target.lhs = target  # pyright: ignore[reportAttributeAccessIssue]

    identity = goto_target_boundary_identity_8616(CGoto(target, None, codegen=codegen))
    token = goto_target_effect_token_8616(CGoto(target, None, codegen=codegen))
    verdict = goto_target_identity_8616(CGoto(target, None, codegen=codegen))

    assert identity[0] == "goto"
    assert "opaque:cycle" in token
    assert not verdict.complete
    assert GotoTargetIdentityReason8616.CYCLIC_TARGET in verdict.reasons


def test_deeply_nested_target_stays_bounded() -> None:
    codegen = _DummyCodegen()
    target = _const(0, codegen)
    for _ in range(80):
        target = CBinaryOp("Add", target, _const(1, codegen), codegen=codegen)

    token = goto_target_effect_token_8616(CGoto(target, None, codegen=codegen))
    verdict = goto_target_identity_8616(CGoto(target, None, codegen=codegen))

    assert token.startswith("goto:")
    assert "opaque:bounded" in token
    assert not verdict.complete
    assert GotoTargetIdentityReason8616.BOUND_EXCEEDED in verdict.reasons


def test_scalar_none_target_does_not_crash() -> None:
    codegen = _DummyCodegen()
    token = goto_target_effect_token_8616(CGoto(0x1000, None, codegen=codegen))
    goto = CGoto(0x1000, None, codegen=codegen)
    # Deliberately None target outside the CGoto constructor contract.
    goto.target = None  # pyright: ignore[reportAttributeAccessIssue]
    verdict = goto_target_identity_8616(goto)

    assert token == "goto:4096"
    assert goto_target_effect_token_8616(goto) == "goto:none"
    # A missing top-level target is unproven evidence, not a known identity.
    assert not verdict.complete
    assert verdict.reasons == (GotoTargetIdentityReason8616.MISSING_TARGET,)


def test_absent_target_idx_stays_complete() -> None:
    """``target_idx=None`` is normal for non-switch gotos, never unproven."""
    codegen = _DummyCodegen()
    verdict = goto_target_identity_8616(CGoto(0x1234, None, codegen=codegen))

    assert verdict.complete
    assert verdict.reasons == ()
