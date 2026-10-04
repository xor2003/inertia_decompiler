"""Parent controls for closed counts and replay of mutable candidate operands."""

from dataclasses import replace

import test_x86_16_near_return_expression as fixture
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort


def test_refusal_never_claims_unmaterialized_classification():
    codegen, congruence, _ = fixture._congruence()
    result = fixture._build(codegen, congruence, src=fixture._selector(codegen, -1))
    assert not result.complete
    assert result.stats.classified_fact_count == result.stats.materialized_count == 0


def test_retained_selector_mutation_revokes_completeness():
    codegen, congruence, _ = fixture._congruence()
    result = fixture._build(codegen, congruence)
    assert result.complete
    result.source_selector.value = -1
    assert not result.complete


def test_boolean_evidence_count_is_not_integer_receipt():
    codegen, congruence, _ = fixture._congruence()
    result = fixture._build(codegen, congruence)
    assert result.complete
    assert not replace(result, stats=replace(result.stats, raw_fact_count=True)).complete


def test_outer_cast_does_not_prove_signed_multiply_defined():
    codegen, congruence, _ = fixture._congruence()
    product = structured_c.CBinaryOp("Mul",
        structured_c.CConstant(32767, SimTypeShort(True), codegen=codegen),
        structured_c.CConstant(32767, SimTypeShort(True), codegen=codegen), codegen=codegen)
    selector = structured_c.CTypeCast(None, SimTypeShort(False), product, codegen=codegen)
    assert not fixture._build(codegen, congruence, src=selector).complete


def test_mutated_scale_type_revokes_completeness():
    codegen, congruence, _ = fixture._congruence()
    result = fixture._build(codegen, congruence)
    assert result.complete
    product = result.expression.expr.args[3].expr
    product.rhs = structured_c.CConstant(product.rhs.value, SimTypeShort(True), codegen=codegen)
    assert not result.complete


def test_unsigned_short_multiply_can_overflow_host_promoted_int():
    codegen, congruence, _ = fixture._congruence()
    product = structured_c.CBinaryOp("Mul", fixture._selector(codegen, 65535),
        fixture._selector(codegen, 65535), codegen=codegen)
    selector = structured_c.CTypeCast(None, SimTypeShort(False), product, codegen=codegen)
    assert not fixture._build(codegen, congruence, src=selector).complete


def test_signed_word_negation_can_overflow_dos_int():
    codegen, congruence, _ = fixture._congruence()
    value = structured_c.CConstant(-32768, SimTypeShort(True), codegen=codegen)
    negated = structured_c.CUnaryOp("Neg", value, codegen=codegen)
    selector = structured_c.CTypeCast(None, SimTypeShort(False), negated, codegen=codegen)
    assert not fixture._build(codegen, congruence, src=selector).complete


def test_unsigned_char_left_shift_can_overflow_dos_promoted_int():
    codegen, congruence, _ = fixture._congruence()
    value = structured_c.CConstant(255, SimTypeChar(False), codegen=codegen)
    shifted = structured_c.CBinaryOp("Shl", value, fixture._selector(codegen, 15), codegen=codegen)
    selector = structured_c.CTypeCast(None, SimTypeShort(False), shifted, codegen=codegen)
    assert not fixture._build(codegen, congruence, src=selector).complete


def test_constant_metadata_does_not_prove_unsigned_c_literal_shift():
    """A small C integer literal may be signed int16 despite AST u16 metadata."""
    codegen, congruence, _ = fixture._congruence()
    value = fixture._selector(codegen, 255)
    shifted = structured_c.CBinaryOp("Shl", value, fixture._selector(codegen, 15), codegen=codegen)
    selector = structured_c.CTypeCast(None, SimTypeShort(False), shifted, codegen=codegen)
    assert not fixture._build(codegen, congruence, src=selector).complete


def test_explicit_unsigned_word_cast_proves_left_shift_promotion():
    """An actual u16 cast controls integer promotion on both supported targets."""
    codegen, congruence, _ = fixture._congruence()
    value = structured_c.CTypeCast(None, SimTypeShort(False), fixture._selector(codegen, 255), codegen=codegen)
    shifted = structured_c.CBinaryOp("Shl", value, fixture._selector(codegen, 15), codegen=codegen)
    selector = structured_c.CTypeCast(None, SimTypeShort(False), shifted, codegen=codegen)
    assert fixture._build(codegen, congruence, src=selector).complete


def test_constant_reference_substitution_revokes_selector_purity():
    """A substituted reference can render an expression rather than a literal."""
    codegen, congruence, _ = fixture._congruence()
    result = fixture._build(codegen, congruence)
    assert result.complete
    selector = result.source_selector
    selector.reference_values = {selector.value: structured_c.CFunctionCall("other", None, [], codegen=codegen)}
    assert not result.complete
    refused = fixture._build(codegen, congruence, src=selector)
    assert not refused.complete
    assert refused.stats.classified_fact_count == refused.stats.materialized_count == 0
