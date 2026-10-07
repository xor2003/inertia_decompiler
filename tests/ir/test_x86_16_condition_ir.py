from __future__ import annotations

"""Regression tests for Condition IR.

AGENTS rule: conditions must be explicit (x < y), never flag-based (if (tmp_*)).

Verifies:
  - cmp ax,bx + jl → SLT(ax,bx)
  - test ax,ax + jz → ZERO(ax)
  - Flag mask decoding produces typed conditions
  - JCC mnemonic mapping is correct
"""

import pytest

from inertia.ir.condition_ir import (
    ConditionIR,
    build_condition_from_cmp_8616,
    build_condition_from_test_8616,
    build_condition_ir_8616,
    canonicalize_condition_storage_fingerprint_8616,
    condition_compare_symbol_8616,
    inverted_comparison_op_8616,
    is_condition_compare_family_8616,
    is_condition_truth_test_8616,
    is_signed_condition_8616,
    is_unsigned_condition_8616,
    normalize_condition_fingerprint_algebraic_8616,
    normalize_condition_op_8616,
)
from inertia.ir.core import IRBinaryValue, IRValue, MemSpace
from inertia.semantics.condition_recovery import (
    ConditionConfidence,
    RecoveredCondition,
    build_typed_condition_from_cmp_pair_8616,
    classify_flag_mask_bit_8616,
)


class TestConditionIRConstruction:
    """IRCondition must encode typed operations, not flags."""

    def test_slt_condition(self):
        lhs = IRValue(MemSpace.REG, name="ax", offset=0, size=2)
        rhs = IRValue(MemSpace.REG, name="bx", offset=3, size=2)
        cond = build_condition_ir_8616("slt", lhs, rhs, expr=("cmp",))
        assert cond.op == "slt"
        assert cond.args[0].name == "ax"
        assert cond.args[1].name == "bx"

    def test_zero_condition(self):
        op = IRValue(MemSpace.REG, name="ax", offset=0, size=2)
        cond = build_condition_ir_8616("zero", op, expr=("test_self",))
        assert cond.op == "zero"
        assert len(cond.args) == 1
        assert cond.args[0].name == "ax"

    def test_nonzero_condition(self):
        op = IRValue(MemSpace.REG, name="cx", offset=1, size=2)
        cond = build_condition_ir_8616("nonzero", op, expr=("test_self",))
        assert cond.op == "nonzero"

    def test_cmp_width_preserves_word_view_of_wider_storage(self):
        storage = IRValue(
            MemSpace.SS,
            offset=-2,
            size=4,
            memory_access_size=2,
        )
        limit = IRValue(MemSpace.CONST, const=10, size=2)

        condition = build_condition_from_cmp_8616(
            storage,
            limit,
            "jbe",
            width_bits=16,
        )

        assert isinstance(condition, ConditionIR)
        assert condition.lhs.size == 4
        assert condition.lhs.memory_access_size == 2
        assert condition.rhs.size == 4

    def test_unsigned_lt_condition(self):
        lhs = IRValue(MemSpace.REG, name="ax", size=2)
        rhs = IRValue(MemSpace.CONST, const=10, size=2)
        cond = build_condition_ir_8616("ult", lhs, rhs)
        assert cond.op == "ult"
        assert cond.args[1].const == 10

    def test_idempotent_or_self_test_keeps_register_identity(self):
        operand = IRValue(MemSpace.REG, name="ax", offset=0, size=2)

        condition = build_condition_from_test_8616(
            IRBinaryValue("or", operand, operand, size=2),
            "je",
        )

        assert isinstance(condition, ConditionIR)
        assert condition.op == "zero"
        assert condition.lhs is operand


class TestConditionOpNormalization:
    """Condition ops must be normalized to canonical form."""

    def test_slt_is_normalized(self):
        assert normalize_condition_op_8616("slt") == "slt"

    def test_lt_normalizes_to_slt(self):
        assert normalize_condition_op_8616("lt") == "slt"

    def test_le_normalizes_to_sle(self):
        assert normalize_condition_op_8616("le") == "sle"

    def test_gt_normalizes_to_sgt(self):
        assert normalize_condition_op_8616("gt") == "sgt"

    def test_ge_normalizes_to_sge(self):
        assert normalize_condition_op_8616("ge") == "sge"

    def test_segmented_index_duplicate_displacement_normalizes(self):
        raw = (
            "CmpLE("
            "Dereference(Add(Mul(reg:ds,const:16),"
            "Add(Shl(stack_slot:SS:BP-0x6:size2,const:1),const:2892),"
            "const:2892)),"
            "stack_slot:SS:BP-0x4:size2)"
        )

        assert normalize_condition_fingerprint_algebraic_8616(raw) == (
            "CmpLE("
            "Dereference(Add(Mul(reg:ds,const:16),"
            "Shl(stack_slot:SS:BP-0x6:size2,const:1),"
            "const:2892)),"
            "stack_slot:SS:BP-0x4:size2)"
        )

    def test_add_value_and_its_negation_normalizes_to_zero(self):
        assert normalize_condition_fingerprint_algebraic_8616(
            "Add(reg:ax,Neg(reg:ax))"
        ) == "const:0"

    @pytest.mark.parametrize(
        ("raw", "expected"),
        (
            ("Add(reg:ax,Neg(reg:bx))", "Sub(reg:ax,reg:bx)"),
            ("Add(Neg(reg:bx),reg:ax)", "Sub(reg:ax,reg:bx)"),
            (
                "CmpEQ(Add(stack_slot:SS:BP+0x6:size2,"
                "Neg(stack_slot:SS:BP+0x4:size2)),const:1)",
                "CmpEQ(Sub(stack_slot:SS:BP+0x6:size2,"
                "stack_slot:SS:BP+0x4:size2),const:1)",
            ),
        ),
    )
    def test_add_negation_normalizes_to_subtraction(
        self,
        raw: str,
        expected: str,
    ) -> None:
        assert normalize_condition_fingerprint_algebraic_8616(raw) == expected

    def test_named_stack_argument_fingerprint_normalizes_to_exact_bp_slot(self):
        value = (
            "CmpGT(stack_slot:SS:BP-0x4:size2,"
            "stack_arg:iMaxLevel:size2:bp+0x4)"
        )

        assert canonicalize_condition_storage_fingerprint_8616(value) == (
            "CmpGT(stack_slot:SS:BP-0x4:size2,"
            "stack_slot:SS:BP+0x4:size2)"
        )

    @pytest.mark.parametrize(
        ("value", "expected"),
        (
            (
                "CmpGT(Dereference(Add(Mul(reg:ds,const:16),const:2978)),"
                "stack_slot:SS:BP-0x8:size2)",
                "CmpGT(ds_global:0xba2,stack_slot:SS:BP-0x8:size2)",
            ),
            (
                "CmpGT(global:0xba2,stack_slot:SS:BP-0x8:size2)",
                "CmpGT(ds_global:0xba2,stack_slot:SS:BP-0x8:size2)",
            ),
            (
                "CmpNE(Reference(global:0xba2),const:0)",
                "CmpNE(Reference(global:0xba2),const:0)",
            ),
        ),
    )
    def test_ds_condition_storage_normalizes_without_flattening_segment_space(
        self,
        value: str,
        expected: str,
    ) -> None:
        assert canonicalize_condition_storage_fingerprint_8616(value) == expected

    def test_lt_u_normalizes_to_ult(self):
        assert normalize_condition_op_8616("lt_u") == "ult"

    def test_masked_nonzero_normalizes_to_nonzero(self):
        assert normalize_condition_op_8616("masked_nonzero") == "nonzero"

    def test_masked_zero_normalizes_to_zero(self):
        assert normalize_condition_op_8616("masked_zero") == "zero"

    def test_unknown_op_falls_back_to_compare(self):
        assert normalize_condition_op_8616("garbage_op") == "compare"

    def test_and_or_not_pass_through(self):
        assert normalize_condition_op_8616("and") == "and"
        assert normalize_condition_op_8616("or") == "or"
        assert normalize_condition_op_8616("not") == "not"

    def test_condition_fingerprint_normalizes_ds_byte_pair_to_global_word(self):
        value = (
            "CmpLT(stack_slot:SS:BP-0x2:size2,"
            "Or(global:0x160,"
            "Shl(Dereference(Add(Add(Mul(reg:ds,const:16),const:352),const:1)),const:8)))"
        )

        assert normalize_condition_fingerprint_algebraic_8616(value) == "CmpLT(stack_slot:SS:BP-0x2:size2,global:0x160)"

    def test_condition_fingerprint_normalizes_prefixed_ds_byte_pair_to_global_word(self):
        value = (
            "if:CmpLT(stack_slot:SS:BP-0x2:size2,"
            "Or(global:0x160,"
            "Shl(Dereference(Add(Add(Mul(reg:ds,const:16),const:352),const:1)),const:8)))"
        )

        assert (
            normalize_condition_fingerprint_algebraic_8616(value) == "if:CmpLT(stack_slot:SS:BP-0x2:size2,global:0x160)"
        )


class TestConditionClassification:
    """Correct classification of truth-test vs. comparison conditions."""

    def test_zero_is_truth_test(self):
        assert is_condition_truth_test_8616("zero")

    def test_nonzero_is_truth_test(self):
        assert is_condition_truth_test_8616("nonzero")

    def test_eq_is_compare(self):
        assert is_condition_compare_family_8616("eq")
        assert not is_condition_truth_test_8616("eq")

    def test_slt_is_compare(self):
        assert is_condition_compare_family_8616("slt")

    def test_signed_vs_unsigned(self):
        assert is_signed_condition_8616("slt")
        assert not is_signed_condition_8616("ult")
        assert is_unsigned_condition_8616("ult")
        assert not is_unsigned_condition_8616("slt")


class TestCompareSymbols:
    """Compare ops must have correct C symbol mappings."""

    def test_eq_symbol(self):
        assert condition_compare_symbol_8616("eq") == "=="

    def test_ne_symbol(self):
        assert condition_compare_symbol_8616("ne") == "!="

    def test_slt_symbol(self):
        assert condition_compare_symbol_8616("slt") == "<"

    def test_sle_symbol(self):
        assert condition_compare_symbol_8616("sle") == "<="

    def test_sgt_symbol(self):
        assert condition_compare_symbol_8616("sgt") == ">"

    def test_sge_symbol(self):
        assert condition_compare_symbol_8616("sge") == ">="

    def test_unsigned_uses_same_symbols(self):
        assert condition_compare_symbol_8616("ult") == "<"
        assert condition_compare_symbol_8616("ugt") == ">"


class TestInvertedComparisonOp:
    """Inverted comparison ops must follow deterministic rules."""

    def test_cmpeq_inverts_to_cmpne(self):
        assert inverted_comparison_op_8616("CmpEQ") == "CmpNE"

    def test_cmpne_inverts_to_cmpeq(self):
        assert inverted_comparison_op_8616("CmpNE") == "CmpEQ"

    def test_cmplt_inverts_to_cmpge(self):
        assert inverted_comparison_op_8616("CmpLT") == "CmpGE"

    def test_cmpge_inverts_to_cmplt(self):
        assert inverted_comparison_op_8616("CmpGE") == "CmpLT"

    def test_unknown_op_returns_none(self):
        assert inverted_comparison_op_8616("Foobar") is None


class TestJccMnemonicMapping:
    """JCC mnemonics must map to correct typed conditions."""

    def _make_vex_reg(self, name: str, reg_offset: int):
        """Minimal mock for VEX register expression."""
        return type("VexReg", (), {"reg": reg_offset, "reg_name": name})()

    def _make_vex_const(self, value: int):
        """Minimal mock for VEX constant expression."""
        return type("VexConst", (), {"value": value})()

    def test_jz_maps_to_eq_with_jcc(self):
        lhs = self._make_vex_reg("ax", 0)
        rhs = self._make_vex_const(0)
        recovered = build_typed_condition_from_cmp_pair_8616(lhs, rhs, jcc_mnemonic="jz")
        assert recovered is not None
        assert recovered.condition.op == "eq"
        assert recovered.confidence == ConditionConfidence.PROVEN

    def test_jnz_maps_to_ne_with_jcc(self):
        lhs = self._make_vex_reg("ax", 0)
        rhs = self._make_vex_const(0)
        recovered = build_typed_condition_from_cmp_pair_8616(lhs, rhs, jcc_mnemonic="jnz")
        assert recovered is not None
        assert recovered.condition.op == "ne"

    def test_jl_maps_to_slt(self):
        lhs = self._make_vex_reg("ax", 0)
        rhs = self._make_vex_reg("bx", 3)
        recovered = build_typed_condition_from_cmp_pair_8616(lhs, rhs, jcc_mnemonic="jl")
        assert recovered is not None
        assert recovered.condition.op == "slt"

    def test_jg_maps_to_sgt(self):
        lhs = self._make_vex_reg("ax", 0)
        rhs = self._make_vex_reg("bx", 3)
        recovered = build_typed_condition_from_cmp_pair_8616(lhs, rhs, jcc_mnemonic="jg")
        assert recovered is not None
        assert recovered.condition.op == "sgt"

    def test_jb_maps_to_ult(self):
        lhs = self._make_vex_reg("ax", 0)
        rhs = self._make_vex_reg("bx", 3)
        recovered = build_typed_condition_from_cmp_pair_8616(lhs, rhs, jcc_mnemonic="jb")
        assert recovered is not None
        assert recovered.condition.op == "ult"

    def test_test_self_detected(self):
        """TEST AX,AX should be detected as self-test (nonzero)."""
        reg = self._make_vex_reg("ax", 0)
        recovered = build_typed_condition_from_cmp_pair_8616(reg, reg)
        assert recovered is not None
        assert recovered.condition.op == "nonzero"
        assert recovered.condition.expr == ("test_self",)


class TestFlagMaskDecoding:
    """Flag bitmask values must decode to correct flag names."""

    def test_zf_mask(self):
        flag, _ = classify_flag_mask_bit_8616(0x40)
        assert flag == "ZF"

    def test_cf_mask(self):
        flag, _ = classify_flag_mask_bit_8616(0x1)
        assert flag == "CF"

    def test_sf_mask(self):
        flag, _ = classify_flag_mask_bit_8616(0x80)
        assert flag == "SF"

    def test_of_mask(self):
        flag, _ = classify_flag_mask_bit_8616(0x800)
        assert flag == "OF"

    def test_unknown_mask(self):
        flag, _value = classify_flag_mask_bit_8616(0x4)
        assert flag is None


class TestRecoveredConditionProperties:
    """RecoveredCondition must carry confidence and operand metadata."""

    def test_proven_confidence_by_default(self):
        lhs = IRValue(MemSpace.REG, name="ax", size=2)
        rhs = IRValue(MemSpace.REG, name="bx", size=2)
        cond = build_condition_ir_8616("slt", lhs, rhs)
        recovered = RecoveredCondition(condition=cond)
        assert recovered.is_proven
        assert recovered.is_likely

    def test_guessed_confidence(self):
        lhs = IRValue(MemSpace.REG, name="ax", size=2)
        cond = build_condition_ir_8616("zero", lhs)
        recovered = RecoveredCondition(condition=cond, confidence=ConditionConfidence.GUESSED)
        assert not recovered.is_proven
        assert not recovered.is_likely
