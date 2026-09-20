from __future__ import annotations

"""Regressions for width-proven identity masks in Condition IR."""

from unittest.mock import MagicMock

import pytest
from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CVariable
from angr.sim_type import SimTypeInt
from angr.sim_variable import SimVariable
from angr_platforms.X86_16.ir.condition_fingerprint_masks import (
    normalize_condition_full_width_masks_8616,
)
from angr_platforms.X86_16.ir.condition_ir import normalize_condition_fingerprint_algebraic_8616
from angr_platforms.X86_16.ir.ir_canonicalize_8616 import canonicalize_expr_8616


@pytest.mark.parametrize("bits,mask", [(8, 255), (16, 65535)])
@pytest.mark.parametrize("signed", ["true", "false"])
def test_integer_narrowing_cast_absorbs_exact_destination_mask(bits, mask, signed):
    conversion = f"SimTypeLong:bits=32:signed=false->SimTypeShort:bits={bits}:signed={signed}"
    before = f"SemanticCast({conversion},And(memory:unknown-width,const:{mask}))"
    expected = f"SemanticCast({conversion},memory:unknown-width)"
    assert normalize_condition_fingerprint_algebraic_8616(before) == expected


@pytest.mark.parametrize(
    "conversion,mask,operator",
    [
        ("SimTypeShort:bits=16:signed=false->SimTypeChar:bits=8:signed=true", 127, "And"),
        ("SimTypeShort:bits=16:signed=false->SimTypeLong:bits=32:signed=true", 255, "And"),
        ("SimTypeFloat:bits=32:signed=false->SimTypeChar:bits=8:signed=true", 255, "And"),
        ("unknown->SimTypeChar:bits=8:signed=true", 255, "And"),
        ("SimTypeShort:bits=16:signed=false->SimTypeChar:bits=8:signed=true", 255, "Or"),
    ],
)
def test_cast_mask_normalization_refuses_unproven_conversion(conversion, mask, operator):
    value = f"SemanticCast({conversion},{operator}(memory:unknown-width,const:{mask}))"
    assert normalize_condition_fingerprint_algebraic_8616(value) == value


@pytest.mark.parametrize(
    ("raw", "expected"),
    (
        (
            "CmpNE(And(stack_slot:SS:BP-0xc:size2,const:65535),const:0)",
            "CmpNE(stack_slot:SS:BP-0xc:size2,const:0)",
        ),
        (
            "if:CmpEQ(And(const:0xffff,stack_arg:value:size2:bp+0x4),const:0)",
            "if:CmpEQ(stack_arg:value:size2:bp+0x4,const:0)",
        ),
        (
            "CmpNE(And(stack_slot:SS:BP-0xc:size2,const:255),const:0)",
            "CmpNE(And(stack_slot:SS:BP-0xc:size2,const:255),const:0)",
        ),
        (
            "CmpNE(And(stack_slot:SS:BP-0xc:size4,const:65535),const:0)",
            "CmpNE(And(stack_slot:SS:BP-0xc:size4,const:65535),const:0)",
        ),
        (
            "CmpNE(And(stack_slot:SS:BP-0xc:size4,const:0xffffffff),const:0)",
            "CmpNE(stack_slot:SS:BP-0xc:size4,const:0)",
        ),
        (
            "CmpNE(And(stack_slot:SS:BP-0xc,const:65535),const:0)",
            "CmpNE(And(stack_slot:SS:BP-0xc,const:65535),const:0)",
        ),
    ),
)
def test_condition_mask_normalization_requires_exact_width(raw: str, expected: str) -> None:
    assert normalize_condition_full_width_masks_8616(raw) == expected
    assert normalize_condition_fingerprint_algebraic_8616(raw) == expected


def _variable(size: int) -> CVariable:
    codegen = MagicMock()
    codegen.next_idx.return_value = 0
    return CVariable(SimVariable(size, None, f"value_{size}", None, None), codegen=codegen)


def _masked(variable: CVariable, mask: int) -> CBinaryOp:
    codegen = variable.codegen
    constant = CConstant(mask, SimTypeInt(signed=False), codegen=codegen)
    return CBinaryOp("And", variable, constant, codegen=codegen)


def test_local_value_canonicalizer_removes_proven_word_identity_mask() -> None:
    variable = _variable(2)

    assert canonicalize_expr_8616(_masked(variable, 0xFFFF)) is variable


def test_local_value_canonicalizer_keeps_partial_dword_mask() -> None:
    variable = _variable(4)

    assert isinstance(canonicalize_expr_8616(_masked(variable, 0xFFFF)), CBinaryOp)


def test_local_value_canonicalizer_removes_proven_dword_identity_mask() -> None:
    variable = _variable(4)

    assert canonicalize_expr_8616(_masked(variable, 0xFFFFFFFF)) is variable


@pytest.mark.parametrize("inner", ["And(load,const:255)", "And(const:0xff,load)"])
@pytest.mark.parametrize("mask_first", [False, True])
def test_repeated_exact_mask_preserves_inner_narrowing(inner, mask_first):
    args = f"const:255,{inner}" if mask_first else f"{inner},const:255"
    raw = f"CmpLE(Xor(And({args}),const:128),rhs)"
    expected = f"CmpLE(Xor({inner},const:128),rhs)"
    assert normalize_condition_full_width_masks_8616(raw) == expected
    assert normalize_condition_fingerprint_algebraic_8616(raw) == expected


@pytest.mark.parametrize("operand", [
    "And(load,const:15)",
    "Or(load,const:255)",
    "SemanticCast(unsigned->signed,And(load,const:255))",
    "And(load,const:unknown)",
])
def test_mask_identity_refuses_different_mask_or_intervening_operation(operand):
    raw = f"And({operand},const:255)"
    assert normalize_condition_full_width_masks_8616(raw) == raw
