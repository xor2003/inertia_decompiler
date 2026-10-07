from __future__ import annotations

from inertia.ir.condition_ir import build_condition_ir_8616
import inertia.semantics.flag_semantics as flag_semantics
import inertia.semantics.memory_semantics as memory_semantics


def test_x86_16_flag_semantics_exports_typed_condition_helpers() -> None:
    assert flag_semantics.__all__ == [
        "build_compare_condition_8616",
        "build_condition_ir_8616",
        "condition_compare_symbol_8616",
        "is_condition_compare_family_8616",
        "is_signed_condition_8616",
        "is_unsigned_condition_8616",
    ]
    assert flag_semantics.build_condition_ir_8616 is build_condition_ir_8616
    assert flag_semantics.is_signed_condition_8616("slt") is True
    assert flag_semantics.is_unsigned_condition_8616("ult") is True


def test_x86_16_memory_semantics_exports_effect_summaries() -> None:
    assert memory_semantics.__all__ == [
        "CallsiteSummary8616",
        "FunctionEffectSummary",
        "summarize_x86_16_callsite",
        "summarize_x86_16_function_effects",
    ]
    assert memory_semantics.CallsiteSummary8616.__name__ == "CallsiteSummary8616"
    assert memory_semantics.FunctionEffectSummary.__name__ == "FunctionEffectSummary"
