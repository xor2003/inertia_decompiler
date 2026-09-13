"""Exact displacements and refusal boundaries for physical call arguments."""

import pytest
from angr_platforms.X86_16.callsite_summary import CallsitePushExprOp8616
from angr_platforms.X86_16.semantics.call_stack_effect_contracts import CallStackEffectFailure8616
from angr_platforms.X86_16.semantics.call_stack_provenance import stack_address_offset_8616


@pytest.mark.parametrize("operation", ["add", CallsitePushExprOp8616.ADD])
def test_constant_displacements_preserve_exact_pointer_provenance(operation):
    source = ("expr", ("bp_addr", -8), ((operation, 4), ("sub", 2)))
    assert stack_address_offset_8616(source) == (-6, None)


@pytest.mark.parametrize("source", [
    None, (), ("unknown",), ("bp_addr",), ("bp_addr", "bad"),
    ("expr", ("imm", 0)), ("expr", "bad", ()),
    ("expr", ("imm", 0), []),
    ("expr", ("imm", 0), ((),)),
    ("expr", ("imm", 0), (("unknown",),)),
    ("expr", ("imm", 0), (("add", "bad"),)),
    ("expr", ("imm", 0), (("add_source", None),)),
    ("expr", ("imm", 0), (("add_source", ("unknown",)),)),
])
def test_malformed_sources_remain_incomplete(source):
    assert stack_address_offset_8616(source) == (
        None, CallStackEffectFailure8616.ARGUMENT_SOURCES_INCOMPLETE,
    )


@pytest.mark.parametrize("operation", ["add_source", "adc_source", "sub_source", "sbb_source"])
@pytest.mark.parametrize("base,nested", [(("bp_addr", -2), ("imm", 0)),
                                       (("imm", 0), ("bp_addr", -2))])
def test_composite_pointer_arithmetic_remains_escaped(operation, base, nested):
    assert stack_address_offset_8616(("expr", base, ((operation, nested),))) == (
        None, CallStackEffectFailure8616.POINTER_ARGUMENT_MAY_ESCAPE,
    )


@pytest.mark.parametrize("base,expected", [
    (("imm", 1), (None, None)),
    (("bp_addr", -2), (None, CallStackEffectFailure8616.POINTER_ARGUMENT_MAY_ESCAPE)),
])
def test_non_displacement_operation_does_not_invent_pointer_proof(base, expected):
    assert stack_address_offset_8616(("expr", base, (("neg",),))) == expected
