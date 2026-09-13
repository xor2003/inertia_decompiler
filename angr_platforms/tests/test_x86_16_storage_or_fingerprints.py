"""Idempotent storage OR projections preserve exact location distinctions."""

import pytest
from angr_platforms.X86_16.ir.condition_ir import canonicalize_condition_storage_fingerprint_8616 as normalize


@pytest.mark.parametrize("storage", ["stack_slot:SS:BP+0x4:size2", "ds_global:0x160"])
def test_repeated_stable_storage_or_has_scalar_identity(storage):
    assert normalize(f"Or({storage},{storage})") == storage
    assert normalize(f"Or(Or({storage},{storage}),{storage})") == storage
    assert normalize(normalize(f"Or({storage},{storage})")) == storage


@pytest.mark.parametrize("other", [
    "stack_slot:SS:BP+0x6:size2", "stack_slot:SS:BP+0x4:size1", "stack_slot:DS:BP+0x4:size2",
])
def test_distinct_storage_or_is_not_collapsed(other):
    value = f"Or(stack_slot:SS:BP+0x4:size2,{other})"
    assert normalize(value) == value


def test_call_fingerprint_is_not_promoted_to_scalar_storage_identity():
    assert normalize("Or(call:0x4000,call:0x4000)") != "call:0x4000"
