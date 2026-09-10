"""Accepted argument groupings must reach the authoritative callsite inventory."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.callsite_summary import CallsiteArgumentClass8616, CallsiteSummary8616
from angr_platforms.X86_16.lowering.call_argument_shape import reconcile_materialized_call_argument_shape_8616
from angr_platforms.X86_16.lowering.call_argument_shape_publication import publish_reconciled_call_argument_shape_8616


def _summary() -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x1020, target_addr=0x2000, return_addr=0x1023, kind="near",
        arg_count=4, arg_widths=(2, 2, 2, 2), stack_cleanup=8,
        return_register=None, return_used=False,
        push_arg_sources=(("ret_reg", 0x1008, "dx"), ("ret_reg", 0x1008, "ax"),
                          ("imm", 0x16A), ("bp_addr", -18)),
        push_arg_instruction_addrs=(0x1010, 0x1011, 0x1014, 0x1018),
        stack_cleanup_instruction_addr=0x1023,
        logical_arg_widths=(2, 2, 2, 2),
        logical_arg_classes=(CallsiteArgumentClass8616.VALUE,) * 4,
    )


def test_accepted_wide_argument_replaces_stale_inventory_projection() -> None:
    inventory = _summary()
    result = reconcile_materialized_call_argument_shape_8616(inventory, (2, 2, 4))
    published = publish_reconciled_call_argument_shape_8616(inventory, result.summary, result)
    assert published.logical_arg_widths == (2, 2, 4)
    assert published.logical_arg_classes == ()
    assert published.arg_widths == inventory.arg_widths
    assert published.push_arg_sources == inventory.push_arg_sources
    assert published.push_arg_instruction_addrs == inventory.push_arg_instruction_addrs
    assert published.stack_cleanup == 8
    assert inventory.logical_arg_widths == (2, 2, 2, 2)
    assert publish_reconciled_call_argument_shape_8616(published, result.summary, result) is published


@pytest.mark.parametrize("field,value", [
    ("callsite_addr", 0x1021), ("target_addr", 0x3000), ("stack_cleanup", 6),
    ("push_arg_instruction_addrs", (0x1010, 0x1012, 0x1014, 0x1018)),
    ("push_arg_sources", (("imm", 0),) * 4),
])
def test_different_physical_call_refuses_publication(field: str, value: object) -> None:
    inventory = _summary()
    result = reconcile_materialized_call_argument_shape_8616(inventory, (2, 2, 4))
    different = replace(inventory, **{field: value})
    assert publish_reconciled_call_argument_shape_8616(different, result.summary, result) is different


def test_failed_reconciliation_cannot_replace_existing_shape() -> None:
    inventory = _summary()
    result = reconcile_materialized_call_argument_shape_8616(inventory, (2, 2, 4))
    failed = replace(result, failure_count=1, materialized_count=0)
    assert publish_reconciled_call_argument_shape_8616(inventory, result.summary, failed) is inventory


def test_modified_summary_cannot_borrow_another_reconciliation() -> None:
    inventory = _summary()
    result = reconcile_materialized_call_argument_shape_8616(inventory, (2, 2, 4))
    unproven = replace(result.summary, logical_arg_widths=(4, 4))
    assert publish_reconciled_call_argument_shape_8616(inventory, unproven, result) is inventory
