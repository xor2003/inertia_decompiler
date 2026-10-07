from __future__ import annotations

from types import SimpleNamespace

from inertia.postprocess.callsite_stack_metadata import _typed_callsite_summary_map_8616
from inertia.semantics.callsite_summary import CallsiteSummary8616


def test_callsite_stack_metadata_uses_typed_callsite_summary_fields() -> None:
    summary = CallsiteSummary8616(
        callsite_addr=0x1000,
        target_addr=0x2000,
        return_addr=0x1003,
        kind="near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=None,
        return_register="ax",
        return_used=True,
        stack_probe_helper=True,
        helper_return_state="stack_address",
        helper_return_space="ss",
        helper_return_width=2,
        helper_return_address_kind="stack",
    )
    codegen = SimpleNamespace(
        _inertia_callsite_summaries={
            1: object(),
            "bad": summary,
            2: summary,
        }
    )

    assert _typed_callsite_summary_map_8616(codegen) == {2: summary}
