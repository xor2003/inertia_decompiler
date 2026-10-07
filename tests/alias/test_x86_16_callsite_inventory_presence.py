from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
import inertia.postprocess.decompiler_postprocess_calls as calls
from inertia.semantics.callsite_summary import CallsiteSummary8616


def _codegen() -> SimpleNamespace:
    return SimpleNamespace(
        next_ident=lambda name: name,
        next_node_idx=lambda: 1,
    )


def test_attached_summary_satisfies_inventory_despite_rebased_callee_name(monkeypatch) -> None:
    """Presence follows exact typed callsite identity, not a rendered callee name."""
    codegen = _codegen()
    call = CFunctionCall("sub_794", None, [], codegen=codegen)
    summary = CallsiteSummary8616(
        callsite_addr=0x4012,
        target_addr=0x5000,
        return_addr=0x4015,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register=None,
        return_used=False,
    )
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}
    codegen._inertia_callsite_summaries = {id(call): summary}
    monkeypatch.setattr(calls, "_iter_c_nodes_deep_8616", lambda _root: iter((call,)))
    monkeypatch.setattr(
        calls,
        "_lookup_callee_function_8616",
        lambda *_args, **_kwargs: SimpleNamespace(name="sub_5000"),
    )

    missing, summaries_by_name = calls._missing_calls_from_owned_inventory_8616(
        SimpleNamespace(),
        codegen,
        SimpleNamespace(),
    )

    assert missing == []
    assert summaries_by_name == {}


def test_stale_attached_summary_does_not_satisfy_live_inventory(monkeypatch) -> None:
    """A detached node identity cannot hide a missing binary call."""
    codegen = _codegen()
    live_call = CFunctionCall("sub_794", None, [], codegen=codegen)
    stale_call = CFunctionCall("sub_794", None, [], codegen=codegen)
    summary = CallsiteSummary8616(
        callsite_addr=0x4012,
        target_addr=0x5000,
        return_addr=0x4015,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=0,
        return_register=None,
        return_used=False,
    )
    codegen._inertia_callsite_summary_inventory_8616 = {summary.callsite_addr: summary}
    codegen._inertia_callsite_summaries = {id(stale_call): summary}
    monkeypatch.setattr(calls, "_iter_c_nodes_deep_8616", lambda _root: iter((live_call,)))
    monkeypatch.setattr(
        calls,
        "_lookup_callee_function_8616",
        lambda *_args, **_kwargs: SimpleNamespace(name="sub_5000"),
    )

    missing, summaries_by_name = calls._missing_calls_from_owned_inventory_8616(
        SimpleNamespace(),
        codegen,
        SimpleNamespace(),
    )

    assert missing == ["sub_5000"]
    assert summaries_by_name == {"sub_5000": [summary]}
