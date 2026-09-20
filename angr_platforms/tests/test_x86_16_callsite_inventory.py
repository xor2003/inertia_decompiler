"""Keep shared call-summary publication independent of cleanup ordering."""

from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.lowering import callsite_inventory
from test_x86_16_call_stack_effects import _summary


def test_existing_inventory_is_reused_without_native_lookup():
    summary = _summary()
    inventory = {summary.callsite_addr: summary}
    codegen = SimpleNamespace(_inertia_callsite_summary_inventory_8616=inventory)

    assert callsite_inventory.ensure_callsite_summary_inventory_8616(codegen) is inventory


@pytest.mark.parametrize("published", [None, [], {1: object()}])
def test_malformed_owned_inventory_is_not_silently_replaced(published):
    codegen = SimpleNamespace(_inertia_callsite_summary_inventory_8616=published)

    with pytest.raises(TypeError):
        callsite_inventory.ensure_callsite_summary_inventory_8616(codegen)


@pytest.mark.parametrize("function", [None, SimpleNamespace(), SimpleNamespace(get_call_sites=lambda: None)])
def test_missing_native_evidence_remains_unknown(function):
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000), project=SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **kwargs: function)),
    ))

    assert callsite_inventory.ensure_callsite_summary_inventory_8616(codegen) == {}


def test_empty_inventory_can_be_populated_after_native_discovery(monkeypatch):
    summary = _summary()
    sites = []
    function = SimpleNamespace(get_call_sites=lambda: tuple(sites))
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000), project=SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda **kwargs: function)),
    ))
    observed = []

    def build(owner, addresses):
        assert owner is function
        observed.append(addresses)
        return {summary.callsite_addr: summary} if addresses else {}

    monkeypatch.setattr(callsite_inventory, "build_callsite_summary_inventory_8616", build)
    assert callsite_inventory.ensure_callsite_summary_inventory_8616(codegen) == {}
    sites.append(summary.callsite_addr)
    result = callsite_inventory.ensure_callsite_summary_inventory_8616(codegen)
    assert result == {summary.callsite_addr: summary}
    assert codegen._inertia_callsite_summary_inventory_8616 is result
    assert observed == [(), (summary.callsite_addr,)]
