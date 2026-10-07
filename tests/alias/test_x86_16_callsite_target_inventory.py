from __future__ import annotations

from types import SimpleNamespace

import inertia.semantics.callsite_summary as callsite_summary_module
import inertia.semantics.callsite_target_inventory as target_inventory_module
from inertia.semantics.callsite_summary import CallsiteSummary8616, build_callsite_summary_inventory_8616
from inertia.semantics.callsite_target_inventory import CallsiteTargetInventory8616

from inertia.lowering.analysis_helpers import CallTargetKind8616, CallTargetSeed


def test_summary_inventory_collects_call_targets_once(monkeypatch) -> None:
    function = SimpleNamespace()
    seeds = (
        CallTargetSeed(0x4010, 0x5000, 0x4013, CallTargetKind8616.DIRECT_NEAR_CALL),
        CallTargetSeed(0x4020, 0x6000, 0x4023, CallTargetKind8616.DIRECT_NEAR_CALL),
    )
    collect_calls: list[object] = []
    observed_inventories: list[object] = []

    def _collect_targets(candidate: object) -> list[CallTargetSeed]:
        collect_calls.append(candidate)
        return list(seeds)

    def _summarize(
        _function: object,
        callsite_addr: int,
        *,
        target_inventory: CallsiteTargetInventory8616,
    ) -> CallsiteSummary8616:
        observed_inventories.append(target_inventory)
        seed = target_inventory.seed_for_callsite(callsite_addr)
        assert seed is not None
        return CallsiteSummary8616(
            callsite_addr,
            seed.target_addr,
            seed.return_addr,
            seed.kind.value,
            0,
            (),
            0,
            None,
            False,
        )

    monkeypatch.setattr(target_inventory_module, "collect_neighbor_call_targets", _collect_targets)
    monkeypatch.setattr(callsite_summary_module, "summarize_x86_16_callsite", _summarize)

    summaries = build_callsite_summary_inventory_8616(function, (0x4020, 0x4010))

    assert collect_calls == [function]
    assert list(summaries) == [0x4010, 0x4020]
    assert len({id(inventory) for inventory in observed_inventories}) == 1


def test_inventory_recovers_direct_target_without_cfg_seed(monkeypatch) -> None:
    instruction = SimpleNamespace(address=0x4010, mnemonic="call", size=3)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(instruction,)))
    project = SimpleNamespace(factory=SimpleNamespace(block=lambda _addr, **_kwargs: block))
    function = SimpleNamespace(project=project)

    monkeypatch.setattr(target_inventory_module, "collect_neighbor_call_targets", lambda _function: ())
    monkeypatch.setattr(
        target_inventory_module,
        "resolve_direct_call_target_from_block",
        lambda _project, _callsite_addr: 0x5000,
    )

    inventory = CallsiteTargetInventory8616.collect(function, (0x4010,))

    assert inventory.seeds == (
        CallTargetSeed(
            0x4010,
            0x5000,
            0x4013,
            CallTargetKind8616.DIRECT_NEAR_CALL,
        ),
    )
