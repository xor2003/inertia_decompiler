"""Tests for typed frontend evidence in direct-callsite recovery."""

from __future__ import annotations

from types import SimpleNamespace

import inertia.lowering.analysis_helpers as analysis_helpers

from inertia.frontend.x86_16.frontend_function_instructions import (
    FunctionInstructionInventory8616,
    FunctionInstructionInventoryStatus8616,
)


def _inventory(
    instruction: object,
    *,
    status: FunctionInstructionInventoryStatus8616,
) -> FunctionInstructionInventory8616:
    """Build one closed frontend inventory for a focused test."""
    failure_count = int(status is not FunctionInstructionInventoryStatus8616.COMPLETE)
    return FunctionInstructionInventory8616(
        function_entry=0x100,
        block_addrs=(0x100,),
        instructions=(instruction,) if failure_count == 0 else (),
        status=status,
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=1 - failure_count,
        failure_count=failure_count,
    )


def _install_common_boundaries(monkeypatch, project: object) -> None:
    """Install dynamic angr boundary adapters unrelated to decode selection."""
    monkeypatch.setattr(
        analysis_helpers,
        "_x86_16_project_for_function_8616",
        lambda _function: project,
    )
    monkeypatch.setattr(
        analysis_helpers,
        "sanitize_direct_call_sites_8616",
        lambda _function: SimpleNamespace(pruned_count=0),
    )
    monkeypatch.setattr(
        analysis_helpers,
        "_resolve_direct_call_target_from_insn",
        lambda _project, _instruction: 0x200,
    )


def test_patch_direct_calls_uses_complete_frontend_inventory(monkeypatch) -> None:
    instruction = SimpleNamespace(mnemonic="call", address=0x110, size=3)
    project = SimpleNamespace()
    function = SimpleNamespace(addr=0x100, _call_sites={})
    _install_common_boundaries(monkeypatch, project)
    monkeypatch.setattr(
        analysis_helpers,
        "collect_function_instruction_inventory_8616",
        lambda *_args, **_kwargs: _inventory(
            instruction,
            status=FunctionInstructionInventoryStatus8616.COMPLETE,
        ),
    )
    monkeypatch.setattr(
        analysis_helpers,
        "_analysis_project_block_8616",
        lambda *_args: (_ for _ in ()).throw(AssertionError("block fallback used")),
    )

    changed = analysis_helpers.patch_direct_call_sites(function)

    assert changed is True
    assert function._call_sites == {0x110: (0x200, 0x113)}


def test_patch_direct_calls_retains_incomplete_inventory_fallback(monkeypatch) -> None:
    instruction = SimpleNamespace(mnemonic="call", address=0x110, size=3)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=(instruction,)))
    project = SimpleNamespace()
    function = SimpleNamespace(addr=0x100, block_addrs_set={0x100}, _call_sites={})
    _install_common_boundaries(monkeypatch, project)
    monkeypatch.setattr(
        analysis_helpers,
        "collect_function_instruction_inventory_8616",
        lambda *_args, **_kwargs: _inventory(
            instruction,
            status=FunctionInstructionInventoryStatus8616.DECODE_REFUSED,
        ),
    )
    monkeypatch.setattr(
        analysis_helpers,
        "_analysis_project_block_8616",
        lambda _project, _addr: block,
    )

    changed = analysis_helpers.patch_direct_call_sites(function)

    assert changed is True
    assert function._call_sites == {0x110: (0x200, 0x113)}
