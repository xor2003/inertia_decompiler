"""Focused tests for typed external tail-call inventory.

Layer: postprocess evidence consumption
Responsibility: preserve every frontend-proven callsite in validation inventory.
"""

from types import SimpleNamespace

import pytest
import inertia.lowering.analysis_helpers as analysis_helpers
import inertia.postprocess.decompiler_postprocess_calls as calls


def test_all_function_callsites_include_frontend_proven_tail_call(monkeypatch) -> None:
    """Count an external tail jump separately from an ordinary machine call."""
    function = SimpleNamespace(get_call_sites=lambda: (0x1001,))
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    monkeypatch.setattr(
        calls,
        "collect_neighbor_call_targets",
        lambda _function: (
            SimpleNamespace(callsite_addr=0x1001),
            SimpleNamespace(callsite_addr=0x1010),
        ),
    )

    assert calls._all_function_callsite_addrs_8616(project, function) == (0x1001, 0x1010)


def test_tail_jump_target_requires_sidecar_function_entry_evidence() -> None:
    """Do not misclassify an IDA function chunk as a separate tail-called function."""
    project = SimpleNamespace(
        _inertia_lst_metadata=SimpleNamespace(function_entry_addrs=frozenset({0x103CA, 0x14590})),
    )

    assert analysis_helpers._tail_jump_target_is_function_entry_8616(project, 0x103CA) is True
    assert analysis_helpers._tail_jump_target_is_function_entry_8616(project, 0x14590) is True
    assert analysis_helpers._tail_jump_target_is_function_entry_8616(project, 0x10E35) is False


@pytest.mark.parametrize("tail_kind", [
    analysis_helpers.CallTargetKind8616.DIRECT_NEAR_TAIL_JUMP,
    analysis_helpers.CallTargetKind8616.DIRECT_FAR_TAIL_JUMP,
    analysis_helpers.CallTargetKind8616.STORED_NEAR_TAIL_JUMP,
])
@pytest.mark.parametrize("proven_entry", [True, False])
def test_neighbor_inventory_preserves_tail_kind_after_cfg_patching(monkeypatch, tail_kind, proven_entry) -> None:
    """Keep decoded tail origin when CFG exposes the jump as a callsite."""
    project = SimpleNamespace()
    function = SimpleNamespace(addr=0x1000, block_addrs_set=(0x1010,))
    monkeypatch.setattr(analysis_helpers, "_x86_16_project_for_function_8616", lambda _function: project)
    monkeypatch.setattr(analysis_helpers, "patch_direct_call_sites", lambda _function: False)
    monkeypatch.setattr(analysis_helpers, "_neighbor_image_bounds", lambda _project: (0x1000, 0x9000))
    monkeypatch.setattr(analysis_helpers, "_analysis_function_call_sites_8616", lambda _function: (0x1010,))
    monkeypatch.setattr(
        analysis_helpers,
        "_analysis_function_call_target_8616",
        lambda _function, _callsite: 0x5000,
    )
    monkeypatch.setattr(analysis_helpers, "resolve_direct_call_target_from_block", lambda *_args: None)
    monkeypatch.setattr(analysis_helpers, "_direct_call_target_kind_8616", lambda *_args: None)
    monkeypatch.setattr(
        analysis_helpers,
        "resolve_direct_jump_target_from_block",
        lambda *_args: None if tail_kind is analysis_helpers.CallTargetKind8616.STORED_NEAR_TAIL_JUMP else 0x5000,
    )
    monkeypatch.setattr(
        analysis_helpers,
        "resolve_stored_near_jump_target_from_function",
        lambda *_args: 0x5000,
    )
    monkeypatch.setattr(
        analysis_helpers,
        "_direct_tail_jump_kind_8616",
        lambda *_args: tail_kind,
    )
    monkeypatch.setattr(
        analysis_helpers,
        "_tail_jump_target_is_function_entry_8616",
        lambda _project, target: proven_entry and target == 0x5000,
    )
    monkeypatch.setattr(analysis_helpers, "_analysis_function_call_return_8616", lambda *_args: 0x1013)

    targets = analysis_helpers.collect_neighbor_call_targets(function)

    assert len(targets) == 1
    assert targets[0].callsite_addr == 0x1010
    assert targets[0].target_addr == 0x5000
    expected_kind = tail_kind if proven_entry else analysis_helpers.CallTargetKind8616.CFG_RESOLVED_CALL
    assert targets[0].kind is expected_kind
    assert targets[0].return_addr == (None if proven_entry else 0x1013)


def test_tail_seed_projects_to_owned_callsite_summary() -> None:
    """Give later consumers typed evidence for a decoded external tail jump."""
    seed = analysis_helpers.CallTargetSeed(
        callsite_addr=0x103C6,
        target_addr=0x14590,
        return_addr=None,
        kind=analysis_helpers.CallTargetKind8616.DIRECT_NEAR_TAIL_JUMP,
    )

    summary = calls._tail_call_summary_from_seed_8616(seed)

    assert summary is not None
    assert summary.callsite_addr == seed.callsite_addr
    assert summary.target_addr == seed.target_addr
    assert summary.kind == seed.kind.value
    assert summary.arg_count == 0
    assert summary.return_used is False
