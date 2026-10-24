from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest

import inertia.cli.cli_core as cli_core
from inertia.cli.analysis_timeout import AnalysisTimeout
from inertia.cli.cli_core import (
    DirectClinicPolicy8616,
    _clinic_policy_needs_callsite_count_8616,
    _direct_addr_wall_clock_budget,
    _direct_clinic_policy_8616,
    _enforce_function_timeout_cap,
    _safe_function_callsite_count_8616,
    _validated_generated_c_acceptance_8616,
)


def test_direct_clinic_policy_keeps_non_x86_standard():
    assert (
        _direct_clinic_policy_8616(
            arch_name="AMD64",
            direct_addr_mode=True,
            block_count=80,
            byte_count=700,
            call_site_count=12,
        )
        is DirectClinicPolicy8616.STANDARD
    )


def test_direct_clinic_policy_keeps_whole_binary_standard():
    assert (
        _direct_clinic_policy_8616(
            arch_name="86_16",
            direct_addr_mode=False,
            block_count=80,
            byte_count=700,
            call_site_count=12,
        )
        is DirectClinicPolicy8616.STANDARD
    )


def test_direct_clinic_policy_uses_fast_peephole_for_large_x86_function():
    assert (
        _direct_clinic_policy_8616(
            arch_name="86_16",
            direct_addr_mode=True,
            block_count=32,
            byte_count=188,
            call_site_count=8,
        )
        is DirectClinicPolicy8616.FAST_PEEPHOLE
    )


def test_direct_clinic_policy_uses_fast_peephole_for_call_heavy_medium_x86_function():
    assert (
        _direct_clinic_policy_8616(
            arch_name="86_16",
            direct_addr_mode=True,
            block_count=15,
            byte_count=188,
            call_site_count=8,
        )
        is DirectClinicPolicy8616.FAST_PEEPHOLE
    )


def test_direct_clinic_policy_keeps_sparse_medium_x86_function_standard():
    assert (
        _direct_clinic_policy_8616(
            arch_name="86_16",
            direct_addr_mode=True,
            block_count=15,
            byte_count=188,
            call_site_count=2,
        )
        is DirectClinicPolicy8616.STANDARD
    )


def test_safe_function_callsite_count_handles_missing_or_failing_getter():
    assert _safe_function_callsite_count_8616(SimpleNamespace()) == 0

    def _raises():
        raise RuntimeError("boom")

    assert _safe_function_callsite_count_8616(SimpleNamespace(get_call_sites=_raises)) == 0
    assert _safe_function_callsite_count_8616(SimpleNamespace(get_call_sites=lambda: [1, 2, 3])) == 3


def test_safe_function_callsite_count_uses_neighbor_call_evidence(monkeypatch):
    monkeypatch.setattr(
        cli_core,
        "collect_neighbor_call_targets",
        lambda _func: tuple(range(7)),
    )

    assert _safe_function_callsite_count_8616(SimpleNamespace(get_call_sites=lambda: ())) == 7


def test_clinic_policy_skips_callsite_count_when_large_shape_already_decides_guard():
    assert (
        _clinic_policy_needs_callsite_count_8616(
            arch_name="86_16",
            direct_addr_mode=True,
            block_count=32,
            byte_count=188,
        )
        is False
    )
    assert (
        _clinic_policy_needs_callsite_count_8616(
            arch_name="86_16",
            direct_addr_mode=True,
            block_count=15,
            byte_count=188,
        )
        is True
    )


def test_function_timeout_cap_keeps_default_cap_without_explicit_timeout(monkeypatch):
    monkeypatch.delenv("INERTIA_MAX_FUNCTION_TIMEOUT", raising=False)

    assert _enforce_function_timeout_cap(240, context="test") == cli_core._DEFAULT_FUNCTION_TIMEOUT_CAP


def test_function_timeout_cap_respects_explicit_cli_floor(monkeypatch):
    monkeypatch.delenv("INERTIA_MAX_FUNCTION_TIMEOUT", raising=False)

    assert _enforce_function_timeout_cap(272, context="test", explicit_timeout_floor=240) == 240


def test_function_timeout_cap_respects_explicit_env_cap(monkeypatch):
    monkeypatch.setenv("INERTIA_MAX_FUNCTION_TIMEOUT", "90")

    assert _enforce_function_timeout_cap(272, context="test", explicit_timeout_floor=240) == 90


def test_direct_addr_wall_clock_budget_respects_explicit_cli_timeout(monkeypatch):
    monkeypatch.delenv("INERTIA_MAX_FUNCTION_TIMEOUT", raising=False)

    budget = _direct_addr_wall_clock_budget(240, explicit_timeout=True)

    assert 240 < budget <= 248


def test_direct_addr_wall_clock_budget_adds_wrapper_overhead_for_explicit_timeout(monkeypatch):
    monkeypatch.delenv("INERTIA_MAX_FUNCTION_TIMEOUT", raising=False)

    budget = _direct_addr_wall_clock_budget(60, explicit_timeout=True)

    assert 60 < budget <= 68


def test_direct_addr_wall_clock_budget_ignores_shape_expansion_for_explicit_timeout(monkeypatch):
    monkeypatch.delenv("INERTIA_MAX_FUNCTION_TIMEOUT", raising=False)

    raw_budget = _direct_addr_wall_clock_budget(12, explicit_timeout=True)
    shaped_budget = _direct_addr_wall_clock_budget(12, effective_timeout=24, explicit_timeout=True)

    assert shaped_budget == raw_budget
    assert shaped_budget <= 20


def test_direct_addr_wall_clock_budget_respects_explicit_env_cap(monkeypatch):
    monkeypatch.setenv("INERTIA_MAX_FUNCTION_TIMEOUT", "62")

    assert _direct_addr_wall_clock_budget(60, explicit_timeout=True) == 62


def test_acceptance_uses_validation_snapshot_not_source_call_order(monkeypatch):
    payload = """
void menu(int key)
{
    if (key == 'B') {
        Reset();
        SortB();
        Done();
    } else if (key == 'A') {
        Reset();
        SortA();
        Done();
    }
}
"""
    snapshot = {
        "structuring": {"status": "stable", "changed": False, "mode": "live_out"},
        "postprocess": {"status": "stable", "changed": False, "mode": "live_out"},
    }

    monkeypatch.setattr(
        cli_core,
        "_collect_recompilation_payloads_8616",
        lambda accepted_payload: ([("portable-flat", accepted_payload)], None),
    )

    result = _validated_generated_c_acceptance_8616(
        status="ok",
        payload=payload,
        tail_validation_snapshot=snapshot,
        tail_validation_enabled=True,
        expected_validation_stages=("structuring", "postprocess"),
        emit_failure_diagnostics=False,
    )

    assert result.status == "ok"
    assert result.blocker is None


def _direct_probe_state(timeout: int) -> SimpleNamespace:
    """Build a receiver namespace for the optional sidecar re-recovery seam."""
    return SimpleNamespace(
        precise_sidecar_regions=True,
        lst_metadata=SimpleNamespace(absolute_addrs=True),
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16"), entry=0x10000),
        direct_addr=0x12340,
        cfg=SimpleNamespace(name="original_cfg"),
        func=SimpleNamespace(name="original_func"),
        args=SimpleNamespace(timeout=timeout, window=128),
        low_memory_path=False,
    )


@pytest.mark.parametrize(("cli_timeout", "probe_timeout"), [(2, 2), (30, 6)])
def test_optional_sidecar_probe_expiry_keeps_original_function(
    monkeypatch: pytest.MonkeyPatch, cli_timeout: int, probe_timeout: int
) -> None:
    """AnalysisTimeout in the optional re-recovery keeps the original CFG/func."""
    state = _direct_probe_state(cli_timeout)
    seen: dict[str, object] = {}
    marked: list[tuple[object, object]] = []

    def fake_recover(*args: object, **kwargs: object) -> tuple[object, object]:
        seen["timeout"] = kwargs["timeout"]
        seen["window"] = kwargs["window"]
        raise AnalysisTimeout

    monkeypatch.setattr(cli_core, "_lst_code_region", lambda metadata, addr: (0x12340, 0x12380))
    monkeypatch.setattr(cli_core, "_function_complexity", lambda func: (2, 16))
    monkeypatch.setattr(cli_core, "_lst_code_label", lambda metadata, addr, entry: "add_sc")
    monkeypatch.setattr(cli_core, "_recover_lst_function", fake_recover)
    monkeypatch.setattr(cli_core, "mark_function_original_addr", lambda func, addr: marked.append((func, addr)))

    original_cfg, original_func = state.cfg, state.func
    result = cli_core._DirectAddrCliRun8616._phase_direct_probe_setup_8616(
        cast(cli_core._DirectAddrCliRun8616, state)
    )

    assert result is None
    assert state.cfg is original_cfg
    assert state.func is original_func
    assert seen["timeout"] == probe_timeout
    assert seen["window"] == state.args.window
    assert marked == []


def test_optional_sidecar_probe_unexpected_error_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected defects in the optional re-recovery are not swallowed."""
    state = _direct_probe_state(30)
    cause = ValueError("stub metadata")
    failure = RuntimeError("sidecar decode failed")
    failure.__cause__ = cause

    def fake_recover(*args: object, **kwargs: object) -> tuple[object, object]:
        raise failure

    monkeypatch.setattr(cli_core, "_lst_code_region", lambda metadata, addr: (0x12340, 0x12380))
    monkeypatch.setattr(cli_core, "_function_complexity", lambda func: (2, 16))
    monkeypatch.setattr(cli_core, "_lst_code_label", lambda metadata, addr, entry: "add_sc")
    monkeypatch.setattr(cli_core, "_recover_lst_function", fake_recover)

    original_cfg, original_func = state.cfg, state.func
    with pytest.raises(RuntimeError) as excinfo:
        cli_core._DirectAddrCliRun8616._phase_direct_probe_setup_8616(
            cast(cli_core._DirectAddrCliRun8616, state)
        )

    assert excinfo.value is failure
    assert excinfo.value.__cause__ is cause
    assert state.cfg is original_cfg
    assert state.func is original_func


def test_optional_sidecar_probe_refinement_still_applies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A successful optional re-recovery still refines CFG/func and marks origin."""
    state = _direct_probe_state(30)
    new_cfg = SimpleNamespace(name="refined_cfg")
    new_func = SimpleNamespace(name="refined_func")
    marked: list[tuple[object, object]] = []

    monkeypatch.setattr(cli_core, "_lst_code_region", lambda metadata, addr: (0x12340, 0x12380))
    monkeypatch.setattr(cli_core, "_function_complexity", lambda func: (2, 16))
    monkeypatch.setattr(cli_core, "_lst_code_label", lambda metadata, addr, entry: "add_sc")
    monkeypatch.setattr(cli_core, "_recover_lst_function", lambda *args, **kwargs: (new_cfg, new_func))
    monkeypatch.setattr(cli_core, "mark_function_original_addr", lambda func, addr: marked.append((func, addr)))

    result = cli_core._DirectAddrCliRun8616._phase_direct_probe_setup_8616(
        cast(cli_core._DirectAddrCliRun8616, state)
    )

    assert result is None
    assert state.cfg is new_cfg
    assert state.func is new_func
    assert marked == [(new_func, 0x12340)]
