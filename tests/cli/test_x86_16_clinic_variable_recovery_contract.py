from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.clinic import Clinic

from inertia.cli.cli_core import DirectClinicPolicy8616, _temporary_clinic_policy_8616
from inertia.cli.runtime_support import guard_angr_clinic_stage_markers


def test_bounded_resource_policy_keeps_variable_recovery_enabled() -> None:
    project = SimpleNamespace()

    with _temporary_clinic_policy_8616(project, DirectClinicPolicy8616.FAST_PEEPHOLE):
        assert "_inertia_skip_clinic_recover_variables_full" not in vars(project)
        assert "_inertia_recover_variables_seed_empty" not in vars(project)


def test_clinic_stage_guard_ignores_legacy_variable_recovery_skip_flag(monkeypatch) -> None:
    calls: list[object] = []

    def recover_variables(clinic: object) -> str:
        calls.append(clinic)
        return "recovered"

    monkeypatch.setattr(Clinic, "_stage_recover_variables", recover_variables)
    project = SimpleNamespace(
        _inertia_skip_clinic_recover_variables_full=True,
        _inertia_recover_variables_seed_empty=True,
    )
    clinic = SimpleNamespace()

    with guard_angr_clinic_stage_markers(project):
        assert Clinic._stage_recover_variables(clinic) == "recovered"

    assert calls == [clinic]
