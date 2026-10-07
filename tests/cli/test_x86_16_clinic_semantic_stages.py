from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from angr.analyses.decompiler.clinic import Clinic
from pytest import MonkeyPatch

from inertia.cli.runtime_support import guard_angr_clinic_stage_markers


@dataclass
class _ClinicStub:
    _ail_graph: object


@dataclass
class _ProjectStub:
    _inertia_skip_clinic_simplify_block: bool = True
    _inertia_skip_clinic_pre_ssa: bool = True
    _inertia_skip_clinic_post_ssa: bool = True
    _inertia_tiny_core_disable_peephole: bool = True
    _inertia_decompiler_stage: str = ""


def _record_stage(calls: list[str], name: str) -> Callable[..., object]:
    def stage(clinic: _ClinicStub, *_args: object, **_kwargs: object) -> object:
        calls.append(name)
        return clinic._ail_graph

    return stage


def test_clinic_cost_guards_do_not_skip_semantic_stages(monkeypatch: MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(Clinic, "_stage_pre_ssa_level1_simplifications", _record_stage(calls, "pre_ssa"))
    monkeypatch.setattr(Clinic, "_stage_transform_to_ssa_level1", _record_stage(calls, "ssa"))
    monkeypatch.setattr(Clinic, "_stage_post_ssa_level1_simplifications", _record_stage(calls, "post_ssa"))

    clinic = _ClinicStub(_ail_graph=object())
    with guard_angr_clinic_stage_markers(_ProjectStub()):
        Clinic._stage_pre_ssa_level1_simplifications(clinic)
        Clinic._stage_transform_to_ssa_level1(clinic)
        Clinic._stage_post_ssa_level1_simplifications(clinic)

    assert calls == ["pre_ssa", "ssa", "post_ssa"]
