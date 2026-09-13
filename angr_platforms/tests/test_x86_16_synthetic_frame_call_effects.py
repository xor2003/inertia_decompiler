"""Check the MS C synthetic ABI without treating real callees as placeholders."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.semantics.call_register_effects import (
    SyntheticCallRegisterEffectVerdict8616 as Verdict,
)
from angr_platforms.X86_16.semantics.call_register_effects import (
    classify_synthetic_call_register_effect_8616,
)
from angr_platforms.X86_16.semantics.call_stack_effects import materialize_call_stack_effects_8616
from angr_platforms.X86_16.synthetic_call_stub_evidence import record_synthetic_call_stubs_8616
from test_x86_16_call_stack_effects import _artifact, _summary

from inertia_decompiler.project_loading import _build_project_from_bytes


@pytest.fixture
def project():
    result = _build_project_from_bytes(b"\xc3", base_addr=0x1000, entry_point=0x1000)
    record_synthetic_call_stubs_8616(result, frozenset({0x2000}))
    return result


@pytest.mark.parametrize("register,verdict", [
    ("bp", Verdict.PRESERVED), ("BP", Verdict.PRESERVED),
    ("si", Verdict.PRESERVED), ("di", Verdict.PRESERVED),
    ("bx", Verdict.CLOBBERED), ("ax", Verdict.CLOBBERED),
    ("cx", Verdict.CLOBBERED), ("dx", Verdict.CLOBBERED),
    ("ebp", Verdict.UNKNOWN_REFUSE), ("sp", Verdict.UNKNOWN_REFUSE),
])
def test_synthetic_msc_word_register_contract(project, register, verdict):
    result = classify_synthetic_call_register_effect_8616(
        project, callsite_addr=0x1003, target_addr=0x2000, register=register,
    )

    assert result.verdict is verdict
    assert result.closes_evidence is (verdict is not Verdict.UNKNOWN_REFUSE)


def test_synthetic_frame_effect_materializes_bp_proof(project):
    result = materialize_call_stack_effects_8616(_artifact(), {0x1003: _summary()}, project=project)

    assert result.complete
    assert result.facts[0].effect.bp_preserved
    assert result.facts[0].effect.net_stack_delta == 0
    calls = [i for b in result.function.blocks for i in b.instrs if i.op == "CALL"]
    assert calls[0].call_stack_effect == result.facts[0].effect


@pytest.mark.parametrize("target", [0x1000, 0x2001])
def test_real_return_bytes_and_unregistered_targets_do_not_prove_bp(project, target):
    result = materialize_call_stack_effects_8616(
        _artifact(), {0x1003: replace(_summary(), target_addr=target)}, project=project,
    )

    assert not result.facts[0].effect.bp_preserved


def test_synthetic_bp_proof_does_not_override_refused_stack_effect(project):
    result = materialize_call_stack_effects_8616(
        _artifact(duplicate_call=True), {0x1003: _summary()}, project=project,
    )

    assert not result.complete
    assert all(not fact.effect.bp_preserved for fact in result.facts)


def test_zero_stack_delta_without_project_is_not_bp_proof():
    result = materialize_call_stack_effects_8616(_artifact(), {0x1003: _summary()})

    assert result.complete
    assert not result.facts[0].effect.bp_preserved


def test_unregistered_convention_refuses_bp(project, monkeypatch):
    monkeypatch.setattr("angr_platforms.X86_16.semantics.call_register_effects.default_cc", lambda *_args: None)
    result = classify_synthetic_call_register_effect_8616(
        project, callsite_addr=0x1003, target_addr=0x2000, register="bp",
    )

    assert result.verdict is Verdict.UNKNOWN_REFUSE


def test_summary_for_another_call_does_not_supply_bp_proof(project):
    summary = replace(_summary(), callsite_addr=0x1004)
    result = materialize_call_stack_effects_8616(_artifact(), {0x1003: summary}, project=project)

    assert not result.facts[0].effect.bp_preserved


def test_corrupt_stub_registry_does_not_supply_bp_proof(project):
    record_synthetic_call_stubs_8616(project, frozenset({-1}))
    result = materialize_call_stack_effects_8616(_artifact(), {0x1003: _summary()}, project=project)

    assert not result.facts[0].effect.bp_preserved
