"""A fresh conditional prefix is consumed once; retained domains replay later."""
from dataclasses import replace

import pytest

from inertia.ir import entry_domain_call_preservation as consumer
from inertia.ir import real16_invocation_domain as domain
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from tests.ir.test_declared_function_entry_domain import _recompute, _world
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes


def _fresh(project, boot, link):
    source = consumer.Real16InvocationSource8616(boot, _recompute, None)
    return consumer._declared_function_premise_8616(
        project, source, link.admission, link.artifact, link.boundary, 0x1023,
    )


def test_immediate_consumer_derives_once_and_public_complete_replays(monkeypatch):
    project, boot, link = _world()
    original = domain._derive_invocation_domain_8616
    calls = []

    def tracked(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(domain, "_derive_invocation_domain_8616", tracked)
    premise = _fresh(project, boot, link)
    assert premise is not None
    assert len(calls) == 1
    assert premise.complete
    assert len(calls) == 2
    assert domain.Real16InvocationAssumption8616.DECLARED_FUNCTION_ENTRY in premise.assumptions


@pytest.mark.parametrize("mutation", ["bytes", "declaration", "environment"])
def test_later_public_complete_reauthenticates(mutation):
    project, boot, link = _world()
    premise = _fresh(project, boot, link)
    assert premise is not None
    if mutation == "bytes":
        project.loader.memory.store(0x1021, b"\x35")
    elif mutation == "declaration":
        admission = replace(link.admission, spec=replace(link.admission.spec, entry_offset=0x21))
        premise = replace(premise, chain=replace(link, admission=admission))
    else:
        changed = program_from_mz_bytes(
            boot.source, replace(boot.environment, version_policy=None),
            code_ranges=boot.image.code_ranges,
        )
        premise = replace(premise, boot=changed)
    assert not premise.complete


@pytest.mark.parametrize("guard", ["budget", "depth", "deadline"])
def test_fresh_consumer_preserves_traversal_admission(monkeypatch, guard):
    project, boot, link = _world()
    with segment_call_dependency_traversal_scope_8616() as traversal:
        if guard == "budget":
            traversal.remaining_domains = 0
        elif guard == "depth":
            traversal.active_domains.update(range(domain._CHAIN_DEPTH_LIMIT_8616))
        else:
            monkeypatch.setattr(domain, "_census_deadline_8616", lambda: 0.0)
        assert _fresh(project, boot, link) is None


@pytest.mark.parametrize("mutation", ["accounting", "refusal"])
def test_fresh_consumer_refuses_invalid_derivation(monkeypatch, mutation):
    project, boot, link = _world()
    original = domain._derive_invocation_domain_8616

    def invalid(*args, **kwargs):
        result = original(*args, **kwargs)
        assert result.failure is None
        if mutation == "accounting":
            return replace(result, materialized_count=result.materialized_count + 1)
        return replace(result, failure=domain.Real16InvocationFailure8616.DECLARED_ENTRY_UNPROVEN)

    monkeypatch.setattr(domain, "_derive_invocation_domain_8616", invalid)
    assert _fresh(project, boot, link) is None


def _prove_boot_once(project, boot, link, recompute=_recompute):
    return domain.prove_fresh_real16_declared_function_entry_domain_8616(
        project, link, 0x1023, boot=boot, boot_recompute=recompute,
    )

def test_one_source_extraction_per_fresh_derivation(monkeypatch):
    project, boot, link = _world()
    original = domain._invocation_boot_evidence_8616
    calls = []
    def tracked(current):
        calls.append(current)
        return original(current)
    monkeypatch.setattr(domain, "_invocation_boot_evidence_8616", tracked)
    result = _prove_boot_once(project, boot, link)
    assert result is not None
    assert len(calls) == 1
    assert result.complete
    assert len(calls) == 2

@pytest.mark.parametrize("callback", [None, lambda boot: None, lambda boot: (_ for _ in ()).throw(ValueError("invalid"))])
def test_missing_wrong_or_refused_recompute_stays_refused(callback):
    project, boot, link = _world()
    assert _prove_boot_once(project, boot, link, callback) is None

def test_independent_boot_validation_rejects_changed_source():
    project, boot, link = _world()
    wrong = replace(boot)
    object.__setattr__(wrong, "source", boot.source[:-1] + b"\x01")
    assert domain._recompute_boot_8616(wrong, lambda current: current) is not None
    assert _prove_boot_once(project, wrong, link) is None
