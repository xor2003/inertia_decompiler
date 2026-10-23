"""Layer: Tests.
Responsibility: reuse only native-bound missing-service prerequisites from registered boot IR.
"""

from dataclasses import replace

import pytest

from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from inertia.frontend.x86_16.mz_static_boot import mz_static_boot_8616, recompute_mz_static_boot_8616
from inertia.ir import entry_domain_call_preservation as owner
from inertia.ir.function_ir_registry import publish_function_ir_artifact_8616
from inertia.ir.ir_boundary_cfg import prove_ir_boundary_coverage_8616
from inertia.ir.raw_boot_blocked_prefix import (
    raw_boot_blocked_prefix_matches_8616,
    retain_raw_boot_blocked_prefix_8616,
)
from inertia.ir.real16_invocation_domain import (
    Real16InvocationFailure8616,
    Real16InvocationKind8616,
    prove_real16_invocation_domain_8616,
)
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_x86_16_boot_entry_link import _world


def _registered_world():
    """Publish genuine native boot IR whose first INT lacks a declared service."""
    project, boundary, _, declared_boot = _world(bytes.fromhex("b430cd21"))
    artifact = build_x86_16_ir_function_artifact(project, boundary)
    assert publish_function_ir_artifact_8616(project, artifact).artifact is artifact
    coverage = prove_ir_boundary_coverage_8616(project, boundary, artifact)
    assert coverage.complete
    boot = mz_static_boot_8616(declared_boot.source, 0x1000)
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=lambda instruction:
        resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    source = owner.Real16InvocationSource8616(boot, recompute_mz_static_boot_8616, index)
    premise = prove_real16_invocation_domain_8616(
        project, coverage, 0x10010, boot=boot, boot_recompute=recompute_mz_static_boot_8616,
    )
    assert premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    assert premise.chain is None
    return project, boundary, source, premise


def test_registered_boot_refusal_retains_only_unchanged_native_prerequisite():
    """A registered refusal gains no proof authority and invalidates on byte changes."""
    project, _, source, premise = _registered_world()
    retained = retain_raw_boot_blocked_prefix_8616(project, source, 0x10000, 0x10010, premise)
    assert retained is not None
    assert retained.premise.failure is Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
    assert not retained.premise.complete
    assert raw_boot_blocked_prefix_matches_8616(retained, project, source, 0x10000, 0x10010)
    assert not raw_boot_blocked_prefix_matches_8616(retained, project, replace(source), 0x10000, 0x10010)
    project.loader.memory.store(0x10002, b"\x90\x90")
    assert not raw_boot_blocked_prefix_matches_8616(retained, project, source, 0x10000, 0x10010)


def test_registered_missing_service_does_not_repeat_universal_census(monkeypatch: pytest.MonkeyPatch):
    """One bounded request consumes its registered missing prerequisite only once."""
    project, boundary, source, _ = _registered_world()
    monkeypatch.setattr(owner, "_exact_boundary_for_8616", lambda current, head: boundary)
    monkeypatch.setattr(owner, "_raw_boot_invocation_premise_8616", lambda *args: None)
    original = owner._caller_premise_surface_8616
    calls = []
    def observed(current, head):
        calls.append(head)
        return original(current, head)
    monkeypatch.setattr(owner, "_caller_premise_surface_8616", observed)
    session = owner._PremiseResolution8616()
    for _ in range(2):
        assert owner._registered_invocation_premise_8616(project, 0x10000, 0x10010, source, session) is None
    assert calls == [0x10000]
    assert session.blocked_prefix_reuse_count == 1
    assert session.remaining == 62
    assert session.in_flight == frozenset()


@pytest.mark.parametrize("mutate", [
    lambda domain: replace(domain, failure=Real16InvocationFailure8616.CALL_BOUNDARY_UNPROVEN),
    lambda domain: replace(domain, coverage=None),
    lambda domain: replace(domain, coverage=replace(domain.coverage, scoped_view=object())),
    lambda domain: replace(domain, coverage=replace(
        domain.coverage, artifact=replace(domain.coverage.artifact, function_addr=0x10001),
    )),
    lambda domain: replace(domain, chain=object()),
    lambda domain: replace(domain, kind=Real16InvocationKind8616.CALL_CHAINED),
    lambda domain: replace(domain, refusal_site=replace(
        domain.refusal_site, instruction_addr=domain.refusal_site.instruction_addr + 1,
    )),
])
def test_registered_blocker_rejects_changed_provenance(mutate):
    """Copied verdicts cannot substitute scoped, foreign or mismatched evidence."""
    project, _, source, premise = _registered_world()
    changed = mutate(premise)
    assert retain_raw_boot_blocked_prefix_8616(project, source, 0x10000, 0x10010, changed) is None
