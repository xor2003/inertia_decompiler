"""Demand native caller authority only under the bounded premise guard."""
from pathlib import Path
from types import SimpleNamespace

import pytest
import inertia.ir.entry_domain_call_preservation as owner
import inertia.ir.vex_import as vex_import
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRRefusal

import tests.integration.test_x86_16_near_return_continuation as native
from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from inertia.frontend.x86_16.frontend_function_boundary import mapped_entry_function_boundary_8616


@pytest.mark.parametrize("stale_boot", [False, True])
def test_native_chain_imports_missing_parent(tmp_path: Path, stale_boot: bool) -> None:
    """Demand-import only native raw bytes; stale boot never authorizes scope."""
    boot, project = native._mz_world(tmp_path)
    parent = mapped_entry_function_boundary_8616(project, native._MZ_CALLER)
    assert parent is not None
    index = build_boundary_direct_callsite_index_8616(parent, direct_target_resolver=native._mz_resolver(project))
    source = owner.Real16InvocationSource8616(boot, (lambda _: None) if stale_boot else native._mz_boot_recompute, index)
    owner.install_real16_invocation_source_8616(project, source)
    assert owner.registered_function_ir_artifact_8616(project, parent.addr).failure is owner.FunctionIRArtifactFailure8616.NOT_REGISTERED
    resolved = owner._callee_artifact_and_boundary_8616(project, native._MZ_CALLEE)
    assert resolved is not None
    artifact, boundary = resolved
    scope = owner.entry_domain_invocation_premise_8616(project, artifact, boundary, native._MZ_JMP_HEAD)
    if stale_boot:
        assert scope is None
    else:
        assert scope is not None and scope.complete
    registered = owner.registered_function_ir_artifact_8616(project, parent.addr)
    assert registered.verdict is owner.FunctionIRArtifactVerdict8616.PROVEN
    assert owner.registered_function_ir_artifact_8616(project, native._MZ_CALLEE).failure is owner.FunctionIRArtifactFailure8616.NOT_REGISTERED


@pytest.mark.parametrize("problem", ["pending", "block_refused", "wrong_head", "foreign_project", "coverage", "exception", "cycle"])
def test_intake_refuses_defects_and_guards_before_import(monkeypatch: pytest.MonkeyPatch, problem: str) -> None:
    """Refuse invalid imports without bypassing the bounded session."""
    project=SimpleNamespace()
    head=0x10020
    boundary=SimpleNamespace(addr=head, project=object() if problem == "foreign_project" else project)
    session=owner._PremiseResolution8616()
    source=SimpleNamespace(boot=None, boot_recompute=None, declared_services=(), callsite_index=None)
    monkeypatch.setattr(owner, "_exact_boundary_for_8616", lambda *a: boundary)
    def import_native(*args: object) -> IRFunctionArtifact:
        assert head in session.in_flight
        if problem == "exception":
            raise ValueError("bad native source")
        if problem == "cycle":
            assert owner._registered_invocation_premise_8616(project, head, head, source, session) is None
        return IRFunctionArtifact(head + 1 if problem == "wrong_head" else head, blocks=(IRBlock(head, (), refusals=(IRRefusal("unsupported", "refused", head),)),) if problem == "block_refused" else (), refusals=(IRRefusal("near_return_continuation_pending", "conditional", head),) if problem in {"pending", "cycle"} else ())
    monkeypatch.setattr(vex_import, "build_x86_16_ir_function_artifact", import_native)
    monkeypatch.setattr(owner, "prove_ir_boundary_coverage_8616", lambda *a: SimpleNamespace(complete=False))
    if problem == "exception":
        with pytest.raises(ValueError, match="bad native source"):
            owner._registered_invocation_premise_8616(project, head, head, source, session)
    else:
        assert owner._registered_invocation_premise_8616(project, head, head, source, session) is None
    assert session.in_flight == frozenset()
    assert session.remaining == 63
    registered = owner.registered_function_ir_artifact_8616(project, head)
    if problem == "coverage":
        assert registered.verdict is owner.FunctionIRArtifactVerdict8616.PROVEN
    else:
        assert registered.failure is owner.FunctionIRArtifactFailure8616.NOT_REGISTERED
