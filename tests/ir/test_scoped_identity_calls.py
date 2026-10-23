"""Unchanged declared CFGs retain separate control and CALL obligations."""
from dataclasses import replace

from inertia.ir.entry_jump_domain import (
    EntryJumpDomainApplicationStatus8616,
    ScopedCallTargetStatus8616,
    prove_entry_jump_domains_8616,
)
from inertia.ir.entry_projection_mode import EntryProjectionMode8616
from inertia.ir.real16_invocation_domain import (
    DeclaredFunctionEntryLink8616,
    prove_real16_declared_function_entry_domain_8616,
)
from inertia.ir.scoped_function_ir_view import prove_scoped_function_ir_view_8616
from inertia.ir.vex_import import raw_x86_16_import_bundle_for_artifact_8616
from tests.ir.test_declared_function_entry_domain import _recompute
from tests.ir.test_forward_declared_call_scope import _forward_world


def test_declared_unchanged_calls_keep_control_and_target_proofs_separate() -> None:
    """A complete unchanged native CFG grants no unproved CALL facts."""
    project,boot,artifact,boundary,_resolver,admission=_forward_world()
    scope=prove_real16_declared_function_entry_domain_8616(project,DeclaredFunctionEntryLink8616(admission,artifact,boundary),artifact.function_addr,boot=boot,boot_recompute=_recompute)
    assert scope.complete,scope.failure
    bundle=raw_x86_16_import_bundle_for_artifact_8616(project,boundary,artifact)
    assert bundle is not None
    proof=prove_entry_jump_domains_8616(artifact,bundle.terminal_evidence,project=project)
    assert not proof.admitted and not proof.refusals and not proof.source_binding.pending
    view=prove_scoped_function_ir_view_8616(artifact,boundary,proof,invocation_scope=scope)
    assert view.failure is None,view.detail
    assert view.application.status is EntryJumpDomainApplicationStatus8616.EMPTY
    projection=view.cfg_projection_for(scope)
    assert projection is not None and projection.applied == ()
    assert projection.call_target_status is ScopedCallTargetStatus8616.NOT_REQUESTED
    assert projection.call_targets == ()
    assert projection.call_target_stats.materialized_count == 0
    assert all(a is b for a,b in zip(projection.blocks,artifact.blocks,strict=True))
    semantic=view.cfg_projection_for(scope,mode=EntryProjectionMode8616.CALL_TARGETS)
    assert semantic is None or (semantic.call_target_status is ScopedCallTargetStatus8616.UNPROVED and not semantic.call_targets)
    foreign=replace(scope,chain=replace(scope.chain,artifact=replace(artifact)))
    assert view.cfg_projection_for(foreign) is None
    assert view.cfg_projection_for(None) is None
    project.loader.memory.store(0x1041,b"\x00")
    assert view.cfg_projection_for(scope) is None


def test_identity_rejects_unresolved_cfg() -> None:
    """A moved successor remains a native/control refusal, never identity coverage."""
    project,boot,artifact,boundary,_resolver,admission=_forward_world()
    scope=prove_real16_declared_function_entry_domain_8616(project,DeclaredFunctionEntryLink8616(admission,artifact,boundary),artifact.function_addr,boot=boot,boot_recompute=_recompute)
    assert scope.complete
    bundle=raw_x86_16_import_bundle_for_artifact_8616(project,boundary,artifact)
    assert bundle is not None
    proof=prove_entry_jump_domains_8616(artifact,bundle.terminal_evidence,project=project)
    object.__setattr__(artifact.blocks[0],"successor_addrs",(0xdead,))
    view=prove_scoped_function_ir_view_8616(artifact,boundary,proof,invocation_scope=scope)
    assert view.failure is not None
    assert view.cfg_projection_for(scope) is None


def test_identity_rejects_expired_scope_budget() -> None:
    """An exhausted canonical entry proof cannot authorize unchanged code."""
    import time

    from inertia.ir.direct_evidence_deadline import direct_evidence_deadline_scope_8616
    project,boot,artifact,boundary,_resolver,admission=_forward_world()
    scope=prove_real16_declared_function_entry_domain_8616(project,DeclaredFunctionEntryLink8616(admission,artifact,boundary),artifact.function_addr,boot=boot,boot_recompute=_recompute)
    assert scope.complete
    bundle=raw_x86_16_import_bundle_for_artifact_8616(project,boundary,artifact)
    assert bundle is not None
    proof=prove_entry_jump_domains_8616(artifact,bundle.terminal_evidence,project=project)
    with direct_evidence_deadline_scope_8616(project,time.monotonic()-1):
        view=prove_scoped_function_ir_view_8616(artifact,boundary,proof,invocation_scope=scope)
        assert view.failure is not None
