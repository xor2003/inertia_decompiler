"""Conditional switch inventory requires authentic invocation discharge."""

from dataclasses import replace

import pytest

from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from inertia.frontend.x86_16.frontend_function_boundary import mapped_entry_function_boundary_8616
from inertia.frontend.x86_16.frontend_instruction_reachability import ConditionalIndirectEdge8616
from inertia.ir import entry_domain_call_preservation as call_owner
from inertia.ir import real16_invocation_domain as census
from inertia.ir import scoped_indirect_target_view as view_owner
from inertia.ir.core import IRRefusal, IRValue, MemSpace
from inertia.ir.entry_domain_call_preservation import _scoped_callee_coverage_8616
from inertia.ir.function_ir_registry import FunctionIRArtifactVerdict8616, registered_function_ir_artifact_8616
from inertia.ir.invocation_indirect_target import discover_invocation_indirect_target_8616
from inertia.ir.ir_boundary_cfg import prove_scoped_ir_boundary_coverage_8616
from inertia.ir.scoped_indirect_target_view import prove_scoped_indirect_target_view_8616
from inertia.ir.segment_effect_closure import prove_segment_effect_closure_8616
from inertia.ir.segment_state import build_x86_16_segment_state_artifact
from inertia.ir.vex_import import raw_x86_16_function_bundle_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from inertia.semantics.direct_near_call_target_binding import _consume_direct_near_call_target_binding_from_decoded_8616
from tests.ir.test_invocation_indirect_target import _fixture

pytestmark = pytest.mark.decompiler


def _native_view(mutation=None):
    parent, _ = _fixture(2)
    project = parent.project
    caller, caller_boundary = census._retained_parent_census_surface_8616(parent)
    index = build_boundary_direct_callsite_index_8616(
        caller_boundary, direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    decoded = index.for_target(0x130A)[0]
    discovery = discover_invocation_indirect_target_8616(parent, decoded)
    assert discovery is not None
    edge = ConditionalIndirectEdge8616(discovery.block_addr, discovery.instruction_addr, discovery.target)
    boundary = mapped_entry_function_boundary_8616(project, 0x130A, conditional_edges=(edge,))
    assert boundary is not None
    bundle = raw_x86_16_function_bundle_8616(project, boundary)
    raw = bundle.artifact
    call_block = census._callsite_block_8616(caller, parent.callsite_addr)
    instruction = next(row for row in call_block.instrs if row.op == "CALL")
    binding = _consume_direct_near_call_target_binding_from_decoded_8616(
        project, block=call_block, instruction=instruction, decoded=decoded, invocation=parent,
        consumer=lambda current: current.complete,
    )
    assert binding.complete
    chain = census.Real16CallChainLink8616(
        parent, index, decoded, caller, caller_boundary, parent.callsite_call_state,
        raw, boundary, entry_binding=binding,
    )
    scope = census.prove_real16_chained_invocation_domain_8616(
        project, None, raw.function_addr, boot=parent.boot, boot_recompute=parent.boot_recompute, chain=chain,
    )
    assert scope.complete, scope.failure
    if mutation == "receipt":
        discovery = replace(discovery, target=discovery.target + 1)
    elif mutation == "native":
        project.loader.memory.store(discovery.instruction_addr, b"\x90")
    elif mutation == "raw_operand":
        terminal = next(block.instrs[-1] for block in raw.blocks if block.addr == discovery.block_addr)
        object.__setattr__(terminal, "args", (IRValue(MemSpace.CONST, const=discovery.target + 1, size=4),))
    elif mutation == "unrelated_refusal":
        block = next(block for block in raw.blocks if block.addr == discovery.block_addr)
        object.__setattr__(block, "refusals", (*block.refusals, IRRefusal("opaque_effect", "test unknown effect", block.addr)))
    view = prove_scoped_indirect_target_view_8616(
        project, raw, boundary, discovery, scope, bundle.terminal_evidence,
    )
    return view, scope


def test_actual_switch_scoped_projection_keeps_original_pending_body():
    view, scope = _native_view()
    assert view.failure is None
    projection = view.cfg_projection_for(scope)
    assert projection is not None
    assert projection.source_artifact is view.source_artifact
    assert projection.successors[0x1317] == (0x1323,)
    assert not any(projection.pending.values())
    assert any(block.refusals for block in view.source_artifact.blocks)


@pytest.mark.parametrize("mutation", ["receipt", "native", "raw_operand", "unrelated_refusal"])
def test_changed_indirect_evidence_refuses(mutation):
    view, scope = _native_view(mutation)
    assert view.failure is not None
    assert view.cfg_projection_for(scope) is None


def test_foreign_or_changed_scope_cannot_consume_view():
    view, scope = _native_view()
    assert view.failure is None
    assert view.cfg_projection_for(replace(scope, project=object())) is None
    object.__setattr__(scope, "failure_count", 1)
    assert view.cfg_projection_for(scope) is None


def test_late_declared_table_mutation_cannot_reuse_earlier_discovery(monkeypatch):
    """A fresh head-scope proof does not seal data only consumed by the JMP."""
    original = view_owner.prove_entry_jump_domains_8616

    def mutate_after_proof(*args, **kwargs):
        proof = original(*args, **kwargs)
        import inspect

        frame = inspect.currentframe().f_back
        view = frame.f_locals["view"]
        admission = view.discovery.invocation.chain.admission
        memory = tuple(
            replace(span, data=bytes.fromhex("1e0323031e032a03")) if span.address == 0x1339 else span
            for span in admission.spec.memory
        )
        object.__setattr__(admission.spec, "memory", memory)
        return proof

    monkeypatch.setattr(view_owner, "prove_entry_jump_domains_8616", mutate_after_proof)
    view, scope = _native_view()
    assert view.failure is not None
    assert view.cfg_projection_for(scope) is None


def test_indirect_projection_proves_only_current_scoped_coverage():
    """An authenticated indirect theorem reaches coverage without universalizing it."""
    view, scope = _native_view()
    assert view.cfg_projection_for(scope) is not None
    result = prove_scoped_ir_boundary_coverage_8616(
        view.project, view.boundary, view.source_artifact, view,
    )
    assert result.complete_for(scope), result.failure
    assert not result.complete
    state = build_x86_16_segment_state_artifact(
        view.source_artifact, scoped_view=view, invocation_scope=scope,
    )
    closure = prove_segment_effect_closure_8616(result, state)
    assert closure.complete_for(scope), closure.failure
    assert not closure.complete
    assert not result.complete_for(replace(scope, project=object()))
    view.project.loader.memory.store(view.discovery.instruction_addr, b"\x90")
    assert not result.complete_for(scope)


def test_scoped_callee_coverage_consumes_indirect_theorem():
    """Callee coverage must discover the owned theorem for pending indirect edges."""
    view, scope = _native_view()
    result = _scoped_callee_coverage_8616(
        view.project, view.source_artifact, view.boundary, scope,
    )
    assert result is not None
    assert result.complete_for(scope), result.failure
    assert not result.complete
    view.project.loader.memory.store(view.discovery.instruction_addr, b"\x90")
    assert _scoped_callee_coverage_8616(
        view.project, view.source_artifact, view.boundary, scope,
    ) is None


@pytest.mark.parametrize("known_argument", [True, False], ids=("known", "unknown"))
@pytest.mark.parametrize("deferred", [False, True], ids=("bound", "deferred"))
def test_raw_callee_scope_discovers_only_proven_indirect_edges(known_argument: bool, deferred: bool):
    """On-demand intake may use a native singleton but must refuse unknown inputs."""
    parent, decoded = _fixture(2, known_argument=known_argument)
    project = parent.project
    link = parent.chain
    assert type(link) is census.DeclaredFunctionEntryLink8616
    def resolver(instruction):
        return resolve_direct_call_target_from_instruction_8616(project, instruction)
    index = build_boundary_direct_callsite_index_8616(link.boundary, direct_target_resolver=resolver)
    call_owner.install_real16_invocation_source_8616(
        project, call_owner.Real16InvocationSource8616(
            parent.boot, parent.boot_recompute, index, function_entries=(link.admission,),
        ),
    )
    parent = census.prove_real16_declared_function_entry_domain_8616(
        project, link, parent.callsite_addr, boot=parent.boot, boot_recompute=parent.boot_recompute,
    )
    assert parent.complete, parent.failure
    decoded = index.for_target(decoded.target_addr)[0]
    block = census._callsite_block_8616(link.artifact, parent.callsite_addr)
    instruction = next(row for row in block.instrs if row.op == "CALL")
    if deferred:
        binding, route, scope = call_owner._deferred_declared_raw_callee_scope_8616(
            project, link.artifact, link.boundary, block, instruction, decoded,
            decoded.target_addr, (),
        )
    else:
        binding = _consume_direct_near_call_target_binding_from_decoded_8616(
            project, block=block, instruction=instruction, decoded=decoded, invocation=parent,
            consumer=lambda current: current.complete,
        )
        assert binding.complete
        route, scope = call_owner._raw_callee_call_scope_8616(
            project, decoded.target_addr, decoded, parent, binding,
        )
    if known_argument:
        assert binding is not None and binding.complete
        assert route is call_owner._RawCalleeRoute8616.SCOPED_BODY
        assert scope is not None and scope.complete
        assert scope.coverage is None
        assert scope.chain.callee_boundary.conditional_edges
        assert scope.chain.callee_artifact.refusals
    else:
        assert route is call_owner._RawCalleeRoute8616.REFUSED
        assert scope is None
    assert registered_function_ir_artifact_8616(
        project, decoded.target_addr,
    ).verdict is not FunctionIRArtifactVerdict8616.PROVEN


def test_indirect_view_diagnostics_reauthenticate_before_reporting_edges():
    view, scope = _native_view()
    assert view.cfg_projection_for(None) is None
    receipt = view.to_dict()
    assert receipt["authenticated"] is True
    assert receipt["successors"][str(0x1317)] == [0x1323]
    object.__setattr__(scope, "failure_count", 1)
    stale = view.to_dict()
    assert stale["authenticated"] is False
    assert stale["successors"] == {}
