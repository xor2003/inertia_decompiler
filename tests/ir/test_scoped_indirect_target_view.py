"""Conditional switch inventory requires authentic invocation discharge."""

from dataclasses import replace

import pytest

from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from inertia.frontend.x86_16.frontend_function_boundary import mapped_entry_function_boundary_8616
from inertia.frontend.x86_16.frontend_instruction_reachability import ConditionalIndirectEdge8616
from inertia.ir import real16_invocation_domain as census
from inertia.ir import scoped_indirect_target_view as view_owner
from inertia.ir.core import IRRefusal, IRValue, MemSpace
from inertia.ir.invocation_indirect_target import discover_invocation_indirect_target_8616
from inertia.ir.scoped_indirect_target_view import prove_scoped_indirect_target_view_8616
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
