"""Layer: IR tests.
Responsibility: preserve exact terminal prefixes and fresh selector-batch application.
"""
from types import SimpleNamespace

import pytest

from inertia.ir import declared_entry_pipeline as pipeline
from inertia.ir import declared_selector_call_preservation as collector
from inertia.ir import entry_domain_call_preservation as records_owner
from inertia.ir import entry_jump_domain as jump
from inertia.ir import real16_invocation_domain as domain
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.declared_selector_invariant import prove_declared_selector_invariant_8616
from inertia.ir.native_import_surface_cache import native_import_request_8616
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616
from tests.ir.test_declared_call_target_projection import _native_entry_world

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize('entry', [0x1020, 0x1026])
def test_native_head_census_excludes_only_suffix_calls(entry: int) -> None:
    """CS-only records suffice before CALL, but never substitute its effects afterward."""
    project, source, admission = _native_entry_world()
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        boundary = pipeline.exact_function_range_boundary_8616(
            project, admission.spec.range_start, admission.spec.range_end)
        artifact = pipeline.real16_native_census_import_8616(project, boundary)
        link = domain.DeclaredFunctionEntryLink8616(admission, artifact, boundary)
        selector = prove_declared_selector_invariant_8616(project, source, link)
        records = collector.collect_declared_selector_call_preservations_8616(project, selector)
        assert records and all(record.failure is None and record.callee is None for record in records)
        result = domain.prove_real16_declared_function_entry_domain_8616(
            project, link, entry, boot=source.boot, boot_recompute=source.boot_recompute,
            entry_call_preservations=records, declared_services=source.declared_services)
        if entry == 0x1020:
            assert result.failure is None
            assert result.failure_count == 0
        else:
            assert result.failure is domain.Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN


def test_higher_address_predecessor_call_still_requires_callee(monkeypatch: pytest.MonkeyPatch) -> None:
    """A terminal cutoff does not discard a higher-address predecessor's CALL."""
    terminal = IRBlock(0x100, (IRInstr('NOP', None, (), addr=0x100),))
    call = IRInstr('CALL', None, (), addr=0x200)
    predecessor = IRBlock(0x200, (call,), successor_addrs=(0x100,))
    artifact = IRFunctionArtifact(0x200, (predecessor, terminal))
    proof = SimpleNamespace(callee=None)
    consumed = SimpleNamespace(proof=proof)
    seen = []

    def consume(ctx: object, actual_artifact: IRFunctionArtifact, block: IRBlock,
                instruction: IRInstr) -> SimpleNamespace:
        seen.append((actual_artifact, block, instruction))
        return consumed

    monkeypatch.setattr(domain, '_consume_call_boundary_8616', consume)
    monkeypatch.setattr(domain, '_call_scope_uses_owned_identity_8616', lambda ctx: True)
    result = domain._census_path_callees_8616(
        SimpleNamespace(stop_block_addr=0x100), artifact,
        {block.addr: block for block in artifact.blocks}, frozenset((0x100, 0x200)), 0x100)
    assert result is domain.Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
    assert seen == [(artifact, predecessor, call)]


@pytest.mark.parametrize("call_addr", [0x101, None])
def test_terminal_prefix_keeps_prior_or_unlocated_call(
    monkeypatch: pytest.MonkeyPatch, call_addr: int | None,
) -> None:
    """Only proved suffix coordinates permit omission of a callee obligation."""
    call = IRInstr("CALL", None, (), addr=call_addr)
    target = IRInstr("NOP", None, (), addr=0x105)
    block = IRBlock(0x100, (call, target))
    artifact = IRFunctionArtifact(0x100, (block,))
    seen: list[IRInstr] = []
    consumed = SimpleNamespace(proof=SimpleNamespace(callee=None))

    def consume(
        ctx: object, actual: IRFunctionArtifact, owner: IRBlock, row: IRInstr,
    ) -> SimpleNamespace:
        assert actual is artifact and owner is block
        seen.append(row)
        return consumed

    monkeypatch.setattr(domain, "_consume_call_boundary_8616", consume)
    monkeypatch.setattr(domain, "_call_scope_uses_owned_identity_8616", lambda ctx: True)
    result = domain._census_path_callees_8616(
        SimpleNamespace(stop_block_addr=block.addr), artifact,
        {block.addr: block}, frozenset((block.addr,)), target.addr,
    )
    assert result is domain.Real16InvocationFailure8616.CALLEE_WRITE_UNPROVEN
    assert seen == [call]


@pytest.mark.parametrize('mutation', [None, 'scope', 'dependency', 'record'])
def test_late_selector_batch_mutation_refuses_application(monkeypatch: pytest.MonkeyPatch, mutation: str | None) -> None:
    """A fresh application consumes one batch, then checks original owned fields."""
    project, source, admission = _native_entry_world()
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        result = pipeline._prepare_native_entry_8616(project, source, admission)
    proof = result.view.proof
    scope = proof.invocation_scope
    assert scope is not None
    assert proof.admitted and proof.admitted[0].call_dependencies
    original = records_owner.consume_entry_selector_call_preservation_batch_8616
    calls = []

    def consume(records: tuple, selector: object) -> tuple[bool, ...]:
        admitted = original(records, selector)
        assert all(admitted)
        calls.append(records)
        if mutation == 'scope':
            object.__setattr__(scope, 'failure_count', 1)
        elif mutation == 'dependency':
            dependency = proof.admitted[0].call_dependencies[0]
            object.__setattr__(dependency, 'callsite_addr', dependency.callsite_addr + 1)
        elif mutation == 'record':
            object.__setattr__(records[0], 'callsite_addr', records[0].callsite_addr + 1)
        return admitted

    monkeypatch.setattr(records_owner, 'consume_entry_selector_call_preservation_batch_8616', consume)
    with native_import_request_8616(), segment_call_dependency_traversal_scope_8616():
        application = jump.apply_entry_jump_domain_8616(result.bundle.artifact, proof, invocation_scope=scope)
    assert len(calls) == 1
    if mutation is None:
        assert application.status is jump.EntryJumpDomainApplicationStatus8616.APPLIED
    else:
        assert application.status is jump.EntryJumpDomainApplicationStatus8616.STALE_INPUT
