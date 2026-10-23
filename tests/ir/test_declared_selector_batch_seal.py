"""Layer: IR tests.
Responsibility: reject late whole-graph mutation during selector batch callbacks.
"""
from __future__ import annotations

from typing import cast

import pytest

from inertia.frontend.x86_16.declared_function_entry import DeclaredFunctionEntryAdmission8616
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.ir import declared_selector_invariant as owner
from inertia.ir import real16_invocation_domain as domain
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from inertia.ir.entry_domain_call_preservation import Real16InvocationSource8616
from inertia.ir.real16_invocation_domain import DeclaredFunctionEntryLink8616
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize('callback', ['none', 'native_import', 'call_bytes', 'final_authority'])
@pytest.mark.parametrize('mutation', ['argument', 'provenance', 'selectors'])
def test_batch_final_seal_checks_noncall_graph(
    monkeypatch: pytest.MonkeyPatch, callback: str, mutation: str,
) -> None:
    """A late callback changing non-CALL semantics or provenance refuses all calls."""
    project = object()
    value = IRValue(MemSpace.CONST, const=7, size=2)
    effect = IRInstr('MOV', None, (value,), addr=0x1000)
    calls = (IRInstr('CALL', None, (), addr=0x1001),
             IRInstr('CALL', None, (), addr=0x1004))
    block = IRBlock(0x1000, (effect, *calls))
    artifact = IRFunctionArtifact(0x1000, (block,))
    boundary = ExactFunctionRangeBoundary8616(
        project, 0x1000, 7, frozenset({0x1000}),
        frozenset({0x1000, 0x1001, 0x1004}), (),
    )
    admission = cast(DeclaredFunctionEntryAdmission8616, object())
    link = DeclaredFunctionEntryLink8616(admission, artifact, boundary)
    cohort = owner.Cohort(1, 1, 1, 0)
    scope = owner.DeclaredSegmentInvariant(
        owner.InvariantStatus.PROVEN_CONDITIONAL, cohort, cohort, cohort,
        (), (), (), (), 3, {'cs': 0x100}, 0, 0, 0x1000, admission,
        project=project, source=cast(Real16InvocationSource8616, object()), root_link=link,
        instruction_states=tuple(owner.DeclaredSelectorInstructionState8616(
            artifact, block, call, (('cs', 0x100),)) for call in calls),
        consumed_pairs=((boundary, artifact),),
    )
    projections = tuple(owner.DeclaredSelectorCallsite8616(
        scope, block, call, cast(int, call.addr), 0x1040,
        cast(int, call.addr) + 3, 0x100) for call in calls)
    imports = []
    authorities = []
    changed = []

    def mutate() -> None:
        if not changed:
            _mutate_retained_facts(scope, block, projections, value, mutation)
            changed.append(True)

    def native(project_arg: object, boundary_arg: ExactFunctionRangeBoundary8616) -> IRFunctionArtifact:
        imports.append((project_arg, boundary_arg))
        if callback == 'native_import':
            mutate()
        return artifact

    def authority(*args: object, **kwargs: object) -> None:
        authorities.append(True)
        if callback == 'final_authority' and len(authorities) == 2:
            mutate()

    def load(project_arg: object, address: int, size: int) -> bytes:
        assert project_arg is project and size == 3
        if callback == 'call_bytes':
            mutate()
        return b'\xe8' + (0x1040 - address - 3).to_bytes(2, 'little', signed=True)

    monkeypatch.setattr(domain, 'real16_native_census_import_8616', native)
    monkeypatch.setattr(owner, '_authenticate_authority', authority)
    monkeypatch.setattr(owner, '_loaded_bytes_8616', load)
    with segment_call_dependency_traversal_scope_8616():
        verdicts = owner.consume_declared_selector_callsite_batch_8616(project, projections)
    assert len(imports) == 1
    assert len(authorities) == 2
    assert verdicts == ((True, True) if callback == 'none' else (False, False))
    assert bool(changed) == (callback != 'none')


def _mutate_retained_facts(
    scope: owner.DeclaredSegmentInvariant, block: IRBlock,
    projections: tuple[owner.DeclaredSelectorCallsite8616, ...],
    value: IRValue, mutation: str,
) -> None:
    """Corrupt independently retained selectors or a non-call graph operand."""
    if mutation == 'selectors':
        for projection in projections:
            state = owner._retained_instruction_state_8616(scope, block, projection.instruction)
            assert state is not None
            object.__setattr__(state, 'selectors', (('cs', 0x80),))
            object.__setattr__(projection, 'incoming_cs', 0x80)
    else:
        object.__setattr__(value, 'const' if mutation == 'argument' else 'source_tmp', 999)


@pytest.mark.parametrize('mutation', ['none', 'argument', 'boundary'])
def test_standalone_native_rebind_retains_precallback_evidence(
    monkeypatch: pytest.MonkeyPatch, mutation: str,
) -> None:
    """An importer returning the same altered graph cannot authenticate itself."""
    from inertia.ir import ir_boundary_cfg as boundary_owner

    project = object()
    value = IRValue(MemSpace.CONST, const=7, size=2)
    block = IRBlock(0x1000, (IRInstr('MOV', None, (value,), addr=0x1000),))
    artifact = IRFunctionArtifact(0x1000, (block,))
    boundary = ExactFunctionRangeBoundary8616(
        project, 0x1000, 1, frozenset({0x1000}), frozenset({0x1000}), (),
    )

    def native(project_arg: object, boundary_arg: ExactFunctionRangeBoundary8616) -> IRFunctionArtifact:
        assert project_arg is project and boundary_arg is boundary
        if mutation == 'argument':
            object.__setattr__(value, 'const', 999)
        elif mutation == 'boundary':
            object.__setattr__(boundary, 'size', 2)
        return artifact

    monkeypatch.setattr(domain, 'real16_native_census_import_8616', native)
    failure = boundary_owner._scoped_native_failure_8616(project, boundary, artifact)
    assert (failure is None) == (mutation == 'none')
