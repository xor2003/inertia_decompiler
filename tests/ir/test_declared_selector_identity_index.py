"""Immutable selector lookups rebuild from retained tuples and charge shared work."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.ir import declared_selector_invariant as owner
from inertia.ir.core import IRBlock, IRFunctionArtifact, IRInstr
from inertia.ir.real16_invocation_domain import DeclaredFunctionEntryLink8616
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

pytestmark = pytest.mark.decompiler


@pytest.fixture
def receipt():
    row = IRInstr('CALL', None, (), addr=0x1000)
    block = IRBlock(0x1000, (row,))
    artifact = IRFunctionArtifact(0x1000, (block,))
    boundary = SimpleNamespace(project=object())
    link = DeclaredFunctionEntryLink8616(object(), artifact, boundary)
    state = owner.DeclaredSelectorInstructionState8616(artifact, block, row, (('cs', 0x100),))
    cohort = owner.Cohort(1, 1, 1, 0)
    return owner.DeclaredSegmentInvariant(
        owner.InvariantStatus.PROVEN_CONDITIONAL, cohort, cohort, cohort, (), (), (), (),
        1, {'cs': 0x100}, 0, 0, 0x1000, link.admission,
        root_link=link, instruction_states=(state,), consumed_pairs=((boundary, artifact),),
    )


def test_replace_rebuilds_instruction_identity_lookup(receipt):
    old = receipt.instruction_states[0]
    row = replace(old.instruction)
    block = replace(old.block, instrs=(row,))
    updated_state = replace(old, block=block, instruction=row, selectors=(('cs', 0x101),))
    updated = replace(receipt, instruction_states=(updated_state,))
    assert owner._retained_instruction_state_8616(updated, old.block, old.instruction) is None
    assert owner._retained_instruction_state_8616(updated, block, row) is updated_state
    assert owner._retained_instruction_state_8616(receipt, old.block, old.instruction) is old
    with pytest.raises(TypeError, match='init=False'):
        replace(receipt, _identity_index=receipt._identity_index)


def test_duplicate_instruction_identity_refuses(receipt):
    state = receipt.instruction_states[0]
    ambiguous = replace(receipt, instruction_states=(state, replace(state)))
    assert owner._retained_instruction_state_8616(ambiguous, state.block, state.instruction) is None


def test_conflicting_artifact_boundary_refuses(receipt):
    root = receipt.root_link
    ambiguous = replace(receipt, consumed_pairs=((object(), root.artifact),))
    assert owner._retained_surface_for(ambiguous, root.artifact) is None
    assert owner._retained_surface_for(receipt, root.artifact) == (root.boundary, root.artifact)


def test_index_is_immutable_and_charged_once_per_construction(receipt):
    state = receipt.instruction_states[0]
    units = len(receipt.instruction_states) + len(receipt.consumed_pairs) + 1
    with segment_call_dependency_traversal_scope_8616() as traversal:
        initial = traversal.census_work_units
        rebuilt = replace(receipt)
        assert traversal.census_work_units - initial == units
        assert rebuilt.work_units - receipt.work_units == units
        assert rebuilt.shared_work_units == traversal.census_work_units
        for _ in range(20):
            assert owner._retained_instruction_state_8616(rebuilt, state.block, state.instruction) is state
            assert owner._retained_surface_for(rebuilt, state.artifact) is not None
        assert traversal.census_work_units - initial == units
    with pytest.raises(TypeError):
        rebuilt._identity_index.states[(id(state.block), id(state.instruction))] = None


def test_index_construction_cannot_escape_shared_budget(receipt):
    with segment_call_dependency_traversal_scope_8616() as traversal:
        traversal.census_work_units = 20000
        rebuilt = replace(receipt)
        assert rebuilt.status is owner.InvariantStatus.REFUSED
        assert rebuilt._identity_index is None
        assert any(item.kind is owner.ObligationKind.BUDGET_EXCEEDED for item in rebuilt.obligations)


def test_factory_private_limit_includes_later_index_construction():
    budget = owner._Budget(float('inf'), 3)
    budget.units = 2
    obligations = []
    owner._check_index_private_budget_8616(budget, 2, 0x1000, obligations)
    assert len(obligations) == 1
    assert obligations[0].kind is owner.ObligationKind.BUDGET_EXCEEDED
