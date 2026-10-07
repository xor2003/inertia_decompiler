"""Native source, projection and dependency corruption controls for scoped IR."""
from __future__ import annotations

from dataclasses import replace

import pytest
import tools.dosunit.tests.test_x86_16_scoped_native_inputs as native
from tools.dosunit.tests.test_x86_16_scoped_native_inputs import _view, world  # noqa: F401


def test_native_view_retains_scope_and_raw_call_identity(world: tuple) -> None:  # noqa: F811
    """Expose a proved edge only under its actual entry; retain raw CALLs."""
    view, scope, artifact = _view(world)
    assert view.failure is None, view.to_dict()
    assert not view.complete
    assert view.complete_for(scope), view.to_dict()
    source = next(block for block in artifact.blocks if block.addr == native.CALLER)
    assert view.source_block(native.CALLER) is source
    assert view.source_block(native.CALLER).instrs is source.instrs
    jump_block = view.proof.admitted[0].block_addr
    assert native.ISLAND in view.effective_successors_for(scope, jump_block)
    assert jump_block in view.effective_predecessors_for(scope, native.ISLAND)
    projection = view.cfg_projection_for(scope)
    assert projection is not None
    assert projection.source_artifact is artifact
    assert projection.scope is scope
    assert native.ISLAND in projection.successors_for(jump_block)
    assert jump_block in projection.predecessors_for(native.ISLAND)
    assert projection.successors_for(-1) is None
    assert projection.predecessors_for(-1) is None
    assert view.effective_blocks_for(None) is None
    assert not view.complete_for(replace(scope, boot=object()))


@pytest.mark.parametrize('mutation', ['target', 'dependency', 'source'])
def test_native_view_rejects_retained_evidence_mutation(world: tuple, mutation: str) -> None:  # noqa: F811
    """Authenticate the retained input/application again at consumption."""
    view, scope, artifact = _view(world)
    assert view.complete_for(scope)
    jump = view.proof.admitted[0]
    if mutation == 'target':
        altered = replace(jump, target=jump.target + 1)
        corrupt = replace(view, proof=replace(view.proof, admitted=(altered,)))
    elif mutation == 'dependency':
        assert jump.call_dependencies
        altered = replace(jump, call_dependencies=())
        corrupt = replace(view, proof=replace(view.proof, admitted=(altered,)))
    else:
        corrupt = replace(view, source_artifact=replace(artifact, blocks=artifact.blocks[:-1]))
    assert not corrupt.complete_for(scope)
    assert corrupt.effective_blocks_for(scope) is None


@pytest.mark.parametrize('mutation', [
    'application_scope', 'application_dependencies', 'application_provenance', 'raw_fact_count',
    'normalized_fact_count', 'classified_fact_count', 'materialized_count',
    'failure_count',
])
def test_native_view_rejects_equality_hidden_mutation(world: tuple, mutation: str) -> None:  # noqa: F811
    """Retained compare=False metadata and accounting cannot evade revalidation."""
    view, scope, _artifact = _view(world)
    assert view.complete_for(scope)
    application = view.application
    assert application is not None
    if mutation == 'application_scope':
        assert application.invocation_scope is not None
        corrupt = replace(view, application=replace(application, invocation_scope=None))
    elif mutation == 'application_dependencies':
        admission = application.applied[0]
        assert admission.call_dependencies
        corrupt = replace(view, application=replace(
            application, applied=(replace(admission, call_dependencies=()),),
        ))
    elif mutation == 'application_provenance':
        head = application.applied[0].head
        blocks = tuple(replace(block, instrs=tuple(
            replace(instruction, args=(
                replace(instruction.args[0], source_tmp=999999),
            )) if instruction.addr == head and instruction.op == 'JMP'
            else instruction for instruction in block.instrs
        )) if block.addr == application.applied[0].block_addr else block
            for block in application.blocks)
        altered = replace(application, blocks=blocks)
        assert altered == application  # Ordinary equality misses this metadata.
        corrupt = replace(view, application=altered)
    elif mutation == 'raw_fact_count':
        corrupt = replace(view, raw_fact_count=0)
    elif mutation == 'normalized_fact_count':
        corrupt = replace(view, normalized_fact_count=0)
    elif mutation == 'classified_fact_count':
        corrupt = replace(view, classified_fact_count=0)
    elif mutation == 'materialized_count':
        corrupt = replace(view, materialized_count=0)
    else:
        corrupt = replace(view, failure_count=view.failure_count + 1)
    assert not corrupt.complete_for(scope)
    assert corrupt.effective_blocks_for(scope) is None
