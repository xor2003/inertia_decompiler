"""Parent synthetic controls for counter types and coherent CFG projections."""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
import test_x86_16_scoped_ir_view as fixtures
from test_x86_16_scoped_ir_view import world  # noqa: F401


@pytest.mark.parametrize('name', [
    'raw_fact_count', 'normalized_fact_count', 'classified_fact_count',
    'materialized_count', 'failure_count',
])
@pytest.mark.parametrize('coerce', [bool, float], ids=['bool', 'float'])
def test_counter_types_must_not_impersonate_integer_evidence(
    world: SimpleNamespace, name: str, coerce: type[bool] | type[float],  # noqa: F811
) -> None:
    """Numeric equality is insufficient for the owned integer ledger."""
    view = fixtures._authentic_view(world)
    values = {
        'raw_fact_count': view.raw_fact_count,
        'normalized_fact_count': view.normalized_fact_count,
        'classified_fact_count': view.classified_fact_count,
        'materialized_count': view.materialized_count,
        'failure_count': view.failure_count,
    }
    corrupt = replace(view, **{name: coerce(values[name])})
    assert not corrupt.complete_for(world.scope)
    assert corrupt.to_dict()['authenticated'] is False


def test_pending_recorded_in_edges_match_bulk_and_individual(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pending source edge remains diagnostic evidence in both APIs."""
    original = fixtures._source

    def source_with_recorded_edge(**kwargs: object) -> tuple:
        artifact, instructions = original(**kwargs)
        if kwargs.get('second_pending'):
            artifact = replace(artifact, blocks=(
                *artifact.blocks[:2],
                replace(artifact.blocks[2], successor_addrs=(fixtures.ISLAND,)),
            ))
        return artifact, instructions

    monkeypatch.setattr(fixtures, '_source', source_with_recorded_edge)
    view, scope, _artifact = fixtures._partial_view(monkeypatch)
    assert view.complete_for(scope)
    projection = view.cfg_projection_for(scope)
    assert projection is not None
    assert projection.successors_for(fixtures.SECOND) is None
    assert projection.pending_for(fixtures.SECOND)
    assert projection.predecessors_for(fixtures.ISLAND) == (fixtures.FUNC, fixtures.SECOND)
    assert projection.predecessors_for(fixtures.ISLAND) == view.effective_predecessors_for(
        scope, fixtures.ISLAND,
    )
