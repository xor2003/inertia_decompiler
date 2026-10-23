"""An explicit request budget remains shared without altering proof authority."""
import time

import pytest

from inertia.ir.declared_selector_call_preservation import _charge_collection_8616
from inertia.ir.declared_selector_invariant import ObligationKind, _Budget
from inertia.ir.segment_call_preservation import segment_call_dependency_traversal_scope_8616

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize('limit', [20000, 30000])
def test_configured_budget_is_shared_at_exact_boundary(limit: int) -> None:
    with segment_call_dependency_traversal_scope_8616(census_work_limit=limit) as ledger:
        assert ledger.census_work_limit == limit
        assert _charge_collection_8616(object(), limit)
        with segment_call_dependency_traversal_scope_8616() as nested:
            assert nested is ledger
            assert _charge_collection_8616(object(), 0)
            assert not _charge_collection_8616(object(), 1)
        assert ledger.census_work_units == limit + 1
    with segment_call_dependency_traversal_scope_8616() as fresh:
        assert fresh.census_work_limit == 20000
        assert fresh.census_work_units == 0


@pytest.mark.parametrize('inner', [1, 40000])
def test_nested_configuration_cannot_replace_ambient_budget(inner: int) -> None:
    with segment_call_dependency_traversal_scope_8616(census_work_limit=30000) as ledger:
        ledger.census_work_units = 123
        with pytest.raises(ValueError, match='ambient'), segment_call_dependency_traversal_scope_8616(census_work_limit=inner):
            pytest.fail('nested replacement admitted')
        assert ledger.census_work_limit == 30000
        assert ledger.census_work_units == 123


@pytest.mark.parametrize('invalid', [True, 0, -1, 1.5])
def test_invalid_request_budget_is_rejected(invalid: object) -> None:
    with pytest.raises((TypeError, ValueError)), segment_call_dependency_traversal_scope_8616(census_work_limit=invalid):
        pytest.fail('invalid budget admitted')


def test_selector_charges_configured_shared_limit_and_keeps_local_bound() -> None:
    with segment_call_dependency_traversal_scope_8616(census_work_limit=30000) as ledger:
        ledger.census_work_units = 20000
        budget = _Budget(time.monotonic() + 5, 2)
        assert budget.charge(2, 0)
        assert ledger.census_work_units == 20002
        assert not budget.charge(1, 0)
        assert budget.obligations[-1].kind is ObligationKind.BUDGET_EXCEEDED


def test_larger_work_allowance_does_not_renew_expired_deadline() -> None:
    with segment_call_dependency_traversal_scope_8616(census_work_limit=30000) as ledger:
        ledger.census_deadline = 0.0
        budget = _Budget(time.monotonic() + 5, 30000)
        assert not budget.charge(1, 0)
        assert budget.obligations[-1].kind is ObligationKind.DEADLINE_EXCEEDED
        assert not _charge_collection_8616(object(), 0)


def test_selector_batch_allowance_is_local_and_inherited() -> None:
    with segment_call_dependency_traversal_scope_8616(
        census_work_limit=100000, selector_batch_work_limit=25000,
    ) as ledger:
        with segment_call_dependency_traversal_scope_8616() as nested:
            assert nested is ledger
            assert nested.selector_batch_work_limit == 25000
        with pytest.raises(ValueError, match='ambient'), segment_call_dependency_traversal_scope_8616(
            selector_batch_work_limit=30000,
        ):
            pytest.fail('nested local cap reset admitted')
    with segment_call_dependency_traversal_scope_8616() as fresh:
        assert fresh.selector_batch_work_limit == 20000


@pytest.mark.parametrize('invalid', [True, 0, -1, 1.5])
def test_invalid_selector_batch_budget_is_rejected(invalid: object) -> None:
    with pytest.raises((TypeError, ValueError)), segment_call_dependency_traversal_scope_8616(
        selector_batch_work_limit=invalid,
    ):
        pytest.fail('invalid local budget admitted')


def test_batch_consumer_exposes_local_budget_obligation(monkeypatch: pytest.MonkeyPatch) -> None:
    from inertia.ir import declared_selector_invariant as selector

    def consume(_project: object, _projections: tuple, budget: _Budget, **_kwargs: object) -> tuple[bool]:
        assert budget.limit == 25000
        assert not budget.charge(25001, 0)
        return (False,)

    monkeypatch.setattr(selector, '_consume_selector_callsite_batch_8616', consume)
    obligations: list[selector.Obligation] = []
    with segment_call_dependency_traversal_scope_8616(
        census_work_limit=100000, selector_batch_work_limit=25000,
    ) as ledger:
        assert selector.consume_declared_selector_cs_preservation_batch_8616(
            object(), (), obligations=obligations,
        ) == (False,)
        assert ledger.census_work_units == 25001
    assert [item.kind for item in obligations] == [ObligationKind.BUDGET_EXCEEDED]


@pytest.mark.parametrize('ambient', [False, True])
def test_declared_preparation_owns_allowance_only_for_new_request(
    monkeypatch: pytest.MonkeyPatch, ambient: bool,
) -> None:
    from types import SimpleNamespace

    from inertia.ir import declared_entry_pipeline as pipeline
    from tests.ir.test_declared_function_entry_domain import _world
    from tests.ir.test_declared_function_entry_intake import _install

    project, boot, link = _world()
    _install(project, boot, link)
    captured = []

    def prepare(_project: object, _source: object, _admission: object) -> None:
        with segment_call_dependency_traversal_scope_8616() as current:
            captured.append((current.census_work_limit, current.selector_batch_work_limit,
                             current.census_work_units, current.census_deadline))

    monkeypatch.setattr(pipeline, '_prepare_native_entry_8616', prepare)
    if ambient:
        with segment_call_dependency_traversal_scope_8616(
            census_work_limit=100, selector_batch_work_limit=50,
        ) as outer:
            outer.census_work_units = 7
            outer.census_deadline = 0.0
            pipeline.prepare_declared_entry_pipeline_8616(project, SimpleNamespace(), link.artifact.function_addr)
            assert outer.census_work_limit == 100
            assert outer.census_deadline == 0.0
        assert captured == [(100, 50, 7, 0.0)]
    else:
        before = time.monotonic()
        pipeline.prepare_declared_entry_pipeline_8616(project, SimpleNamespace(), link.artifact.function_addr)
        assert len(captured) == 1
        shared, local, work, deadline = captured[0]
        assert (shared, local, work) == (128000, 25000, 0)
        assert before + 49 <= deadline <= time.monotonic() + 50
    with segment_call_dependency_traversal_scope_8616() as fresh:
        assert (fresh.census_work_limit, fresh.selector_batch_work_limit) == (20000, 20000)


@pytest.mark.parametrize('declared', [False, True])
@pytest.mark.parametrize('ambient', [False, True])
def test_scoped_replay_uses_declared_policy_without_renewing_outer_request(
    monkeypatch: pytest.MonkeyPatch, declared: bool, ambient: bool,
) -> None:
    from inertia.ir.scoped_function_ir_view import ScopedFunctionIRView8616
    from tests.frontend.test_declared_control_target_transport import _native_conversion

    _clinic, entry = _native_conversion('call')
    assert entry is not None
    captured = []

    def replay(_self: object, _scope: object, _mode: object) -> None:
        with segment_call_dependency_traversal_scope_8616() as current:
            captured.append((current.census_work_limit, current.selector_batch_work_limit,
                             current.census_work_units, current.census_deadline))

    # Isolate resource dispatch only; these mocks never return an admitted view.
    monkeypatch.setattr(ScopedFunctionIRView8616, '_consumption_bound_8616', lambda *_: True)
    monkeypatch.setattr(ScopedFunctionIRView8616, '_replay_authentic_8616', replay)
    scope = entry.scope if declared else None
    if ambient:
        with segment_call_dependency_traversal_scope_8616(
            census_work_limit=100, selector_batch_work_limit=50,
        ) as outer:
            outer.census_deadline = 0.0
            outer.census_work_units = 7
            assert entry.view.cfg_projection_for(scope) is None
        assert captured == [(100, 50, 7, 0.0)]
    else:
        before = time.monotonic()
        assert entry.view.cfg_projection_for(scope) is None
        shared, local, work, deadline = captured[0]
        assert (shared, local, work) == ((128000, 25000, 0) if declared else (20000, 20000, 0))
        if declared:
            assert before + 49 <= deadline <= time.monotonic() + 50
        else:
            assert deadline is None
