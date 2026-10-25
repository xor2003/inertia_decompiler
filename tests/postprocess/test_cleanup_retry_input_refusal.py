"""Cleanup retries must not attempt to repair refused source call positions.

Layer: Postprocess orchestration regression tests.
Responsibility: retain the original tree and refusal when cleanup cannot supply
missing Alias evidence, while preserving retries for other existing cases.
"""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from inertia.pipeline import call_stack_input_outcome as contracts
from inertia.postprocess import decompiler_postprocess_stage as owner

pytestmark = pytest.mark.decompiler

_RETRIES = (
    "_salvage_direct_stack_update_after_discard_8616",
    "_salvage_direct_global_update_after_discard_8616",
    "_salvage_segmented_global_materialization_after_discard_8616",
    "_salvage_signed_idiv_stack_move_after_discard_8616",
    "_salvage_direct_stack_move_after_discard_8616",
    "_salvage_callsite_stack_args_after_discard_8616",
    "_salvage_flag_cleanup_after_discard_8616",
    "_salvage_dce_after_discard_8616",
)


def _outcome(failure: contracts.CallStackInputFailure8616 | None) -> contracts.CallStackInputResult8616:
    """Use the actual publication schema for a materialized or refused input."""
    refused = failure is not None
    return contracts.CallStackInputResult8616(
        status=contracts.CallStackInputStatus8616.REFUSED if refused else contracts.CallStackInputStatus8616.STABLE,
        stats=contracts.CallStackInputStats8616(1, 0 if refused else 1, 0 if refused else 1,
                                             0 if refused else 1, 0, refusal_count=int(refused)),
        failure=failure,
    )


def _collect(monkeypatch: pytest.MonkeyPatch, outcome: object) -> tuple[list[str], object, object]:
    """Observe real retry selection without executing unrelated cleanup passes."""
    called: list[str] = []
    for name in _RETRIES:
        def retry(*args: object, _name: str = name, **kwargs: object) -> int:
            called.append(_name)
            return 0
        monkeypatch.setattr(owner, name, retry)
    tree = object()
    codegen = SimpleNamespace(
        _inertia_structuring_validation_failed=False,
        _inertia_call_stack_input_lowering_8616=outcome,
        cfunc=SimpleNamespace(statements=tree),
    )
    owner._collect_discard_salvages_8616(
        SimpleNamespace(codegen=codegen), validation_mode="live_out", snapshot_function_info={},
        destructive_discard_delta=False, destructive_salvage_family=None, function=None, log=Mock(),
    )
    assert codegen.cfunc.statements is tree
    assert codegen._inertia_call_stack_input_lowering_8616 is outcome
    return called, tree, codegen


def test_unknown_call_position_skips_cleanup_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    """A retained source-proof refusal cannot be repaired by cleanup passes."""
    outcome = _outcome(contracts.CallStackInputFailure8616.POSITION_UNPROVEN)
    called, _tree, _codegen = _collect(monkeypatch, outcome)
    assert called == []
    assert outcome.status is contracts.CallStackInputStatus8616.REFUSED
    assert outcome.stats.materialized_count == 0


@pytest.mark.parametrize("outcome", (None, _outcome(None), _outcome(contracts.CallStackInputFailure8616.CALL_IDENTITY)))
def test_other_retry_selection_is_preserved(monkeypatch: pytest.MonkeyPatch, outcome: object) -> None:
    """Missing publication and other outcomes preserve the existing retry path."""
    called, _tree, _codegen = _collect(monkeypatch, outcome)
    assert called == list(_RETRIES)


def test_missing_codegen_publication_is_a_typed_nonresult() -> None:
    """A backend that did not run this lowering has no recorded outcome."""
    assert contracts.call_stack_input_lowering_result_8616(SimpleNamespace()) is None


def test_malformed_codegen_publication_is_loud() -> None:
    """A corrupt third-party extension slot cannot silently become no evidence."""
    with pytest.raises(TypeError):
        contracts.call_stack_input_lowering_result_8616(SimpleNamespace(_inertia_call_stack_input_lowering_8616="refused"))


def _codegen_for_postprocess(outcome: object) -> SimpleNamespace:
    """Build a minimal structured-codegen surface carrying one call-input outcome."""
    return SimpleNamespace(
        _inertia_call_stack_input_lowering_8616=outcome,
        cfunc=SimpleNamespace(statements=SimpleNamespace(), addr=None),
    )


def test_position_refusal_selector_returns_the_published_refusal() -> None:
    """The early-refusal selector returns only the unproven-position outcome."""
    outcome = _outcome(contracts.CallStackInputFailure8616.POSITION_UNPROVEN)
    codegen = _codegen_for_postprocess(outcome)
    assert owner._call_stack_input_position_refusal_8616(codegen) is outcome


@pytest.mark.parametrize(
    "outcome",
    (None, _outcome(None), _outcome(contracts.CallStackInputFailure8616.CALL_IDENTITY)),
)
def test_position_refusal_selector_ignores_other_outcomes(outcome: object) -> None:
    """Missing, stable, and differently refused outcomes keep the normal path."""
    codegen = _codegen_for_postprocess(outcome)
    assert owner._call_stack_input_position_refusal_8616(codegen) is None


def test_position_unproven_refusal_refuses_postprocess_early(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unproven call positions make guarded cleanup necessarily fail; skip it early."""
    invoked: list[str] = []
    forbidden = (
        "_decompiler_postprocess_passes_for_function",
        "_postprocess_runtime_config_8616",
        "_transfer_typed_conditions_once_8616",
        "_postprocess_run_bootstrap_steps_8616",
        "_postprocess_run_optimization_step_8616",
        "_postprocess_run_pass_specs_8616",
        "_regenerate_final_postprocess_text_8616",
    )
    for name in forbidden:
        def _forbidden(*args: object, _name: str = name, **kwargs: object) -> None:
            invoked.append(_name)
            raise AssertionError(f"{_name} must not run after a position-unproven refusal")
        monkeypatch.setattr(owner, name, _forbidden)
    outcome = _outcome(contracts.CallStackInputFailure8616.POSITION_UNPROVEN)
    codegen = _codegen_for_postprocess(outcome)
    project = SimpleNamespace()
    result = owner._postprocess_codegen_8616(project, codegen)
    assert result is False
    assert codegen._inertia_postprocess_validation_failed is True
    assert codegen._inertia_postprocess_validation_failure_pass is None
    assert "call_interfaces" in codegen._inertia_postprocess_validation_failure_error
    assert "positions unproven" in codegen._inertia_postprocess_validation_failure_error
    assert codegen._inertia_postprocess_changed is False
    assert project._inertia_decompiler_stage == "postprocess"
    assert invoked == []
