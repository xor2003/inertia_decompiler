"""Terminal ``PipelineHardError`` propagation across the angr/CLI boundary.

A ``PipelineHardError`` raised inside ``Decompiler._decompile_with_cache`` is
a per-function pipeline contract failure: it must escape angr's
``Analysis._resilience`` (which otherwise records every ``Exception`` and lets
``Decompiler.__init__`` retry the identical failed invariant under the basic
preset), surface as an honest ``validation_failed`` result with its typed
context preserved, and leave the whole-binary sweep free to continue with the
next function. Ordinary recoverable errors must keep upstream resilience and
basic-preset fallback behavior.
"""

from __future__ import annotations

from collections import defaultdict
from types import SimpleNamespace
from typing import Any

import pytest
from angr.analyses.decompiler.decompiler import Decompiler

import inertia.cli.cli_decompilation as cli_decompilation
from inertia.cli.cli_decompilation import _decompile_function_with_stats
from inertia.frontend.x86_16.analysis_failures import (
    guard_angr_analysis_hard_failure_passthrough,
)
from inertia.pipeline.errors import PipelineHardError

_FUNC_ADDR = 0x1C1A


def _fake_func() -> SimpleNamespace:
    """Fabricate the function/CFG/kb/project surface ``Decompiler.__init__`` consumes."""
    return SimpleNamespace(addr=_FUNC_ADDR, name="sub_1c1a", evicted=False)


def _fake_kb(func: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(functions={func.addr: func}, decompilations={})


def _fake_project(kb: SimpleNamespace) -> SimpleNamespace:
    return SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        simos=SimpleNamespace(name="simdos"),
        kb=kb,
    )


def _init_decompiler(attempts: list[int], failure: BaseException) -> Decompiler:
    """Drive ``Decompiler.__init__`` with a counted fake decompilation producer.

    Mirrors the ``AnalysisFactory.prep`` wrapper attribute setup so the real
    ``Analysis._resilience`` and real ``Decompiler`` basic-preset retry lane
    decide how the producer failure is handled.
    """
    func = _fake_func()
    kb = _fake_kb(func)
    dec = object.__new__(Decompiler)
    dec.named_errors = defaultdict(list)
    dec.errors = []
    dec.log = []
    dec._fail_fast = False
    dec._name = "Decompiler"
    dec.project = _fake_project(kb)
    dec.kb = kb
    dec._progress_callback = None
    dec._show_progressbar = False

    def _counting_decompile_with_cache(self: Decompiler) -> None:
        attempts.append(1)
        raise failure

    dec._decompile_with_cache = lambda: _counting_decompile_with_cache(dec)
    Decompiler.__init__(
        dec,
        func.addr,
        cfg=SimpleNamespace(name="cfg"),
        use_cache=False,
        update_cache=False,
    )
    return dec


def _hard_error() -> PipelineHardError:
    return PipelineHardError(
        "declared entry scoped CFG is unproved",
        layer="ir",
        function_addr=_FUNC_ADDR,
        details={"scope": "unbound"},
    )


def test_hard_error_unguarded_resilience_swallows_and_retries() -> None:
    """Baseline: upstream angr logs the failure and repeats it under the basic preset."""
    attempts: list[int] = []
    dec = _init_decompiler(attempts, _hard_error())
    assert attempts == [1, 1]
    assert dec.errors
    assert all(
        isinstance(entry.exc_value, PipelineHardError) for entry in dec.errors
    )
    assert dec.codegen is None


def test_hard_error_terminal_through_guarded_resilience() -> None:
    """Under the guard the typed error escapes once, before the basic-preset retry."""
    attempts: list[int] = []
    with (
        guard_angr_analysis_hard_failure_passthrough(),
        pytest.raises(PipelineHardError) as excinfo,
    ):
        _init_decompiler(attempts, _hard_error())
    assert attempts == [1]
    assert excinfo.value.layer == "ir"
    assert excinfo.value.function_addr == _FUNC_ADDR
    assert excinfo.value.details == {"scope": "unbound"}


def test_ordinary_error_still_resilient_under_guard() -> None:
    """Non-hard errors keep upstream resilience logging and basic-pretry fallback."""
    attempts: list[int] = []
    with guard_angr_analysis_hard_failure_passthrough():
        dec = _init_decompiler(attempts, ValueError("ordinary recoverable failure"))
    assert attempts == [1, 1]
    assert all(isinstance(entry.exc_value, ValueError) for entry in dec.errors)
    assert dec.codegen is None


def _stats_function(name: str, addr: int) -> SimpleNamespace:
    return SimpleNamespace(
        addr=addr,
        name=name,
        project=None,
        info={},
        blocks=(),
        _local_blocks={},
        block_addrs_set=set(),
    )


def test_stats_maps_hard_error_to_terminal_validation_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The stats boundary converts the hard error once, preserving typed details."""
    calls: list[int] = []

    def _raising_decompile(*args: Any, **kwargs: Any) -> tuple[str, str]:
        calls.append(1)
        raise _hard_error()

    monkeypatch.setattr(cli_decompilation, "_decompile_function", _raising_decompile)
    status, payload, *_ = _decompile_function_with_stats(
        SimpleNamespace(),
        SimpleNamespace(),
        _stats_function("sub_1c1a", _FUNC_ADDR),
        5,
        "default",
    )
    assert status == "validation_failed"
    assert calls == [1]
    assert "Pipeline contract violation" in payload
    assert "declared entry scoped CFG is unproved" in payload
    assert "layer=ir" in payload
    assert "function=0x1c1a" in payload
    assert "scope" in payload


def test_sweep_continues_after_hard_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A per-function hard failure does not abort the whole-binary sweep."""
    outcomes = iter([None, ("ok", "int sub_1c20(void) { return 0; }")])

    def _flaky_decompile(*args: Any, **kwargs: Any) -> tuple[str, str]:
        outcome = next(outcomes)
        if outcome is None:
            raise _hard_error()
        return outcome

    monkeypatch.setattr(cli_decompilation, "_decompile_function", _flaky_decompile)
    project = SimpleNamespace()
    first = _decompile_function_with_stats(
        project, SimpleNamespace(), _stats_function("sub_1c1a", _FUNC_ADDR), 5, "default"
    )
    second = _decompile_function_with_stats(
        project, SimpleNamespace(), _stats_function("sub_1c20", 0x1C20), 5, "default"
    )
    assert first[0] == "validation_failed"
    assert second[0] == "ok"
    assert second[1] == "int sub_1c20(void) { return 0; }"


def test_guard_delegates_to_installed_resilience(monkeypatch: pytest.MonkeyPatch) -> None:
    """An installed upstream policy remains the owner of recoverable errors."""
    from contextlib import contextmanager

    from angr.analyses.analysis import Analysis

    original = Analysis._resilience
    visits = []

    @contextmanager
    def policy(analysis, name=None, exception=Exception):
        visits.append(name)
        with original(analysis, name=name, exception=exception):
            yield

    monkeypatch.setattr(Analysis, '_resilience', policy)
    attempts = []
    with guard_angr_analysis_hard_failure_passthrough():
        result = _init_decompiler(attempts, ValueError('recoverable'))
    assert visits == [None, None]
    assert attempts == [1, 1]
    assert len(result.errors) == 2
    assert Analysis._resilience is policy


def test_terminal_guard_preserves_exception_identity_and_cause() -> None:
    """Terminal transport must retain the original exception and causal link."""
    failure = _hard_error()
    cause = ValueError('original producer cause')
    failure.__cause__ = cause
    with guard_angr_analysis_hard_failure_passthrough(), pytest.raises(PipelineHardError) as caught:
        _init_decompiler([], failure)
    assert caught.value is failure
    assert caught.value.__cause__ is cause


def test_terminal_failure_skips_direct_sidecar_retry() -> None:
    """Terminal failures cannot enter the sidecar lane outside its budget gate."""
    from inertia.cli.cli_core import _DirectAddrCliRun8616

    def forbidden_retry() -> None:
        pytest.fail("terminal failure entered sidecar retry")

    run = SimpleNamespace(
        fast_direct_probe=False,
        direct_result=SimpleNamespace(
            status="validation_failed", skip_heavy_fallbacks=True,
        ),
        precise_sidecar_regions=True,
        lst_metadata=object(),
        timeout_was_explicit=False,
        _phase_direct_emit_batch_8616_part0_8616_b3_zb0=forbidden_retry,
        _phase_direct_emit_batch_8616_part0_8616_b3_zb1=forbidden_retry,
    )
    assert _DirectAddrCliRun8616._phase_direct_emit_batch_8616_part0_8616_b3(run) is None


def test_direct_run_retains_terminal_failure() -> None:
    """The real slotted CLI state must accept terminal provenance at runtime."""
    from inertia.cli.cli_core import _DirectAddrCliRun8616
    from inertia.cli.work_items import TerminalDecompileFailure8616

    run = _DirectAddrCliRun8616(context=SimpleNamespace())
    marker = TerminalDecompileFailure8616("failure", "ir", _FUNC_ADDR, {})
    run.direct_terminal_failure = marker
    assert run.direct_terminal_failure is marker
