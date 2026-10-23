"""Terminal ``PipelineHardError`` disables owned outer retry lanes.

A ``PipelineHardError`` is a per-function pipeline contract failure: the typed
``TerminalDecompileFailure8616`` marker crossing the
``_decompile_function_with_stats``/``FunctionWorkResult`` boundary must set
``skip_heavy_fallbacks`` so structurer, direct-address and non-optimized
fallback lanes never repeat the identical failed invariant. Ordinary
recoverable failures keep retry eligibility, and sweeps continue to the next
function.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

import inertia.cli.cli_core as cli_core
import inertia.cli.cli_decompilation as cli_decompilation
from inertia.cli.cli_core import _finalize_work_result_8616, _validation_failed_retry_gate_8616
from inertia.cli.cli_decompilation import _decompile_function_with_stats
from inertia.cli.direct_addr_failure_family import FailureFamilyState
from inertia.cli.work_items import (
    FunctionWorkItem,
    FunctionWorkResult,
    TerminalDecompileFailure8616,
)
from inertia.pipeline.errors import PipelineHardError

_FUNC_ADDR = 0x1C1A


def _hard_error() -> PipelineHardError:
    return PipelineHardError(
        "declared entry scoped CFG is unproved",
        layer="ir",
        function_addr=_FUNC_ADDR,
        details={"scope": "unbound"},
    )


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


def _work_ctx(function: SimpleNamespace) -> cli_core._WorkRunCtx8616:
    item = FunctionWorkItem(index=1, function_cfg=SimpleNamespace(), function=function)
    return cli_core._WorkRunCtx8616(
        item=item,
        api_style="default",
        binary_path=None,
        lst_metadata=None,
        cod_metadata=None,
        synthetic_globals=None,
        effective_timeout=5,
        enable_structured_simplify=True,
        enable_postprocess=True,
        allow_isolated_retry=True,
        force_isolated_project=False,
        process_isolated_worker=False,
        failure_family_state=FailureFamilyState(),
    )


def _finalize(*, terminal: bool) -> FunctionWorkResult:
    return _finalize_work_result_8616(
        _work_ctx(_stats_function("sub_1c1a", _FUNC_ADDR)),
        status="validation_failed",
        payload="Pipeline contract violation: declared entry scoped CFG is unproved",
        partial_payload=None,
        debug_output="",
        tail_validation_snapshot=None,
        elapsed=0.01,
        block_count=0,
        byte_count=0,
        decompile_project=SimpleNamespace(),
        decompile_function=_stats_function("sub_1c1a", _FUNC_ADDR),
        decompile_cfg=SimpleNamespace(),
        cache_key=None,
        tail_validation_enabled=False,
        expected_validation_stages=(),
        terminal_failure=(
            TerminalDecompileFailure8616(
                message="declared entry scoped CFG is unproved",
                layer="ir",
                function_addr=_FUNC_ADDR,
                details={"scope": "unbound"},
            )
            if terminal
            else None
        ),
    )


def _gate(result: FunctionWorkResult) -> bool:
    return _validation_failed_retry_gate_8616(
        SimpleNamespace(addr=None),
        SimpleNamespace(arch=SimpleNamespace(name="86_16")),
        result,
        None,
        None,
    )


def test_stats_emits_terminal_marker_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """The source producer runs once; the marker preserves the typed failure."""
    calls: list[int] = []

    def _raising_decompile(*args: Any, **kwargs: Any) -> tuple[str, str]:
        calls.append(1)
        raise _hard_error()

    monkeypatch.setattr(cli_decompilation, "_decompile_function", _raising_decompile)
    status, _payload, _partial, _blocks, _bytes, _elapsed, marker = _decompile_function_with_stats(
        SimpleNamespace(),
        SimpleNamespace(),
        _stats_function("sub_1c1a", _FUNC_ADDR),
        5,
        "default",
    )
    assert status == "validation_failed"
    assert calls == [1]
    assert isinstance(marker, TerminalDecompileFailure8616)
    assert marker.layer == "ir"
    assert marker.function_addr == _FUNC_ADDR
    assert marker.details == {"scope": "unbound"}
    assert marker.message == "declared entry scoped CFG is unproved"


def test_ordinary_failure_has_no_terminal_marker(monkeypatch: pytest.MonkeyPatch) -> None:
    """Recoverable empties do not mark the result terminal."""
    monkeypatch.setattr(
        cli_decompilation,
        "_decompile_function",
        lambda *args, **kwargs: ("empty", "Decompiler did not produce code."),
    )
    status, _payload, _partial, _blocks, _bytes, _elapsed, marker = _decompile_function_with_stats(
        SimpleNamespace(),
        SimpleNamespace(),
        _stats_function("sub_1c1a", _FUNC_ADDR),
        5,
        "default",
    )
    assert status == "empty"
    assert marker is None


def test_terminal_marker_sets_skip_heavy_fallbacks() -> None:
    """Work-result provenance disables every heavy fallback lane for the function."""
    terminal_result = _finalize(terminal=True)
    ordinary_result = _finalize(terminal=False)
    assert terminal_result.skip_heavy_fallbacks is True
    assert terminal_result.status == "validation_failed"
    assert ordinary_result.skip_heavy_fallbacks is False


def test_outer_retry_gate_blocks_terminal_keeps_ordinary() -> None:
    """The real retry gate admits zero retries for terminal, retries for ordinary."""
    attempts: list[int] = []

    def _counted_retry() -> None:
        attempts.append(1)

    terminal_result = _finalize(terminal=True)
    ordinary_result = _finalize(terminal=False)
    if _gate(terminal_result):
        _counted_retry()
    assert attempts == []
    if _gate(ordinary_result):
        _counted_retry()
    assert attempts == [1]


def test_sweep_continues_after_terminal_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """A terminal failure on one function does not abort the binary sweep."""
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
    assert isinstance(first[6], TerminalDecompileFailure8616)
    assert second[0] == "ok"
    assert second[6] is None
