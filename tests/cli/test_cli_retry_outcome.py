"""A retry that never starts cannot overwrite completed semantic evidence."""
from types import SimpleNamespace

import pytest

from inertia.cli import cli_decompilation as cli


def _run() -> cli._DecompileRun8616:
    """Build only the state needed by the real isolated-retry methods."""
    run = cli._DecompileRun8616.__new__(cli._DecompileRun8616)
    run.allow_isolated_retry = True
    run.binary_path = "unused.exe"
    run.project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0, max_addr=0x1000)),
    )
    run.function = SimpleNamespace(addr=0x100, name="fixture")
    run.deadline = 100.0
    run.timeout = 20
    run.isolated_retry_budget_exhausted = False
    return run


@pytest.mark.parametrize("threads", [1, 4])
def test_expired_unstarted_retry_preserves_result(
    monkeypatch: pytest.MonkeyPatch, threads: int,
) -> None:
    """Both fork and nested routes leave the caller's result intact."""
    run = _run()
    monkeypatch.setattr(cli.threading, "active_count", lambda: threads)
    monkeypatch.setattr(cli.time, "monotonic", lambda: 101.0)
    assert run._retry_in_isolated_project() is None
    assert run.isolated_retry_budget_exhausted


def test_retry_deadline_cannot_replace_validation_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """The deadline may expire between admission and launching the retry."""
    run = _run()
    run.best_status = "validation_failed"
    run.best_payload = {"evidence": "retained"}
    original_payload = run.best_payload
    ticks = iter([80.0, 101.0])
    monkeypatch.setattr(cli.threading, "active_count", lambda: 4)
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(ticks))
    assert run._call_semantics_retry_attempt_8616() is None
    assert run.best_status == "validation_failed"
    assert run.best_payload is original_payload
    assert run.isolated_retry_budget_exhausted


def test_started_retry_timeout_remains_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    """An actual attempted fork timeout remains distinguishable from no attempt."""
    run = _run()
    ticks = iter([80.0, 101.0])
    monkeypatch.setattr(cli.threading, "active_count", lambda: 1)
    monkeypatch.setattr(cli.time, "monotonic", lambda: next(ticks))

    def timed_out(*args: object, **kwargs: object) -> object:
        raise TimeoutError("attempt exceeded its budget")

    monkeypatch.setattr(cli, "_run_with_timeout_in_fork", timed_out)
    result = run._retry_in_isolated_project()
    assert result is not None and result[0] == "timeout"
    assert not run.isolated_retry_budget_exhausted


def test_successful_retry_is_preserved(monkeypatch: pytest.MonkeyPatch) -> None:
    """A completed retry still returns its actual result."""
    run = _run()
    monkeypatch.setattr(cli.threading, "active_count", lambda: 1)
    monkeypatch.setattr(cli.time, "monotonic", lambda: 80.0)
    result = ("ok", "int fixture(void) { return 1; }")
    monkeypatch.setattr(cli, "_run_with_timeout_in_fork", lambda *args, **kwargs: result)
    assert run._retry_in_isolated_project() == result
    assert not run.isolated_retry_budget_exhausted
