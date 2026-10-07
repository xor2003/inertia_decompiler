"""Tests for bounded parallel dispatch of focused decompile jobs."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest


def _import_roots() -> list[Path]:
    """Locate this test's module root and the real repository root."""
    container = Path(__file__).resolve().parents[2]
    roots = [container]
    if not (container / "inertia" / "cli" / "fork_timeout.py").is_file():
        # Mirrored staging overlay: the real repository is an ancestor.
        for ancestor in container.parents:
            if (ancestor / "inertia" / "cli" / "fork_timeout.py").is_file():
                roots.extend([ancestor, ancestor / "angr_platforms"])
                break
        else:
            raise RuntimeError("repository root not found")
    else:
        roots.append(container / "angr_platforms")
    return roots


for _path in reversed(_import_roots()):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from inertia.cli.fork_timeout import ForkChildExitError
import tools.dev.batch_decompile_procs as batch
import tools.dev.batch_decompile_scheduler as scheduler

_BARRIER_SECONDS = 8.0
_DEATH_POLL_SECONDS = 5.0


def _proc_name(argv: list[str]) -> str:
    """Extract the focused procedure name from a generated job argv."""
    return argv[argv.index("--proc") + 1]


def _observe_overlap(active_dir: Path, peak_log: Path, expected: int) -> int:
    """Retain a real saturation observation so departing peers cannot hide it.

    These tests require one observed overlap per cohort, not a barrier at each
    scheduling wave. Each child still reports its own measured peak; the witness
    only releases waiting peers after a child actually observed enough markers.
    """
    witness = peak_log.with_suffix(".overlap")
    peak = 0
    deadline = time.monotonic() + _BARRIER_SECONDS
    while time.monotonic() < deadline:
        count = sum(1 for _ in active_dir.iterdir())
        peak = max(peak, count)
        if count >= expected:
            witness.touch()
            break
        if witness.exists():
            break
        time.sleep(0.01)
    return peak


def _probe_cli_factory(active_dir: Path, peak_log: Path, expected: int):
    """Build a fake CLI that records how many job children ran concurrently."""

    def cli(argv: list[str]) -> int:
        name = _proc_name(argv)
        marker = active_dir / name
        marker.write_text(str(os.getpid()), encoding="utf-8")
        peak = _observe_overlap(active_dir, peak_log, expected)
        with peak_log.open("a", encoding="utf-8") as stream:
            stream.write(f"{name} {peak}\n")
        marker.unlink()
        return 0

    return cli


def _probe_work_factory(active_dir: Path, peak_log: Path, name: str, expected: int):
    """Build scheduler work that records how many children ran concurrently."""

    def work() -> str:
        marker = active_dir / name
        marker.write_text(str(os.getpid()), encoding="utf-8")
        peak = _observe_overlap(active_dir, peak_log, expected)
        with peak_log.open("a", encoding="utf-8") as stream:
            stream.write(f"{name} {peak}\n")
        marker.unlink()
        return name

    return work


def test_overlap_witness_releases_peers_without_inventing_their_peaks(tmp_path, monkeypatch):
    """A departed peer cannot force a full wait or inflate later observations."""
    active_dir = tmp_path / "active"
    active_dir.mkdir()
    first = active_dir / "first"
    first.touch()
    (active_dir / "second").touch()
    peak_log = tmp_path / "peaks.txt"

    def unexpected_wait(_seconds: float) -> None:
        pytest.fail("overlap was already observed; no barrier wait is needed")

    monkeypatch.setattr(time, "sleep", unexpected_wait)
    assert _observe_overlap(active_dir, peak_log, expected=2) == 2
    first.unlink()
    assert _observe_overlap(active_dir, peak_log, expected=2) == 1


def _read_peaks(peak_log: Path) -> list[int]:
    """Return the concurrency peak each job observed."""
    return [int(line.split()[1]) for line in peak_log.read_text(encoding="utf-8").splitlines()]


def _assert_dead(pid_file: Path) -> None:
    """Poll until the recorded process is reaped or fail with its state."""
    assert pid_file.exists(), "child never recorded its pid"
    pid = int(pid_file.read_text(encoding="utf-8").strip())
    deadline = time.monotonic() + _DEATH_POLL_SECONDS
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    pytest.fail(f"child process {pid} survived parent cleanup")


def _wait_for(path: Path, timeout: float = _BARRIER_SECONDS) -> None:
    """Wait until a marker file exists, deterministically gating children."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not path.exists():
        time.sleep(0.01)
    assert path.exists(), f"child readiness marker was not published: {path}"


def _descendant_still_runs(pid: int) -> bool:
    """A descendant is live work only while it runs; zombies are already dead."""
    try:
        waited, _status = os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        waited = 0
    if waited == pid:
        # The scheduler does not adopt grandchildren, but if this process
        # became the adoptive parent, reaping here keeps the table clean.
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return False
    # The state field sits right after the comm field's closing parenthesis.
    return stat.rpartition(")")[2].split()[0] not in {"Z", "X"}


def _assert_descendant_dead(pid_file: Path) -> None:
    """Poll until a group-killed descendant leaves the live-process table."""
    assert pid_file.exists(), "child never recorded its descendant pid"
    pid = int(pid_file.read_text(encoding="utf-8").strip())
    deadline = time.monotonic() + _DEATH_POLL_SECONDS
    while time.monotonic() < deadline:
        if not _descendant_still_runs(pid):
            return
        time.sleep(0.05)
    pytest.fail(f"descendant process {pid} survived process-group cleanup")


def _descendant_work_factory(child_pid_file: Path, descendant_pid_file: Path):
    """Build work that forks one same-group sleeping descendant, then idles."""

    def work() -> None:
        descendant_pid = os.fork()
        if descendant_pid == 0:
            try:
                time.sleep(60)
            finally:
                os._exit(0)
        descendant_pid_file.write_text(str(descendant_pid), encoding="utf-8")
        child_pid_file.write_text(str(os.getpid()), encoding="utf-8")
        time.sleep(60)

    return work


def test_bounded_jobs_actually_overlap(tmp_path, monkeypatch):
    """Two requested workers must run as live children at the same time."""
    active_dir = tmp_path / "active"
    active_dir.mkdir()
    peak_log = tmp_path / "peaks.txt"
    monkeypatch.setattr(
        batch.decompiler_cli, "main", _probe_cli_factory(active_dir, peak_log, expected=2)
    )
    out_dir = tmp_path / "out"
    argv = ["input.exe", "--out-dir", str(out_dir), "--proc", "alpha", "--proc", "beta"]
    try:
        returncode = batch.main([*argv, "--workers", "2"])
    except SystemExit:
        # The baseline serial API has no --workers; rerun under its contract
        # so the red failure shows real serialized children, not arg parsing.
        returncode = batch.main(argv)
    assert returncode == 0
    peaks = _read_peaks(peak_log)
    assert len(peaks) == 2
    assert max(peaks) >= 2, f"jobs never overlapped (peaks={peaks})"


def test_batch_parallel_report_preserves_input_order(tmp_path, monkeypatch):
    """Out-of-order completion must still produce input-ordered results."""
    fast_done = tmp_path / "fast.done"
    done_log = tmp_path / "done.txt"

    def cli(argv: list[str]) -> int:
        name = _proc_name(argv)
        if name == "slow":
            _wait_for(fast_done)
        with done_log.open("a", encoding="utf-8") as stream:
            stream.write(f"{name}\n")
        if name == "fast":
            # Publish only after the log is closed: announcing first lets the
            # slow child append before the supposed fast completion is visible.
            fast_done.write_text("done", encoding="utf-8")
        return 0

    monkeypatch.setattr(batch.decompiler_cli, "main", cli)
    out_dir = tmp_path / "out"
    returncode = batch.main(
        ["input.exe", "--out-dir", str(out_dir), "--proc", "slow", "--proc", "fast", "--workers", "2"]
    )
    assert returncode == 0
    assert done_log.read_text(encoding="utf-8").splitlines() == ["fast", "slow"]
    report = json.loads((out_dir / "batch_report.json").read_text(encoding="utf-8"))
    assert [item["proc"] for item in report["results"]] == ["slow", "fast"]


def test_batch_parallel_checkpoints_each_completed_job(tmp_path, monkeypatch):
    """Each completion must checkpoint; mid-run reports keep input order."""
    fast_done = tmp_path / "fast.done"
    snapshots: list[list[str]] = []
    real_write = batch._write_batch_report

    def spy(args, results, cross_unit=None):
        snapshots.append([item.proc for item in results])
        real_write(args, results, cross_unit)

    def cli(argv: list[str]) -> int:
        name = _proc_name(argv)
        if name == "slow":
            _wait_for(fast_done)
        else:
            fast_done.write_text("done", encoding="utf-8")
        return 0

    monkeypatch.setattr(batch, "_write_batch_report", spy)
    monkeypatch.setattr(batch.decompiler_cli, "main", cli)
    returncode = batch.main(
        [
            "input.exe", "--out-dir", str(tmp_path / "out"),
            "--proc", "slow", "--proc", "fast", "--workers", "2",
        ]
    )
    assert returncode == 0
    # One checkpoint per completion; each keeps results in input order.
    assert snapshots[0] == []
    assert snapshots[-1] == ["slow", "fast"]
    assert len(snapshots) == 3
    assert len(snapshots[1]) == 1
    assert snapshots[1][0] in {"slow", "fast"}


def test_batch_parallel_hard_exit_records_failure(tmp_path, monkeypatch):
    """A hard-exiting child must become a failed record, not end the batch."""

    def cli(argv: list[str]) -> int:
        name = _proc_name(argv)
        print(f"emitted {name}", flush=True)
        if name == "first":
            os._exit(3)
        return 0

    monkeypatch.setattr(batch.decompiler_cli, "main", cli)
    out_dir = tmp_path / "out"
    returncode = batch.main(
        ["input.exe", "--out-dir", str(out_dir), "--proc", "first", "--proc", "second", "--workers", "2"]
    )
    assert returncode == 1
    report = json.loads((out_dir / "batch_report.json").read_text(encoding="utf-8"))
    assert [(item["proc"], item["returncode"]) for item in report["results"]] == [
        ("first", 3),
        ("second", 0),
    ]
    assert (out_dir / "first.stdout.c").read_text(encoding="utf-8") == "emitted first\n"
    assert (out_dir / "second.stdout.c").read_text(encoding="utf-8") == "emitted second\n"


def test_batch_parallel_timeout_records_terminal_status(tmp_path, monkeypatch):
    """A job exceeding its bounded deadline must record the timeout contract."""
    from inertia.cli.cli_terminal_status import CliTerminalStatus, read_terminal_status

    def cli(argv: list[str]) -> int:
        if _proc_name(argv) == "stuck":
            time.sleep(60)
        return 0

    monkeypatch.setattr(batch.decompiler_cli, "main", cli)
    monkeypatch.setattr(batch, "focused_decompile_process_timeout", lambda _timeout: 1)
    out_dir = tmp_path / "out"
    returncode = batch.main(
        ["input.exe", "--out-dir", str(out_dir), "--proc", "stuck", "--proc", "done", "--workers", "2"]
    )
    assert returncode == 1
    report = json.loads((out_dir / "batch_report.json").read_text(encoding="utf-8"))
    assert [(item["proc"], item["returncode"]) for item in report["results"]] == [
        ("stuck", 3),
        ("done", 0),
    ]
    stderr_text = (out_dir / "stuck.stderr.txt").read_text(encoding="utf-8")
    assert read_terminal_status(stderr_text) is CliTerminalStatus.TIMEOUT


def test_batch_parallel_loud_error_kills_siblings(tmp_path, monkeypatch):
    """An unexpected child error must abort the batch without survivors."""
    sibling_pid = tmp_path / "sibling.pid"

    def cli(argv: list[str]) -> int:
        if _proc_name(argv) == "sleeper":
            sibling_pid.write_text(str(os.getpid()), encoding="utf-8")
            time.sleep(60)
            return 0
        _wait_for(sibling_pid)
        raise RuntimeError("analysis exploded")

    monkeypatch.setattr(batch.decompiler_cli, "main", cli)
    with pytest.raises(RuntimeError, match="analysis exploded"):
        batch.main(
            [
                "input.exe", "--out-dir", str(tmp_path / "out"),
                "--proc", "sleeper", "--proc", "boom", "--workers", "2",
            ]
        )
    _assert_dead(sibling_pid)


def test_batch_parallel_clean_exit_without_result_is_loud(tmp_path, monkeypatch):
    """A vanished IPC result must propagate instead of fabricating success."""

    def cli(argv: list[str]) -> int:
        if _proc_name(argv) == "ghost":
            os._exit(0)
        return 0

    monkeypatch.setattr(batch.decompiler_cli, "main", cli)
    with pytest.raises(ForkChildExitError):
        batch.main(
            [
                "input.exe", "--out-dir", str(tmp_path / "out"),
                "--proc", "ghost", "--proc", "beta", "--workers", "2",
            ]
        )


def test_batch_parent_interrupt_leaves_no_children(tmp_path, monkeypatch):
    """Interrupting the parent mid-dispatch must reap every running child."""
    sibling_pid = tmp_path / "sibling.pid"
    real_write = batch._write_batch_report

    def cli(argv: list[str]) -> int:
        if _proc_name(argv) == "sleeper":
            sibling_pid.write_text(str(os.getpid()), encoding="utf-8")
            time.sleep(60)
            return 0
        _wait_for(sibling_pid)
        return 0

    def interrupting_write(args, results, cross_unit=None):
        real_write(args, results, cross_unit)
        if results:
            raise KeyboardInterrupt

    monkeypatch.setattr(batch.decompiler_cli, "main", cli)
    monkeypatch.setattr(batch, "_write_batch_report", interrupting_write)
    with pytest.raises(KeyboardInterrupt):
        batch.main(
            [
                "input.exe", "--out-dir", str(tmp_path / "out"),
                "--proc", "gate", "--proc", "sleeper", "--workers", "2",
            ]
        )
    _assert_dead(sibling_pid)


@pytest.mark.parametrize("workers", ["0", "5"])
def test_batch_rejects_out_of_range_workers(tmp_path, workers):
    """The worker bound is a validated contract, not a silent clamp."""
    with pytest.raises(SystemExit):
        batch.main(["input.exe", "--out-dir", str(tmp_path / "out"), "--proc", "a", "--workers", workers])


def test_batch_workers_request_capped_to_selected_jobs(tmp_path, monkeypatch):
    """Requesting more workers than jobs must still dispatch correctly."""
    active_dir = tmp_path / "active"
    active_dir.mkdir()
    peak_log = tmp_path / "peaks.txt"
    monkeypatch.setattr(
        batch.decompiler_cli, "main", _probe_cli_factory(active_dir, peak_log, expected=2)
    )
    out_dir = tmp_path / "out"
    returncode = batch.main(
        [
            "input.exe", "--out-dir", str(out_dir),
            "--proc", "alpha", "--proc", "beta", "--workers", "4",
        ]
    )
    assert returncode == 0
    peaks = _read_peaks(peak_log)
    assert len(peaks) == 2
    assert max(peaks) == 2


@pytest.mark.parametrize("workers", ["1", "2"])
def test_batch_refuses_colliding_job_names(tmp_path, monkeypatch, workers):
    """Sanitized duplicate names must be refused before any job writes."""
    monkeypatch.setattr(batch.decompiler_cli, "main", lambda _argv: 0)
    job_file = tmp_path / "jobs.json"
    job_file.write_text(
        json.dumps({"jobs": [{"name": "a/b", "binary": "in.exe"}, {"name": "a_b", "binary": "in.exe"}]}),
        encoding="utf-8",
    )
    out_dir = tmp_path / "out"
    with pytest.raises(SystemExit, match="collide"):
        batch.main(["--out-dir", str(out_dir), "--job-file", str(job_file), "--workers", workers])
    report = json.loads((out_dir / "batch_report.json").read_text(encoding="utf-8"))
    assert report["results"] == []
    assert not (out_dir / "a_b.stdout.c").exists()


def test_batch_cross_unit_gated_until_all_jobs_succeed(tmp_path, monkeypatch):
    """Cross-unit linking must run only after every job individually passed."""
    from tools.compiler_toolchain.compiler_coverage_cross_unit import CrossUnitResult, CrossUnitStatus

    calls: list[list[str]] = []

    def fake_check(sources, object_path):
        calls.append([str(source) for source in sources])
        return CrossUnitResult(CrossUnitStatus.PASSED, tuple(str(s) for s in sources), (), 0, "")

    monkeypatch.setattr(batch, "check_cross_unit_c", fake_check)
    monkeypatch.setattr(batch.decompiler_cli, "main", lambda _argv: 0)
    passing_dir = tmp_path / "pass"
    returncode = batch.main(
        [
            "input.exe", "--out-dir", str(passing_dir),
            "--proc", "one", "--proc", "two", "--check-cross-unit", "--workers", "2",
        ]
    )
    assert returncode == 0
    assert len(calls) == 1
    report = json.loads((passing_dir / "batch_report.json").read_text(encoding="utf-8"))
    assert report["cross_unit"]["status"] == "passed"


def test_batch_cross_unit_not_attempted_when_any_job_fails(tmp_path, monkeypatch):
    """A failed parallel job must keep the cross-unit contract NOT_ATTEMPTED."""
    from tools.compiler_toolchain.compiler_coverage_cross_unit import CrossUnitResult, CrossUnitStatus

    calls: list[list[str]] = []

    def fake_check(sources, object_path):
        calls.append([str(source) for source in sources])
        return CrossUnitResult(CrossUnitStatus.PASSED, tuple(str(s) for s in sources), (), 0, "")

    def cli(argv: list[str]) -> int:
        return 2 if _proc_name(argv) == "bad" else 0

    monkeypatch.setattr(batch, "check_cross_unit_c", fake_check)
    monkeypatch.setattr(batch.decompiler_cli, "main", cli)
    failing_dir = tmp_path / "fail"
    returncode = batch.main(
        [
            "input.exe", "--out-dir", str(failing_dir),
            "--proc", "ok", "--proc", "bad", "--check-cross-unit", "--workers", "2",
        ]
    )
    assert returncode == 1
    assert calls == []
    report = json.loads((failing_dir / "batch_report.json").read_text(encoding="utf-8"))
    assert report["cross_unit"]["status"] == "not_attempted"


def test_msc6_batch_command_requests_bounded_workers(tmp_path):
    """The MS C focused batch must request the bounded worker contract."""
    import tools.compiler_toolchain.build_msc6_examples as build

    options = SimpleNamespace(
        exe_path=Path("input.exe"),
        out_dir=tmp_path,
        decompile_py=Path("decompile.py"),
        decompile_timeout=60,
        decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto",
        decompile_rizin_timeout=8,
        decompile_force_rizin_8616=False,
        decompile_pat_backend=None,
        decompile_signature_catalog=None,
        memory_model=SimpleNamespace(default_procedure_kind="NEAR"),
        decompile_c_name="out.c",
    )
    cmd = build._batch_decompile_command(
        options,
        batch_dir=tmp_path / "five",
        fallback_functions=("a", "b", "c", "d", "e"),
        binary_targets=None,
    )
    assert cmd[cmd.index("--workers") + 1] == str(build.MSC6_BATCH_MAX_WORKERS)
    cmd_two = build._batch_decompile_command(
        options,
        batch_dir=tmp_path / "two",
        fallback_functions=("a", "b"),
        binary_targets=None,
    )
    assert cmd_two[cmd_two.index("--workers") + 1] == "2"


def test_scheduler_bounds_concurrency_and_reports_all(tmp_path):
    """Concurrency never exceeds the bound while every job reports once."""
    active_dir = tmp_path / "active"
    active_dir.mkdir()
    peak_log = tmp_path / "peaks.txt"
    jobs = [
        scheduler.ScheduledJob(
            name=f"job{index}",
            work=_probe_work_factory(active_dir, peak_log, f"job{index}", expected=2),
            timeout=30,
        )
        for index in range(4)
    ]
    ends = []
    scheduler.run_jobs_bounded(jobs, workers=2, on_end=lambda _index, end: ends.append(end))
    assert sorted(end.index for end in ends) == [0, 1, 2, 3]
    assert all(end.kind is scheduler.JobEndKind.COMPLETED for end in ends)
    peaks = _read_peaks(peak_log)
    assert len(peaks) == 4
    assert max(peaks) == 2


def test_scheduler_timeout_kills_child_process_group(tmp_path):
    """A child past its deadline is killed and reported as timed out."""
    pid_file = tmp_path / "stuck.pid"

    def work() -> None:
        pid_file.write_text(str(os.getpid()), encoding="utf-8")
        time.sleep(60)

    ends = []
    scheduler.run_jobs_bounded(
        [scheduler.ScheduledJob("stuck", work, timeout=1)],
        workers=1,
        on_end=lambda _index, end: ends.append(end),
    )
    assert len(ends) == 1
    assert ends[0].kind is scheduler.JobEndKind.TIMED_OUT
    assert "Timed out after 1s" in ends[0].detail
    _assert_dead(pid_file)


def test_scheduler_hard_exit_yields_exited_end(tmp_path):
    """A child hard exit must produce the same failed record as serial jobs."""

    def dying() -> None:
        os._exit(4)

    ends = []
    scheduler.run_jobs_bounded(
        [
            scheduler.ScheduledJob("dying", dying, timeout=30),
            scheduler.ScheduledJob("ok", lambda: "fine", timeout=30),
        ],
        workers=2,
        on_end=lambda _index, end: ends.append(end),
    )
    by_index = {end.index: end for end in ends}
    assert by_index[0].kind is scheduler.JobEndKind.EXITED
    assert by_index[0].returncode == 4
    assert by_index[1].kind is scheduler.JobEndKind.COMPLETED
    assert by_index[1].value == "fine"


def test_scheduler_clean_exit_without_result_is_loud(tmp_path):
    """A clean child exit with no IPC result is transport failure, not success."""
    sibling_pid = tmp_path / "sibling.pid"

    def sleeper() -> None:
        sibling_pid.write_text(str(os.getpid()), encoding="utf-8")
        time.sleep(60)

    def ghost() -> None:
        _wait_for(sibling_pid)
        os._exit(0)

    with pytest.raises(ForkChildExitError):
        scheduler.run_jobs_bounded(
            [
                scheduler.ScheduledJob("ghost", ghost, timeout=30),
                scheduler.ScheduledJob("sleeper", sleeper, timeout=30),
            ],
            workers=2,
            on_end=lambda *_args: None,
        )
    _assert_dead(sibling_pid)


def test_scheduler_loud_child_error_kills_siblings(tmp_path):
    """An unexpected child exception must abort every surviving child."""
    sibling_pid = tmp_path / "sibling.pid"

    def sleeper() -> None:
        sibling_pid.write_text(str(os.getpid()), encoding="utf-8")
        time.sleep(60)

    def boom() -> None:
        _wait_for(sibling_pid)
        raise RuntimeError("analysis exploded")

    with pytest.raises(RuntimeError, match="analysis exploded"):
        scheduler.run_jobs_bounded(
            [
                scheduler.ScheduledJob("boom", boom, timeout=30),
                scheduler.ScheduledJob("sleeper", sleeper, timeout=30),
            ],
            workers=2,
            on_end=lambda *_args: None,
        )
    _assert_dead(sibling_pid)


def test_scheduler_truncated_result_frame_is_loud(tmp_path, monkeypatch):
    """A partial IPC frame must surface as transport failure, not a result."""
    import inertia.cli.fork_timeout as fork_timeout

    def truncated_write(fd: int, data: bytes) -> None:
        os.write(fd, data[: len(data) // 2])

    monkeypatch.setattr(fork_timeout, "_write_all", truncated_write)
    with pytest.raises(ForkChildExitError):
        scheduler.run_jobs_bounded(
            [scheduler.ScheduledJob("trunc", lambda: 0, timeout=30)],
            workers=1,
            on_end=lambda *_args: None,
        )


def test_scheduler_incomplete_eof_waits_for_actual_exit(tmp_path, monkeypatch):
    """Closing a partial frame must not let parent SIGKILL mask a clean exit."""
    release = tmp_path / "release-exit"
    child_pid = tmp_path / "child.pid"
    original_settle = scheduler._settle_job_child

    def partial_child(work, write_fd, read_fd, *, owns_process_group):
        del work, owns_process_group
        os.close(read_fd)
        child_pid.write_text(str(os.getpid()), encoding="utf-8")
        os.write(write_fd, (10).to_bytes(8, "little") + b"part")
        os.close(write_fd)
        _wait_for(release)
        os._exit(0)

    def settle_then_release(child):
        result = original_settle(child)
        # The real child cannot exit before the first reap attempt. Release
        # it only after that attempt; no timing-dependent sleep is required.
        release.write_text("exit", encoding="utf-8")
        return result

    monkeypatch.setattr(scheduler, "_run_child", partial_child)
    monkeypatch.setattr(scheduler, "_settle_job_child", settle_then_release)
    with pytest.raises(ForkChildExitError, match="incomplete result"):
        scheduler.run_jobs_bounded(
            [scheduler.ScheduledJob("partial", lambda: 0, timeout=30)],
            workers=1, on_end=lambda *_args: None,
        )
    _assert_dead(child_pid)


def test_scheduler_incomplete_eof_keeps_deadline_without_polling_closed_fd(tmp_path, monkeypatch):
    """A live child with closed IPC keeps its deadline without spinning at EOF."""
    child_pid = tmp_path / "child.pid"
    closed_fds: set[int] = set()
    original_settle = scheduler._settle_job_child
    original_select = scheduler.select.select
    ends = []

    def closed_child(work, write_fd, read_fd, *, owns_process_group):
        del work, owns_process_group
        os.close(read_fd)
        child_pid.write_text(str(os.getpid()), encoding="utf-8")
        os.close(write_fd)
        time.sleep(60)
        os._exit(0)

    def record_settle(child):
        closed_fds.add(child.read_fd)
        return original_settle(child)

    def select_open_fds(read_fds, write_fds, errors, timeout):
        assert not closed_fds.intersection(read_fds), "closed result pipe caused an EOF spin"
        return original_select(read_fds, write_fds, errors, timeout)

    monkeypatch.setattr(scheduler, "_run_child", closed_child)
    monkeypatch.setattr(scheduler, "_settle_job_child", record_settle)
    monkeypatch.setattr(scheduler.select, "select", select_open_fds)
    scheduler.run_jobs_bounded(
        [scheduler.ScheduledJob("closed", lambda: 0, timeout=1)],
        workers=1, on_end=lambda _index, end: ends.append(end),
    )
    assert [end.kind for end in ends] == [scheduler.JobEndKind.TIMED_OUT]
    _assert_dead(child_pid)


def test_scheduler_parent_interrupt_aborts_children(tmp_path):
    """Interrupting completion handling must kill every running child."""
    sibling_pid = tmp_path / "sibling.pid"

    def sleeper() -> None:
        sibling_pid.write_text(str(os.getpid()), encoding="utf-8")
        time.sleep(60)

    def gate() -> str:
        _wait_for(sibling_pid)
        return "done"

    def interrupting_end(_index: int, _end) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        scheduler.run_jobs_bounded(
            [
                scheduler.ScheduledJob("gate", gate, timeout=30),
                scheduler.ScheduledJob("sleeper", sleeper, timeout=30),
            ],
            workers=2,
            on_end=interrupting_end,
        )
    _assert_dead(sibling_pid)


@pytest.mark.parametrize("workers", [0, -1])
def test_scheduler_rejects_invalid_worker_count(workers):
    """The dispatch bound refuses non-positive worker requests."""
    with pytest.raises(ValueError):
        scheduler.run_jobs_bounded(
            [scheduler.ScheduledJob("a", lambda: 0, timeout=1)],
            workers=workers,
            on_end=lambda *_args: None,
        )


def test_scheduler_drain_propagates_genuine_read_error(tmp_path):
    """A real os.read failure must surface, not masquerade as pipe EOF."""
    child = scheduler._spawn_job_child(
        0, scheduler.ScheduledJob("reader", lambda: "done", timeout=30)
    )
    try:
        os.close(child.read_fd)
        child.read_fd = os.open(tmp_path, os.O_RDONLY)
        with pytest.raises(OSError):
            scheduler._drain_ready_fds({child.read_fd: child}, [child.read_fd])
    finally:
        scheduler._abort_active([child])


def test_scheduler_read_error_aborts_batch_with_cause(tmp_path, monkeypatch):
    """A genuine IPC read error must propagate through cleanup, not exit."""
    child_pid = tmp_path / "child.pid"
    real_spawn = scheduler._spawn_job_child

    def corrupting_spawn(index: int, job):
        child = real_spawn(index, job)
        # The spawn records the owned PID: the read failure can arrive
        # before the child's work gets a chance to report it.
        child_pid.write_text(str(child.pid), encoding="utf-8")
        os.close(child.read_fd)
        child.read_fd = os.open(tmp_path, os.O_RDONLY)
        return child

    monkeypatch.setattr(scheduler, "_spawn_job_child", corrupting_spawn)
    with pytest.raises(OSError):
        scheduler.run_jobs_bounded(
            [scheduler.ScheduledJob("sleeper", lambda: time.sleep(60), timeout=30)],
            workers=1,
            on_end=lambda *_args: None,
        )
    _assert_dead(child_pid)


@pytest.mark.parametrize(
    ("failure", "match", "allowed_signals"),
    [
        # A loud decode raises after the child is reaped: no signal is legal.
        ("loud_decode", "analysis exploded", 0),
        # The incomplete-frame path legitimately terminates before reaping.
        ("clean_exit", "without result", 1),
    ],
)
def test_scheduler_never_terminates_already_reaped_child(
    tmp_path, monkeypatch, failure, match, allowed_signals
):
    """A post-reap failure must not re-signal a collected child PID."""
    pid_file = tmp_path / "child.pid"
    terminated: list[int] = []
    real_terminate = scheduler._terminate_child

    def tracking_terminate(pid: int, *, owns_process_group: bool) -> None:
        terminated.append(pid)
        real_terminate(pid, owns_process_group=owns_process_group)

    monkeypatch.setattr(scheduler, "_terminate_child", tracking_terminate)

    if failure == "loud_decode":

        def work() -> None:
            pid_file.write_text(str(os.getpid()), encoding="utf-8")
            raise RuntimeError("analysis exploded")

        expected_error = RuntimeError
    else:

        def work() -> None:
            pid_file.write_text(str(os.getpid()), encoding="utf-8")
            os._exit(0)

        expected_error = ForkChildExitError

    with pytest.raises(expected_error, match=match):
        scheduler.run_jobs_bounded(
            [scheduler.ScheduledJob("victim", work, timeout=30)],
            workers=1,
            on_end=lambda *_args: None,
        )
    child_pid = int(pid_file.read_text(encoding="utf-8").strip())
    with pytest.raises(ChildProcessError):
        # The settle path already collected this child; it is not live work.
        os.waitpid(child_pid, os.WNOHANG)
    assert terminated.count(child_pid) <= allowed_signals


def test_scheduler_timeout_kills_descendant_in_group(tmp_path):
    """Deadline termination must reach a real forked descendant, not only the child."""
    child_pid = tmp_path / "child.pid"
    descendant_pid = tmp_path / "descendant.pid"
    ends = []
    scheduler.run_jobs_bounded(
        [
            scheduler.ScheduledJob(
                "tree", _descendant_work_factory(child_pid, descendant_pid), timeout=1
            )
        ],
        workers=1,
        on_end=lambda _index, end: ends.append(end),
    )
    assert len(ends) == 1
    assert ends[0].kind is scheduler.JobEndKind.TIMED_OUT
    _assert_dead(child_pid)
    _assert_descendant_dead(descendant_pid)


def test_scheduler_abort_kills_sibling_descendant(tmp_path):
    """Interruption cleanup must kill a surviving child's whole process group."""
    child_pid = tmp_path / "child.pid"
    descendant_pid = tmp_path / "descendant.pid"

    def gate() -> str:
        _wait_for(descendant_pid)
        return "done"

    def interrupting_end(_index: int, _end) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        scheduler.run_jobs_bounded(
            [
                scheduler.ScheduledJob("gate", gate, timeout=30),
                scheduler.ScheduledJob(
                    "tree", _descendant_work_factory(child_pid, descendant_pid), timeout=30
                ),
            ],
            workers=2,
            on_end=interrupting_end,
        )
    _assert_dead(child_pid)
    _assert_descendant_dead(descendant_pid)
