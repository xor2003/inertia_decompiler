"""Contracts for source-bound MS C runtime-gate artifact reuse."""

from __future__ import annotations

import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
from pytest import MonkeyPatch

from scripts import msc6_runtime_gate_artifacts as artifact_gate
from scripts.msc6_runtime_gate_artifacts import (
    MSC6RuntimeGateInputs,
    load_or_run_msc6_runtime_gate,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _write_fake_gate(path: Path, *, marker: str = "first") -> None:
    path.write_text(
        "\n".join(
            (
                "import argparse",
                "import time",
                "from pathlib import Path",
                "",
                "parser = argparse.ArgumentParser()",
                'parser.add_argument("--example")',
                'parser.add_argument("--out-dir", type=Path)',
                'args, _unknown = parser.parse_known_args()',
                "counter = args.out_dir.parent.parent / 'producer-count.txt'",
                "count = int(counter.read_text()) if counter.exists() else 0",
                "counter.write_text(str(count + 1))",
                "time.sleep(0.2)",
                "args.out_dir.mkdir(parents=True, exist_ok=True)",
                f"(args.out_dir / 'artifact.txt').write_text({marker!r})",
                "print('status=passed')",
                "print('run_exit=255')",
                "",
            )
        ),
        encoding="utf-8",
    )


def _inputs(tmp_path: Path) -> MSC6RuntimeGateInputs:
    gate_path = tmp_path / "fake_gate.py"
    _write_fake_gate(gate_path)
    executable = tmp_path / "SAMPLE.EXE"
    for path in (
        executable,
        executable.with_suffix(".COD"),
        executable.with_suffix(".MAP"),
        executable.with_suffix(".C"),
    ):
        path.write_bytes(path.name.encode("ascii"))
    kvikdos = tmp_path / "kvikdos"
    kvikdos.write_bytes(b"emulator")
    msc6_root = tmp_path / "msc6"
    msc6_root.mkdir()
    (msc6_root / "compiler.exe").write_bytes(b"compiler")
    return MSC6RuntimeGateInputs(
        repo_root=REPO_ROOT,
        cache_root=tmp_path / "cache",
        fallback_output_root=tmp_path / "fallback",
        runtime_gate_path=gate_path,
        kvikdos_path=kvikdos,
        msc6_root=msc6_root,
        examples=(("sample", executable),),
    )


def test_runtime_gate_cache_reuses_verified_artifacts(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)

    produced = load_or_run_msc6_runtime_gate(inputs)
    reused = load_or_run_msc6_runtime_gate(inputs)

    assert not produced.cache_hit
    assert reused.cache_hit
    assert reused.results["sample"] is not None
    assert (inputs.cache_root / "producer-count.txt").read_text(encoding="utf-8") == "1"


def test_runtime_gate_cache_rebuilds_corrupt_artifact(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    produced = load_or_run_msc6_runtime_gate(inputs)
    artifact = produced.output_root / "sample_runtime_gate" / "artifact.txt"
    artifact.write_text("corrupt", encoding="utf-8")

    rebuilt = load_or_run_msc6_runtime_gate(inputs)

    assert not rebuilt.cache_hit
    assert artifact.read_text(encoding="utf-8") == "first"
    assert (inputs.cache_root / "producer-count.txt").read_text(encoding="utf-8") == "2"


def test_runtime_gate_cache_key_tracks_gate_content(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)
    first = load_or_run_msc6_runtime_gate(inputs)
    _write_fake_gate(inputs.runtime_gate_path, marker="second")

    second = load_or_run_msc6_runtime_gate(inputs)

    assert first.output_root != second.output_root
    assert not second.cache_hit
    assert (second.output_root / "sample_runtime_gate" / "artifact.txt").read_text() == "second"


def test_runtime_gate_cache_serializes_concurrent_producers(tmp_path: Path) -> None:
    inputs = _inputs(tmp_path)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _index: load_or_run_msc6_runtime_gate(inputs), range(2)))

    assert sorted(result.cache_hit for result in results) == [False, True]
    assert (inputs.cache_root / "producer-count.txt").read_text(encoding="utf-8") == "1"


@pytest.mark.parametrize("timed_out", [False, True])
@pytest.mark.parametrize("cacheable", [False, True])
def test_incomplete_batch_artifacts_survive_another_producer(
    tmp_path: Path, monkeypatch: MonkeyPatch, timed_out: bool, cacheable: bool,
) -> None:
    """A sibling failure must not expose successful evidence to retry deletion."""
    inputs = _inputs(tmp_path)
    inputs = replace(inputs, examples=(*inputs.examples, ("sibling", inputs.examples[0][1])))
    monkeypatch.setattr(artifact_gate, "_cache_key", lambda _inputs: "stable-inputs" if cacheable else None)
    attempts = 0

    def run_batch(_inputs, output_root):
        nonlocal attempts
        attempts += 1
        artifact = output_root / "sample.dec.txt"
        artifact.write_text(str(attempts), encoding="utf-8")
        accepted = subprocess.CompletedProcess([], 0, "status=passed run_exit=255", "")
        sibling = accepted
        if attempts == 1:
            sibling = (
                subprocess.TimeoutExpired(["gate"], 1)
                if timed_out else subprocess.CompletedProcess([], 1, "", "failed")
            )
        return {"sample": accepted, "sibling": sibling}

    monkeypatch.setattr(artifact_gate, "_run_all", run_batch)
    first = load_or_run_msc6_runtime_gate(inputs)
    second = load_or_run_msc6_runtime_gate(inputs)

    assert (first.output_root / "sample.dec.txt").read_text() == "1"
    assert (second.output_root / "sample.dec.txt").read_text() == "2"
    assert first.output_root != second.output_root
    assert not first.cache_hit
    assert not second.cache_hit
    assert not artifact_gate._result_is_accepted(first.results["sibling"], inputs.expected_exit_code)
    assert load_or_run_msc6_runtime_gate(inputs).cache_hit is cacheable


def test_runtime_gate_defaults_to_one_example_controller(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    inputs = replace(
        _inputs(tmp_path),
        examples=(("first", tmp_path / "FIRST.EXE"), ("second", tmp_path / "SECOND.EXE")),
    )
    active_count = 0
    peak_active_count = 0
    lock = threading.Lock()

    def fake_run_example(
        item: tuple[str, Path],
        _inputs_value: MSC6RuntimeGateInputs,
        _output_root: Path,
    ) -> tuple[str, None]:
        nonlocal active_count, peak_active_count
        with lock:
            active_count += 1
            peak_active_count = max(peak_active_count, active_count)
        time.sleep(0.02)
        with lock:
            active_count -= 1
        return item[0], None

    monkeypatch.setattr(artifact_gate, "_run_example", fake_run_example)

    assert set(artifact_gate._run_all(inputs, tmp_path / "outputs")) == {"first", "second"}
    assert peak_active_count == 1


def test_runtime_gate_controller_watchdog_scales_with_function_budget(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    inputs = replace(_inputs(tmp_path), timeout_seconds=120)
    captured_timeout = 0

    def fake_run(*_args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal captured_timeout
        captured_timeout = int(kwargs["timeout"])
        return subprocess.CompletedProcess([], 0, "status=passed\nrun_exit=255\n", "")

    monkeypatch.setattr(artifact_gate.subprocess, "run", fake_run)

    name, result = artifact_gate._run_example(inputs.examples[0], inputs, tmp_path / "outputs")

    assert name == "sample"
    assert isinstance(result, subprocess.CompletedProcess)
    expected_controller_timeout = inputs.timeout_seconds * 12
    assert captured_timeout == expected_controller_timeout


def test_parallel_example_controllers_share_two_nested_decompiler_workers(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    inputs = replace(_inputs(tmp_path), parallel_example_workers=2)
    captured_workers = ""

    def fake_run(*_args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal captured_workers
        env = kwargs["env"]
        assert isinstance(env, dict)
        captured_workers = str(env["INERTIA_MSC_RUNTIME_DECOMPILE_WORKERS"])
        return subprocess.CompletedProcess([], 0, "status=passed\nrun_exit=255\n", "")

    monkeypatch.delenv("INERTIA_MSC_RUNTIME_DECOMPILE_WORKERS", raising=False)
    monkeypatch.setattr(artifact_gate.subprocess, "run", fake_run)

    _name, result = artifact_gate._run_example(inputs.examples[0], inputs, tmp_path / "outputs")

    assert isinstance(result, subprocess.CompletedProcess)
    assert captured_workers == "1"
