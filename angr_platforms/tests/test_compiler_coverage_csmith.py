"""Csmith candidates must be bounded, reproducible and never counted as passes."""

import json
import subprocess
import sys
from unittest.mock import Mock

import pytest

from scripts import compiler_coverage_csmith as generator


def test_roundtrip_cli_uses_shared_runner_and_propagates_failure(tmp_path, monkeypatch):
    for name in ("csmith.h", "CSMRT.H", "MSCPLAT.H", "MSSTDINT.H", "safe_math.h"):
        (tmp_path / name).write_text("/* runtime */")
    generate = Mock(return_value=generator.GenerationOutcome.GENERATED)
    run = Mock(return_value=generator.CoverageOutcome.RECOMPILE_FAILED)
    monkeypatch.setattr(generator, "generate_candidate", generate)
    monkeypatch.setattr(generator, "run_source_case", run)
    output = tmp_path / "candidate"
    monkeypatch.setattr(sys, "argv", [
        "generate", "--csmith", str(tmp_path / "tool"), "--seed", "2",
        "--out-dir", str(output), "--roundtrip", "--runtime-source", str(tmp_path),
        "--runtime-build", str(tmp_path), "--memory-model", "large", "--case-timeout", "12",
    ])
    assert generator.main() == 1
    assert run.call_args.args == (output / "csmith.c", output / "roundtrip")
    assert run.call_args.kwargs["expected_exit_code"] == 0
    assert run.call_args.kwargs["memory_model"] is generator.MSCMemoryModel.LARGE
    assert run.call_args.kwargs["timeout"] == 12
    assert run.call_args.kwargs["runtime_headers"]["SAFEMATH.H"] == tmp_path / "safe_math.h"


@pytest.mark.parametrize("seed", [-1, 0x100000000, True, "2"])
def test_invalid_seed_creates_no_artifacts(tmp_path, seed):
    output = tmp_path / "case"
    with pytest.raises(ValueError, match="Seed"):
        generator.generate_candidate(tmp_path / "missing", seed, output)
    assert not output.exists()


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf")])
def test_invalid_timeout_creates_no_artifacts(tmp_path, timeout):
    output = tmp_path / "case"
    with pytest.raises(ValueError, match="timeout"):
        generator.generate_candidate(tmp_path / "missing", 2, output, timeout=timeout)
    assert not output.exists()


def test_seed_replay_retains_source_and_separate_diagnostics(tmp_path, monkeypatch):
    executable = tmp_path / "csmith"
    executable.write_bytes(b"test generator identity")
    commands = []

    def execute(command, **kwargs):
        commands.append(command)
        kwargs["stdout"].write(b"int main(void) { return 0; }\n")
        kwargs["stdout"].flush()
        kwargs["stderr"].write(b"diagnostic only\n")
        assert kwargs["timeout"] == 3
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(generator.subprocess, "run", execute)
    results = []
    for name in ("first", "second"):
        output = tmp_path / name
        assert generator.generate_candidate(executable, 2, output, timeout=3) is generator.GenerationOutcome.GENERATED
        results.append(json.loads((output / "generation.json").read_text()))
        assert "diagnostic" not in (output / "csmith.c").read_text()
        assert (output / "generator.stderr.log").read_text() == "diagnostic only\n"
    assert commands[0] == commands[1]
    assert "--output" not in commands[0]
    assert results[0]["source"]["sha256"] == results[1]["source"]["sha256"]
    assert results[0]["roundtrip_attempted"] is False
    assert results[0]["feature_coverage_verified"] is False
    assert results[0]["generator"]["sha256"]
    with pytest.raises(FileExistsError):
        generator.generate_candidate(executable, 2, tmp_path / "first")


@pytest.mark.parametrize("failure,expected", [
    ("timeout", generator.GenerationOutcome.TIMED_OUT),
    ("exit", generator.GenerationOutcome.FAILED),
    ("launch", generator.GenerationOutcome.FAILED),
    ("empty", generator.GenerationOutcome.FAILED),
])
def test_generation_failures_preserve_artifacts(tmp_path, monkeypatch, failure, expected):
    executable = tmp_path / "csmith"
    executable.write_bytes(b"test generator identity")

    def execute(command, **kwargs):
        if failure != "empty":
            kwargs["stdout"].write(b"partial source")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 1)
        if failure == "launch":
            raise OSError("cannot execute generator")
        return subprocess.CompletedProcess(command, 0 if failure == "empty" else 1)

    monkeypatch.setattr(generator.subprocess, "run", execute)
    output = tmp_path / "case"
    assert generator.generate_candidate(executable, 2, output) is expected
    result = json.loads((output / "generation.json").read_text())
    assert result["outcome"] == expected.value
    assert result["roundtrip_attempted"] is False
    assert (output / "csmith.c").exists()
