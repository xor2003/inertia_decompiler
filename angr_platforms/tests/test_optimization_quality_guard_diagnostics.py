"""Keep failed optimization-gate diagnostics without changing verdicts."""

import json
import subprocess
from pathlib import Path

import pytest

from scripts import benchmark_optimization_quality_guard as guard


@pytest.mark.parametrize("returncode", (0, 2, None))
def test_process_diagnostics_survive_only_failed_gates(tmp_path, monkeypatch, capsys, returncode):
    """Preserve both streams on failure and clean successful temporary runs."""
    original_mkdtemp = guard.tempfile.mkdtemp
    created = []

    def mkdtemp(*, prefix, dir=None):
        path = original_mkdtemp(prefix=prefix, dir=tmp_path if dir is None else dir)
        created.append(Path(path))
        return path

    def run(command, **kwargs):
        assert kwargs["capture_output"] and kwargs["text"]
        if returncode is None:
            raise subprocess.TimeoutExpired(
                command, 1, output=b"partial progress\xff\n", stderr=b"timeout diagnostic\n",
            )
        output = Path(command[command.index("--output-c-dir") + 1])
        (output / "00001000-example.c").write_text("int example(void) { return 0; }\n")
        validation = "passed" if returncode == 0 else "failed"
        return subprocess.CompletedProcess(
            command, returncode,
            stdout=f"validation={validation}\nfull child output\n",
            stderr="exact child diagnostic: unavailable source bytes\n",
        )

    monkeypatch.setattr(guard.tempfile, "mkdtemp", mkdtemp)
    monkeypatch.setattr(guard.subprocess, "run", run)
    monkeypatch.setattr(guard, "_execution_modes_are_equivalent", lambda *args: True)
    report_path = tmp_path / "report.json"
    result = guard.main(["unused.exe", "--report-json", str(report_path)])
    root, execution = created
    if returncode is None:
        assert result == 2
        assert not report_path.exists()
        assert (execution / "decompiler.stdout.log").read_bytes() == b"partial progress\xff\n"
        assert (execution / "decompiler.stderr.log").read_bytes() == b"timeout diagnostic\n"
        assert str(root) in capsys.readouterr().out
        return
    report = json.loads(report_path.read_text())
    assert result == (0 if returncode == 0 else 1)
    assert report["passed"] is (returncode == 0)
    if returncode == 0:
        assert not root.exists()
        assert report["baseline"]["diagnostics_directory"] is None
    else:
        assert root.is_dir()
        assert (execution / "decompiler.stdout.log").read_text() == "validation=failed\nfull child output\n"
        assert (execution / "decompiler.stderr.log").read_text() == "exact child diagnostic: unavailable source bytes\n"
        assert report["baseline"]["diagnostics_directory"] == str(execution)
        assert report["candidate"]["diagnostics_directory"] == str(execution)
        assert str(root) in capsys.readouterr().out
