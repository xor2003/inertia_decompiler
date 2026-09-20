"""Original-program observations survive failure of the decompilation phase."""

import hashlib
import json
import sys

import pytest

from scripts import build_msc6_examples as harness
from scripts.msc6_memory_model import MSCMemoryModel
from scripts.msc6_original_evidence import record_original_execution


@pytest.mark.parametrize("model", list(MSCMemoryModel))
def test_original_evidence_precedes_decompiler_failure(tmp_path, monkeypatch, model):
    source_dir = tmp_path / "sources"
    source_dir.mkdir()
    source = source_dir / "case.c"
    source.write_text("int main(void) { return 0; }\n")
    output = tmp_path / "output"
    monkeypatch.setattr(sys, "argv", [
        "build_msc6_examples.py", "--examples-dir", str(source_dir),
        "--out-dir", str(output), "--memory-model", model.value,
        "--harvest-success-code", "0",
    ])

    def compile_case(*args, **kwargs):
        (output / "CASE.EXE").write_bytes(b"test fixture")
        return True, "compile output", "compile diagnostic", "link output", ""

    def fail_decompilation(*args, **kwargs):
        evidence = json.loads((output / "CASE.original.json").read_text())
        assert evidence["run_ok"] is True
        assert evidence["run_exit_code"] == 0
        assert evidence["run_stdout"] == "checksum = 1234\r\n"
        assert evidence["run_stderr"] == "emulator diagnostic"
        assert evidence["memory_model"] == model.value
        assert evidence["source"]["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
        assert evidence["compile_stderr"] == "compile diagnostic"
        assert evidence["decompilation_evidence"] == "not_collected"
        raise TimeoutError("deliberate decompiler failure")

    monkeypatch.setattr(harness, "_compile_and_link", compile_case)
    monkeypatch.setattr(harness, "_run_example", lambda *args, **kwargs: (
        True, 0, "checksum = 1234\r\n", "emulator diagnostic",
    ))
    monkeypatch.setattr(harness, "_decompile_and_validate", fail_decompilation)
    with pytest.raises(TimeoutError, match="deliberate decompiler failure"):
        harness.main()
    assert not (output / "report.json").exists()


@pytest.mark.parametrize(("build_ok", "returncode"), [(False, None), (False, 0), (True, None), (True, 1)])
def test_incomplete_or_failed_original_is_not_success(tmp_path, build_ok, returncode):
    source = tmp_path / "CASE.C"
    source.write_text("int main(void) { return 0; }")
    report = record_original_execution(
        source, memory_model=MSCMemoryModel.SMALL, build_ok=build_ok,
        expected_exit_code=0, returncode=returncode, stdout="", stderr="failure",
        compile_output=("", ""), link_output=("", ""),
    )
    evidence = json.loads(report.read_text())
    assert evidence["run_ok"] is False
    assert evidence["decompilation_evidence"] == "not_collected"
