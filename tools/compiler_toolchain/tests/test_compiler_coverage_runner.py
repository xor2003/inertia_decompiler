"""The coverage adapter must bound execution and reject stale evidence."""

import json
import os
import signal
import subprocess
import sys
import time
from contextlib import suppress
from pathlib import Path
from unittest.mock import Mock

import pytest

from tools.compiler_toolchain import compiler_coverage_runner as runner
from tools.compiler_toolchain.compiler_coverage_result import CoverageOutcome


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), float("inf"), -float("inf")])
def test_invalid_deadline_rejected_before_creating_artifacts(tmp_path, monkeypatch, timeout):
    launch = Mock()
    monkeypatch.setattr(runner.subprocess, "Popen", launch)
    output = tmp_path / "case"
    with pytest.raises(ValueError, match="timeout"):
        runner.run_existing_case("storage_classes", output, timeout=timeout)
    assert not output.exists()
    launch.assert_not_called()


def test_existing_artifacts_cannot_be_reused(tmp_path, monkeypatch):
    launch = Mock()
    monkeypatch.setattr(runner.subprocess, "Popen", launch)
    with pytest.raises(FileExistsError):
        runner.run_existing_case("storage_classes", tmp_path)
    launch.assert_not_called()


def test_external_fixture_uses_existing_owner_and_fingerprints_headers(tmp_path, monkeypatch):
    source = tmp_path / "csmith.c"
    source.write_text("int main(void) { return 0; }")
    header = tmp_path / "runtime.h"
    header.write_text("/* fixture runtime */")
    catalog = tmp_path / "runtime.pat"
    catalog.write_text("---\n")
    execute = Mock(return_value=(1, False))
    monkeypatch.setattr(runner, "_execute", execute)
    output = tmp_path / "case"
    result = runner.run_source_case(
        source, output, expected_exit_code=0, runtime_headers={"RUNTIME.H": header},
        signature_catalog=catalog,
    )
    assert result is CoverageOutcome.HARNESS_FAILED  # No report, not a fabricated pass.
    command = execute.call_args.args[0]
    assert command[1].endswith("tools/compiler_toolchain/build_msc6_examples.py")
    assert "--decompile-ignore-local-sidecar-hints" in command
    assert command[command.index("--compiler-profile") + 1] == "msc6_ax"
    assert "--profile-evidence" not in command
    assert command[command.index("--examples-dir") + 1] == str(tmp_path)
    assert command[command.index("--harvest-success-code") + 1] == "0"
    assert command[command.index("--signature-catalog") + 1] == str(catalog)
    assert (output / "RUNTIME.H").read_bytes() == header.read_bytes()
    report = json.loads((output / "coverage-result.json").read_text())
    assert report["inputs"]["runtime_headers"]["RUNTIME.H"]["sha256"]
    assert report["inputs"]["signature_catalog"]["sha256"]
    assert report["inputs"]["environment"]["installed_distributions"]
    assert report["inputs"]["environment"]["kvm"]["status"]


def test_runtime_sources_and_expected_stdout_reach_child_and_provenance(tmp_path, monkeypatch):
    """Frozen rows must stage runtime TUs and forward the stdout checksum pin."""
    source = tmp_path / "csmith.c"
    source.write_text("int main(void) { return 0; }")
    runtime = tmp_path / "csmrt_source.c"
    runtime.write_text("void helper(void) {}")
    execute = Mock(return_value=(1, False))
    monkeypatch.setattr(runner, "_execute", execute)
    output = tmp_path / "case"
    result = runner.run_source_case(
        source, output, expected_exit_code=0,
        expected_stdout_contains="checksum = 637A4628",
        stage_budget_seconds=37,
        runtime_sources={"CSMRT.C": runtime},
    )
    assert result is CoverageOutcome.HARNESS_FAILED
    command = execute.call_args.args[0]
    assert command[command.index("--harvest-stdout-contains") + 1] == "checksum = 637A4628"
    assert command[command.index("--runtime-source") + 1] == "CSMRT.C"
    assert command[command.index("--stage-timeout") + 1] == "37"
    assert command[command.index("--decompile-run-timeout") + 1] == "37"
    assert (output / "CSMRT.C").read_bytes() == runtime.read_bytes()
    report = json.loads((output / "coverage-result.json").read_text())
    assert report["inputs"]["expected_stdout_contains"] == "checksum = 637A4628"
    assert report["inputs"]["expected_exit_code"] == 0
    assert report["inputs"]["stage_budget_seconds"] == 37
    assert report["inputs"]["runtime_sources"]["CSMRT.C"]["sha256"]


def test_signature_catalogs_merge_deterministically(tmp_path, monkeypatch):
    """Multiple pinned catalogs stage as one byte-concatenated catalog."""
    source = tmp_path / "fixture.c"
    source.write_text("int main(void) { return 0; }")
    first = tmp_path / "a.pat"
    second = tmp_path / "b.pat"
    first.write_bytes(b"AAA\n")
    second.write_bytes(b"BBB\n")
    execute = Mock(return_value=(1, False))
    monkeypatch.setattr(runner, "_execute", execute)
    output = tmp_path / "case"
    runner.run_source_case(
        source, output, signature_catalogs=(first, second),
    )
    merged = output / "signature-catalogs.pat"
    assert merged.read_bytes() == b"AAA\nBBB\n"
    command = execute.call_args.args[0]
    assert command[command.index("--signature-catalog") + 1] == str(merged)
    report = json.loads((output / "coverage-result.json").read_text())
    assert len(report["inputs"]["signature_catalogs"]) == 2
    assert report["inputs"]["signature_catalog"]["sha256"]


def test_signature_catalog_forms_are_mutually_exclusive(tmp_path, monkeypatch):
    source = tmp_path / "fixture.c"
    source.write_text("int main(void) { return 0; }")
    catalog = tmp_path / "a.pat"
    catalog.write_bytes(b"AAA\n")
    execute = Mock()
    monkeypatch.setattr(runner, "_execute", execute)
    output = tmp_path / "case"
    with pytest.raises(ValueError, match="signature_catalog"):
        runner.run_source_case(
            source, output, signature_catalog=catalog, signature_catalogs=(catalog,),
        )
    execute.assert_not_called()
    assert not output.exists()


@pytest.mark.parametrize("names", [("../escape.c",), ("TOOLONGNAME.c",), ("file.h",), ("A.C", "a.c")])
def test_invalid_runtime_source_destinations_fail_before_launch(tmp_path, monkeypatch, names):
    source = tmp_path / "fixture.c"
    source.write_text("int main(void) { return 0; }")
    execute = Mock()
    monkeypatch.setattr(runner, "_execute", execute)
    output = tmp_path / "case"
    with pytest.raises(ValueError, match="source"):
        runner.run_source_case(source, output, runtime_sources=dict.fromkeys(names, source))
    execute.assert_not_called()
    assert not output.exists()


def test_empty_expected_stdout_is_rejected_before_launch(tmp_path, monkeypatch):
    source = tmp_path / "fixture.c"
    source.write_text("int main(void) { return 0; }")
    execute = Mock()
    monkeypatch.setattr(runner, "_execute", execute)
    with pytest.raises(ValueError, match="stdout"):
        runner.run_source_case(
            source, tmp_path / "case", expected_stdout_contains="",
        )
    execute.assert_not_called()


@pytest.mark.parametrize("changed", [False, True])
def test_source_identity_is_retained_and_changes_refuse_acceptance(tmp_path, monkeypatch, changed):
    """A successful child must not hide concurrent edits to its implementation."""
    root = tmp_path / "repo"
    root.mkdir()
    helper = root / "decompile.py"
    helper.write_text("# before\n")
    source = tmp_path / "fixture.c"
    source.write_text("int main(void) { return 0; }")
    monkeypatch.setattr(runner, "ROOT", root)
    monkeypatch.setattr(runner, "classify_roundtrip_report", lambda *args: CoverageOutcome.PASSED)

    def execute(*args):
        if changed:
            helper.write_text("# after\n")
        return 0, False

    monkeypatch.setattr(runner, "_execute", execute)
    output = tmp_path / "case"
    outcome = runner.run_source_case(source, output)
    expected = CoverageOutcome.HARNESS_FAILED if changed else CoverageOutcome.PASSED
    assert outcome is expected
    report = json.loads((output / "coverage-result.json").read_text())
    assert report["implementation_unchanged"] is (not changed)
    assert report["inputs"]["implementation"]["sha256"]
    assert (report["inputs"]["implementation"] == report["implementation_after"]) is (not changed)


def _pinned_tool(root: Path, dos_path: str, payload: bytes) -> dict[str, str]:
    """Create the host file for one e:-mounted tool and return its pinned record."""
    import hashlib

    host = root.joinpath(*dos_path[3:].split("\\"))
    host.parent.mkdir(parents=True, exist_ok=True)
    host.write_bytes(payload)
    return {"dos_path": dos_path, "sha256": hashlib.sha256(payload).hexdigest()}


def _bc31_registry(tmp_path: Path, toolchain_root: Path) -> Path:
    """Write a minimal valid registry exposing one canonical bc31 profile."""
    import hashlib

    record = {
        "id": "bc31-small",
        "probe_id": "bcpp31-small",
        "aliases": ["bcpp31-small"],
        "dependency_group": "bcpp31",
        "compiler": "Borland C++ 3.1",
        "memory_model": "small",
        "declared_flags": ["-Od", "-ms"],
        "compile_backend": "dosbox",
        "run_backend": "kvikdos",
        "toolchain_root": str(toolchain_root),
        "tools": {
            "compiler": _pinned_tool(toolchain_root, "e:\\BIN\\BCC.EXE", b"bcc"),
            "linker": _pinned_tool(toolchain_root, "e:\\BIN\\TLINK.EXE", b"tlink"),
        },
        "libraries": [_pinned_tool(toolchain_root, "e:\\LIB\\CS.LIB", b"cs")],
        "compiler_path_dos": ["e:\\BIN"],
        "linker_path_dos": ["e:\\BIN"],
        "compiler_environment": [["INCLUDE", "e:\\INCLUDE;c:\\"], ["LIB", "e:\\LIB"]],
        "linker_environment": [["LIB", "e:\\LIB"]],
        "compile_arguments": ["-Od", "-ms", "-c", "-oc:\\{obj}", "c:\\{source}"],
        "cod_argument": None,
        "link_argument": "e:\\LIB\\C0S+c:\\{obj}{extra_objs},c:\\{exe},c:\\{map},e:\\LIB\\CS",
        "extra_object_format": "+c:\\{extra_obj}",
    }
    dependency = _pinned_tool(toolchain_root, "e:\\BIN\\DPMILOAD.EXE", b"dpmi")
    inventory = {
        dependency["dos_path"]: dependency["sha256"],
        record["tools"]["linker"]["dos_path"]: record["tools"]["linker"]["sha256"],
    }
    probe = tmp_path / "probe.json"
    probe.write_text(json.dumps({"schema": 1, "profiles": [{
        "id": "bcpp31-small", "compiler": {"product": "Borland C++ 3.1"},
        "model": "small", "model_flag": "-ms",
        "compile_runner": "dosbox", "run_runner": "kvikdos",
    }], "toolchain_children": {"bcpp31": inventory}}), encoding="utf-8")
    kvikdos = tmp_path / "kvikdos.bin"
    kvikdos.write_bytes(b"kvikdos")
    dosbox = tmp_path / "dosbox.bin"
    dosbox.write_bytes(b"dosbox")
    registry = {
        "schema": 1,
        "profiles": [record],
        "runners": {
            "kvikdos": {"path": str(kvikdos), "sha256": hashlib.sha256(b"kvikdos").hexdigest()},
            "dosbox": {
                "path": str(dosbox), "sha256": hashlib.sha256(b"dosbox").hexdigest(),
                "host_environment": {"SDL_VIDEODRIVER": "dummy"},
            },
        },
        "probe_evidence": {
            "path": str(probe), "sha256": hashlib.sha256(probe.read_bytes()).hexdigest(),
        },
        "dependencies": {"bcpp31": {dependency["dos_path"]: dependency["sha256"]}},
    }
    path = tmp_path / "toolchains.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    return path


def test_selected_profile_reaches_child_command_and_provenance(tmp_path, monkeypatch):
    """A verified non-MS C 6 toolchain must route through the same child owner."""
    from tools.compiler_toolchain.compiler_profile import CompilerProfileSelection, load_compiler_profiles

    source = tmp_path / "fixture.c"
    source.write_text("int main(void) { return 0; }")
    toolchain_root = tmp_path / "bcc31"
    registry = _bc31_registry(tmp_path, toolchain_root)
    selection = CompilerProfileSelection(
        toolchain=load_compiler_profiles(registry)[0], evidence_path=registry,
    )
    execute = Mock(return_value=(1, False))
    monkeypatch.setattr(runner, "_execute", execute)
    output = tmp_path / "case"
    result = runner.run_source_case(source, output, compiler_profile=selection)
    assert result is CoverageOutcome.HARNESS_FAILED
    command = execute.call_args.args[0]
    assert command[command.index("--compiler-profile") + 1] == "bc31-small"
    assert command[command.index("--profile-evidence") + 1] == str(registry)
    assert command[command.index("--memory-model") + 1] == "small"
    assert command[command.index("--kvikdos") + 1] == str(tmp_path / "kvikdos.bin")
    report = json.loads((output / "coverage-result.json").read_text())
    assert report["inputs"]["compiler"]["path"] == str(toolchain_root.resolve())
    assert report["inputs"]["compiler_profile"]["profile_id"] == "bc31-small"
    assert report["inputs"]["compiler_profile"]["compiler_program"] == "e:\\BIN\\BCC.EXE"
    assert report["inputs"]["compiler_profile"]["compile_backend"] == "dosbox"
    assert report["inputs"]["compiler_profile"]["run_backend"] == "kvikdos"
    assert report["inputs"]["compiler_profile"]["dosbox_executable"] == str(tmp_path / "dosbox.bin")
    assert report["inputs"]["compiler_profile"]["kvikdos_executable"] == str(tmp_path / "kvikdos.bin")
    assert report["inputs"]["emulator"]["path"] == str((tmp_path / "kvikdos.bin").resolve())
    assert report["inputs"]["profile_evidence"]["sha256"]
    assert report["compiler_profile"]["profile_id"] == "bc31-small"


def test_conflicting_memory_model_refuses_before_artifacts(tmp_path, monkeypatch):
    """An explicit model cannot quietly disagree with the selected profile."""
    from tools.compiler_toolchain.compiler_profile import CompilerProfileSelection, msc6_ax_toolchain

    source = tmp_path / "fixture.c"
    source.write_text("int main(void) { return 0; }")
    selection = CompilerProfileSelection(
        toolchain=msc6_ax_toolchain(
            root=tmp_path / "msc6", memory_model=runner.MSCMemoryModel.SMALL,
        ),
        evidence_path=None,
    )
    execute = Mock()
    monkeypatch.setattr(runner, "_execute", execute)
    output = tmp_path / "case"
    with pytest.raises(ValueError, match="conflicts"):
        runner.run_source_case(
            source, output, memory_model=runner.MSCMemoryModel.LARGE, compiler_profile=selection,
        )
    execute.assert_not_called()
    assert not output.exists()


def test_environment_drift_refuses_an_otherwise_passing_roundtrip(tmp_path, monkeypatch):
    """A valid child report cannot attest to a different runtime environment."""
    source = tmp_path / "fixture.c"
    source.write_text("int main(void) { return 0; }")
    monkeypatch.setattr(runner, "classify_roundtrip_report", lambda *args: CoverageOutcome.PASSED)
    monkeypatch.setattr(runner, "_execute", Mock(return_value=(0, False)))
    environment = Mock()
    environment.to_dict.side_effect = [
        {"installed_distributions": [["angr", "before"]]},
        {"installed_distributions": [["angr", "after"]]},
    ]
    monkeypatch.setattr(runner, "runtime_environment_snapshot", Mock(return_value=environment))

    outcome = runner.run_source_case(source, tmp_path / "case")

    assert outcome is CoverageOutcome.HARNESS_FAILED
    report = json.loads((tmp_path / "case" / "coverage-result.json").read_text())
    assert report["environment_unchanged"] is False
    assert report["inputs"]["environment"] != report["environment_after"]
    assert "Runtime environment changed" in report["error"]


@pytest.mark.parametrize("names", [("../escape.h",), ("file.c",), ("R.H", "r.h")])
def test_invalid_runtime_header_destinations_fail_before_launch(tmp_path, monkeypatch, names):
    source = tmp_path / "fixture.c"
    source.write_text("int main(void) { return 0; }")
    execute = Mock()
    monkeypatch.setattr(runner, "_execute", execute)
    output = tmp_path / "case"
    with pytest.raises(ValueError, match="header"):
        runner.run_source_case(source, output, runtime_headers=dict.fromkeys(names, source))
    execute.assert_not_called()
    assert not output.exists()


@pytest.mark.parametrize("disappeared", [False, True])
def test_timeout_kills_group_and_reaps_child(tmp_path, monkeypatch, disappeared):
    monkeypatch.setattr(runner, "process_tree_pids", lambda roots: roots)
    process = Mock(pid=123)
    process.wait.side_effect = [subprocess.TimeoutExpired("compiler", 1), -9]
    monkeypatch.setattr(runner.subprocess, "Popen", Mock(return_value=process))
    kill = Mock(side_effect=ProcessLookupError if disappeared else None)
    monkeypatch.setattr(runner.os, "killpg", kill)
    output = tmp_path / "case"
    assert runner.run_existing_case("storage_classes", output, timeout=1) is CoverageOutcome.TIMED_OUT
    kill.assert_called_once_with(123, runner.signal.SIGKILL)
    assert process.wait.call_count == 2
    report = json.loads((output / "coverage-result.json").read_text())
    assert report["outcome"] == "timed_out"
    assert report["returncode"] == -9


def test_launch_failure_retains_structured_result(tmp_path, monkeypatch):
    monkeypatch.setattr(runner.subprocess, "Popen", Mock(side_effect=OSError("launch failed")))
    output = tmp_path / "case"
    assert runner.run_existing_case("storage_classes", output) is CoverageOutcome.HARNESS_FAILED
    report = json.loads((output / "coverage-result.json").read_text())
    assert report["outcome"] == "harness_failed"
    assert "launch failed" in report["error"]


def test_missing_report_is_not_success(tmp_path, monkeypatch):
    process = Mock()
    process.wait.return_value = 0
    launch = Mock(return_value=process)
    monkeypatch.setattr(runner.subprocess, "Popen", launch)
    assert runner.run_existing_case("storage_classes", tmp_path / "case") is CoverageOutcome.HARNESS_FAILED
    assert launch.call_args.kwargs["start_new_session"] is True
    assert launch.call_args.kwargs["env"]["PYTHONHASHSEED"] == "0"


@pytest.mark.skipif(sys.platform != "linux", reason="Checks Linux descendant process state")
@pytest.mark.parametrize("detached", [False, True])
def test_real_timeout_stops_descendants_and_retains_both_output_streams(tmp_path, detached):
    """A real forked child must stop, not merely the adapter's direct child."""
    inventory = tmp_path / "processes.json"
    script = """
import json, os, sys, time
child = os.fork()
if not child and sys.argv[2] == "detach":
    os.setsid()
if child:
    with open(sys.argv[1], "w") as report:
        json.dump([os.getpid(), child], report)
    print("parent stdout", flush=True)
    print("parent stderr", file=sys.stderr, flush=True)
time.sleep(60)
"""
    pids = []
    try:
        with (tmp_path / "runner.log").open("w") as log:
            returncode, timed_out = runner._execute(
                [sys.executable, "-c", script, str(inventory), "detach" if detached else "group"],
                log, timeout=2,
            )
        assert timed_out
        assert returncode == -signal.SIGKILL
        pids = json.loads(inventory.read_text())
        deadline = time.monotonic() + 2
        while True:
            live = []
            for pid in pids:
                with suppress(FileNotFoundError, ProcessLookupError):
                    # An orphan may remain a zombie until the host init reaps it.
                    state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
                    if state not in {"Z", "X"}:
                        live.append(pid)
            if not live or time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        assert not live, f"Timeout left live descendants: {live}"
        output = (tmp_path / "runner.log").read_text()
        assert "parent stdout" in output
        assert "parent stderr" in output
    finally:
        if inventory.exists():
            for pid in json.loads(inventory.read_text()):
                with suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)


def test_interruption_kills_group_and_propagates(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "process_tree_pids", lambda roots: roots)
    process = Mock(pid=123)
    process.wait.side_effect = [KeyboardInterrupt, -signal.SIGKILL]
    monkeypatch.setattr(runner.subprocess, "Popen", Mock(return_value=process))
    kill = Mock()
    monkeypatch.setattr(runner.os, "killpg", kill)
    with (tmp_path / "runner.log").open("w") as log, pytest.raises(KeyboardInterrupt):
        runner._execute(["compiler"], log, timeout=1)
    kill.assert_called_once_with(123, signal.SIGKILL)
    assert process.wait.call_count == 2
