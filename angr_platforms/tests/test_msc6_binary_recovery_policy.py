"""Ensure compiler round trips cannot substitute alternate source recovery."""

import json
import subprocess
from types import SimpleNamespace

import pytest

from inertia_decompiler.cli_terminal_status import (
    CliTerminalStatus,
    emit_terminal_status,
    read_terminal_status,
)
from scripts import batch_decompile_procs, build_msc6_examples
from scripts.msc6_function_targets import BinaryFunctionTarget, TargetBindingStatus, bind_function_targets
from scripts.msc6_memory_model import MSCMemoryModel


def test_structured_cli_timeout_is_preserved_before_validation_diagnostics():
    """The terminal transport, not error prose or exit 3, owns timeout status."""
    diagnostic = ('[inertia-terminal] {"schema":1,"status":"timeout"}\n'
                  '[tail-validation] severity=uncollected merge_gate=hold\n')
    profile = build_msc6_examples._parse_decompile_profile(diagnostic)
    assert profile["timeout"] is True
    accepted, reason = build_msc6_examples._is_decompile_output_acceptable("", diagnostic, profile)
    assert not accepted
    assert reason is build_msc6_examples.HarnessAcceptanceReason.TIMEOUT


def test_terminal_status_transport_roundtrip_and_absence(capsys):
    emit_terminal_status(CliTerminalStatus.TIMEOUT)
    output = capsys.readouterr()
    assert not output.out
    assert read_terminal_status(output.err * 2) is CliTerminalStatus.TIMEOUT
    assert read_terminal_status("architecture guard failed; exit=3; timeout mentioned") is None


@pytest.mark.parametrize("record", [
    "not json", "[]", '{}', '{"schema":true,"status":"timeout"}',
    '{"schema":2,"status":"timeout"}', '{"schema":1,"status":"unknown"}',
    '{"schema":1,"status":"timeout","extra":1}',
])
def test_malformed_terminal_transport_is_not_silently_accepted(record):
    with pytest.raises(ValueError):
        read_terminal_status("[inertia-terminal] " + record)


def test_hard_exit_timeout_emits_structured_record_before_exit(monkeypatch, capsys):
    from inertia_decompiler import runtime_support

    def exit_process(code):
        raise SystemExit(code)

    monkeypatch.setattr(runtime_support.os, "_exit", exit_process)
    with pytest.raises(SystemExit) as caught:
        runtime_support.emit_timeout_and_exit(60, "during recovery")
    assert caught.value.code == 3
    assert read_terminal_status(capsys.readouterr().err) is CliTerminalStatus.TIMEOUT


def test_direct_terminal_timeout_emits_record(monkeypatch, capsys):
    from inertia_decompiler import cli_core

    monkeypatch.setattr(cli_core, "_emit_tail_validation_snapshot_or_uncollected", lambda *a, **kw: None)
    state = SimpleNamespace(
        direct_result=SimpleNamespace(status="timeout", tail_validation=None, payload="budget exhausted"),
        cfg=None, func=None, args=SimpleNamespace(binary="TEST.EXE", timeout=60),
    )
    assert cli_core._DirectAddrCliRun8616._phase_direct_serial_gate_8616(state) == 3
    assert read_terminal_status(capsys.readouterr().err) is CliTerminalStatus.TIMEOUT


def test_extraction_does_not_recover_stack_arguments_from_rendered_names():
    """Missing typed stack recovery must remain visible to the compiler gate."""
    emitted = "int probe(int value)\n{\n    return arg_4 + value;\n}\n"
    assert build_msc6_examples._extract_decompiled_function_definition(emitted, "probe") == emitted


@pytest.mark.parametrize("timed_out", [True, False])
def test_binary_function_command_uses_only_address_selection(monkeypatch, tmp_path, timed_out):
    """No source procedure kind or debug metadata enters address-only recovery."""
    commands = []

    def capture(command, **kwargs):
        commands.append(command)
        if timed_out:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=b"partial C", stderr=b"diagnostic")
        return subprocess.CompletedProcess(command, 4, stdout="partial C", stderr="diagnostic")

    monkeypatch.setattr(build_msc6_examples, "_run", capture)
    build_msc6_examples._decompile_function_with_options(
        tmp_path / "TEST.EXE", decompile_py=tmp_path / "decompile.py",
        decompile_timeout=1, decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto", decompile_rizin_timeout=1,
        decompile_force_rizin_8616=False, decompile_pat_backend=None,
        decompile_signature_catalog=None, function_name="probe", proc_kind="FAR",
        binary_target=BinaryFunctionTarget("probe", 0x10100),
        artifact_stem=tmp_path / "probe.attempt-000",
    )
    command, = commands
    assert "--ignore-local-sidecar-hints" in command
    assert "--no-alternate-source-c" in command
    assert command[command.index("--addr") + 1] == "0x10100"
    assert "--proc" not in command and "--proc-kind" not in command
    assert (tmp_path / "probe.attempt-000.stdout.c").read_text() == "partial C"
    assert (tmp_path / "probe.attempt-000.stderr.log").read_text().startswith("diagnostic")


@pytest.mark.parametrize("prefix", ["", "unsigned short seen = 3;\n"])
def test_preparation_does_not_invent_or_alias_global_storage(prefix):
    """The harness has no binary alias proof or type for a missing global."""
    body = "unsigned short probe(void)\n{\n    return g_0234;\n}\n"
    prepared = build_msc6_examples._prepare_decompiled_source_for_c89(prefix + body)
    assert body.rstrip() in prepared
    assert prefix in prepared
    assert "unsigned short g_0234" not in prepared


@pytest.mark.parametrize("returned_name,compiles", [("value", True), ("arg_4", False)])
def test_extracted_argument_corruption_is_not_hidden_from_compiler(returned_name, compiles):
    """A real compiler distinguishes emitted arguments from unproven carriers."""
    emitted = f"int probe(int value)\n{{\n    return {returned_name};\n}}\n"
    extracted = build_msc6_examples._extract_decompiled_function_definition(emitted, "probe")
    result = subprocess.run(
        ["gcc", "-x", "c", "-fsyntax-only", "-"], input=extracted,
        text=True, capture_output=True, check=False, timeout=10,
    )
    assert (result.returncode == 0) is compiles, result.stderr
    if not compiles:
        assert "arg_4" in result.stderr


@pytest.mark.parametrize("mode", ["focused", "main", "functions"])
def test_roundtrip_commands_disable_alternate_source(monkeypatch, tmp_path, mode):
    commands = []

    def capture_timeout(command, **kwargs):
        commands.append(command)
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(build_msc6_examples, "_run", capture_timeout)
    options = {
        "decompile_py": tmp_path / "decompile.py",
        "decompile_timeout": 1,
        "decompile_function_discovery_backend": "auto",
        "decompile_seed_engine": "auto",
        "decompile_rizin_timeout": 1,
        "decompile_force_rizin_8616": False,
        "decompile_pat_backend": None,
        "decompile_signature_catalog": None,
    }
    binary = tmp_path / "TEST.EXE"
    if mode == "focused":
        build_msc6_examples._decompile_function_with_options(
            binary, function_name="probe", **options,
        )
    else:
        monkeypatch.setattr(build_msc6_examples, "_resolve_main_candidates_from_metadata", lambda *_: [])
        build_msc6_examples._decompile(
            binary, tmp_path, decompile_run_timeout=1, decompile_mode=mode,
            decompile_cod_path=None, decompile_max_functions=0,
            decompile_ignore_local_sidecar_hints=False, **options,
        )
    assert len(commands) == 1
    assert "--no-alternate-source-c" in commands[0]
    assert "--alternate-source-c" not in commands[0]


def test_batch_proc_commands_disable_alternate_source(monkeypatch, tmp_path):
    def capture(command):
        assert "--no-alternate-source-c" in command
        assert "--alternate-source-c" not in command
        return 0

    monkeypatch.setattr(batch_decompile_procs.decompiler_cli, "main", capture)
    assert batch_decompile_procs.main([
        str(tmp_path / "TEST.EXE"), "--out-dir", str(tmp_path / "batch"),
        "--proc", "probe",
    ]) == 0
    report = json.loads((tmp_path / "batch" / "batch_report.json").read_text())
    assert len(report["results"]) == 1


@pytest.mark.parametrize("model", [MSCMemoryModel.SMALL, MSCMemoryModel.LARGE])
def test_missing_body_retry_preserves_procedure_model(monkeypatch, tmp_path, model):
    """A retry must not reinterpret a far entry as a near procedure."""
    kinds = []

    def recover(*args, function_name, proc_kind="NEAR", **kwargs):
        kinds.append(proc_kind)
        return True, "", "", {}, "probe command", function_name

    def missing_body(*args):
        raise RuntimeError("missing generated definition")

    monkeypatch.setenv("INERTIA_DISABLE_MSC6_BATCH_FALLBACK", "1")
    monkeypatch.setattr(build_msc6_examples, "_decompile_function_with_options", recover)
    monkeypatch.setattr(build_msc6_examples, "_extract_decompiled_function_definition", missing_body)
    result = build_msc6_examples._build_from_function_decompiles(
        tmp_path / "TEST.EXE", tmp_path,
        decompile_py=tmp_path / "decompile.py", decompile_timeout=1,
        decompile_run_timeout=1, decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto", decompile_rizin_timeout=1,
        decompile_force_rizin_8616=False, decompile_pat_backend=None,
        decompile_signature_catalog=None, fallback_functions=("probe",),
        fallback_harness="", fallback_prefix="", decompile_c_name="TEST.C",
        decompile_obj_name="TEST.OBJ", decompile_exe_name="REBUILT.EXE",
        decompile_map_name="TEST.MAP", kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path / "msc6", memory_model=model,
    )
    assert result[0] is False
    assert kinds == [model.default_procedure_kind] * 2


def test_source_free_failure_cannot_retry_through_named_sidecar_recovery(monkeypatch, tmp_path):
    """Missing target labels cannot downgrade to named or whole-binary recovery."""
    attempts = []

    def named_fallback(*args, **kwargs):
        pytest.fail("source-free execution entered sidecar-backed named fallback")

    def binary_recovery(*args, **kwargs):
        attempts.append(kwargs)
        return False, tmp_path / "out.c", tmp_path / "err.txt", 1.0, {}

    monkeypatch.setattr(build_msc6_examples, "_build_from_function_decompiles", named_fallback)
    monkeypatch.setattr(build_msc6_examples, "_decompile", binary_recovery)
    monkeypatch.setattr(build_msc6_examples, "_lookup_sidecar_code_labels", lambda _: {})
    result = build_msc6_examples._decompile_and_validate(
        tmp_path / "TEST.EXE", tmp_path, kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path / "msc6", decompile_py=tmp_path / "decompile.py",
        decompile_timeout=1, decompile_run_timeout=1, decompile_mode="functions",
        decompile_cod_path=None, decompile_max_functions=0, expected_exit_code=255,
        decompile_ignore_local_sidecar_hints=True,
        decompile_fallback_rebuild={"functions": ("probe",), "harness": "int main(void) { return 255; }"},
    )
    assert result[0] is False
    assert not attempts
    assert json.loads(result[-1])["fallback_rebuild"]["target_binding_status"] == "missing_label"


@pytest.mark.parametrize("names,labels,prefix,status", [
    (("probe",), {"probe": 0x10000}, "", TargetBindingStatus.BOUND),
    (("probe",), {}, "", TargetBindingStatus.MISSING_LABEL),
    (("probe", "other"), {"probe": 0x10000}, "", TargetBindingStatus.MISSING_LABEL),
    (("probe", "other"), {"probe": 1, "other": 1}, "", TargetBindingStatus.AMBIGUOUS_ADDRESS),
    (("probe",), {"probe": -1}, "", TargetBindingStatus.INVALID_ADDRESS),
    (("probe",), {"probe": True}, "", TargetBindingStatus.INVALID_ADDRESS),
    (("probe", "probe"), {"probe": 1}, "", TargetBindingStatus.INVALID_NAMES),
    (("main",), {"main": 1}, "", TargetBindingStatus.INVALID_NAMES),
    (("probe",), {"probe": 1}, "int injected = 3;", TargetBindingStatus.PREFIX_UNSUPPORTED),
])
def test_binary_target_binding_is_atomic(names, labels, prefix, status):
    binding = bind_function_targets(names, labels, prefix=prefix)
    assert binding.status is status
    if status is not TargetBindingStatus.BOUND:
        assert not binding.targets


@pytest.mark.parametrize("accepted", [True, False])
def test_source_free_binding_preserves_bodies_contracts_and_behavior(monkeypatch, tmp_path, accepted):
    """Exercise shared orchestration with real host compilation, not DOS acceptance."""
    from angr_platforms.X86_16.lowering import c_runtime_header

    bodies = {
        "inner": "int sub_10000(void)\n{\n    return 7;\n}\n",
        "probe": "int sub_10010(void)\n{\n    return sub_10000();\n}\n",
    }
    calls = []
    monkeypatch.setattr(build_msc6_examples, "_lookup_sidecar_code_labels", lambda _: {"inner": 0x10000, "probe": 0x10010})
    monkeypatch.setattr(c_runtime_header, "render_c_runtime_header_8616", lambda _: "")
    monkeypatch.setattr(build_msc6_examples, "_prepare_decompiled_source_for_c89", lambda source: source)

    def recover(*args, function_name, binary_target, **kwargs):
        assert binary_target.name == function_name
        calls.append(binary_target)
        profile = {} if accepted else {"acceptance_reason": "nonzero_exit"}
        return accepted, bodies[function_name], "", profile, "binary command", function_name

    def compile_source(source, directory, **kwargs):
        assert accepted, "unaccepted binary recovery must not reach the compiler"
        text = source.read_text()
        for body in bodies.values():
            assert body in text
        assert text.index(bodies["probe"]) < text.index("#define probe sub_10010")
        result = subprocess.run(
            ["gcc", "-x", "c", "-o", str(directory / kwargs["exe_name"]), "-"],
            input=text + "\nvoid inertia_init_segments(void) {}\n", text=True,
            capture_output=True, check=False, timeout=10,
        )
        return result.returncode == 0, result.stdout, result.stderr, "", ""

    def execute(binary, directory, **kwargs):
        result = subprocess.run([str(binary)], capture_output=True, text=True, check=False, timeout=10)
        return True, result.returncode, result.stdout, result.stderr

    monkeypatch.setattr(build_msc6_examples, "_decompile_function_with_options", recover)
    monkeypatch.setattr(build_msc6_examples, "_compile_and_link", compile_source)
    monkeypatch.setattr(build_msc6_examples, "_run_example", execute)
    result = build_msc6_examples._decompile_and_validate(
        tmp_path / "TEST.EXE", tmp_path, kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path / "msc6", decompile_py=tmp_path / "decompile.py",
        decompile_timeout=1, decompile_run_timeout=1, decompile_mode="functions",
        decompile_cod_path=None, decompile_max_functions=0, expected_exit_code=255,
        decompile_ignore_local_sidecar_hints=True,
        decompile_fallback_rebuild={
            "functions": ("inner", "probe"),
            "harness": "int main(void) { return probe() == 7 ? 255 : 3; }",
            "source_contracts": (build_msc6_examples.GeneratedFunctionSourceContract(
                function_name="probe", required_returned_call="inner",
            ),),
        },
    )
    assert result[0] is accepted, result
    if not accepted:
        assert len(calls) == 2  # One bounded retry, still at the same binary target.
        assert calls[0] == calls[1]
        return
    assert result[5] == 255
    assert len(calls) == 2
    profile = json.loads(result[-1])["fallback_rebuild"]
    assert profile["target_binding_status"] == "bound"
    assert profile["source_contracts_passed"] is True


def test_missing_required_function_cannot_be_skipped_before_rebuild(monkeypatch, tmp_path):
    """An omitted target fails even when the remaining harness would compile."""
    monkeypatch.setenv("INERTIA_DISABLE_MSC6_BATCH_FALLBACK", "1")

    def missing(*args, function_name, **kwargs):
        return False, "", f"did not find {function_name} PROC", {}, "probe command", function_name

    def forbidden_rebuild(*args, **kwargs):
        pytest.fail("rebuild attempted after a required function disappeared")

    monkeypatch.setattr(build_msc6_examples, "_decompile_function_with_options", missing)
    monkeypatch.setattr(build_msc6_examples, "_compile_and_link", forbidden_rebuild)
    result = build_msc6_examples._build_from_function_decompiles(
        tmp_path / "TEST.EXE", tmp_path,
        decompile_py=tmp_path / "decompile.py", decompile_timeout=1,
        decompile_run_timeout=1, decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto", decompile_rizin_timeout=1,
        decompile_force_rizin_8616=False, decompile_pat_backend=None,
        decompile_signature_catalog=None, fallback_functions=("probe",),
        fallback_harness="int main(void) { return 255; }", fallback_prefix="",
        decompile_c_name="TEST.C", decompile_obj_name="TEST.OBJ",
        decompile_exe_name="REBUILT.EXE", decompile_map_name="TEST.MAP",
        kvikdos=tmp_path / "kvikdos", msc6_root=tmp_path / "msc6",
    )
    assert result[0] is False
    assert not (tmp_path / "TEST.C").exists()
