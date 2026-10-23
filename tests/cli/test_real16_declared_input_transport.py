"""CLI transport preserves explicit real-mode declaration authority across workers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from inertia.cli import cli_arg_parser as parser_module
from inertia.cli import cli_core
from inertia.cli import direct_request_identity as direct_identity
from inertia.cli import discovery_evidence_project as discovery_module
from inertia.cli import serial_worker_cache as worker_cache


@pytest.fixture
def declared_args(tmp_path, monkeypatch):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ exact source bytes")
    declaration = tmp_path / "input.json"
    declaration.write_text("first declaration")
    observed = []

    def read_declared(path, source):
        observed.append((path, source))
        return SimpleNamespace(boot=SimpleNamespace(
            image=SimpleNamespace(load_segment=0x1200),
            entry=SimpleNamespace(linear=lambda: 0x12003),
        ))

    monkeypatch.setattr(parser_module, "read_declared_real16_input_8616", read_declared)
    argv = [str(binary), "--addr", "0x12003", "--real16-declared-input", str(declaration)]
    return argv, declaration, observed


def test_undeclared_defaults_and_explicit_coordinates():
    args = parser_module.parse_cli_arguments(["sample.exe"])
    assert (args.base_addr, args.entry_point, args.real16_declared_input) == (0x1000, 0x1000, None)
    args = parser_module.parse_cli_arguments(["sample.exe", "--base-addr", "0x2000", "--entry-point", "0x2010"])
    assert (args.base_addr, args.entry_point) == (0x2000, 0x2010)


@pytest.mark.parametrize("coordinates", [[], ["--base-addr", "0x1200"], ["--base-addr", "0x12000"], ["--entry-point", "0x12003"]])
def test_declared_coordinates_and_exact_source_transport(declared_args, coordinates):
    argv, declaration, observed = declared_args
    args = parser_module.parse_cli_arguments(argv + coordinates)
    assert (args.base_addr, args.entry_point) == (0x1200, 0x12003)
    assert args.real16_declared_input == declaration
    assert observed == [(declaration, args.binary.read_bytes())]


@pytest.mark.parametrize("requested", ["0x110", "0x1100"])
def test_declared_low_base_accepts_only_exact_coordinate_projections(declared_args, monkeypatch, requested):
    argv, declaration, _ = declared_args
    boot = SimpleNamespace(
        image=SimpleNamespace(load_segment=0x110),
        entry=SimpleNamespace(linear=lambda: 0x1100),
    )
    monkeypatch.setattr(parser_module, "read_declared_real16_input_8616", lambda *_: SimpleNamespace(boot=boot))
    args = parser_module.parse_cli_arguments([*argv, "--base-addr", requested])
    assert (args.base_addr, args.entry_point) == (0x110, 0x1100)
    assert args.real16_declared_input == declaration


@pytest.mark.parametrize("conflict", [["--base-addr", "0x12001"], ["--base-addr", "0x1000"], ["--entry-point", "0x1000"], ["--blob"], ["--proc", "main"]])
def test_declared_conflicts_refuse_with_clear_failure(declared_args, conflict, capsys):
    argv, _, _ = declared_args
    with pytest.raises(SystemExit) as exc:
        parser_module.parse_cli_arguments(argv + conflict)
    assert exc.value.code == 2
    assert "--real16-declared-input" in capsys.readouterr().err


def test_com_declaration_refuses(declared_args, capsys):
    argv, _, _ = declared_args
    argv[0] = "sample.COM"
    with pytest.raises(SystemExit) as exc:
        parser_module.parse_cli_arguments(argv)
    assert exc.value.code == 2
    assert ".COM" in capsys.readouterr().err


def test_adapter_refusal_remains_cli_failure(declared_args, monkeypatch, capsys):
    argv, _, _ = declared_args

    def refuse(path, source):
        raise ValueError("source_sha256 mismatch")

    monkeypatch.setattr(parser_module, "read_declared_real16_input_8616", refuse)
    with pytest.raises(SystemExit) as exc:
        parser_module.parse_cli_arguments(argv)
    assert exc.value.code == 2
    assert "source_sha256 mismatch" in capsys.readouterr().err


def test_clean_worker_preserves_declaration_and_resolved_coordinates(declared_args):
    argv, declaration, _ = declared_args
    args = parser_module.parse_cli_arguments(argv)
    command = cli_core._serial_clean_worker_command_8616(args, recovery_addr=0x12003, timeout=5)
    reparsed = parser_module.parse_cli_arguments(command[3:])
    assert reparsed.real16_declared_input == declaration
    assert (reparsed.base_addr, reparsed.entry_point) == (args.base_addr, args.entry_point)


def test_isolated_discovery_reload_inherits_declaration(tmp_path, monkeypatch):
    declaration = tmp_path / "input.json"
    project = SimpleNamespace(loader=SimpleNamespace(main_object=SimpleNamespace(
        binary=tmp_path / "sample.exe", linked_base=0x12000,
    )), entry=0x12003)
    isolated = SimpleNamespace()
    observed = []

    def build(binary, **kwargs):
        observed.append(kwargs)
        return isolated

    monkeypatch.setattr(discovery_module, "declared_input_path_8616", lambda source: declaration)
    monkeypatch.setattr(discovery_module, "_build_project_cached", build)
    monkeypatch.setattr(discovery_module, "_copy_signature_policy", lambda source, target: None)
    assert discovery_module.isolated_discovery_evidence_project_8616(project) is isolated
    assert observed[0]["real16_declared_input"] == declaration


def test_declaration_mutation_changes_both_cache_keys_and_disables_reuse(declared_args, tmp_path, monkeypatch):
    argv, declaration, _ = declared_args
    args = parser_module.parse_cli_arguments(argv)
    monkeypatch.setattr(direct_identity, "_recovery_cache_key", lambda **kwargs: kwargs["extra"])
    monkeypatch.setattr(worker_cache, "_recovery_cache_key", lambda **kwargs: kwargs["extra"])
    direct_inputs = direct_identity.DirectRequestCacheInputs8616.from_cli(args, signature_catalog=None)
    assert direct_inputs is not None
    evidence = tmp_path / "evidence.json"
    evidence.write_text("{}")
    worker_inputs = worker_cache.serial_worker_cache_inputs_8616(
        args, requested_addr=0x12003, recovery_addr=0x12003, timeout=5,
        evidence_path=evidence, environment={}, result_schema=1,
    )
    before_direct = direct_identity.build_direct_request_cache_key_8616(direct_inputs)
    before_worker = worker_cache.build_serial_worker_cache_key_8616(worker_inputs)
    declaration.write_text("second declaration")
    assert direct_identity.build_direct_request_cache_key_8616(direct_inputs) != before_direct
    assert worker_cache.build_serial_worker_cache_key_8616(worker_inputs) != before_worker
    assert not direct_identity.direct_request_cache_enabled_8616(args)
    lookup = worker_cache.load_serial_worker_cache_8616(worker_inputs, enabled=True)
    assert lookup.verdict is worker_cache.SerialWorkerCacheVerdict8616.DISABLED
    assert lookup.reason is worker_cache.SerialWorkerCacheReason8616.LIVE_DECLARATION_AUTHORITY_REQUIRED
    assert lookup.key is None
