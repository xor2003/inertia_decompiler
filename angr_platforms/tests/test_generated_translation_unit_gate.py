from __future__ import annotations

from pathlib import Path

import pytest

from scripts.check_generated_translation_unit import (
    CompilerDiagnosticKind,
    CompilerDiagnosticSeverity,
    assemble_translation_unit,
    compile_translation_unit,
    parse_compiler_diagnostics,
)


def _write_artifact(root: Path, address: int, payload: str) -> None:
    (root / f"{address:08x}-sub_{address:x}.c").write_text(payload, encoding="utf-8")


def test_assembly_preserves_function_payloads_without_diagnostics(tmp_path: Path) -> None:
    function_dir = tmp_path / "functions"
    function_dir.mkdir()
    first = "void sub_1000(void)\n{\n    return;\n}\n"
    second = "int sub_2000(void)\n{\n    return 2;\n}\n"
    _write_artifact(function_dir, 0x1000, first)
    _write_artifact(function_dir, 0x2000, second)
    output = tmp_path / "generated.c"
    expected_addresses = (0x1000, 0x2000)

    count = assemble_translation_unit(function_dir, output, expected_addresses=expected_addresses)

    assembled = output.read_text(encoding="utf-8")
    assert count == len(expected_addresses)
    assert "void sub_1000(void);" in assembled
    assert "int sub_2000(void);" in assembled
    assert "return 2;" in assembled
    assert "[dbg]" not in assembled


def test_assembly_refuses_missing_function_artifact(tmp_path: Path) -> None:
    _write_artifact(tmp_path, 0x1000, "void sub_1000(void) {}\n")

    with pytest.raises(ValueError, match="inventory mismatch"):
        assemble_translation_unit(tmp_path, tmp_path / "generated.c", expected_addresses=(0x1000, 0x2000))


@pytest.mark.parametrize("suffix", [".c", ".dec", ""])
def test_compiler_gate_classifies_conflicting_function_contract(tmp_path: Path, suffix: str) -> None:
    source = tmp_path / f"conflict{suffix}"
    source.write_text("int f(void);\nvoid f(void) {}\n", encoding="utf-8")

    report = compile_translation_unit(
        source,
        function_count=1,
        maximum_errors=0,
        maximum_warnings=0,
    )

    assert report.passed is False
    assert report.error_count >= 1
    assert any(item.kind is CompilerDiagnosticKind.CONFLICTING_TYPE for item in report.diagnostics)


def test_compiler_gate_refuses_nonzero_exit_without_parsed_diagnostics(tmp_path: Path) -> None:
    source = tmp_path / "valid.c"
    source.write_text("int f(void) { return 0; }\n", encoding="utf-8")

    report = compile_translation_unit(
        source,
        compiler="false",
        function_count=1,
        maximum_errors=1,
        maximum_warnings=1,
    )

    assert report.compiler_returncode != 0
    assert report.error_count == report.warning_count == 0
    assert report.passed is False


def test_diagnostic_parser_returns_typed_severity_and_kind() -> None:
    diagnostics = parse_compiler_diagnostics(
        "/tmp/generated.c:12:3: warning: unused variable 'x' [-Wunused-variable]\n"
    )

    assert len(diagnostics) == 1
    assert diagnostics[0].severity is CompilerDiagnosticSeverity.WARNING
    assert diagnostics[0].kind is CompilerDiagnosticKind.UNUSED
