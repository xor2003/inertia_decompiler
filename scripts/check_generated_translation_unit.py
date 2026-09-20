"""Compile untouched generated-function artifacts as one C translation unit.

Layer: Tooling/gates.
Responsibility: assemble clean validated payload artifacts through the structured
export syntax layer, run the configured C compiler, and report typed diagnostic
counts. This gate never recovers decompiler semantics from rendered C.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Direct script execution needs the repository root before project imports.
from angr_platforms.X86_16.lowering.c_runtime_header import render_c_runtime_header_8616  # noqa: E402

from inertia_decompiler.generated_translation_unit_assembly import (  # noqa: E402
    assemble_generated_translation_unit,
)
from scripts.check_sortd_sidecar_free import EXPECTED_SORTD_FUNCTION_ADDRS  # noqa: E402

_ARTIFACT_NAME_RE = re.compile(r"^(?P<address>[0-9a-fA-F]{8})-.+\.c$")
_GCC_DIAGNOSTIC_RE = re.compile(
    r"^(?P<file>.*?):(?P<line>\d+):(?P<column>\d+): "
    r"(?P<severity>fatal error|error|warning|note): (?P<message>.*)$"
)


class CompilerDiagnosticSeverity(StrEnum):
    """Typed compiler severity used by the ratchet."""

    ERROR = "error"
    WARNING = "warning"
    NOTE = "note"


class CompilerDiagnosticKind(StrEnum):
    """Stable diagnostic families tracked across generated-C improvements."""

    CONFLICTING_TYPE = "conflicting-type"
    REDEFINITION = "redefinition"
    INCOMPATIBLE_POINTER = "incompatible-pointer"
    UNUSED = "unused"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class CompilerDiagnostic:
    """One parsed compiler diagnostic from the generated translation unit."""

    severity: CompilerDiagnosticSeverity
    kind: CompilerDiagnosticKind
    line: int
    column: int
    message: str


@dataclass(frozen=True, slots=True)
class TranslationUnitReport:
    """Compilation and ratchet result for one assembled generated-C unit."""

    function_count: int
    compiler_returncode: int
    error_count: int
    warning_count: int
    diagnostics: tuple[CompilerDiagnostic, ...]
    passed: bool


def _diagnostic_kind(message: str) -> CompilerDiagnosticKind:
    """Classify one GCC message without using it as decompiler evidence."""
    normalized = message.casefold()
    if "conflicting types for" in normalized:
        return CompilerDiagnosticKind.CONFLICTING_TYPE
    if "redefinition of" in normalized:
        return CompilerDiagnosticKind.REDEFINITION
    if "incompatible pointer type" in normalized:
        return CompilerDiagnosticKind.INCOMPATIBLE_POINTER
    if "unused" in normalized:
        return CompilerDiagnosticKind.UNUSED
    return CompilerDiagnosticKind.OTHER


def parse_compiler_diagnostics(output: str) -> tuple[CompilerDiagnostic, ...]:
    """Parse GCC's external diagnostic protocol into typed records."""
    diagnostics: list[CompilerDiagnostic] = []
    for line_text in output.splitlines():
        match = _GCC_DIAGNOSTIC_RE.match(line_text)
        if match is None:
            continue
        raw_severity = match.group("severity")
        if raw_severity in {"error", "fatal error"}:
            severity = CompilerDiagnosticSeverity.ERROR
        elif raw_severity == "warning":
            severity = CompilerDiagnosticSeverity.WARNING
        else:
            severity = CompilerDiagnosticSeverity.NOTE
        message = match.group("message")
        diagnostics.append(
            CompilerDiagnostic(
                severity=severity,
                kind=_diagnostic_kind(message),
                line=int(match.group("line")),
                column=int(match.group("column")),
                message=message,
            )
        )
    return tuple(diagnostics)


def assemble_translation_unit(
    function_c_dir: Path,
    output_path: Path,
    *,
    expected_addresses: Sequence[int] = EXPECTED_SORTD_FUNCTION_ADDRS,
) -> int:
    """Write the runtime header followed by every untouched function artifact."""
    artifacts_by_address: dict[int, Path] = {}
    for artifact in sorted(function_c_dir.glob("*.c")):
        match = _ARTIFACT_NAME_RE.match(artifact.name)
        if match is None:
            continue
        address = int(match.group("address"), 16)
        if address in artifacts_by_address:
            raise ValueError(f"duplicate generated-C artifact for {address:#x}")
        artifacts_by_address[address] = artifact
    missing = tuple(address for address in expected_addresses if address not in artifacts_by_address)
    unexpected = tuple(address for address in artifacts_by_address if address not in expected_addresses)
    if missing or unexpected:
        raise ValueError(f"generated-C artifact inventory mismatch: missing={missing!r} unexpected={unexpected!r}")
    payloads = tuple(artifacts_by_address[address].read_text(encoding="utf-8") for address in expected_addresses)
    assembled = assemble_generated_translation_unit(payloads)
    if assembled.function_count != len(expected_addresses):
        raise ValueError(
            f"generated-C function definition mismatch: expected={len(expected_addresses)} "
            f"actual={assembled.function_count}"
        )
    parts = [render_c_runtime_header_8616("portable-flat").rstrip(), assembled.source.rstrip()]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n\n".join(parts) + "\n", encoding="utf-8")
    return len(expected_addresses)


def compile_translation_unit(
    translation_unit: Path,
    *,
    compiler: str = "gcc",
    function_count: int,
    maximum_errors: int,
    maximum_warnings: int,
) -> TranslationUnitReport:
    """Compile one generated unit and evaluate its monotonic diagnostic ceilings."""
    completed = subprocess.run(
        [compiler, "-x", "c", "-std=c11", "-Wall", "-Wextra", "-fsyntax-only", str(translation_unit)],
        capture_output=True,
        text=True,
        check=False,
    )
    diagnostics = parse_compiler_diagnostics(f"{completed.stderr}{completed.stdout}")
    error_count = sum(item.severity is CompilerDiagnosticSeverity.ERROR for item in diagnostics)
    warning_count = sum(item.severity is CompilerDiagnosticSeverity.WARNING for item in diagnostics)
    return TranslationUnitReport(
        function_count=function_count,
        compiler_returncode=completed.returncode,
        error_count=error_count,
        warning_count=warning_count,
        diagnostics=diagnostics,
        passed=(
            completed.returncode == 0
            and error_count <= maximum_errors
            and warning_count <= maximum_warnings
        ),
    )


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse translation-unit gate arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--function-c-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report-out", type=Path)
    parser.add_argument("--compiler", default="gcc")
    parser.add_argument("--maximum-errors", type=int, default=0)
    parser.add_argument("--maximum-warnings", type=int, default=0)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the generated translation-unit assembly and compilation ratchet."""
    args = _parse_args(argv)
    try:
        function_count = assemble_translation_unit(args.function_c_dir, args.output)
        report = compile_translation_unit(
            args.output,
            compiler=args.compiler,
            function_count=function_count,
            maximum_errors=args.maximum_errors,
            maximum_warnings=args.maximum_warnings,
        )
    except (OSError, ValueError) as ex:
        print(f"generated translation-unit gate failed: {ex}")
        return 2
    if args.report_out is not None:
        args.report_out.parent.mkdir(parents=True, exist_ok=True)
        args.report_out.write_text(json.dumps(asdict(report), indent=2) + "\n", encoding="utf-8")
    print(
        "generated translation-unit "
        f"functions={report.function_count} errors={report.error_count} warnings={report.warning_count} "
        f"compiler_exit={report.compiler_returncode} ratchet={'passed' if report.passed else 'failed'}"
    )
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
