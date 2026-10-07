"""Run a selected existing MS C case through the established round-trip owner.

Layer: Tooling/gates.
Responsibility: isolate artifacts, bound the child process tree, and retain a
compact structured result. Compilation and decompilation stay in the old runner.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import shutil
import signal
import subprocess
import sys
import time
from collections.abc import Mapping
from contextlib import suppress
from pathlib import Path
from typing import TextIO

ROOT: Path = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.compiler_toolchain.compiler_coverage_provenance import (  # noqa: E402
    implementation_fingerprint,
    input_fingerprint,
    runtime_environment_snapshot,
)
from tools.compiler_toolchain.compiler_coverage_result import (  # noqa: E402
    CoverageOutcome,
    classify_roundtrip_report,
    roundtrip_diagnostics,
)
from tools.compiler_toolchain.compiler_profile import (  # noqa: E402
    MSC6_AX_PROFILE_ID,
    MSC6_AX_TOOLCHAIN_ROOT,
    CompilerProfileSelection,
    CompilerToolchain,
    msc6_ax_toolchain,
    profile_registry_path,
    resolve_case_toolchain,
)
from tools.compiler_toolchain.msc6_memory_model import MSCMemoryModel  # noqa: E402
from tools.dev.process_metrics import process_tree_pids  # noqa: E402

COMPILER_ROOT: Path = MSC6_AX_TOOLCHAIN_ROOT
KVIKDOS: Path = Path("/home/xor/kvikdos/kvikdos")
CHILD_ENVIRONMENT_OVERRIDES: dict[str, str] = {"PYTHON_JIT": "1", "PYTHONHASHSEED": "0"}


def _kill_and_reap(process: subprocess.Popen[bytes]) -> int:
    """Stop visible descendants, including detached workers, before the root."""
    # Snapshot before killing the root: afterward detached children are reparented.
    descendants = process_tree_pids((process.pid,)) or (process.pid,)
    for pid in reversed(descendants):
        if pid != process.pid:
            with suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
    # The group may exit between the deadline and signal delivery.
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    return process.wait()


def _execute(command: list[str], log: TextIO, timeout: float) -> tuple[int, bool]:
    """Bound the child tree and also clean it up when execution is interrupted."""
    environment = dict(os.environ, **CHILD_ENVIRONMENT_OVERRIDES)
    process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT,
                               start_new_session=True)
    try:
        return process.wait(timeout=timeout), False
    except subprocess.TimeoutExpired:
        return _kill_and_reap(process), True
    except BaseException:
        _kill_and_reap(process)
        raise


def _evidence_arguments(selection: CompilerProfileSelection) -> list[str]:
    """Forward the probe evidence path only when it supplied the toolchain."""
    if selection.evidence_path is None:
        return []
    return ["--profile-evidence", str(selection.evidence_path)]


def _evidence_fingerprint(selection: CompilerProfileSelection) -> dict[str, str | int] | None:
    """Fingerprint the probe file that verified a non-built-in toolchain."""
    if selection.evidence_path is None:
        return None
    return dict(input_fingerprint(selection.evidence_path))


def _resolve_profile_selection(
    memory_model: MSCMemoryModel | None,
    compiler_profile: CompilerProfileSelection | None,
) -> CompilerProfileSelection:
    """Default to the built-in MS C 6 lane; reject conflicting settings."""
    if compiler_profile is None:
        return CompilerProfileSelection(
            toolchain=msc6_ax_toolchain(
                root=COMPILER_ROOT, memory_model=memory_model or MSCMemoryModel.SMALL,
            ),
            evidence_path=None,
        )
    if memory_model is not None and memory_model is not compiler_profile.toolchain.memory_model:
        raise ValueError("memory_model conflicts with the selected compiler profile")
    return compiler_profile


def run_existing_case(
    case: str, output: Path, *, timeout: float = 600,
    memory_model: MSCMemoryModel | None = None,
    compiler_profile: CompilerProfileSelection | None = None,
) -> CoverageOutcome:
    """Run one known fixture in a new artifact directory; never reuse stale reports."""
    source = ROOT / "examples" / "msc6_constructs" / f"{case}.c"
    if not case.isidentifier() or not source.is_file():
        raise ValueError(f"Unknown MS C fixture: {case!r}")
    return run_source_case(
        source, output, timeout=timeout, memory_model=memory_model, compiler_profile=compiler_profile,
    )


def _validated_runtime_headers(runtime_headers: Mapping[str, Path] | None) -> dict[str, Path]:
    """Reject unsafe or ambiguous header destinations before creating artifacts."""
    headers = dict(runtime_headers or {})
    for name, path in headers.items():
        if Path(name).name != name or Path(name).suffix.lower() != ".h" or not path.is_file():
            raise ValueError(f"Invalid runtime header: {name!r}")
    if len({name.casefold() for name in headers}) != len(headers):
        raise ValueError("Runtime header names collide under DOS case folding")
    return headers


def _validated_runtime_sources(runtime_sources: Mapping[str, Path] | None) -> dict[str, Path]:
    """Reject unsafe or ambiguous runtime translation units before staging."""
    sources = dict(runtime_sources or {})
    for name, path in sources.items():
        if Path(name).name != name or Path(name).suffix.lower() != ".c" or not path.is_file():
            raise ValueError(f"Invalid runtime source: {name!r}")
        base, _dot, ext = name.partition(".")
        if not base or len(base) > 8 or len(ext) > 3:
            raise ValueError(f"Runtime source must be a DOS 8.3 name: {name!r}")
    if len({name.casefold() for name in sources}) != len(sources):
        raise ValueError("Runtime source names collide under DOS case folding")
    return sources


def _merge_signature_catalogs(catalogs: tuple[Path, ...], output: Path) -> Path:
    """Concatenate pinned catalogs into one deterministic staging artifact."""
    merged = output / "signature-catalogs.pat"
    merged.write_bytes(b"".join(path.read_bytes() for path in catalogs))
    return merged


def _read_roundtrip_report(report: Path) -> object:
    """Return report evidence, or no evidence when the child left none usable."""
    try:
        return json.loads(report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _stable_input_outcome(
    outcome: CoverageOutcome,
    *,
    implementation_unchanged: bool,
    environment_unchanged: bool,
) -> tuple[CoverageOutcome, str | None]:
    """Refuse a reported pass when its execution identity changed in flight."""
    if outcome is not CoverageOutcome.PASSED:
        return outcome, None
    if not implementation_unchanged:
        return CoverageOutcome.HARNESS_FAILED, "Owned Python sources changed during execution; replay with stable inputs"
    if not environment_unchanged:
        return CoverageOutcome.HARNESS_FAILED, "Runtime environment changed during execution; replay with stable inputs"
    return outcome, None


def _validate_stage_budget(stage_budget_seconds: int | None) -> None:
    """Reject a frozen per-stage budget outside its positive 120-second ceiling."""
    if stage_budget_seconds is not None and not 0 < stage_budget_seconds <= 120:
        raise ValueError("Stage budget must be within 1..120 seconds")


def _resolved_signature_catalogs(
    signature_catalog: Path | None,
    signature_catalogs: tuple[Path, ...],
) -> tuple[Path, ...]:
    """Reject conflicting catalog arguments and resolve every pinned catalog."""
    if signature_catalog is not None and signature_catalogs:
        raise ValueError("Pass either signature_catalog or signature_catalogs, not both")
    items = signature_catalogs or ((signature_catalog,) if signature_catalog is not None else ())
    catalogs = tuple(item.resolve(strict=True) for item in items)
    for item in catalogs:
        if not item.is_file():
            raise ValueError("Signature catalog must be a file")
    return catalogs


def _case_provenance(
    *,
    source: Path,
    toolchain: CompilerToolchain,
    selection: CompilerProfileSelection,
    kvikdos: Path,
    expected_exit_code: int,
    expected_stdout_contains: str | None,
    stage_budget_seconds: int | None,
    headers: dict[str, Path],
    runtime_sources: dict[str, Path],
    catalogs: tuple[Path, ...],
    catalog: Path | None,
) -> dict[str, object]:
    """Record every hashed input that a frozen row consumed."""
    provenance: dict[str, object] = {
        "source": input_fingerprint(source),
        "compiler": input_fingerprint(toolchain.toolchain_root),
        "emulator": input_fingerprint(kvikdos),
        "python": input_fingerprint(Path(sys.executable)),
        "runner": input_fingerprint(ROOT / "tools/compiler_toolchain/build_msc6_examples.py"),
        "compiler_profile": toolchain.to_dict(),
        "profile_evidence": _evidence_fingerprint(selection),
        "expected_exit_code": expected_exit_code,
        "expected_stdout_contains": expected_stdout_contains,
        "stage_budget_seconds": stage_budget_seconds,
        "runtime_headers": {name: input_fingerprint(path) for name, path in headers.items()},
        "runtime_sources": {name: input_fingerprint(path) for name, path in runtime_sources.items()},
        "signature_catalogs": [input_fingerprint(item) for item in catalogs],
        "signature_catalog": input_fingerprint(catalog) if catalog is not None else None,
        "implementation": implementation_fingerprint(ROOT),
        "environment": runtime_environment_snapshot().to_dict(),
        "child_environment_overrides": dict(CHILD_ENVIRONMENT_OVERRIDES),
    }
    return provenance


def _case_command(
    *,
    case: str,
    source: Path,
    output: Path,
    toolchain: CompilerToolchain,
    kvikdos: Path,
    expected_exit_code: int,
    expected_stdout_contains: str | None,
    stage_budget_seconds: int | None,
    runtime_sources: dict[str, Path],
    selection: CompilerProfileSelection,
    catalog: Path | None,
) -> list[str]:
    """Build the pinned child command for one source round-trip."""
    command = [
        sys.executable, "-m", "tools.compiler_toolchain.build_msc6_examples",
        "--only-constructs", case, "--out-dir", str(output),
        "--examples-dir", str(source.parent), "--harvest-success-code", str(expected_exit_code),
        "--decompile-mode", "functions", "--decompile-max-functions", "0",
        "--decompile-ignore-local-sidecar-hints",
        "--decompile-timeout", "60", "--decompile-run-timeout",
        str(stage_budget_seconds if stage_budget_seconds is not None else 600),
        "--msc6-root", str(toolchain.toolchain_root), "--kvikdos", str(kvikdos),
    ]
    if stage_budget_seconds is not None:
        command += ["--stage-timeout", str(stage_budget_seconds)]
    command += [
        "--memory-model", toolchain.memory_model.value,
        "--compiler-profile", toolchain.profile_id,
    ]
    if expected_stdout_contains is not None:
        command += ["--harvest-stdout-contains", expected_stdout_contains]
    for name in runtime_sources:
        command += ["--runtime-source", name]
    command += _evidence_arguments(selection)
    command += ["--signature-catalog", str(catalog)] if catalog is not None else []
    return command


def run_source_case(
    source: Path, output: Path, *, timeout: float = 600,
    memory_model: MSCMemoryModel | None = None,
    expected_exit_code: int = 255,
    expected_stdout_contains: str | None = None,
    stage_budget_seconds: int | None = None,
    runtime_headers: Mapping[str, Path] | None = None,
    runtime_sources: Mapping[str, Path] | None = None,
    signature_catalog: Path | None = None,
    signature_catalogs: tuple[Path, ...] = (),
    compiler_profile: CompilerProfileSelection | None = None,
) -> CoverageOutcome:
    """Feed an external fixture through the same bounded legacy round-trip owner."""
    source = source.resolve(strict=True)
    selection = _resolve_profile_selection(memory_model, compiler_profile)
    toolchain = selection.toolchain
    case = source.stem
    if not case.isidentifier() or source.suffix != ".c" or not source.is_file():
        raise ValueError("Fixture must be a .c file with an identifier stem")
    if type(expected_exit_code) is not int or not 0 <= expected_exit_code <= 255:
        raise ValueError("Expected exit code must be an integer DOS exit status")
    if expected_stdout_contains is not None and not expected_stdout_contains:
        raise ValueError("Expected stdout substring must be nonempty or absent")
    _validate_stage_budget(stage_budget_seconds)
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("Case timeout must be positive and finite")
    headers = _validated_runtime_headers(runtime_headers)
    runtime_srcs = _validated_runtime_sources(runtime_sources)
    catalogs = _resolved_signature_catalogs(signature_catalog, signature_catalogs)
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    for name, path in (*headers.items(), *runtime_srcs.items()):
        shutil.copy2(path, output / name)
    catalog = _merge_signature_catalogs(catalogs, output) if len(catalogs) > 1 else (
        catalogs[0] if catalogs else None
    )
    kvikdos = toolchain.kvikdos_executable or KVIKDOS
    command = _case_command(
        case=case,
        source=source,
        output=output,
        toolchain=toolchain,
        kvikdos=kvikdos,
        expected_exit_code=expected_exit_code,
        expected_stdout_contains=expected_stdout_contains,
        stage_budget_seconds=stage_budget_seconds,
        runtime_sources=runtime_srcs,
        selection=selection,
        catalog=catalog,
    )
    provenance = _case_provenance(
        source=source,
        toolchain=toolchain,
        selection=selection,
        kvikdos=kvikdos,
        expected_exit_code=expected_exit_code,
        expected_stdout_contains=expected_stdout_contains,
        stage_budget_seconds=stage_budget_seconds,
        headers=headers,
        runtime_sources=runtime_srcs,
        catalogs=catalogs,
        catalog=catalog,
    )
    start = time.monotonic()
    outcome = CoverageOutcome.HARNESS_FAILED
    returncode: int | None = None
    error: str | None = None
    with (output / "runner.log").open("w", encoding="utf-8") as log:
        try:
            returncode, timed_out = _execute(command, log, timeout)
            if timed_out:
                outcome = CoverageOutcome.TIMED_OUT
        except OSError as failure:
            error = str(failure)
            log.write(f"Harness execution failed: {error}\n")
    report = output / "report.json"
    payload: object = None
    if outcome is not CoverageOutcome.TIMED_OUT and returncode is not None:
        payload = _read_roundtrip_report(report)
        outcome = classify_roundtrip_report(payload, case, returncode)
    implementation_after = implementation_fingerprint(ROOT)
    implementation_unchanged = provenance["implementation"] == implementation_after
    environment_after = runtime_environment_snapshot().to_dict()
    environment_unchanged = provenance["environment"] == environment_after
    outcome, stability_error = _stable_input_outcome(
        outcome,
        implementation_unchanged=implementation_unchanged,
        environment_unchanged=environment_unchanged,
    )
    if stability_error is not None:
        error = stability_error
    summary = {
        "schema": 1, "case": case, "outcome": outcome.value,
        "seconds": time.monotonic() - start, "returncode": returncode,
        "command": command, "report": str(report),
        "error": error,
        "diagnostics": roundtrip_diagnostics(payload),
        "inputs": provenance,
        "implementation_after": implementation_after,
        "implementation_unchanged": implementation_unchanged,
        "environment_after": environment_after,
        "environment_unchanged": environment_unchanged,
        "memory_model": toolchain.memory_model.value,
        "compiler_profile": toolchain.to_dict(),
        "scope": "existing_roundtrip_only_not_feature_coverage",
    }
    (output / "coverage-result.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return outcome


def main() -> int:
    """Expose selected-case execution without flooding the console with harness logs."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", required=True)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument("--memory-model", type=MSCMemoryModel, choices=list(MSCMemoryModel), default=MSCMemoryModel.SMALL)
    parser.add_argument("--compiler-profile", default=MSC6_AX_PROFILE_ID)
    parser.add_argument("--profile-evidence", type=Path)
    args = parser.parse_args()
    try:
        toolchain = resolve_case_toolchain(
            profile_id=args.compiler_profile, memory_model=args.memory_model,
            evidence_path=args.profile_evidence,
        )
        profile = CompilerProfileSelection(
            toolchain=toolchain,
            evidence_path=(
                profile_registry_path(args.profile_evidence)
                if toolchain.profile_id != MSC6_AX_PROFILE_ID else None
            ),
        )
        outcome = run_existing_case(
            args.case, args.out_dir, timeout=args.timeout, compiler_profile=profile,
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(f"{args.case}: {outcome.value}; artifacts={args.out_dir}")
    return 0 if outcome is CoverageOutcome.PASSED else 1


if __name__ == "__main__":
    raise SystemExit(main())
