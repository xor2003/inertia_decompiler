#!/usr/bin/env python3
"""Build selected UltraDecompiler QuickC fixtures through kvikdos.

Layer: Tooling/gates.
Responsibility: owns importing and building selected QuickC fixtures.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

if __package__:
    from .generated_c_contracts import (
        CallGuardedAssignmentRequirement,
        GeneratedCContract,
        GeneratedCContractResult,
        GeneratedCContractStatus,
    )
    from .generated_c_indexed_argument_contract import IndexedArgumentUseRequirement
else:
    from generated_c_contracts import (
        CallGuardedAssignmentRequirement,
        GeneratedCContract,
        GeneratedCContractResult,
        GeneratedCContractStatus,
    )
    from generated_c_indexed_argument_contract import IndexedArgumentUseRequirement

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
DEFAULT_ULTRA_QUICKC_ROOT: Path = REPO_ROOT / "borrow" / "UltraDecompiler" / "QuickC"
DEFAULT_KVIKDOS: Path = Path("/home/xor/kvikdos/kvikdos")
DEFAULT_OUTPUT: Path = REPO_ROOT / "examples" / "build_ultra_quickc"
DEFAULT_COMPILE_FLAGS: tuple[str, ...] = ("/Od", "/AS")
DEFAULT_LINK_FLAGS: tuple[str, ...] = ()
DEFAULT_DECOMPILE: Path = REPO_ROOT / "decompile.py"
DEFAULT_SIGNATURE_CATALOG: Path = REPO_ROOT / "signature_catalogs" / "all_compilers_catalog_bundle.zip"
DECOMPILE_PROCESS_SETUP_TIMEOUT_SECONDS: int = 120
type ExpectedStatus = Literal["required", "xfail"]


@dataclass(frozen=True, slots=True)
class QuickCFixtureSpec:
    """Structured build, run, and decompile expectations for one QuickC fixture."""

    name: str
    source_rel: str
    expected_exit_code: int = 0
    expected_stdout_contains: tuple[str, ...] = ()
    run_args: tuple[str, ...] = ()
    decompile_targets: tuple[str, ...] = ()
    decompile_addr: int | None = None
    decompile_target_override_reason: str | None = None
    memory_model: str = "small"
    compiler_flags: tuple[str, ...] = DEFAULT_COMPILE_FLAGS
    link_flags: tuple[str, ...] = DEFAULT_LINK_FLAGS
    exclude_reason: str | None = None
    expected_status: ExpectedStatus = "required"
    expected_blocker: str | None = None
    generated_c_contract: GeneratedCContract | None = None


ARGS_FIXTURE: QuickCFixtureSpec = QuickCFixtureSpec(
    "args",
    "PROGRAMS/args.c",
    expected_stdout_contains=("total: 2",),
    run_args=("-v", "alpha", "beta"),
    generated_c_contract=GeneratedCContract(
        forbidden_fragments=(
            "SEG_U16(ds, arg_5 + (local_2 << 1))",
            "local_2 = 104;",
            "local_2 = 118;",
        ),
        guarded_assignments=(
            CallGuardedAssignmentRequirement(
                guard_call="sub_10010",
                guard_argument=118,
                assignment_name="local_4",
                assignment_value=1,
            ),
        ),
        indexed_argument_uses=(
            IndexedArgumentUseRequirement(
                base_name="arg_6",
                index_name="local_2",
                minimum_count=3,
                guard_call="sub_10010",
                required_guard_arguments=(104, 118),
            ),
        ),
    ),
)

DEFAULT_FIXTURES: tuple[QuickCFixtureSpec, ...] = (
    QuickCFixtureSpec("hello", "PROGRAMS/hello.c", expected_stdout_contains=("Hello world",)),
    QuickCFixtureSpec("add", "PROGRAMS/add.c", expected_stdout_contains=("15",)),
    QuickCFixtureSpec(
        "whsum",
        "PROGRAMS/whsum.c",
        expected_stdout_contains=("while sum: 15",),
        generated_c_contract=GeneratedCContract(
            required_fragments=("void sub_105e6(unsigned short a0, unsigned short a1);",),
        ),
    ),
    ARGS_FIXTURE,
)

PROMOTED_FIXTURES: tuple[QuickCFixtureSpec, ...] = (
    ARGS_FIXTURE,
)

EXCLUDED_FIXTURES: tuple[QuickCFixtureSpec, ...] = (
    QuickCFixtureSpec(
        "switch",
        "PROGRAMS/switch.c",
        exclude_reason="candidate retained until QuickC switch decompile is deterministic under the fast-lane timeout",
    ),
    QuickCFixtureSpec(
        "fptr",
        "PROGRAMS/fptr.c",
        exclude_reason="candidate retained for later callsite-specific decompile triage",
    ),
    QuickCFixtureSpec(
        "st",
        "PROGRAMS/st.c",
        exclude_reason="candidate retained until struct-output expectations are made deterministic",
    ),
)


@dataclass(frozen=True)
class DecompileTargetSelection:
    """Evidence-backed decompile target chosen for a compiled fixture."""

    mode: str
    evidence_source: str
    targets: tuple[str, ...]
    addr: int | None
    reason: str
    symbol_name: str | None = None
    obj_path: str | None = None

    def to_json(self) -> dict[str, Any]:
        """Return a stable JSON representation for fixture reports."""

        return {
            "mode": self.mode,
            "evidence_source": self.evidence_source,
            "targets": list(self.targets),
            "addr": f"0x{self.addr:x}" if self.addr is not None else None,
            "reason": self.reason,
            "symbol_name": self.symbol_name,
            "obj_path": self.obj_path,
        }


def _run(cmd: list[str], *, timeout: int = 90) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="latin1",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _run_with_env(
    cmd: list[str],
    *,
    timeout: int = 90,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a subprocess with explicit environment additions and captured output."""

    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="latin1",
        errors="replace",
        timeout=timeout,
        check=False,
        env=merged_env,
    )


def _decompile_process_timeout(analysis_timeout: int) -> int:
    """Return outer CLI process budget separate from inner analysis timeout."""

    return max(int(analysis_timeout), 30) + DECOMPILE_PROCESS_SETUP_TIMEOUT_SECONDS


def _kvikdos_base(kvikdos: Path, out_dir: Path, quickc_root: Path) -> list[str]:
    return [
        str(kvikdos),
        f"--mount=c:{out_dir}/",
        f"--mount=e:{quickc_root}/",
        "--drive=c",
        "--cwd-dos=c:\\",
    ]


def _stage_result(
    name: str,
    cmd: list[str],
    proc: subprocess.CompletedProcess[str],
    *,
    wall_seconds: float,
) -> dict[str, Any]:
    return {
        "stage": name,
        "command": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "wall_seconds": round(wall_seconds, 3),
    }


def _timed_run(cmd: list[str], *, timeout: int = 90) -> tuple[subprocess.CompletedProcess[str], float]:
    """Run a command and return its wall-clock duration."""

    start = time.monotonic()
    proc = _run(cmd, timeout=timeout)
    return proc, time.monotonic() - start


def _parse_quickc_map_entry_addr(map_path: Path) -> int | None:
    if not map_path.is_file():
        return None
    for line in map_path.read_text(encoding="latin1", errors="replace").splitlines():
        stripped = line.strip()
        prefix = "Program entry point at "
        if not stripped.startswith(prefix):
            continue
        raw = stripped[len(prefix) :].strip()
        if ":" not in raw:
            return None
        segment_text, offset_text = raw.split(":", 1)
        try:
            segment = int(segment_text, 16)
            offset = int(offset_text, 16)
        except ValueError:
            return None
        return 0x10000 + ((segment << 4) + offset)
    return None


def _quickc_obj_public_candidates(obj_path: Path) -> tuple[dict[str, Any], ...]:
    if not obj_path.is_file():
        return ()
    try:
        import omf_pat
    except Exception:
        return ()
    try:
        _module_name, segments, publics, _refs = omf_pat._parse_omf_obj(obj_path)
    except Exception:
        return ()
    candidates: list[dict[str, Any]] = []
    for public in publics:
        seg_index = public.seg_index
        if not isinstance(seg_index, int) or seg_index <= 0 or seg_index > len(segments):
            continue
        segment = segments[seg_index - 1]
        if segment.class_name.upper() != "CODE":
            continue
        name = public.name
        if not isinstance(name, str) or not name:
            continue
        offset = public.offset
        if not isinstance(offset, int):
            continue
        candidates.append(
            {
                "symbol_name": name,
                "segment_name": segment.name,
                "segment_class": segment.class_name,
                "offset": offset,
                "addr": 0x10010 + offset,
            }
        )
    return tuple(sorted(candidates, key=lambda item: (0 if item["symbol_name"].lower() == "_main" else 1, item["offset"])))


def _select_decompile_target(spec: QuickCFixtureSpec, map_path: Path, obj_path: Path | None = None) -> DecompileTargetSelection:
    if spec.decompile_addr is not None and spec.decompile_targets:
        return DecompileTargetSelection(
            mode="override",
            evidence_source="fixture_metadata",
            targets=tuple(spec.decompile_targets),
            addr=spec.decompile_addr,
            reason=spec.decompile_target_override_reason or "fixture provides focused decompile target",
        )
    if obj_path is not None:
        public_candidates = _quickc_obj_public_candidates(obj_path)
        if public_candidates:
            selected = public_candidates[0]
            addr = int(selected["addr"])
            return DecompileTargetSelection(
                mode="auto",
                evidence_source="omf_public",
                targets=(f"sub_{addr:x}",),
                addr=addr,
                reason="QuickC OBJ PUBDEF provides CODE-segment user function candidate",
                symbol_name=str(selected["symbol_name"]),
                obj_path=str(obj_path),
            )
    entry_addr = _parse_quickc_map_entry_addr(map_path)
    if entry_addr is not None:
        return DecompileTargetSelection(
            mode="auto",
            evidence_source="map_entry_point",
            targets=("_start",),
            addr=entry_addr,
            reason="QuickC MAP provides entry point but no user function symbols",
        )
    fallback_targets = tuple(spec.decompile_targets) or ("sub_10010",)
    fallback_addr = spec.decompile_addr if spec.decompile_addr is not None else 0x10010
    return DecompileTargetSelection(
        mode="fallback",
        evidence_source="legacy_default",
        targets=fallback_targets,
        addr=fallback_addr,
        reason="no structured target evidence available",
    )


def _decompile_fixture(
    exe_path: Path,
    *,
    selection: DecompileTargetSelection,
    decompile: Path,
    timeout: int,
    generated_c_contract: GeneratedCContract | None = None,
) -> dict[str, Any]:
    targets = list(selection.targets)
    command = [
        sys.executable,
        "-u",
        str(decompile),
        str(exe_path),
    ]
    if selection.addr is not None:
        command.extend(["--addr", f"0x{selection.addr:x}"])
    command.extend(
        [
        "--max-functions",
        "1",
        "--timeout",
        str(timeout),
        "--no-alternate-source-c",
        "--brief",
        ]
    )
    if not decompile.is_file():
        return {
            "status": "skipped",
            "reason": f"missing decompile entrypoint: {decompile}",
            "command": command,
            "target_selection": selection.to_json(),
            "targets": targets,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "generated_c_present": False,
            "missing_targets": targets,
            "wall_seconds": 0.0,
            "validation_status": "unavailable",
            "validation_unavailable_reason": "decompile entrypoint missing",
        }
    start = time.monotonic()
    try:
        proc = _run_with_env(
            command,
            timeout=_decompile_process_timeout(timeout),
            env={"INERTIA_ENABLE_TAIL_VALIDATION": "1", "INERTIA_DISABLE_TIMING": "1", "PYTHONHASHSEED": "0"},
        )
    except subprocess.TimeoutExpired as ex:
        elapsed = time.monotonic() - start
        return {
            "status": "failed",
            "reason": f"timed out after {ex.timeout} seconds",
            "command": command,
            "target_selection": selection.to_json(),
            "targets": targets,
            "returncode": None,
            "stdout": (ex.stdout or "") if isinstance(ex.stdout, str) else "",
            "stderr": (ex.stderr or "") if isinstance(ex.stderr, str) else "",
            "generated_c_present": False,
            "missing_targets": targets,
            "wall_seconds": round(elapsed, 3),
            "validation_status": "unavailable",
            "validation_unavailable_reason": "decompile process timed out",
        }
    elapsed = time.monotonic() - start
    return _decompile_result_from_output(
        command=command,
        selection=selection,
        targets=targets,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        wall_seconds=elapsed,
        generated_c_contract=generated_c_contract,
    )


def _decompile_result_from_output(
    *,
    command: list[str],
    selection: DecompileTargetSelection,
    targets: list[str],
    returncode: int | None,
    stdout: str,
    stderr: str,
    wall_seconds: float,
    generated_c_contract: GeneratedCContract | None = None,
) -> dict[str, Any]:
    """Build the standard decompile result from captured CLI output."""

    combined = f"{stdout}\n{stderr}"
    generated_c_present = "{" in stdout and "}" in stdout and any(f"{target}(" in stdout for target in targets)
    missing_targets = [target for target in targets if f"{target}(" not in stdout and f"_{target}(" not in stdout]
    validation_status = "unavailable"
    validation_unavailable_reason = "tail validation summary not emitted"
    if "validation=passed" in combined or "whole-tail validation clean" in combined:
        validation_status = "passed"
        validation_unavailable_reason = ""
    elif "validation=failed" in combined or "tail validation failed" in combined:
        validation_status = "failed"
        validation_unavailable_reason = ""
    contract_result = (
        generated_c_contract.assess(stdout)
        if generated_c_contract is not None
        else GeneratedCContractResult(GeneratedCContractStatus.NOT_REQUIRED)
    )
    status = "passed"
    if (
        returncode != 0
        or not generated_c_present
        or missing_targets
        or validation_status == "failed"
        or not contract_result.passed
    ):
        status = "failed"
    return {
        "status": status,
        "command": command,
        "target_selection": selection.to_json(),
        "targets": targets,
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
        "generated_c_present": generated_c_present,
        "missing_targets": missing_targets,
        "wall_seconds": round(wall_seconds, 3),
        "validation_status": validation_status,
        "validation_unavailable_reason": validation_unavailable_reason,
        "generated_c_contract": contract_result.to_json(),
    }


def _compiler_evidence_for_fixture(exe_path: Path, *, catalog: Path = DEFAULT_SIGNATURE_CATALOG) -> dict[str, Any]:
    try:
        from scripts import report_compiler_matches as matcher
    except Exception as ex:
        return {
            "status": "gap",
            "family": "unknown",
            "memory_model": "unknown",
            "flags": [],
            "raw_features": {"import_error": str(ex)},
            "evidence_gap": "compiler matcher module unavailable",
        }
    raw = exe_path.read_bytes() if exe_path.is_file() else b""
    runtime_hits = matcher._detect_ms_runtime_libraries(raw)
    linker_family = matcher._linker_family_from_raw(raw)
    family = "Microsoft QuickC family" if any("Quick C" in hit for hit in runtime_hits) else "unknown"
    status = "passed" if family == "Microsoft QuickC family" else "gap"
    evidence_gap = "" if status == "passed" else "no QuickC runtime marker found"
    return {
        "status": status,
        "family": family,
        "memory_model": "small",
        "flags": ["/Od", "/AS"],
        "raw_features": {
            "runtime_hits": runtime_hits,
            "linker_family": linker_family,
            "catalog": str(catalog),
            "catalog_present": catalog.exists(),
        },
        "evidence_gap": evidence_gap,
    }


def _fixture_stem(spec: QuickCFixtureSpec) -> str:
    stem = spec.name.upper().replace("-", "_")
    if not stem or len(stem) > 8 or not all(char.isalnum() or char == "_" for char in stem):
        raise ValueError(f"fixture name cannot be represented as DOS 8.3 stem: {spec.name}")
    return stem


def build_fixture(
    spec: QuickCFixtureSpec,
    output_root: Path,
    *,
    kvikdos: Path = DEFAULT_KVIKDOS,
    quickc_root: Path = DEFAULT_ULTRA_QUICKC_ROOT,
    decompile: Path = DEFAULT_DECOMPILE,
    decompile_timeout: int = 30,
    decompile_now: bool = True,
) -> dict[str, Any]:
    """Compile, run, decompile, and report one QuickC fixture."""
    fixture_start = time.monotonic()
    source_path = quickc_root / spec.source_rel
    result = _fixture_base_result(spec, source_path, kvikdos, quickc_root)
    skip_reason = _fixture_skip_reason(spec, source_path, kvikdos, quickc_root)
    if skip_reason is not None:
        result.update({"status": "skipped", "skip_reason": skip_reason, "wall_seconds": 0.0})
        return result

    stem = _fixture_stem(spec)
    out_dir = output_root / spec.name
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    source_copy = out_dir / f"{stem}.C"
    shutil.copyfile(source_path, source_copy)

    _record_fixture_stages(spec, stem, out_dir, kvikdos, quickc_root, result)
    passed, missing_stdout = _fixture_stages_verdict(spec, result)

    exe_path = out_dir / f"{stem}.EXE"
    map_path = out_dir / f"{stem}.MAP"
    obj_path = out_dir / f"{stem}.OBJ"
    target_selection = _select_decompile_target(spec, map_path, obj_path=obj_path)
    result["decompile_target_selection"] = target_selection.to_json()
    if exe_path.is_file():
        result["decompile"] = _fixture_decompile_section(
            spec,
            exe_path,
            target_selection,
            decompile=decompile,
            decompile_timeout=decompile_timeout,
            decompile_now=decompile_now,
        )
        result["compiler_match"] = _compiler_evidence_for_fixture(exe_path)
        passed = passed and result["compiler_match"]["status"] in {"passed", "gap"}
        if decompile_now:
            passed = passed and result["decompile"]["status"] == "passed"
    else:
        result["decompile"], result["compiler_match"] = _missing_exe_sections(
            spec,
            target_selection,
        )
        passed = False
    result["wall_seconds"] = round(time.monotonic() - fixture_start, 3)
    result["pre_decompile_passed"] = passed
    if not decompile_now and isinstance(result.get("decompile"), dict) and result["decompile"].get("status") == "pending":
        result["status"] = "pending" if passed else "failed"
    else:
        result["status"] = "passed" if passed else "failed"
    if missing_stdout:
        result["missing_expected_stdout"] = missing_stdout
    if exe_path.is_file():
        result["exe"] = str(exe_path)
    if obj_path.is_file():
        result["obj"] = str(obj_path)
    if map_path.is_file():
        result["map"] = str(map_path)
    return result


def _fixture_base_result(
    spec: QuickCFixtureSpec,
    source_path: Path,
    kvikdos: Path,
    quickc_root: Path,
) -> dict[str, Any]:
    """Build the shared report skeleton for one fixture."""
    return {
        "name": spec.name,
        "source": str(source_path),
        "origin": "borrow/UltraDecompiler/QuickC",
        "runner": "kvikdos",
        "kvikdos": str(kvikdos),
        "toolchain_root": str(quickc_root),
        "compiler": "QCL.EXE",
        "linker": "LINK.EXE",
        "library": "SLIBCE.LIB",
        "memory_model": spec.memory_model,
        "compiler_flags": list(spec.compiler_flags),
        "link_flags": list(spec.link_flags),
        "expected_status": spec.expected_status,
        "expected_blocker": spec.expected_blocker,
        "expected_exit_code": spec.expected_exit_code,
        "expected_stdout_contains": list(spec.expected_stdout_contains),
        "run_args": list(spec.run_args),
        "decompile_targets": list(spec.decompile_targets),
        "decompile_addr": f"0x{spec.decompile_addr:x}" if spec.decompile_addr is not None else None,
        "decompile_target_override_reason": spec.decompile_target_override_reason,
        "stages": [],
        "excluded_fixtures": [
            {"name": excluded.name, "source_rel": excluded.source_rel, "reason": excluded.exclude_reason}
            for excluded in EXCLUDED_FIXTURES
        ],
        "promoted_fixtures": [
            {
                "name": promoted.name,
                "source_rel": promoted.source_rel,
                "expected_status": promoted.expected_status,
                "expected_blocker": promoted.expected_blocker,
                "run_args": list(promoted.run_args),
            }
            for promoted in PROMOTED_FIXTURES
        ],
        "generated_c_contract_spec": (
            spec.generated_c_contract.to_json() if spec.generated_c_contract is not None else None
        ),
    }


def _fixture_skip_reason(
    spec: QuickCFixtureSpec,
    source_path: Path,
    kvikdos: Path,
    quickc_root: Path,
) -> str | None:
    """Return the skip reason for one fixture, or None when it can build."""
    if spec.exclude_reason:
        return spec.exclude_reason
    if not source_path.is_file():
        return f"missing source fixture: {source_path}"
    if not kvikdos.is_file():
        return f"missing kvikdos executable: {kvikdos}"
    if not (quickc_root / "QCL.EXE").is_file() or not (quickc_root / "LINK.EXE").is_file():
        return f"missing QuickC tools under: {quickc_root}"
    return None


def _record_fixture_stages(
    spec: QuickCFixtureSpec,
    stem: str,
    out_dir: Path,
    kvikdos: Path,
    quickc_root: Path,
    result: dict[str, Any],
) -> None:
    """Compile, link, and run the fixture, appending stage results."""
    compile_cmd = (
        [*_kvikdos_base(kvikdos, out_dir, quickc_root), "--path-dos=e:\\", "--env=INCLUDE=e:\\INCLUDE", "--env=LIB=e:\\", "--prog=e:\\QCL.EXE", "e:\\QCL.EXE", *spec.compiler_flags, "/c", f"/Foc:\\{stem}.OBJ", f"c:\\{stem}.C"]
    )
    compile_proc, compile_seconds = _timed_run(compile_cmd)
    result["stages"].append(_stage_result("compile", compile_cmd, compile_proc, wall_seconds=compile_seconds))

    link_cmd = (
        [*_kvikdos_base(kvikdos, out_dir, quickc_root), "--env=LIB=e:\\", "--prog=e:\\LINK.EXE", "e:\\LINK.EXE", *spec.link_flags, f"c:\\{stem}.OBJ,c:\\{stem}.EXE,c:\\{stem}.MAP,e:\\SLIBCE.LIB;"]
    )
    link_proc, link_seconds = _timed_run(link_cmd)
    result["stages"].append(_stage_result("link", link_cmd, link_proc, wall_seconds=link_seconds))

    run_cmd = (
        [str(kvikdos), f"--mount=c:{out_dir}/", "--drive=c", "--cwd-dos=c:\\", f"--prog=c:\\{stem}.EXE", f"c:\\{stem}.EXE", *list(spec.run_args)]
    )
    if (out_dir / f"{stem}.EXE").is_file():
        run_proc, run_seconds = _timed_run(run_cmd)
        result["stages"].append(_stage_result("run", run_cmd, run_proc, wall_seconds=run_seconds))
    else:
        result["stages"].append(
            {
                "stage": "run",
                "command": run_cmd,
                "returncode": None,
                "stdout": "",
                "stderr": "skipped: executable was not produced",
                "wall_seconds": 0.0,
            }
        )


def _fixture_stages_verdict(
    spec: QuickCFixtureSpec,
    result: dict[str, Any],
) -> tuple[bool, list[str]]:
    """Return the pre-decompile pass verdict and missing stdout needles."""
    stage_codes = {stage["stage"]: stage["returncode"] for stage in result["stages"]}
    run_stage = result["stages"][-1]
    stdout = str(run_stage["stdout"])
    missing_stdout = [needle for needle in spec.expected_stdout_contains if needle not in stdout]
    passed = (
        stage_codes.get("compile") == 0
        and stage_codes.get("link") == 0
        and stage_codes.get("run") == spec.expected_exit_code
        and not missing_stdout
    )
    return passed, missing_stdout


def _fixture_decompile_section(
    spec: QuickCFixtureSpec,
    exe_path: Path,
    target_selection: DecompileTargetSelection,
    *,
    decompile: Path,
    decompile_timeout: int,
    decompile_now: bool,
) -> dict[str, Any]:
    """Return the decompile section for a produced executable."""
    if decompile_now:
        return _decompile_fixture(
            exe_path,
            selection=target_selection,
            decompile=decompile,
            timeout=decompile_timeout,
            generated_c_contract=spec.generated_c_contract,
        )
    return {
        "status": "pending",
        "target_selection": target_selection.to_json(),
        "targets": list(target_selection.targets),
        "generated_c_present": False,
        "missing_targets": list(target_selection.targets),
        "validation_status": "unavailable",
        "validation_unavailable_reason": "batch decompile not run yet",
        "wall_seconds": 0.0,
    }


def _missing_exe_sections(
    spec: QuickCFixtureSpec,
    target_selection: DecompileTargetSelection,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return the decompile and compiler-match sections for a missing exe."""
    decompile_section = {
        "status": "failed",
        "reason": "executable was not produced",
        "target_selection": target_selection.to_json(),
        "targets": list(target_selection.targets),
        "generated_c_present": False,
        "missing_targets": list(target_selection.targets),
        "validation_status": "unavailable",
        "validation_unavailable_reason": "executable was not produced",
    }
    compiler_match = {
        "status": "gap",
        "family": "unknown",
        "memory_model": spec.memory_model,
        "flags": list(spec.compiler_flags),
        "raw_features": {},
        "evidence_gap": "executable was not produced",
    }
    return decompile_section, compiler_match


def _selection_from_json(selection: dict[str, Any]) -> DecompileTargetSelection:
    """Recreate a decompile target selection from report JSON."""

    raw_addr = selection.get("addr")
    addr = int(raw_addr, 16) if isinstance(raw_addr, str) and raw_addr.startswith("0x") else None
    raw_targets = selection.get("targets")
    targets = tuple(str(target) for target in raw_targets) if isinstance(raw_targets, list) else ()
    return DecompileTargetSelection(
        mode=str(selection.get("mode", "missing")),
        evidence_source=str(selection.get("evidence_source", "missing")),
        targets=targets,
        addr=addr,
        reason=str(selection.get("reason", "")),
        symbol_name=selection.get("symbol_name") if isinstance(selection.get("symbol_name"), str) else None,
        obj_path=selection.get("obj_path") if isinstance(selection.get("obj_path"), str) else None,
    )


def _finalize_decompile_status(result: dict[str, Any]) -> None:
    """Set final fixture status after a pending decompile result is attached."""

    decompile = result.get("decompile")
    compiler_match = result.get("compiler_match")
    passed = (
        result.get("pre_decompile_passed") is True
        and isinstance(decompile, dict)
        and decompile.get("status") == "passed"
        and isinstance(compiler_match, dict)
        and compiler_match.get("status") in {"passed", "gap"}
    )
    result["status"] = "passed" if passed else "failed"
    result["wall_seconds"] = round(
        sum(
            float(stage.get("wall_seconds", 0.0))
            for stage in result.get("stages", [])
            if isinstance(stage, dict) and isinstance(stage.get("wall_seconds"), int | float)
        )
        + (float(decompile.get("wall_seconds", 0.0)) if isinstance(decompile, dict) else 0.0),
        3,
    )


def _decompile_pending_results_serially(
    results: list[dict[str, Any]],
    *,
    decompile: Path,
    decompile_timeout: int,
) -> None:
    """Decompile pending fixtures serially through isolated CLI subprocesses."""

    for result in results:
        if result.get("status") != "pending" or result.get("pre_decompile_passed") is not True:
            continue
        exe = result.get("exe")
        selection_json = result.get("decompile_target_selection")
        if not isinstance(exe, str) or not isinstance(selection_json, dict):
            continue
        result["decompile"] = _decompile_fixture(
            Path(exe),
            selection=_selection_from_json(selection_json),
            decompile=decompile,
            timeout=decompile_timeout,
            generated_c_contract=GeneratedCContract.from_json(
                result.get("generated_c_contract_spec")
            ),
        )
        _finalize_decompile_status(result)


def selected_fixtures(names: str | None) -> tuple[QuickCFixtureSpec, ...]:
    """Return default or explicitly named QuickC fixture specs."""

    registry = {spec.name: spec for spec in (*DEFAULT_FIXTURES, *PROMOTED_FIXTURES, *EXCLUDED_FIXTURES)}
    if not names:
        return DEFAULT_FIXTURES
    wanted = {name.strip() for name in names.split(",") if name.strip()}
    return tuple(registry[name] for name in sorted(wanted) if name in registry)


def _collected_sections(
    results: list[dict[str, Any]],
    key: str,
) -> list[dict[str, Any]]:
    """Collect each result's `key` section when it is a dict."""
    sections: list[dict[str, Any]] = []
    for result in results:
        section = result.get(key)
        if isinstance(section, dict):
            sections.append(section)
    return sections


def _validation_counts(decompile_sections: list[dict[str, Any]]) -> dict[str, int]:
    """Bucket each decompile section's validation status."""
    validation_counts = {"passed": 0, "unavailable": 0, "failed": 0}
    for section in decompile_sections:
        status = str(section.get("validation_status", "unavailable"))
        if status not in validation_counts:
            status = "unavailable"
        validation_counts[status] += 1
    return validation_counts


def _target_selection_modes(results: list[dict[str, Any]]) -> dict[str, int]:
    """Count decompile target-selection modes across results."""
    target_modes: dict[str, int] = {}
    for result in results:
        selection = result.get("decompile_target_selection")
        if not isinstance(selection, dict):
            selection = result.get("decompile", {}).get("target_selection") if isinstance(result.get("decompile"), dict) else None
        mode = str(selection.get("mode", "missing")) if isinstance(selection, dict) else "missing"
        target_modes[mode] = target_modes.get(mode, 0) + 1
    return target_modes


def _timed_fixtures(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collect per-fixture wall-time rows sorted slowest first."""
    timed_fixtures: list[dict[str, Any]] = []
    for result in results:
        name = result.get("name")
        wall_seconds = result.get("wall_seconds")
        decompile = result.get("decompile")
        if not isinstance(name, str) or not isinstance(wall_seconds, int | float):
            continue
        decompile_seconds = None
        if isinstance(decompile, dict) and isinstance(decompile.get("wall_seconds"), int | float):
            decompile_seconds = round(float(decompile["wall_seconds"]), 3)
        timed_fixtures.append(
            {
                "name": name,
                "wall_seconds": round(float(wall_seconds), 3),
                "decompile_wall_seconds": decompile_seconds,
                "status": result.get("status"),
            }
        )
    timed_fixtures.sort(key=lambda item: float(item["wall_seconds"]), reverse=True)
    return timed_fixtures


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Return structured pass/fail, validation, and evidence counts."""

    selected_count = len(results)
    passed_count = sum(1 for result in results if result.get("status") == "passed")
    xfail_count = sum(1 for result in results if result.get("expected_status") == "xfail")
    decompile_sections = _collected_sections(results, "decompile")
    compiler_sections = _collected_sections(results, "compiler_match")
    validation_counts = _validation_counts(decompile_sections)
    target_modes = _target_selection_modes(results)
    timed_fixtures = _timed_fixtures(results)
    return {
        "selected_fixture_count": selected_count,
        "passed_fixture_count": passed_count,
        "failed_fixture_count": sum(1 for result in results if result.get("status") == "failed"),
        "skipped_fixture_count": sum(1 for result in results if result.get("status") == "skipped"),
        "xfail_fixture_count": xfail_count,
        "excluded_fixture_count": len(EXCLUDED_FIXTURES),
        "promoted_fixture_count": len(PROMOTED_FIXTURES),
        "decompile_passed_count": sum(1 for section in decompile_sections if section.get("status") == "passed"),
        "decompile_failed_count": sum(1 for section in decompile_sections if section.get("status") == "failed"),
        "generated_c_missing_count": sum(
            1 for section in decompile_sections if section.get("generated_c_present") is not True
        ),
        "validation": validation_counts,
        "validation_passed_count": validation_counts["passed"],
        "validation_unavailable_count": validation_counts["unavailable"],
        "validation_failed_count": validation_counts["failed"],
        "compiler_evidence_gap_count": sum(1 for section in compiler_sections if section.get("status") == "gap"),
        "target_selection_modes": target_modes,
        "timed_fixture_count": len(timed_fixtures),
        "wall_seconds_total": round(sum(float(item["wall_seconds"]) for item in timed_fixtures), 3),
        "decompile_wall_seconds_total": round(
            sum(
                float(item["decompile_wall_seconds"])
                for item in timed_fixtures
                if isinstance(item.get("decompile_wall_seconds"), int | float)
            ),
            3,
        ),
        "slowest_fixtures": timed_fixtures[:5],
    }


def _result_matches_expected_status(result: dict[str, Any]) -> bool:
    """Return whether a fixture result matches its required or blocked status."""

    status = result.get("status")
    expected_status = result.get("expected_status", "required")
    if expected_status == "required":
        return status != "failed"
    if expected_status == "xfail":
        return status == "failed" and bool(str(result.get("expected_blocker") or "").strip())
    return False


def main(argv: list[str] | None = None) -> int:
    """Run the selected fixture build pipeline and write its JSON report."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kvikdos", type=Path, default=DEFAULT_KVIKDOS)
    parser.add_argument("--quickc-root", type=Path, default=DEFAULT_ULTRA_QUICKC_ROOT)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--decompile", type=Path, default=DEFAULT_DECOMPILE)
    parser.add_argument("--decompile-timeout", type=int, default=30)
    parser.add_argument("--only", help="comma-separated fixture names; default: hello,add,whsum,args")
    parser.add_argument("--disable-batch-decompile", action="store_true")
    args = parser.parse_args(argv)

    args.output_root.mkdir(parents=True, exist_ok=True)
    results = [
        build_fixture(
            spec,
            args.output_root,
            kvikdos=args.kvikdos,
            quickc_root=args.quickc_root,
            decompile=args.decompile,
            decompile_timeout=args.decompile_timeout,
            decompile_now=bool(args.disable_batch_decompile),
        )
        for spec in selected_fixtures(args.only)
    ]
    if not args.disable_batch_decompile:
        _decompile_pending_results_serially(
            results,
            decompile=args.decompile,
            decompile_timeout=args.decompile_timeout,
        )
    payload = {
        "source": "borrow/UltraDecompiler/QuickC/PROGRAMS",
        "runner": "kvikdos",
        "results": results,
        "excluded_fixtures": [
            {"name": excluded.name, "source_rel": excluded.source_rel, "reason": excluded.exclude_reason}
            for excluded in EXCLUDED_FIXTURES
        ],
        "promoted_fixtures": [
            {
                "name": promoted.name,
                "source_rel": promoted.source_rel,
                "expected_status": promoted.expected_status,
                "expected_blocker": promoted.expected_blocker,
                "run_args": list(promoted.run_args),
            }
            for promoted in PROMOTED_FIXTURES
        ],
        "summary": summarize_results(results),
    }
    report_path = args.output_root / "ultra_quickc_fixtures.json"
    report_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(f"wrote {report_path}")
    return 1 if any(not _result_matches_expected_status(result) for result in results) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
