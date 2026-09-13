#!/usr/bin/env python3
"""Enforce the sidecar-free SORTD whole-binary decompilation ratchet.

Layer: Tooling/gates.
Responsibility: derive an executable-only fixture, run the full decompiler, and
validate structured discovery, attempt-coverage, and acceptance thresholds.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia_decompiler.generated_c_function_extraction import (  # noqa: E402
    generated_function_definition_span,
)
from scripts.runmenu_behavior import (  # noqa: E402
    RunMenuExecutionEvidence,
    collect_runmenu_execution_evidence,
)

EXPECTED_SORTD_FUNCTION_ADDRS: tuple[int, ...] = (
    0x10010,
    0x10060,
    0x101F0,
    0x102E0,
    0x10498,
    0x10560,
    0x10678,
    0x106C8,
    0x10768,
    0x107B8,
    0x10808,
    0x108D0,
    0x10970,
    0x109E8,
    0x10A88,
    0x10B50,
    0x10C18,
    0x10CE0,
    0x10E70,
    0x10F38,
)
REQUIRED_DECOMPILED_SORTD_FUNCTION_ADDRS: tuple[int, ...] = EXPECTED_SORTD_FUNCTION_ADDRS
DEFAULT_MINIMUM_DECOMPILED: int = len(REQUIRED_DECOMPILED_SORTD_FUNCTION_ADDRS)
DEFAULT_MAXIMUM_EMPTY: int = 0
DEFAULT_MAXIMUM_TIMEOUTS: int = 0


def default_decompiler_command(binary: Path) -> tuple[str, ...]:
    """Return the exact argument-free whole-file CLI command under test."""
    return (sys.executable, "decompile.py", str(binary))


def default_decompiler_environment() -> dict[str, str]:
    """Return an inherited environment without a serial test override."""
    env = dict(os.environ)
    env.pop("INERTIA_FORCE_SERIAL_FUNCTION_DECOMPILATION", None)
    return env


_SOURCE_EVIDENCE_RE = re.compile(
    r"source-region discovery evidence: "
    r"raw_fact_count=(?P<raw>\d+) "
    r"normalized_fact_count=(?P<normalized>\d+) "
    r"classified_fact_count=(?P<classified>\d+) "
    r"materialized_count=(?P<materialized>\d+) "
    r"failure_count=(?P<failures>\d+)"
)
_FUNCTION_RE = re.compile(r"/\* == function (?P<addr>0x[0-9a-f]+) [^=]+ == \*/", re.IGNORECASE)
_STATUS_RE = re.compile(r"failure family: status=(?P<status>[a-z_]+)\b")
_FINAL_FUNCTION_INFO_RE = re.compile(
    r"/\* info: function (?P<addr>0x[0-9a-f]+) \S+ "
    r"attempt=(?P<attempt>[a-z_]+) validation=(?P<validation>[a-z_]+) \*/",
    re.IGNORECASE,
)
_QUEUED_RE = re.compile(r"functions queued for decompilation: (?P<count>\d+)")
_SELECTED_RE = re.compile(r"selected (?P<count>\d+) function\(s\) for decompilation")
_ATTEMPTED_RE = re.compile(r"decompilation attempted for (?P<attempted>\d+)/(?P<selected>\d+) selected function")
_SUMMARY_RE = re.compile(r"summary: decompiled (?P<decompiled>\d+)/(?P<selected>\d+) selected functions")
_TIMEOUT_SIGNAL_RE = re.compile(r"(?:Decompilation timeout|c \([^)]*partial timeout[^)]*\))", re.IGNORECASE)
_WORD_TYPE_RE = r"(?:unsigned\s+)?short"
_RUNMENU_ADDR = 0x102E0
_RUNMENU_SIGNATURE_RE = re.compile(r"\bvoid\s+sub_102e0\s*\(\s*void\s*\)")
_RUNMENU_EXIT_CASE_RE = re.compile(r"\bcase\s+27\s*:\s*return\s*;")
_RUNMENU_REDUNDANT_TAIL_RE = re.compile(
    r"\b(?:goto\s+LABEL_10488|LABEL_10488\s*:)", re.IGNORECASE
)
_DRAWTIME_ADDR = 0x10498
_DRAWTIME_SIGNATURE_RE = re.compile(
    rf"\bvoid\s+sub_10498\s*\(\s*(?P<row_type>{_WORD_TYPE_RE})\s+(?P<row>[A-Za-z_]\w*)\s*\)"
)
_UNSUPPORTED_INSTRUCTION_RE = re.compile(r"\b(?:unsupported|unknown)\s+instruction\b", re.IGNORECASE)
_FLAG_ARTIFACT_RE = re.compile(r"\b(?:e?flags|cc_op|cc_dep[12]?)\b", re.IGNORECASE)
_EMPTY_IF_ELSE_RE = re.compile(r"\bif\s*\([^{};]*\)\s*\{\s*\}\s*else\s*\{\s*\}")
_RAW_SS_LINEAR_RE = re.compile(r"\binertia_ss\s*<<\s*4\b")
_BEEP_ADDR = 0x10E70
_BEEP_SIGNATURE_RE = re.compile(
    rf"\bvoid\s+sub_10e70\s*\(\s*{_WORD_TYPE_RE}\s+(?P<frequency>[A-Za-z_]\w*)\s*,\s*"
    rf"{_WORD_TYPE_RE}\s+(?P<duration>[A-Za-z_]\w*)\s*\)"
)
_UNINITIALIZED_BP4_LOCAL_RE = re.compile(r"^[^/\n;]+;\s*//\s*\[bp\+0x4\]", re.MULTILINE)


def _function_transcript_segment(transcript: str, address: int) -> str:
    """Return one function body from canonical C or a legacy marker segment."""
    try:
        start, end = generated_function_definition_span(transcript, f"sub_{address:04x}")
        return transcript[start:end]
    except ValueError:
        pass
    matches = tuple(_FUNCTION_RE.finditer(transcript))
    for index, match in enumerate(matches):
        if int(match.group("addr"), 16) != address:
            continue
        end = matches[index + 1].start() if index + 1 < len(matches) else len(transcript)
        return transcript[match.start() : end]
    return ""


@dataclass(frozen=True, slots=True)
class SortdRatchetResult:
    """Structured observations and violations from one sidecar-free run."""

    decompiler_returncode: int
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    discovery_failure_count: int
    queued_count: int
    selected_count: int
    attempted_count: int
    decompiled_count: int
    empty_count: int
    timeout_count: int
    validation_failed_count: int
    traceback_count: int
    function_addrs: tuple[int, ...]
    decompiled_function_addrs: tuple[int, ...]
    violations: tuple[str, ...]

    @property
    def passed(self) -> bool:
        """Return whether every enforced ratchet invariant passed."""

        return not self.violations


def mz_executable_image(data: bytes) -> bytes:
    """Return the executable image declared by an MZ header, excluding overlays."""
    if len(data) < 6 or data[:2] != b"MZ":
        raise ValueError("source binary is not an MZ executable")
    bytes_in_last_page = int.from_bytes(data[2:4], "little")
    page_count = int.from_bytes(data[4:6], "little")
    if page_count <= 0:
        raise ValueError("MZ executable declares no image pages")
    image_size = page_count * 512 if bytes_in_last_page == 0 else (page_count - 1) * 512 + bytes_in_last_page
    if image_size <= 0 or image_size > len(data):
        raise ValueError(f"MZ executable declares invalid image size {image_size}")
    return data[:image_size]


def evaluate_sortd_transcript(
    transcript: str,
    *,
    decompiler_returncode: int,
    minimum_decompiled: int,
    maximum_empty: int,
    maximum_timeouts: int,
    maximum_tracebacks: int,
    runmenu_execution: RunMenuExecutionEvidence | None = None,
) -> SortdRatchetResult:
    """Evaluate exact whole-binary coverage and gradual acceptance thresholds."""
    violations: list[str] = []
    source_match = _SOURCE_EVIDENCE_RE.search(transcript)
    source_counts = (
        tuple(int(source_match.group(name)) for name in ("raw", "normalized", "classified", "materialized", "failures"))
        if source_match is not None
        else (0, 0, 0, 0, 0)
    )
    if source_match is None:
        violations.append("missing source-region discovery evidence")

    queued_match = _QUEUED_RE.search(transcript)
    selected_match = _SELECTED_RE.search(transcript)
    attempted_match = _ATTEMPTED_RE.search(transcript)
    summary_match = _SUMMARY_RE.search(transcript)
    queued_count = int(queued_match.group("count")) if queued_match is not None else 0
    selected_count = int(selected_match.group("count")) if selected_match is not None else 0
    attempted_count = int(attempted_match.group("attempted")) if attempted_match is not None else 0
    decompiled_count = int(summary_match.group("decompiled")) if summary_match is not None else 0
    function_addrs = tuple(int(match.group("addr"), 16) for match in _FUNCTION_RE.finditer(transcript))
    statuses = tuple(match.group("status") for match in _STATUS_RE.finditer(transcript))
    final_acceptance = {
        int(match.group("addr"), 16): (
            match.group("attempt") == "decompiled" and match.group("validation") == "passed"
        )
        for match in _FINAL_FUNCTION_INFO_RE.finditer(transcript)
    }
    terminal_statuses = tuple(
        "ok" if final_acceptance.get(address, False) else status
        for address, status in zip(function_addrs, statuses, strict=False)
    )
    decompiled_function_addrs = tuple(
        address for address, status in zip(function_addrs, terminal_statuses, strict=False) if status == "ok"
    )
    empty_count = terminal_statuses.count("empty")
    timeout_count = max(terminal_statuses.count("timeout"), len(_TIMEOUT_SIGNAL_RE.findall(transcript)))
    validation_failed_count = terminal_statuses.count("validation_failed")
    traceback_count = transcript.count("Traceback (most recent call last):")

    expected_count = len(EXPECTED_SORTD_FUNCTION_ADDRS)
    if source_counts != (expected_count, expected_count, expected_count, expected_count, 0):
        violations.append(f"source evidence regressed: {source_counts!r}")
    if queued_count != expected_count:
        violations.append(f"queued {queued_count}, expected {expected_count}")
    if selected_count != expected_count:
        violations.append(f"selected {selected_count}, expected {expected_count}")
    if attempted_count != expected_count:
        violations.append(f"attempted {attempted_count}, expected {expected_count}")
    if tuple(sorted(function_addrs)) != EXPECTED_SORTD_FUNCTION_ADDRS:
        violations.append("emitted function address set differs from the executable-only oracle")
    if len(statuses) != expected_count:
        violations.append(f"reported {len(statuses)} terminal function statuses, expected {expected_count}")
    if decompiled_count < minimum_decompiled:
        violations.append(f"decompiled {decompiled_count}, minimum is {minimum_decompiled}")
    missing_decompiled_addrs = tuple(
        address
        for address in REQUIRED_DECOMPILED_SORTD_FUNCTION_ADDRS
        if address not in decompiled_function_addrs
    )
    if missing_decompiled_addrs:
        violations.append(
            "required decompiled function regressions: "
            + ", ".join(f"{address:#x}" for address in missing_decompiled_addrs)
        )
    runmenu_segment = _function_transcript_segment(transcript, _RUNMENU_ADDR)
    escape_proven = (
        runmenu_execution.accepts(runmenu_segment)
        if runmenu_execution is not None
        else _RUNMENU_EXIT_CASE_RE.search(runmenu_segment) is not None
    )
    if not _RUNMENU_SIGNATURE_RE.search(runmenu_segment) or not escape_proven:
        violations.append("RunMenu lacks its void binary-proven ESC exit")
    if runmenu_execution is not None and runmenu_execution.failure is not None:
        violations.append(f"RunMenu execution gate failed: {runmenu_execution.failure}")
    if _RUNMENU_REDUNDANT_TAIL_RE.search(runmenu_segment):
        violations.append("RunMenu retains a redundant switch-to-loop-tail goto")
    drawtime_segment = _function_transcript_segment(transcript, _DRAWTIME_ADDR)
    drawtime_signature = _DRAWTIME_SIGNATURE_RE.search(drawtime_segment)
    if drawtime_signature is None or _UNINITIALIZED_BP4_LOCAL_RE.search(drawtime_segment):
        violations.append("DrawTime lacks its canonical void positive-BP signature")
    elif re.search(
        rf"\bsub_10e70\s*\(\s*(?:\(\s*{re.escape(drawtime_signature.group('row_type'))}\s*\)\s*)?"
        rf"{re.escape(drawtime_signature.group('row'))}\s*\*\s*60\s*,\s*75\s*\)",
        drawtime_segment,
    ) is None:
        violations.append("DrawTime lacks its binary-proven frequency and duration arguments")
    if _EMPTY_IF_ELSE_RE.search(drawtime_segment):
        violations.append("DrawTime retains an empty flag-only branch")
    if _RAW_SS_LINEAR_RE.search(drawtime_segment):
        violations.append("DrawTime retains raw SS linear-address arithmetic")
    beep_segment = _function_transcript_segment(transcript, _BEEP_ADDR)
    beep_signature = _BEEP_SIGNATURE_RE.search(beep_segment)
    if beep_signature is None or _UNINITIALIZED_BP4_LOCAL_RE.search(beep_segment):
        violations.append("Beep lacks its void two-argument positive-BP signature")
    elif re.search(rf"\bif\s*\(\s*{re.escape(beep_signature.group('duration'))}\s*<\s*75\s*\)", beep_segment) is None:
        violations.append("Beep lacks its binary-proven minimum-duration guard")
    if empty_count > maximum_empty:
        violations.append(f"empty function count {empty_count} exceeds {maximum_empty}")
    if timeout_count > maximum_timeouts:
        violations.append(f"timeout signal count {timeout_count} exceeds {maximum_timeouts}")
    if traceback_count > maximum_tracebacks:
        violations.append(f"traceback count {traceback_count} exceeds {maximum_tracebacks}")
    if _UNSUPPORTED_INSTRUCTION_RE.search(transcript):
        violations.append("generated output retains unsupported or unknown instructions")
    if _FLAG_ARTIFACT_RE.search(transcript):
        violations.append("generated output retains raw flag-state artifacts")
    if decompiler_returncode not in {0, 2}:
        violations.append(f"unexpected decompiler exit code {decompiler_returncode}")
    if "no helper metadata (.lst/.map/.cod/debug info) found" not in transcript:
        violations.append("run did not confirm pure binary recovery mode")

    return SortdRatchetResult(
        decompiler_returncode=decompiler_returncode,
        raw_fact_count=source_counts[0],
        normalized_fact_count=source_counts[1],
        classified_fact_count=source_counts[2],
        materialized_count=source_counts[3],
        discovery_failure_count=source_counts[4],
        queued_count=queued_count,
        selected_count=selected_count,
        attempted_count=attempted_count,
        decompiled_count=decompiled_count,
        empty_count=empty_count,
        timeout_count=timeout_count,
        validation_failed_count=validation_failed_count,
        traceback_count=traceback_count,
        function_addrs=function_addrs,
        decompiled_function_addrs=decompiled_function_addrs,
        violations=tuple(violations),
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments for the sidecar-free ratchet."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-binary", type=Path, default=REPO_ROOT / "SORTDEMO.EXE")
    parser.add_argument(
        "--transcript-out",
        type=Path,
        default=REPO_ROOT / "angr_platforms" / ".cache" / "test_pipeline" / "sortd_sidecar_free.txt",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=REPO_ROOT / "angr_platforms" / ".cache" / "test_pipeline" / "sortd_sidecar_free.json",
    )
    parser.add_argument("--function-c-dir", type=Path)
    parser.add_argument("--run-timeout", type=int, default=1200)
    parser.add_argument("--minimum-decompiled", type=int, default=DEFAULT_MINIMUM_DECOMPILED)
    parser.add_argument("--maximum-empty", type=int, default=DEFAULT_MAXIMUM_EMPTY)
    parser.add_argument("--maximum-timeouts", type=int, default=DEFAULT_MAXIMUM_TIMEOUTS)
    parser.add_argument("--maximum-tracebacks", type=int, default=0)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run the isolated executable-only lane and write its structured report."""
    args = _parse_args(argv)
    image = mz_executable_image(args.source_binary.read_bytes())
    args.transcript_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    env = default_decompiler_environment()
    if args.function_c_dir is not None:
        args.function_c_dir.mkdir(parents=True, exist_ok=True)
        if any(args.function_c_dir.glob("*.c")):
            print(f"function C artifact directory must be empty: {args.function_c_dir}")
            return 2
        env["INERTIA_OUTPUT_C_DIR"] = str(args.function_c_dir)

    with tempfile.TemporaryDirectory(prefix="inertia-sortd-sidecar-free-") as temp_dir:
        isolated_binary = Path(temp_dir) / "SORTD.EXE"
        function_c_dir = args.function_c_dir or Path(temp_dir) / "functions"
        function_c_dir.mkdir(parents=True, exist_ok=True)
        env["INERTIA_OUTPUT_C_DIR"] = str(function_c_dir)
        isolated_binary.write_bytes(image)
        command = default_decompiler_command(isolated_binary)
        with args.transcript_out.open("w", encoding="utf-8") as transcript_stream:
            try:
                completed = subprocess.run(
                    command,
                    cwd=REPO_ROOT,
                    env=env,
                    check=False,
                    stdout=transcript_stream,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=max(1, args.run_timeout),
                )
                returncode = completed.returncode
            except subprocess.TimeoutExpired:
                returncode = 124
        runmenu_execution = collect_runmenu_execution_evidence(function_c_dir, Path(temp_dir))

    transcript = args.transcript_out.read_text(encoding="utf-8", errors="replace")
    result = evaluate_sortd_transcript(
        transcript,
        decompiler_returncode=returncode,
        minimum_decompiled=max(0, args.minimum_decompiled),
        maximum_empty=max(0, args.maximum_empty),
        maximum_timeouts=max(0, args.maximum_timeouts),
        maximum_tracebacks=max(0, args.maximum_tracebacks),
        runmenu_execution=runmenu_execution,
    )
    args.report_out.write_text(json.dumps(asdict(result), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(asdict(result), sort_keys=True))
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
