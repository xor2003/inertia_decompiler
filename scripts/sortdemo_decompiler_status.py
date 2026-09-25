"""Build a per-function status scoreboard from a SORTDEMO decompiler transcript.

Layer: Tooling/gates.
Responsibility: summarize SORTDEMO decompiler status from generated reports.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Any, cast

from pycparser import c_ast, c_parser
from pycparser.c_parser import ParseError

REPO_ROOT: Path = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from inertia_decompiler.generated_c_function_extraction import (  # noqa: E402
    generated_function_definition_span,
)

_FUNCTION_HEADER_RE = re.compile(r"/\*\s*==\s*function\s+(0x[0-9a-fA-F]+)\s+(.+?)\s*==\s*\*/")
_DIRECT_FUNCTION_HEADER_RE = re.compile(r"/\*\s*function:\s+(0x[0-9a-fA-F]+)\s+(.+?)\s*\*/")
_FAILURE_FAMILY_RE = re.compile(
    r"failure family:\s+status=(?P<status>\S+)\s+stage=(?P<stage>\S+).*?\s+validation=(?P<validation>\S+)"
)
_COD_PROC_RE = re.compile(r"^\s*_(?P<name>[A-Za-z]\w*)\s+PROC\s+NEAR\b")
_FUNCTION_INFO_RE = re.compile(
    r"info:\s+function\s+(?P<addr>0x[0-9a-fA-F]+)\s+.+?\s+attempt=(?P<attempt>\S+)\s+validation=(?P<validation>\S+)"
)
_RECOVERY_START_RE = re.compile(
    r"recovery worker:\s+start\s+(?P<addr>0x[0-9a-fA-F]+)\s+(?P<name>\S+)\s+mode="
)
_TIMEOUT_DELAY_RE = re.compile(r"timeout delay:\s+(?P<seconds>\d+(?:\.\d+)?)s")
_TIMED_OUT_AFTER_RE = re.compile(r"timed out after\s+(?P<seconds>\d+(?:\.\d+)?)s", re.IGNORECASE)
_STAGE_TIMEOUT_RE = re.compile(r"\bTIMEOUT\s+stage=(?P<stage>\S+)")
_RETRY_RECOVERED_RE = re.compile(r"/\* retry lane: recovered validation-passed candidate \*/$")
_RUN_SUMMARY_START_RE = re.compile(
    r"(?:/\*\s*(?:info:\s+decompilation attempted|summary:)|\[tail-validation\]\s+"
    r"(?:severity=|coverage=|uncollected|detail artifact))"
)
_RUN_ATTEMPTED_RE = re.compile(r"decompilation attempted for (?P<attempted>\d+)/(?:\d+) selected function")
_RUN_DECOMPILED_RE = re.compile(r"decompiled (?P<decompiled>\d+)/(?P<selected>\d+) selected functions")
_RUN_TIMEOUT_RE = re.compile(r"summary:\s+(?P<timed_out>\d+) discovered function\(s\) timed out")
_RUN_FALLBACK_RE = re.compile(r"summary:\s+(?P<fallback>\d+) functions fell back to asm/details")
_RUN_SHOWN_RE = re.compile(
    r"shown=(?P<shown>\d+)\s+decompiled=(?P<decompiled>\d+)\s+asm_or_detail_fallback=(?P<fallback>\d+)"
)
_TAIL_SURFACE_RE = re.compile(r"severity=(?P<severity>\S+)\s+merge_gate=(?P<merge_gate>\S+)")
_TAIL_COVERAGE_RE = re.compile(r"coverage=(?P<coverage>\d+)\s+missing=(?P<missing>\d+)\s+unknown=(?P<unknown>\d+)")
_LEAKAGE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("unresolved_vvar", re.compile(r"\bvvar_\d+\b")),
    ("expr_cycle", re.compile(r"\bexpr_cycle\b")),
    ("raw_segmented_access", re.compile(r"\b(?:SEG_PTR|SEG_U8|SEG_U16|SEG_U32|MK_FP)\s*\(")),
    ("raw_memory_symbol", re.compile(r"\bmem_[0-9a-fA-F]{4,}\b")),
)
_BLOCKING_LEAKAGE_NAMES = frozenset({"unresolved_vvar", "expr_cycle", "raw_memory_symbol"})
_SOURCE_QUALITY_REASON_RE = re.compile(r"quality guard rejected emitted C\s+\((?P<markers>[^)]*)\)")
_SOURCE_QUALITY_REASON_TO_LEAKAGE = {
    "unresolved-vvar": "unresolved_vvar",
    "expr-cycle": "expr_cycle",
    "raw-ds-segmented-access": "raw_segmented_access",
    "raw-ss-segmented-access": "raw_segmented_access",
    "raw-memory-symbol": "raw_memory_symbol",
}
_TRANSCRIPT_LOADING_RE = re.compile(r"/\*\s*loading:\s+SORTDEMO\.EXE\s*\*/", re.IGNORECASE)
_C_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_C_LINE_COMMENT_RE = re.compile(r"//.*$")
_C_PARSE_PREFIX = (
    "typedef int bool; enum { false = 0, true = 1 }; "
    "typedef signed char int8_t; typedef signed short int16_t; "
    "typedef signed long int32_t; "
    "typedef unsigned char uint8_t; typedef unsigned short uint16_t; "
    "typedef unsigned long uint32_t; typedef signed long clock_t; "
    "typedef signed long time_t;\n"
)


class TerminalStatus(StrEnum):
    """Canonical terminal verdict for one function status record."""

    UNKNOWN = "unknown"
    PASSED = "passed"
    UNCOLLECTED = "uncollected"
    FALLBACK = "fallback"
    TAIL_VALIDATION_FAILED = "tail-validation-failed"
    ERROR = "error"
    TIMEOUT = "timeout"
    QUALITY_REFUSED = "quality-refused"
    SOURCE_QUALITY_REFUSED = "source-quality-refused"
    SOURCE_CONTRACT_REFUSED = "source-contract-refused"


class FailureStatus(StrEnum):
    """Structured failure-family status parsed from transcript markers."""

    UNKNOWN = "unknown"
    OK = "ok"
    TIMEOUT = "timeout"
    ERROR = "error"
    VALIDATION_FAILED = "validation_failed"

    @classmethod
    def from_token(cls, token: str | None) -> FailureStatus:
        """Return the known failure status, or UNKNOWN for new transcript tokens."""

        normalized = (token or "").strip().lower()
        for status in cls:
            if status.value == normalized:
                return status
        return cls.UNKNOWN


class ValidationStatus(StrEnum):
    """Structured validation verdict parsed from transcript markers."""

    UNKNOWN = "unknown"
    PASSED = "passed"
    FAILED = "failed"
    UNCOLLECTED = "uncollected"

    @classmethod
    def from_token(cls, token: str | None) -> ValidationStatus:
        """Return the known validation status, or UNKNOWN for new transcript tokens."""

        normalized = (token or "").strip().rstrip("*/ ").lower()
        for status in cls:
            if status.value == normalized:
                return status
        return cls.UNKNOWN


class AttemptStatus(StrEnum):
    """Structured decompilation attempt status parsed from transcript markers."""

    UNKNOWN = "unknown"
    DECOMPILED = "decompiled"
    TIMED_OUT = "timed_out"
    ERROR = "error"
    FALLBACK = "fallback"
    EMPTY = "empty"

    @classmethod
    def from_token(cls, token: str | None) -> AttemptStatus:
        """Return the known attempt status, or UNKNOWN for new transcript tokens."""

        normalized = (token or "").strip().lower()
        for status in cls:
            if status.value == normalized:
                return status
        return cls.UNKNOWN


class ArgumentClass(StrEnum):
    """Source-level argument class required at one generated C callsite."""

    VALUE = "value"
    POINTER = "pointer"
    POINTER_OR_NULL = "pointer-or-null"


class GeneratedCMarker(StrEnum):
    """Accepted clean generated-C block markers emitted by CLI modes."""

    NORMAL = "/* -- c -- */"
    ALTERNATE_SOURCE = "/* == c == */"

    @classmethod
    def from_line(cls, line: str) -> GeneratedCMarker | None:
        """Return the clean C marker represented by a transcript line."""
        return next((marker for marker in cls if marker.value in line), None)


@dataclass(frozen=True, slots=True)
class CallRequirement:
    """Exact callsite count and argument classes required by SORTDEMO source."""

    name: str
    count: int
    argument_classes: tuple[ArgumentClass, ...]


@dataclass(frozen=True, slots=True)
class ConditionalBreakRequirement:
    """Required generated-C if-break condition shape for a source procedure."""

    comparison_ops: frozenset[str]
    required_identifiers: frozenset[str]
    required_arrays: frozenset[str] = frozenset()
    alternative_shapes: tuple[
        tuple[frozenset[str], frozenset[str]], ...
    ] = ()


@dataclass(frozen=True, slots=True)
class FunctionCallContract:
    """Source-backed call and control-flow contract for one SORTDEMO procedure."""

    name: str
    calls: tuple[CallRequirement, ...]
    allowed_extra_calls: frozenset[str] = frozenset()
    conditional_breaks: tuple[ConditionalBreakRequirement, ...] = ()


@dataclass(frozen=True, slots=True)
class CallObservation:
    """One direct generated-C function call parsed from a function body."""

    name: str
    argument_classes: tuple[ArgumentClass, ...]


@dataclass(frozen=True, slots=True)
class ConditionalBreakObservation:
    """One generated-C if condition whose taken body contains a break."""

    comparison_op: str | None
    identifiers: frozenset[str]
    arrays: frozenset[str]


@dataclass(frozen=True, slots=True)
class SourceContractResult:
    """Structured comparison of generated C against one source contract."""

    passed: bool
    missing_calls: tuple[str, ...] = ()
    count_mismatches: tuple[str, ...] = ()
    argument_mismatches: tuple[str, ...] = ()
    unexpected_calls: tuple[str, ...] = ()
    missing_control_flow: tuple[str, ...] = ()
    parse_error: str | None = None

    def to_json(self) -> dict[str, Any]:
        """Serialize source-contract evidence for the status report."""
        return {
            "passed": self.passed,
            "missing_calls": list(self.missing_calls),
            "count_mismatches": list(self.count_mismatches),
            "argument_mismatches": list(self.argument_mismatches),
            "unexpected_calls": list(self.unexpected_calls),
            "missing_control_flow": list(self.missing_control_flow),
            "parse_error": self.parse_error,
        }


def _call_requirement(
    name: str,
    count: int,
    *argument_classes: ArgumentClass,
) -> CallRequirement:
    """Build one concise immutable call requirement."""
    return CallRequirement(name=name, count=count, argument_classes=tuple(argument_classes))


_V = ArgumentClass.VALUE
_P = ArgumentClass.POINTER
_PN = ArgumentClass.POINTER_OR_NULL
_DIV_HELPERS = frozenset({"aNldiv", "aNuldiv", "aNlmul", "aNulmul"})
_GENERATED_MEMORY_INTRINSICS = frozenset(
    {"MK_FP", "SEG_PTR", "SEG_U8", "SEG_U16", "SEG_U32"}
)
_SORTDEMO_BINARY_CALL_ALIASES = {
    f"sub_{addr:x}": name
    for addr, name in (
        (0x10060, "InitMenu"),
        (0x101F0, "DrawFrame"),
        (0x102E0, "RunMenu"),
        (0x10498, "DrawTime"),
        (0x10560, "InitBars"),
        (0x10678, "ReInitBars"),
        (0x106C8, "DrawBar"),
        (0x10768, "SwapBars"),
        (0x107B8, "Swaps"),
        (0x10808, "InsertionSort"),
        (0x108D0, "BubbleSort"),
        (0x10970, "HeapSort"),
        (0x109E8, "PercolateUp"),
        (0x10A88, "PercolateDown"),
        (0x10B50, "ExchangeSort"),
        (0x10C18, "ShellSort"),
        (0x10CE0, "QuickSort"),
        (0x10E70, "Beep"),
        (0x10F38, "Sleep"),
        (0x1123A, "strcpy"),
        (0x1126C, "toupper"),
        (0x11278, "toupper"),
        (0x11292, "getch"),
        (0x112BA, "sprintf"),
        (0x11310, "inp"),
        (0x1131E, "outp"),
        (0x1132C, "time"),
        (0x1137E, "clock"),
        (0x113D4, "memset"),
        (0x11402, "srand"),
        (0x11414, "rand"),
        (0x1143A, "aNldiv"),
        (0x11F38, "aNlmul"),
        (0x12756, "outtext"),
        (0x128E4, "settextposition"),
        (0x1294F, "setvideomode"),
        (0x12A29, "settextrows"),
        (0x12AC8, "getvideoconfig"),
        (0x12B24, "settextcolor"),
        (0x12B3E, "setbkcolor"),
        (0x12B5E, "clearscreen"),
        (0x12BC0, "displaycursor"),
    )
}

SORTDEMO_SOURCE_CALL_CONTRACTS: dict[str, FunctionCallContract] = {
    "main": FunctionCallContract(
        "main",
        (
            _call_requirement("settextrows", 1, _V),
            _call_requirement("clearscreen", 1, _V),
            _call_requirement("displaycursor", 1, _V),
            _call_requirement("InitBars", 1),
            _call_requirement("InitMenu", 1),
            _call_requirement("RunMenu", 1),
            _call_requirement("setvideomode", 1, _V),
        ),
    ),
    "InitMenu": FunctionCallContract(
        "InitMenu",
        (
            _call_requirement("settextcolor", 1, _V),
            _call_requirement("setbkcolor", 1, _V),
            _call_requirement("DrawFrame", 1, _V, _V, _V, _V),
            _call_requirement("settextposition", 5, _V, _V),
            _call_requirement("outtext", 5, _P),
            _call_requirement("strcpy", 3, _P, _P),
            _call_requirement("sprintf", 1, _P, _P, _V),
        ),
        allowed_extra_calls=_DIV_HELPERS,
    ),
    "DrawFrame": FunctionCallContract(
        "DrawFrame",
        (
            _call_requirement("memset", 3, _P, _V, _V),
            _call_requirement("settextposition", 3, _V, _V),
            _call_requirement("outtext", 3, _P),
        ),
    ),
    "RunMenu": FunctionCallContract(
        "RunMenu",
        (
            _call_requirement("settextposition", 1, _V, _V),
            _call_requirement("displaycursor", 2, _V),
            _call_requirement("getch", 1),
            _call_requirement("toupper", 1, _V),
            _call_requirement("ReInitBars", 6),
            _call_requirement("InsertionSort", 1),
            _call_requirement("BubbleSort", 1),
            _call_requirement("HeapSort", 1),
            _call_requirement("ExchangeSort", 1),
            _call_requirement("ShellSort", 1),
            _call_requirement("QuickSort", 1, _V, _V),
            _call_requirement("DrawTime", 6, _V),
            _call_requirement("InitMenu", 3),
        ),
    ),
    "DrawTime": FunctionCallContract(
        "DrawTime",
        (
            _call_requirement("settextcolor", 1, _V),
            _call_requirement("clock", 1),
            _call_requirement("sprintf", 1, _P, _P, _V, _V, _V),
            _call_requirement("settextposition", 1, _V, _V),
            _call_requirement("outtext", 1, _P),
            _call_requirement("Beep", 1, _V, _V),
            _call_requirement("Sleep", 2, _V),
        ),
        allowed_extra_calls=_DIV_HELPERS,
    ),
    "InitBars": FunctionCallContract(
        "InitBars",
        (
            _call_requirement("time", 1, _PN),
            _call_requirement("srand", 1, _V),
            _call_requirement("getvideoconfig", 1, _P),
            _call_requirement("rand", 1),
            _call_requirement("ReInitBars", 1),
        ),
    ),
    "ReInitBars": FunctionCallContract(
        "ReInitBars",
        (
            _call_requirement("clock", 1),
            _call_requirement("DrawBar", 1, _V),
        ),
    ),
    "DrawBar": FunctionCallContract(
        "DrawBar",
        (
            _call_requirement("memset", 2, _P, _V, _V),
            _call_requirement("settextcolor", 1, _V),
            _call_requirement("settextposition", 1, _V, _V),
            _call_requirement("outtext", 1, _P),
        ),
    ),
    "SwapBars": FunctionCallContract(
        "SwapBars",
        (
            _call_requirement("DrawBar", 2, _V),
            _call_requirement("DrawTime", 1, _V),
        ),
    ),
    "Swaps": FunctionCallContract("Swaps", ()),
    "InsertionSort": FunctionCallContract(
        "InsertionSort",
        (
            _call_requirement("DrawBar", 2, _V),
            _call_requirement("DrawTime", 2, _V),
        ),
        conditional_breaks=(
            ConditionalBreakRequirement(
                comparison_ops=frozenset({"<="}),
                required_identifiers=frozenset(
                    {"abarWork", "iRowTmp", "iLength"}
                ),
                required_arrays=frozenset({"abarWork"}),
                alternative_shapes=(
                    (
                        frozenset({"g_0B4C", "local_4", "local_6"}),
                        frozenset({"g_0B4C"}),
                    ),
                ),
            ),
        ),
    ),
    "BubbleSort": FunctionCallContract(
        "BubbleSort",
        (
            _call_requirement("Swaps", 1, _P, _P),
            _call_requirement("SwapBars", 1, _V, _V),
        ),
    ),
    "HeapSort": FunctionCallContract(
        "HeapSort",
        (
            _call_requirement("PercolateUp", 1, _V),
            _call_requirement("Swaps", 1, _P, _P),
            _call_requirement("SwapBars", 1, _V, _V),
            _call_requirement("PercolateDown", 1, _V),
        ),
    ),
    "PercolateUp": FunctionCallContract(
        "PercolateUp",
        (
            _call_requirement("Swaps", 1, _P, _P),
            _call_requirement("SwapBars", 1, _V, _V),
        ),
    ),
    "PercolateDown": FunctionCallContract(
        "PercolateDown",
        (
            _call_requirement("Swaps", 1, _P, _P),
            _call_requirement("SwapBars", 1, _V, _V),
        ),
    ),
    "ExchangeSort": FunctionCallContract(
        "ExchangeSort",
        (
            _call_requirement("DrawTime", 1, _V),
            _call_requirement("Swaps", 1, _P, _P),
            _call_requirement("SwapBars", 1, _V, _V),
        ),
    ),
    "ShellSort": FunctionCallContract(
        "ShellSort",
        (
            _call_requirement("Swaps", 1, _P, _P),
            _call_requirement("SwapBars", 1, _V, _V),
        ),
    ),
    "QuickSort": FunctionCallContract(
        "QuickSort",
        (
            _call_requirement("Swaps", 3, _P, _P),
            _call_requirement("SwapBars", 3, _V, _V),
            _call_requirement("QuickSort", 4, _V, _V),
        ),
    ),
    "Beep": FunctionCallContract(
        "Beep",
        (
            _call_requirement("outp", 5, _V, _V),
            _call_requirement("inp", 1, _V),
            _call_requirement("Sleep", 1, _V),
        ),
        allowed_extra_calls=_DIV_HELPERS,
    ),
    "Sleep": FunctionCallContract("Sleep", (_call_requirement("clock", 2),)),
}


def _leakage_count_text(lines: list[str]) -> str:
    """Return transcript text relevant to emitted-body leakage counting."""
    emitted_lines: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("#define"):
            continue
        if stripped.startswith(("[", "WARNING  |", "ERROR    |")):
            continue
        if stripped.startswith(("Traceback ", "File ")):
            continue
        if "PipelineHardError:" in stripped:
            continue
        emitted_lines.append(line)
    return "\n".join(emitted_lines)


@dataclass(slots=True)
class FunctionStatus:
    """Collected status for one decompiler transcript function block."""

    addr: str
    name: str
    lines: list[str] = field(default_factory=list)
    validation_passed: bool = False
    validation_failed: bool = False
    timeout: bool = False
    fallback: bool = False
    source_quality_refused: bool = False
    final_quality_refused: bool = False
    uncollected: bool = False
    error: bool = False
    failure_status: FailureStatus | None = None
    failure_stage: str | None = None
    attempt: AttemptStatus | None = None
    validation: ValidationStatus | None = None
    timeout_seconds: float | None = None
    timeout_message: str | None = None
    source_contract: SourceContractResult | None = None
    generated_c: str | None = None
    ignore_next_traceback: bool = False

    def generated_c_marker(self) -> GeneratedCMarker | None:
        """Return the clean generated-C marker present in this record."""
        if self.generated_c is not None:
            return GeneratedCMarker.NORMAL
        return next(
            (
                marker
                for line in self.lines
                if (marker := GeneratedCMarker.from_line(line)) is not None
            ),
            None,
        )

    def leakage_counts(self) -> dict[str, int]:
        """Count unresolved-output markers in this function block."""
        text = self.generated_c or _leakage_count_text(self.lines)
        counts = {name: len(pattern.findall(text)) for name, pattern in _LEAKAGE_PATTERNS}
        for match in _SOURCE_QUALITY_REASON_RE.finditer(text):
            markers = tuple(marker.strip() for marker in match.group("markers").split(","))
            for marker in markers:
                leakage_name = _SOURCE_QUALITY_REASON_TO_LEAKAGE.get(marker)
                if leakage_name is not None and counts.get(leakage_name, 0) == 0:
                    counts[leakage_name] = 1
        return counts

    def is_recovery_placeholder(self) -> bool:
        """Return whether this record has no terminal or generated-C evidence."""
        return (
            self.attempt is None
            and self.validation is None
            and self.generated_c_marker() is None
            and not any(
                (
                    self.validation_passed,
                    self.validation_failed,
                    self.timeout,
                    self.fallback,
                    self.uncollected,
                    self.error,
                )
            )
        )

    def terminal_status(self) -> TerminalStatus:
        """Return the single terminal status for this function."""
        refusal = self._terminal_refusal_status()
        if refusal is not None:
            return refusal
        if self.error:
            return TerminalStatus.ERROR
        if self.timeout:
            return TerminalStatus.TIMEOUT
        if self.fallback:
            return TerminalStatus.FALLBACK
        if self.uncollected:
            return TerminalStatus.UNCOLLECTED
        if self.validation_passed:
            return TerminalStatus.PASSED
        return TerminalStatus.UNKNOWN

    def _terminal_refusal_status(self) -> TerminalStatus | None:
        """Return the refusal/validation-failure status, or None."""
        if self.source_quality_refused:
            return TerminalStatus.SOURCE_QUALITY_REFUSED
        if self.final_quality_refused:
            return TerminalStatus.QUALITY_REFUSED
        leakage = self.leakage_counts()
        if self.validation_passed and any(leakage[name] > 0 for name in _BLOCKING_LEAKAGE_NAMES):
            return TerminalStatus.SOURCE_QUALITY_REFUSED
        if self.validation_passed and self.source_contract is not None and not self.source_contract.passed:
            return TerminalStatus.SOURCE_CONTRACT_REFUSED
        if (
            self.validation_failed
            and not self.validation_passed
            and self.failure_status not in {FailureStatus.TIMEOUT, FailureStatus.ERROR}
        ):
            return TerminalStatus.TAIL_VALIDATION_FAILED
        return None

    def to_json(self) -> dict[str, Any]:
        """Serialize this function status."""
        generated_c_marker = self.generated_c_marker()
        return {
            "addr": self.addr,
            "name": self.name,
            "status": self.terminal_status().value,
            "failure_status": self.failure_status.value if self.failure_status is not None else None,
            "failure_stage": self.failure_stage,
            "attempt": self.attempt.value if self.attempt is not None else None,
            "validation": self.validation.value if self.validation is not None else None,
            "timeout_seconds": self.timeout_seconds,
            "timeout_message": self.timeout_message,
            "validation_passed": self.validation_passed,
            "validation_failed": self.validation_failed,
            "generated_c_marker": (
                generated_c_marker.name.lower() if generated_c_marker is not None else None
            ),
            "leakage": self.leakage_counts(),
            "source_contract": self.source_contract.to_json() if self.source_contract is not None else None,
        }


class _DuplicateRecordPriority(IntEnum):
    """Preference order when duplicate transcript fragments describe one PROC."""

    UNKNOWN = 0
    PASSED = 1
    UNCOLLECTED = 2
    FALLBACK = 3
    TAIL_VALIDATION_FAILED = 4
    ERROR = 5
    TIMEOUT = 6
    QUALITY_REFUSED = 7
    SOURCE_QUALITY_REFUSED = 8
    SOURCE_CONTRACT_REFUSED = 9


_TERMINAL_STATUS_PRIORITY: dict[TerminalStatus, _DuplicateRecordPriority] = {
    TerminalStatus.UNKNOWN: _DuplicateRecordPriority.UNKNOWN,
    TerminalStatus.PASSED: _DuplicateRecordPriority.PASSED,
    TerminalStatus.UNCOLLECTED: _DuplicateRecordPriority.UNCOLLECTED,
    TerminalStatus.FALLBACK: _DuplicateRecordPriority.FALLBACK,
    TerminalStatus.TAIL_VALIDATION_FAILED: _DuplicateRecordPriority.TAIL_VALIDATION_FAILED,
    TerminalStatus.ERROR: _DuplicateRecordPriority.ERROR,
    TerminalStatus.TIMEOUT: _DuplicateRecordPriority.TIMEOUT,
    TerminalStatus.QUALITY_REFUSED: _DuplicateRecordPriority.QUALITY_REFUSED,
    TerminalStatus.SOURCE_QUALITY_REFUSED: _DuplicateRecordPriority.SOURCE_QUALITY_REFUSED,
    TerminalStatus.SOURCE_CONTRACT_REFUSED: _DuplicateRecordPriority.SOURCE_CONTRACT_REFUSED,
}


def _record_priority(record: FunctionStatus) -> _DuplicateRecordPriority:
    return _TERMINAL_STATUS_PRIORITY[record.terminal_status()]


def _merge_duplicate_record_into(target: FunctionStatus, source: FunctionStatus) -> None:
    """Merge a later timeout/fallback fragment into the existing PROC record."""
    source_priority = _record_priority(source)
    target_priority = _record_priority(target)
    if source_priority > target_priority:
        target.addr = source.addr
        target.failure_status = source.failure_status or target.failure_status
        target.failure_stage = source.failure_stage or target.failure_stage
        target.attempt = source.attempt or target.attempt
        target.validation = source.validation or target.validation
    else:
        target.failure_status = target.failure_status or source.failure_status
        target.failure_stage = target.failure_stage or source.failure_stage
        target.attempt = target.attempt or source.attempt
        target.validation = target.validation or source.validation
    target.lines.extend(source.lines)
    target.validation_passed = target.validation_passed or source.validation_passed
    target.validation_failed = target.validation_failed or source.validation_failed
    target.timeout = target.timeout or source.timeout
    target.fallback = target.fallback or source.fallback
    target.source_quality_refused = target.source_quality_refused or source.source_quality_refused
    target.final_quality_refused = target.final_quality_refused or source.final_quality_refused
    target.uncollected = target.uncollected or source.uncollected
    target.error = target.error or source.error
    if target.timeout_seconds is None:
        target.timeout_seconds = source.timeout_seconds
    elif source.timeout_seconds is not None:
        target.timeout_seconds = max(target.timeout_seconds, source.timeout_seconds)
    target.timeout_message = target.timeout_message or source.timeout_message
    target.source_contract = target.source_contract or source.source_contract


def _merge_duplicate_proc_records(records: list[FunctionStatus]) -> list[FunctionStatus]:
    """Collapse duplicate same-name PROC fragments produced by timeout fallback text."""
    merged: list[FunctionStatus] = []
    by_name: dict[str, FunctionStatus] = {}
    for record in records:
        previous = by_name.get(record.name)
        if previous is None:
            merged.append(record)
            by_name[record.name] = record
            continue
        _merge_duplicate_record_into(previous, record)
    return merged


def _apply_recovered_flags(record: FunctionStatus, line: str) -> None:
    """Reset verdict fields when a retry-recovered line appears."""
    lowered = line.lower()
    if _RETRY_RECOVERED_RE.search(line) is not None:
        record.validation_passed = True
        record.validation_failed = False
        record.timeout = False
        record.fallback = False
        record.final_quality_refused = False
        record.uncollected = False
        record.error = False
        record.failure_status = FailureStatus.OK
        record.failure_stage = None
        record.attempt = AttemptStatus.DECOMPILED
        record.validation = ValidationStatus.PASSED
        record.timeout_seconds = None
        record.timeout_message = None
    if "[tail-validation] whole-tail validation clean across" in lowered:
        record.validation_passed = True
        record.validation_failed = False
        record.failure_status = FailureStatus.OK
        record.validation = ValidationStatus.PASSED


def _apply_timeout_flags(record: FunctionStatus, line: str, lowered: str) -> None:
    """Apply timeout markers, stage timeouts, and traceback tracking."""
    timeout_delay_match = _TIMEOUT_DELAY_RE.search(line)
    if timeout_delay_match is not None:
        record.timeout_seconds = float(timeout_delay_match.group("seconds"))
    timed_out_after_match = _TIMED_OUT_AFTER_RE.search(line)
    if timed_out_after_match is not None and record.timeout_seconds is None:
        record.timeout_seconds = float(timed_out_after_match.group("seconds"))
    if "timed out" in lowered and "partial timeout" not in lowered:
        record.timeout_message = line.strip()
    stage_timeout_match = _STAGE_TIMEOUT_RE.search(line)
    if stage_timeout_match is not None:
        record.timeout = True
        record.timeout_message = line.strip()
        if record.failure_stage is None:
            record.failure_stage = stage_timeout_match.group("stage")
    if "exception ignored while calling deallocator" in lowered:
        record.ignore_next_traceback = True
    if "traceback (most recent call last):" in lowered:
        if record.ignore_next_traceback:
            record.ignore_next_traceback = False
        else:
            record.error = True
            record.failure_status = FailureStatus.ERROR


def _apply_failure_family_flags(record: FunctionStatus, line: str) -> None:
    """Apply a structured failure-family line to the record."""
    failure_match = _FAILURE_FAMILY_RE.search(line)
    if failure_match is None:
        return
    failure_status = FailureStatus.from_token(failure_match.group("status"))
    record.failure_status = failure_status
    failure_stage = failure_match.group("stage")
    if failure_stage != "not_set" or record.failure_stage is None:
        record.failure_stage = failure_stage
    record.validation = ValidationStatus.from_token(failure_match.group("validation"))
    if failure_status is FailureStatus.TIMEOUT:
        record.timeout = True
    elif failure_status is FailureStatus.ERROR:
        record.error = True
    elif failure_status is FailureStatus.VALIDATION_FAILED:
        record.validation_failed = True
    if record.validation is ValidationStatus.FAILED:
        record.validation_failed = True


def _apply_function_info_flags(record: FunctionStatus, line: str) -> None:
    """Apply a structured function-info line to the record."""
    info_match = _FUNCTION_INFO_RE.search(line)
    if info_match is None:
        return
    attempt = AttemptStatus.from_token(info_match.group("attempt"))
    record.attempt = attempt
    record.validation = ValidationStatus.from_token(info_match.group("validation"))
    if attempt is AttemptStatus.TIMED_OUT:
        record.timeout = True
    elif attempt is AttemptStatus.ERROR:
        record.error = True
    elif attempt is AttemptStatus.FALLBACK:
        record.fallback = True
    elif attempt is AttemptStatus.EMPTY:
        record.uncollected = True
    if record.validation is ValidationStatus.PASSED:
        record.validation_passed = True
    elif record.validation is ValidationStatus.FAILED:
        record.validation_failed = True
    elif record.validation is ValidationStatus.UNCOLLECTED:
        record.uncollected = True


def _apply_marker_flags(record: FunctionStatus, lowered: str) -> None:
    """Apply free-text verdict markers to the record."""
    if "validation=passed" in lowered or "validation passed" in lowered:
        record.validation_passed = True
    direct_failure_after_clean = "direct validation=failed" in lowered and record.validation_passed
    if ("validation=failed" in lowered and not direct_failure_after_clean) or "tail validation failed" in lowered:
        record.validation_failed = True
    if "/* -- timeout -- */" in lowered or ("timed out" in lowered and "partial timeout" not in lowered):
        record.timeout = True
    if "asm fallback" in lowered or "fallback to asm" in lowered:
        record.fallback = True
    if "final quality guard rejected" in lowered:
        record.final_quality_refused = True
        record.validation_failed = True
    if "uncollected" in lowered:
        record.uncollected = True


def _update_flags(record: FunctionStatus, line: str) -> None:
    """Update one function verdict from a structured or fatal transcript line."""
    lowered = line.lower()
    _apply_recovered_flags(record, line)
    _apply_timeout_flags(record, line, lowered)
    _apply_failure_family_flags(record, line)
    _apply_function_info_flags(record, line)
    _apply_marker_flags(record, lowered)


def _parse_run_summary_line(run_summary: dict[str, Any], line: str) -> None:
    attempted_match = _RUN_ATTEMPTED_RE.search(line)
    if attempted_match is not None:
        run_summary["attempted"] = int(attempted_match.group("attempted"))
    decompiled_match = _RUN_DECOMPILED_RE.search(line)
    if decompiled_match is not None:
        run_summary["decompiled"] = int(decompiled_match.group("decompiled"))
        run_summary["selected"] = int(decompiled_match.group("selected"))
    timeout_match = _RUN_TIMEOUT_RE.search(line)
    if timeout_match is not None:
        run_summary["timed_out"] = int(timeout_match.group("timed_out"))
    fallback_match = _RUN_FALLBACK_RE.search(line)
    if fallback_match is not None:
        run_summary["asm_or_detail_fallback"] = int(fallback_match.group("fallback"))
    shown_match = _RUN_SHOWN_RE.search(line)
    if shown_match is not None:
        run_summary["shown"] = int(shown_match.group("shown"))
        run_summary["file_summary_decompiled"] = int(shown_match.group("decompiled"))
        run_summary["file_summary_fallback"] = int(shown_match.group("fallback"))
    surface_match = _TAIL_SURFACE_RE.search(line)
    if surface_match is not None:
        run_summary["tail_validation"] = {
            **dict(run_summary.get("tail_validation", {}) or {}),
            "severity": surface_match.group("severity"),
            "merge_gate": surface_match.group("merge_gate"),
        }
    coverage_match = _TAIL_COVERAGE_RE.search(line)
    if coverage_match is not None:
        run_summary["tail_validation"] = {
            **dict(run_summary.get("tail_validation", {}) or {}),
            "coverage": int(coverage_match.group("coverage")),
            "missing": int(coverage_match.group("missing")),
            "unknown": int(coverage_match.group("unknown")),
        }
    if "[tail-validation] uncollected" in line:
        uncollected = list(run_summary.get("tail_validation_uncollected", []) or [])
        uncollected.append(line.split("uncollected", 1)[1].strip())
        run_summary["tail_validation_uncollected"] = uncollected


def _node_children(node: c_ast.Node) -> tuple[c_ast.Node, ...]:
    """Return typed children across pycparser's dynamic node boundary."""
    children = cast("tuple[tuple[str, c_ast.Node], ...]", node.children())
    return tuple(child for _name, child in children)


class _DeclarationTypeCollector:
    """Collect declared C types needed for pointer/value argument classification."""

    def __init__(self) -> None:
        self.types_by_name: dict[str, c_ast.Node] = {}

    def visit(self, node: c_ast.Node) -> None:
        """Record named object declarations and recurse through children."""
        if isinstance(node, c_ast.Decl) and isinstance(node.name, str):
            self.types_by_name[node.name] = node.type
        for child in _node_children(node):
            self.visit(child)


def _resolved_expression_type(
    expression: c_ast.Node,
    declared_types: dict[str, c_ast.Node],
) -> c_ast.Node | None:
    """Resolve the declaration type carried by a simple generated-C expression."""
    if isinstance(expression, c_ast.ID):
        return declared_types.get(expression.name)
    if isinstance(expression, c_ast.ArrayRef):
        base_type = _resolved_expression_type(expression.name, declared_types)
        if isinstance(base_type, (c_ast.ArrayDecl, c_ast.PtrDecl)):
            return base_type.type
        return None
    if isinstance(expression, c_ast.Cast):
        return expression.to_type.type
    return None


def _expression_is_pointer(
    expression: c_ast.Node,
    declared_types: dict[str, c_ast.Node],
) -> bool:
    """Return whether a generated-C expression has an evident pointer shape."""
    if (
        isinstance(expression, c_ast.FuncCall)
        and isinstance(expression.name, c_ast.ID)
        and expression.name.name in {"MK_FP", "SEG_PTR"}
    ):
        return True
    if isinstance(expression, c_ast.UnaryOp) and expression.op == "&":
        return True
    if isinstance(expression, c_ast.Constant) and expression.type == "string":
        return True
    resolved_type = _resolved_expression_type(expression, declared_types)
    if isinstance(resolved_type, (c_ast.PtrDecl, c_ast.ArrayDecl)):
        return True
    if isinstance(expression, c_ast.BinaryOp) and expression.op in {"+", "-"}:
        return _expression_is_pointer(expression.left, declared_types) or _expression_is_pointer(
            expression.right,
            declared_types,
        )
    if isinstance(expression, c_ast.TernaryOp):
        return _expression_is_pointer(expression.iftrue, declared_types) and _expression_is_pointer(
            expression.iffalse,
            declared_types,
        )
    return False


def _expression_is_null_constant(expression: c_ast.Node) -> bool:
    """Return whether an expression is an integer zero accepted as a null pointer."""
    if not isinstance(expression, c_ast.Constant) or expression.type not in {"int", "long"}:
        return False
    try:
        return int(expression.value.rstrip("uUlL"), 0) == 0
    except ValueError:
        return False


def _argument_class(
    expression: c_ast.Node,
    declared_types: dict[str, c_ast.Node],
) -> ArgumentClass:
    """Classify one generated-C call argument as pointer-shaped or value-shaped."""
    if _expression_is_pointer(expression, declared_types):
        return ArgumentClass.POINTER
    return ArgumentClass.VALUE


class _FunctionCallCollector:
    """Collect direct calls and argument classes from one generated function body."""

    def __init__(self, declared_types: dict[str, c_ast.Node]) -> None:
        self.declared_types = declared_types
        self.observations: list[CallObservation] = []
        self.null_arguments: dict[int, tuple[bool, ...]] = {}

    def visit(self, node: c_ast.Node) -> None:
        """Record direct calls, retaining null-constant evidence by observation index."""
        if isinstance(node, c_ast.FuncCall):
            name = node.name.name if isinstance(node.name, c_ast.ID) else "<indirect>"
            if name not in _GENERATED_MEMORY_INTRINSICS:
                arguments = () if node.args is None else tuple(node.args.exprs)
                observation_index = len(self.observations)
                self.observations.append(
                    CallObservation(
                        name=name,
                        argument_classes=tuple(
                            _argument_class(argument, self.declared_types) for argument in arguments
                        ),
                    )
                )
                self.null_arguments[observation_index] = tuple(
                    _expression_is_null_constant(argument) for argument in arguments
                )
        for child in _node_children(node):
            self.visit(child)


def _is_direct_break_body(node: c_ast.Node) -> bool:
    """Return whether an if body is a direct break carrier."""
    if isinstance(node, c_ast.Break):
        return True
    return isinstance(node, c_ast.Compound) and any(
        isinstance(statement, c_ast.Break)
        for statement in (node.block_items or ())
    )


def _array_base_name(node: c_ast.Node) -> str | None:
    """Return the root identifier for one generated-C array expression."""
    current = node
    while isinstance(current, (c_ast.ArrayRef, c_ast.StructRef)):
        current = current.name
    return current.name if isinstance(current, c_ast.ID) else None


class _ConditionShapeCollector:
    """Collect identifiers and array roots from one generated-C condition."""

    def __init__(self) -> None:
        self.identifiers: set[str] = set()
        self.arrays: set[str] = set()

    def visit(self, node: c_ast.Node) -> None:
        """Record identifiers and array roots, then recurse through children."""
        if isinstance(node, c_ast.ID):
            self.identifiers.add(node.name)
        elif isinstance(node, c_ast.ArrayRef):
            base_name = _array_base_name(node)
            if base_name is not None:
                self.arrays.add(base_name)
        for child in _node_children(node):
            self.visit(child)


class _ConditionalBreakCollector:
    """Collect if conditions whose taken branch contains a break."""

    def __init__(self) -> None:
        self.observations: list[ConditionalBreakObservation] = []

    def visit(self, node: c_ast.Node) -> None:
        """Record conditional breaks and recurse through nested branches."""
        if isinstance(node, c_ast.If) and _is_direct_break_body(node.iftrue):
            shape = _ConditionShapeCollector()
            shape.visit(node.cond)
            condition = node.cond
            while isinstance(condition, c_ast.Cast):
                condition = condition.expr
            negated = isinstance(condition, c_ast.UnaryOp) and condition.op == "!"
            if negated:
                condition = condition.expr
            comparison_op = (
                condition.op
                if isinstance(condition, c_ast.BinaryOp)
                else None
            )
            if negated and comparison_op is not None:
                comparison_op = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "!=", "!=": "=="}.get(
                    comparison_op
                )
            self.observations.append(
                ConditionalBreakObservation(
                    comparison_op=comparison_op,
                    identifiers=frozenset(shape.identifiers),
                    arrays=frozenset(shape.arrays),
                )
            )
        for child in _node_children(node):
            self.visit(child)


def _emitted_c_for_record(record: FunctionStatus) -> str | None:
    """Extract the generated C payload from one transcript function record."""
    if record.generated_c is not None:
        return record.generated_c
    marker_index = next(
        (
            index
            for index, line in enumerate(record.lines)
            if GeneratedCMarker.from_line(line) is not None
        ),
        None,
    )
    if marker_index is None:
        return None
    emitted_lines: list[str] = []
    for line in record.lines[marker_index + 1 :]:
        if _TRANSCRIPT_LOADING_RE.search(line) or _FUNCTION_HEADER_RE.search(line) or _DIRECT_FUNCTION_HEADER_RE.search(
            line
        ):
            break
        stripped = line.lstrip()
        if stripped.startswith(("[", "WARNING  |", "ERROR    |", "Traceback ")):
            continue
        if stripped.startswith("#"):
            continue
        emitted_lines.append(line)
    emitted = "\n".join(emitted_lines).strip()
    return emitted or None


def _parse_generated_contract_observations(
    function_name: str,
    emitted_c: str,
) -> tuple[
    tuple[CallObservation, ...],
    dict[int, tuple[bool, ...]],
    tuple[ConditionalBreakObservation, ...],
]:
    """Parse call and control-flow observations from generated C."""
    without_block_comments = _C_COMMENT_RE.sub("", emitted_c)
    normalized = "\n".join(_C_LINE_COMMENT_RE.sub("", line) for line in without_block_comments.splitlines())
    translation_unit = c_parser.CParser().parse(_C_PARSE_PREFIX + normalized)
    function = next(
        (
            item
            for item in translation_unit.ext
            if isinstance(item, c_ast.FuncDef) and item.decl.name == function_name
        ),
        None,
    )
    if function is None:
        generated_functions = tuple(item for item in translation_unit.ext if isinstance(item, c_ast.FuncDef))
        if len(generated_functions) != 1:
            raise ValueError(f"generated C has no function body for {function_name}")
        function = generated_functions[0]
    declarations = _DeclarationTypeCollector()
    declarations.visit(translation_unit)
    calls = _FunctionCallCollector(declarations.types_by_name)
    calls.visit(function.body)
    conditional_breaks = _ConditionalBreakCollector()
    conditional_breaks.visit(function.body)
    return (
        tuple(calls.observations),
        calls.null_arguments,
        tuple(conditional_breaks.observations),
    )


def _argument_classes_match(
    expected: tuple[ArgumentClass, ...],
    actual: tuple[ArgumentClass, ...],
    null_arguments: tuple[bool, ...],
) -> bool:
    """Return whether one generated call preserves source value/pointer classes."""
    if len(expected) != len(actual):
        return False
    return all(
        expected_class is actual_class
        or (
            expected_class is ArgumentClass.POINTER_OR_NULL
            and (actual_class is ArgumentClass.POINTER or null_arguments[index])
        )
        for index, (expected_class, actual_class) in enumerate(zip(expected, actual, strict=False))
    )


def _source_argument_classes_for_binary_call(
    binary_name: str,
    argument_classes: tuple[ArgumentClass, ...],
) -> tuple[ArgumentClass, ...]:
    """Collapse proven 16-bit ABI words into source-level argument classes."""
    if binary_name in {"sub_12756", "sub_12ac8"} and len(argument_classes) == 2:
        return (ArgumentClass.POINTER,)
    if binary_name == "sub_12b3e" and len(argument_classes) == 2:
        return (ArgumentClass.VALUE,)
    if binary_name == "sub_112ba" and len(argument_classes) >= 2:
        return (
            argument_classes[0],
            ArgumentClass.POINTER,
            *argument_classes[2:],
        )
    return argument_classes


def _conditional_break_matches(
    requirement: ConditionalBreakRequirement,
    observation: ConditionalBreakObservation,
) -> bool:
    """Match source or explicitly proven binary identities for one exit guard."""
    if observation.comparison_op not in requirement.comparison_ops:
        return False
    shapes = (
        (requirement.required_identifiers, requirement.required_arrays),
        *requirement.alternative_shapes,
    )
    return any(
        identifiers <= observation.identifiers and arrays <= observation.arrays
        for identifiers, arrays in shapes
    )


def _normalized_contract_observations_8616(
    observations: list[CallObservation],
    call_name_aliases: Mapping[str, str] | None,
) -> dict[str, list[tuple[int, CallObservation]]]:
    """Group observations by alias-normalized call name."""
    observations_by_name: dict[str, list[tuple[int, CallObservation]]] = {}
    for index, observation in enumerate(observations):
        normalized_name = (call_name_aliases or {}).get(observation.name, observation.name)
        normalized_observation = CallObservation(
            name=normalized_name,
            argument_classes=_source_argument_classes_for_binary_call(
                observation.name,
                observation.argument_classes,
            ),
        )
        observations_by_name.setdefault(normalized_name, []).append(
            (index, normalized_observation)
        )
    return observations_by_name


def _check_call_requirements_8616(
    contract: FunctionCallContract,
    observations_by_name: dict[str, list[tuple[int, CallObservation]]],
    null_arguments: object,
) -> tuple[list[str], list[str], list[str], set[str]]:
    """Return missing/count/argument mismatches plus the expected-name set."""
    missing_calls: list[str] = []
    count_mismatches: list[str] = []
    argument_mismatches: list[str] = []
    expected_names = {requirement.name for requirement in contract.calls}
    for requirement in contract.calls:
        actual_calls = observations_by_name.get(requirement.name, [])
        if not actual_calls:
            missing_calls.append(requirement.name)
        if len(actual_calls) != requirement.count:
            count_mismatches.append(f"{requirement.name}: expected={requirement.count} actual={len(actual_calls)}")
        for occurrence, (observation_index, observation) in enumerate(actual_calls, start=1):
            if _argument_classes_match(
                requirement.argument_classes,
                observation.argument_classes,
                null_arguments[observation_index],
            ):
                continue
            expected_text = ",".join(argument.value for argument in requirement.argument_classes)
            actual_text = ",".join(argument.value for argument in observation.argument_classes)
            argument_mismatches.append(
                f"{requirement.name}[{occurrence}]: expected=({expected_text}) actual=({actual_text})"
            )
    return missing_calls, count_mismatches, argument_mismatches, expected_names


def _evaluate_source_contract(
    contract: FunctionCallContract,
    emitted_c: str | None,
    *,
    call_name_aliases: Mapping[str, str] | None = None,
) -> SourceContractResult:
    """Compare one generated function against its source-call acceptance contract."""
    if emitted_c is None:
        return SourceContractResult(passed=False, parse_error="generated C block missing")
    try:
        observations, null_arguments, conditional_breaks = (
            _parse_generated_contract_observations(
                contract.name,
                emitted_c,
            )
        )
    except (ParseError, ValueError) as ex:
        return SourceContractResult(passed=False, parse_error=str(ex))

    observations_by_name = _normalized_contract_observations_8616(observations, call_name_aliases)

    missing_calls, count_mismatches, argument_mismatches, expected_names = _check_call_requirements_8616(
        contract, observations_by_name, null_arguments,
    )

    unexpected_calls = tuple(
        f"{name}: count={len(calls)}"
        for name, calls in sorted(observations_by_name.items())
        if name not in expected_names and name not in contract.allowed_extra_calls
    )
    missing_control_flow: list[str] = []
    for condition_requirement in contract.conditional_breaks:
        matched = any(
            _conditional_break_matches(condition_requirement, observation)
            for observation in conditional_breaks
        )
        if matched:
            continue
        missing_control_flow.append(
            "conditional-break:"
            f"ops={','.join(sorted(condition_requirement.comparison_ops))}:"
            f"ids={','.join(sorted(condition_requirement.required_identifiers))}:"
            f"arrays={','.join(sorted(condition_requirement.required_arrays))}"
        )
    failures = (
        missing_calls,
        count_mismatches,
        argument_mismatches,
        unexpected_calls,
        missing_control_flow,
    )
    return SourceContractResult(
        passed=not any(failures),
        missing_calls=tuple(missing_calls),
        count_mismatches=tuple(count_mismatches),
        argument_mismatches=tuple(argument_mismatches),
        unexpected_calls=unexpected_calls,
        missing_control_flow=tuple(missing_control_flow),
    )


def _apply_sortdemo_source_contracts(records: list[FunctionStatus]) -> None:
    """Attach source-call evidence to every recognized SORTDEMO procedure record."""
    for record in records:
        contract = SORTDEMO_SOURCE_CALL_CONTRACTS.get(record.name)
        if contract is not None:
            record.source_contract = _evaluate_source_contract(
                contract,
                _emitted_c_for_record(record),
                call_name_aliases=_SORTDEMO_BINARY_CALL_ALIASES,
            )


def _attach_canonical_generated_definitions(
    records: list[FunctionStatus],
    transcript: str,
) -> None:
    """Associate deferred canonical definitions with their function records."""
    deferred: list[tuple[int, int, FunctionStatus]] = []
    for record in records:
        numeric_name = f"sub_{int(record.addr, 16):04x}"
        emitted_c = _emitted_c_for_record(record)
        if emitted_c is not None:
            try:
                _parse_generated_contract_observations(record.name, emitted_c)
            except (ParseError, ValueError):
                pass
            else:
                continue
        for function_name in (record.name, numeric_name):
            try:
                start, end = generated_function_definition_span(transcript, function_name)
            except ValueError:
                continue
            deferred.append((start, end, record))
            break
    if not deferred:
        return
    deferred.sort(key=lambda item: item[0])
    function_results = tuple(_FUNCTION_INFO_RE.finditer(transcript, 0, deferred[0][0]))
    result_end = function_results[-1].end() if function_results else -1
    prelude_start = transcript.find("\n", result_end) + 1 if result_end >= 0 else deferred[0][0]
    canonical_prelude = transcript[prelude_start : deferred[0][0]]
    previous_end: int | None = None
    for start, end, record in deferred:
        record.generated_c = _leakage_count_text(
            (canonical_prelude + transcript[previous_end if previous_end is not None else start : end]).splitlines()
        )
        previous_end = end


@dataclass
class _StatusParseRun8616:
    """Mutable transcript-parse state for one status pass."""

    records: list[FunctionStatus] = field(default_factory=list)
    current: FunctionStatus | None = None
    pending_function: tuple[str, str] | None = None
    run_summary: dict[str, Any] = field(default_factory=dict)

    def flush_current(self) -> None:
        """Append the open record, if any."""
        if self.current is not None:
            self.records.append(self.current)
            self.current = None

    def handle_line(self, line: str) -> None:
        """Fold one transcript line into records and the run summary."""
        recovery_start_match = _RECOVERY_START_RE.search(line)
        if recovery_start_match is not None:
            self.flush_current()
            self.pending_function = (recovery_start_match.group("addr").lower(), recovery_start_match.group("name").strip())
        direct_header_match = _DIRECT_FUNCTION_HEADER_RE.search(line)
        if direct_header_match is not None and self.current is not None:
            direct_name = direct_header_match.group(2).strip()
            if self.current.name == direct_name and (self.current.timeout or self.current.error or self.current.validation_failed):
                self.current.lines.append(line)
                _update_flags(self.current, line)
                return
        function_header_match = _FUNCTION_HEADER_RE.search(line)
        match = function_header_match or direct_header_match
        if match is not None:
            if self.current is not None and not (
                function_header_match is not None and self.current.is_recovery_placeholder()
            ):
                self.records.append(self.current)
            self.current = FunctionStatus(addr=match.group(1).lower(), name=match.group(2).strip())
            self.pending_function = None
        elif self.current is not None and _RUN_SUMMARY_START_RE.search(line):
            self.flush_current()
            _parse_run_summary_line(self.run_summary, line)
            return
        elif self.current is None and self.pending_function is not None and _FAILURE_FAMILY_RE.search(line) is not None:
            self.current = FunctionStatus(addr=self.pending_function[0], name=self.pending_function[1])
            self.pending_function = None
        elif self.current is None:
            _parse_run_summary_line(self.run_summary, line)
        if self.current is None:
            return
        self.current.lines.append(line)
        _update_flags(self.current, line)


def _scoreboard_summary_8616(records: list[FunctionStatus]) -> tuple[dict[str, int], dict[str, dict[str, int]]]:
    """Return (status counts, failure-stage counts) for merged records."""
    summary: dict[str, int] = {"total": len(records)}
    failure_stages: dict[str, dict[str, int]] = {}
    for record in records:
        status = record.terminal_status().value
        summary[status] = summary.get(status, 0) + 1
        stage = record.failure_stage
        if stage:
            stages_for_status = failure_stages.setdefault(status, {})
            stages_for_status[stage] = stages_for_status.get(stage, 0) + 1
    return summary, failure_stages


def parse_status_text(text: str, *, check_source_contracts: bool = False) -> dict[str, Any]:
    """Parse a decompiler transcript into a deterministic scoreboard."""
    run = _StatusParseRun8616()
    for line in text.splitlines():
        run.handle_line(line)
    run.flush_current()
    records = run.records
    run_summary = run.run_summary

    records = _merge_duplicate_proc_records(records)
    _attach_canonical_generated_definitions(records, text)
    if check_source_contracts:
        _apply_sortdemo_source_contracts(records)
    summary, failure_stages = _scoreboard_summary_8616(records)
    functions = [record.to_json() for record in records]
    source_contract_records = [record for record in records if record.source_contract is not None]
    source_contract_summary = {
        "total": len(source_contract_records),
        "passed": sum(record.source_contract.passed for record in source_contract_records if record.source_contract),
        "failed": sum(not record.source_contract.passed for record in source_contract_records if record.source_contract),
    }
    return {
        "summary": summary,
        "source_contract_summary": source_contract_summary,
        "failure_stages": failure_stages,
        "triage": _build_triage(records),
        "run_summary": run_summary,
        "functions": functions,
    }


def _required_status_gate_passes(
    result: dict[str, Any],
    *,
    require_source_contracts: bool,
) -> bool:
    """Return whether a structured status report satisfies the strict gate."""
    summary = result.get("summary")
    if not isinstance(summary, dict):
        return False
    total = summary.get("total")
    passed = summary.get(TerminalStatus.PASSED.value)
    if not isinstance(total, int) or total <= 0 or passed != total:
        return False

    if require_source_contracts:
        source_summary = result.get("source_contract_summary")
        if not isinstance(source_summary, dict):
            return False
        if (
            source_summary.get("total") != total
            or source_summary.get("passed") != total
            or source_summary.get("failed") != 0
        ):
            return False

    command = result.get("command")
    return not (isinstance(command, dict) and command.get("returncode") != 0)


def _build_triage(records: list[FunctionStatus]) -> dict[str, list[dict[str, Any]]]:
    """Build timeout/error triage rows from typed function status records."""

    timeout_rows: list[dict[str, Any]] = []
    error_rows: list[dict[str, Any]] = []
    for record in records:
        status = record.terminal_status()
        if status not in {TerminalStatus.TIMEOUT, TerminalStatus.ERROR}:
            continue
        row: dict[str, Any] = {
            "addr": record.addr,
            "name": record.name,
            "stage": record.failure_stage,
            "attempt": record.attempt.value if record.attempt is not None else None,
            "validation": record.validation.value if record.validation is not None else None,
        }
        if status is TerminalStatus.TIMEOUT:
            row["seconds"] = record.timeout_seconds
            row["message"] = record.timeout_message
            timeout_rows.append(row)
        else:
            error_rows.append(row)

    return {
        "timeout": sorted(timeout_rows, key=_timeout_triage_sort_key),
        "error": sorted(error_rows, key=_error_triage_sort_key),
    }


def _timeout_triage_sort_key(row: dict[str, Any]) -> tuple[float, str, str]:
    """Return a stable sort key that puts slowest timeouts first."""

    seconds = row.get("seconds")
    numeric_seconds = seconds if isinstance(seconds, (int, float)) else -1.0
    return (-float(numeric_seconds), str(row.get("stage") or ""), str(row.get("name") or ""))


def _error_triage_sort_key(row: dict[str, Any]) -> tuple[str, str]:
    """Return a stable sort key for non-timeout error triage rows."""

    return (str(row.get("stage") or ""), str(row.get("name") or ""))


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _sortdemo_decompiler_command(
    binary: Path,
    *,
    decompile_timeout: int | None,
    max_functions: int | None,
) -> list[str]:
    """Build the normal whole-binary decompiler command used by users."""
    command = [sys.executable, "./decompile.py"]
    if decompile_timeout is not None:
        command.extend(("--timeout", str(decompile_timeout)))
    if max_functions is not None and max_functions > 0:
        command.extend(("--max-functions", str(max_functions)))
    command.append(str(binary))
    return command


def _sortdemo_cod_path(binary: Path) -> Path:
    """Return the same-stem COD listing path used for SORTDEMO proc order."""
    upper = binary.with_suffix(".COD")
    if upper.exists():
        return upper
    return binary.with_suffix(".cod")


def _sortdemo_proc_names(cod_path: Path, *, max_functions: int | None) -> list[str]:
    """Read source procedure order from a Microsoft C COD listing."""
    names: list[str] = []
    seen: set[str] = set()
    for line in cod_path.read_text(encoding="latin-1").splitlines():
        match = _COD_PROC_RE.match(line)
        if match is None:
            continue
        name = match.group("name")
        if name in seen:
            continue
        seen.add(name)
        names.append(name)
        if max_functions is not None and len(names) >= max_functions:
            break
    return names


def _sortdemo_proc_command(
    binary: Path,
    proc_name: str,
    *,
    decompile_timeout: int | None,
) -> list[str]:
    command = [
        sys.executable,
        "./decompile.py",
        "--alternate-source-c",
        "--proc",
        proc_name,
        "--proc-kind",
        "NEAR",
    ]
    if decompile_timeout is not None:
        command.extend(("--timeout", str(decompile_timeout)))
    command.append(str(binary))
    return command


def _timeout_output(stdout: str | bytes | None, timeout: int | None) -> str:
    if isinstance(stdout, bytes):
        text = stdout.decode("utf-8", errors="replace")
    elif isinstance(stdout, str):
        text = stdout
    else:
        text = ""
    timeout_text = str(timeout) if timeout is not None else "unknown"
    return (
        text
        + "\n"
        + "/* failure family: status=timeout stage=status_harness sidecar=not_attempted "
        + "nonopt=not_attempted fallback=run_sortdemo validation=failed */\n"
        + f"status harness timed out after {timeout_text}s\n"
    )


def _run_sortdemo_decompiler(
    binary: Path,
    timeout: int | None,
    *,
    decompile_timeout: int | None,
    max_functions: int | None,
) -> tuple[str, int]:
    env = os.environ.copy()
    env["INERTIA_ENABLE_TAIL_VALIDATION"] = "1"
    command = _sortdemo_decompiler_command(
        binary,
        decompile_timeout=decompile_timeout,
        max_functions=max_functions,
    )
    try:
        completed = subprocess.run(
            command,
            check=False,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as ex:
        return _timeout_output(ex.stdout, timeout), 124
    return completed.stdout, int(completed.returncode)


def _run_sortdemo_proc_decompiler(
    binary: Path,
    timeout: int | None,
    *,
    decompile_timeout: int | None,
    max_functions: int | None,
) -> tuple[str, int]:
    env = os.environ.copy()
    env["INERTIA_ENABLE_TAIL_VALIDATION"] = "1"
    deadline = None if timeout is None else time.monotonic() + timeout
    chunks: list[str] = []
    returncode = 0
    for proc_name in _sortdemo_proc_names(_sortdemo_cod_path(binary), max_functions=max_functions):
        remaining = None if deadline is None else max(0.001, deadline - time.monotonic())
        command = _sortdemo_proc_command(binary, proc_name, decompile_timeout=decompile_timeout)
        try:
            completed = subprocess.run(
                command,
                check=False,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=remaining,
            )
        except subprocess.TimeoutExpired as ex:
            chunks.append(_timeout_output(ex.stdout, timeout))
            return "\n".join(chunks), 124
        chunks.append(completed.stdout)
        if completed.returncode != 0:
            returncode = int(completed.returncode)
    return "\n".join(chunks), returncode


def main(argv: list[str] | None = None) -> int:
    """Run the SORTDEMO status parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", default="-", help="Transcript path, or '-' for stdin.")
    parser.add_argument("--out", type=Path, help="Optional JSON output path.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON.")
    parser.add_argument("--run-sortdemo", action="store_true", help="Run decompile.py for SORTDEMO before parsing.")
    parser.add_argument(
        "--check-source-contracts",
        action="store_true",
        help="Parse generated C and enforce all SORTDEMO source-call contracts.",
    )
    parser.add_argument(
        "--require-passed",
        action="store_true",
        help="Exit nonzero unless every reported function and required source contract passes.",
    )
    parser.add_argument(
        "--per-function-proc",
        action="store_true",
        help="With --run-sortdemo, run each COD PROC in an independent decompile.py subprocess.",
    )
    parser.add_argument("--binary", type=Path, default=Path("SORTDEMO.EXE"), help="Binary used with --run-sortdemo.")
    parser.add_argument(
        "--run-timeout",
        type=int,
        default=300,
        help="Wall-clock timeout in seconds for --run-sortdemo. Use 0 to disable.",
    )
    parser.add_argument(
        "--decompile-timeout",
        type=int,
        default=20,
        help="Per-function decompile.py --timeout value for --run-sortdemo. Use 0 to omit.",
    )
    parser.add_argument("--max-functions", type=int, help="Optional decompile.py --max-functions value.")
    parser.add_argument("--transcript-out", type=Path, help="Optional path for the captured decompiler transcript.")
    args = parser.parse_args(argv)

    if args.run_sortdemo:
        run_started = time.monotonic()
        run_timeout = None if args.run_timeout == 0 else args.run_timeout
        decompile_timeout = None if args.decompile_timeout == 0 else args.decompile_timeout
        if args.per_function_proc:
            transcript, returncode = _run_sortdemo_proc_decompiler(
                args.binary,
                run_timeout,
                decompile_timeout=decompile_timeout,
                max_functions=args.max_functions,
            )
        else:
            transcript, returncode = _run_sortdemo_decompiler(
                args.binary,
                run_timeout,
                decompile_timeout=decompile_timeout,
                max_functions=args.max_functions,
            )
        elapsed_seconds = round(time.monotonic() - run_started, 3)
        if args.transcript_out is not None:
            args.transcript_out.parent.mkdir(parents=True, exist_ok=True)
            args.transcript_out.write_text(transcript, encoding="utf-8")
        result = parse_status_text(transcript, check_source_contracts=True)
        command = (
            [
                sys.executable,
                "./decompile.py",
                "--alternate-source-c",
                "--proc",
                "<COD PROC>",
                "--proc-kind",
                "NEAR",
                *(("--timeout", str(decompile_timeout)) if decompile_timeout is not None else ()),
                str(args.binary),
            ]
            if args.per_function_proc
            else _sortdemo_decompiler_command(
                args.binary,
                decompile_timeout=decompile_timeout,
                max_functions=args.max_functions,
            )
        )
        result["command"] = {
            "argv": command,
            "mode": (
                "per-function-proc-diagnostic"
                if args.per_function_proc
                else "whole-binary-authoritative"
            ),
            "authoritative": not args.per_function_proc,
            "returncode": returncode,
            "timed_out": returncode == 124,
            "elapsed_seconds": elapsed_seconds,
            "transcript_path": (
                str(args.transcript_out) if args.transcript_out is not None else None
            ),
        }
    else:
        result = parse_status_text(_read_input(args.input), check_source_contracts=args.check_source_contracts)
    rendered = json.dumps(result, indent=2 if args.pretty else None, sort_keys=True)
    if args.out is not None:
        args.out.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    if args.require_passed and not _required_status_gate_passes(
        result,
        require_source_contracts=bool(args.run_sortdemo or args.check_source_contracts),
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
