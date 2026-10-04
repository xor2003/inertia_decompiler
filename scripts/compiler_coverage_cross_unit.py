"""Check that separately emitted C functions agree on shared interfaces.

Layer: Tooling/gates.
Responsibility: reject cross-translation-unit type conflicts before coverage admission.
"""

from __future__ import annotations

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class CrossUnitStatus(StrEnum):
    """Typed outcome of the portable-flat cross-unit compilation check."""

    NOT_ATTEMPTED = "not_attempted"
    PASSED = "passed"
    COMPILATION_FAILED = "compilation_failed"
    TIMED_OUT = "timed_out"
    COMPILER_UNAVAILABLE = "compiler_unavailable"


@dataclass(frozen=True, slots=True)
class CrossUnitResult:
    """Retain the selected units, compiler verdict, and complete diagnostics."""

    status: CrossUnitStatus
    sources: tuple[str, ...]
    command: tuple[str, ...]
    returncode: int | None
    stderr: str


def check_cross_unit_c(
    sources: Sequence[Path],
    object_path: Path,
    *,
    compiler: str = "gcc",
    timeout: int = 120,
) -> CrossUnitResult:
    """Link emitted units with GCC LTO so incompatible prototypes fail loudly."""

    selected = tuple(sorted((Path(source) for source in sources), key=lambda path: str(path)))
    source_names = tuple(str(source) for source in selected)
    if len(selected) < 2:
        return CrossUnitResult(CrossUnitStatus.NOT_ATTEMPTED, source_names, (), None, "")
    command = (
        compiler,
        "-std=c99",
        "-flto",
        "-Wall",
        "-Werror",
        "-Werror=lto-type-mismatch",
        "-r",
        *source_names,
        "-o",
        str(object_path),
    )
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError as error:
        return CrossUnitResult(CrossUnitStatus.COMPILER_UNAVAILABLE, source_names, command, None, str(error))
    except subprocess.TimeoutExpired as error:
        stderr = error.stderr
        diagnostic = stderr.decode(errors="replace") if isinstance(stderr, bytes) else stderr or ""
        return CrossUnitResult(CrossUnitStatus.TIMED_OUT, source_names, command, None, diagnostic)
    status = CrossUnitStatus.PASSED if completed.returncode == 0 else CrossUnitStatus.COMPILATION_FAILED
    return CrossUnitResult(status, source_names, command, completed.returncode, completed.stderr)
