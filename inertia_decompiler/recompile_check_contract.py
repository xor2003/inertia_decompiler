"""Typed contracts for emitted-C recompilation checks.

Layer: CLI/fallback/reporting.
Responsibility: define authoritative, compiler-independent recompilation outcomes.
Forbidden: invoking compilers, changing generated C, or relaxing acceptance policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class RecompileCheckOutcome(StrEnum):
    """Authoritative outcome of one emitted-C recompilation check."""

    PASSED = "passed"
    FAILED = "failed"
    TOOLCHAIN_UNAVAILABLE = "toolchain_unavailable"


@dataclass(frozen=True, slots=True)
class RecompileCheckResult:
    """Immutable evidence produced by one recompilation target."""

    outcome: RecompileCheckOutcome
    target: str
    exit_code: int
    compiler: str | None
    stdout: str
    stderr: str
    command: tuple[str, ...]
    checked_payload: str
    checked_payload_hash: str
    source_path: str | None = None

    @property
    def passed(self) -> bool:
        """Return whether the compiler accepted the emitted C."""
        return self.outcome is RecompileCheckOutcome.PASSED

    @property
    def toolchain_unavailable(self) -> bool:
        """Return whether the toolchain is missing or cannot execute in this environment."""
        return self.outcome is RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE
