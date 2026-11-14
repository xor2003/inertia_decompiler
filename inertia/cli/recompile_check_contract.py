# cython: language_level=3, infer_types=True
"""Typed contracts for emitted-C recompilation checks.

Layer: CLI/fallback/reporting.
Responsibility: define authoritative, compiler-independent recompilation outcomes.
Forbidden: invoking compilers, changing generated C, or relaxing acceptance policy.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum
import dataclasses


class RecompileCheckOutcome(StrEnum):
    """Authoritative outcome of one emitted-C recompilation check."""

    PASSED = "passed"
    FAILED = "failed"
    TOOLCHAIN_UNAVAILABLE = "toolchain_unavailable"


@dataclasses.dataclass(frozen=True, )
class RecompileCheckResult:
    """Immutable evidence produced by one recompilation target."""

    outcome: RecompileCheckOutcome
    target: object
    exit_code: int | None
    compiler: object
    stdout: object
    stderr: object
    command: object
    checked_payload: object
    checked_payload_hash: object
    source_path: object = None
    compiler_profile: object = None
    launcher_signal: int | None = None

    @property
    def passed(self) -> cython.bint:
        """Return whether the compiler accepted the emitted C."""
        return self.outcome is RecompileCheckOutcome.PASSED

    @property
    def toolchain_unavailable(self) -> cython.bint:
        """Return whether the toolchain is missing or cannot execute in this environment."""
        return self.outcome is RecompileCheckOutcome.TOOLCHAIN_UNAVAILABLE


@dataclasses.dataclass(frozen=True)
class RecompileCacheIdentity:
    """Current frozen selection identity and whether its evidence permits reuse."""

    context: object
    outcome: RecompileCheckOutcome

    @property
    def reusable(self) -> cython.bint:
        """Permit cache hits only after current evidence validation."""
        return self.outcome is RecompileCheckOutcome.PASSED
