"""Function-worker selection policy for CLI orchestration.

Layer: CLI/fallback/reporting.
Responsibility: identify whole-file jobs that require bounded-memory serial
or parallel clean-process execution without owning decompiler semantics.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

CLEAN_PROCESS_WORKER_CAP_8616: int = 4
"""Conservative aggregate-memory cap for isolated x86-16 workers.

Each clean interpreter retains its own angr/native state, while the parent may
also spawn GCC for acceptance checks.  Limiting only the isolated lane keeps
whole-file audits parallel without treating the per-process memory limit as an
aggregate budget.
"""


class _FunctionWorkItem8616(Protocol):
    """Minimal work-item surface required by clean-worker scheduling."""

    @property
    def index(self) -> int:
        """Return the stable output index."""
        ...

    @property
    def function(self) -> object:
        """Return the dynamic function passed to complexity estimation."""
        ...


class CleanProcessOverride8616(StrEnum):
    """Typed interpretation of the legacy clean-worker environment switch."""

    DEFAULT = "default"
    ENABLED = "enabled"
    DISABLED = "disabled"


class FunctionWorkerMode8616(StrEnum):
    """Execution isolation selected for one CLI function batch."""

    SHARED = "shared"
    CLEAN_PROCESS = "clean_process"


@dataclass(frozen=True, slots=True)
class FunctionWorkerPolicy8616:
    """Typed worker mode and bounded concurrency for one function batch."""

    mode: FunctionWorkerMode8616
    workers: int


def requires_isolated_function_decompilation(
    *,
    architecture: str,
    binary_suffix: str,
    address_requested: bool,
) -> bool:
    """Return whether a whole-file x86-16 executable needs isolated workers."""
    return not address_requested and binary_suffix.lower() == ".exe" and architecture == "86_16"


def clean_process_override_8616(value: str | None) -> CleanProcessOverride8616:
    """Parse the legacy clean-worker switch without leaking string states."""
    if value is None or not value.strip():
        return CleanProcessOverride8616.DEFAULT
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return CleanProcessOverride8616.ENABLED
    if normalized in {"0", "false", "no", "off"}:
        return CleanProcessOverride8616.DISABLED
    return CleanProcessOverride8616.DEFAULT


def prioritize_clean_function_work_8616[FunctionWorkItemT8616: _FunctionWorkItem8616](
    items: Sequence[FunctionWorkItemT8616],
    *,
    function_complexity: Callable[[object], tuple[int, int]],
) -> tuple[FunctionWorkItemT8616, ...]:
    """Submit larger clean-process jobs first while preserving output identity.

    Longest-processing-time-first reduces the final worker-wave critical path.
    Stable item indexes break equal-complexity ties deterministically; callers
    still collect and emit results in their original index order.
    """

    def priority(item: FunctionWorkItemT8616) -> tuple[int, int, int]:
        """Return descending block/byte complexity with a stable index tie."""
        block_count, byte_count = function_complexity(item.function)
        return (-max(block_count, 0), -max(byte_count, 0), item.index)

    return tuple(sorted(items, key=priority))


def select_function_worker_policy_8616(
    *,
    isolation_required: bool,
    sidecar_available: bool,
    full_sweep: bool,
    include_library_functions: bool,
    posix_available: bool,
    function_count: int,
    shared_worker_count: int,
    clean_process_override: CleanProcessOverride8616,
) -> FunctionWorkerPolicy8616:
    """Select bounded clean interpreters where shared state is unsafe."""
    del sidecar_available
    if not isolation_required:
        return FunctionWorkerPolicy8616(
            FunctionWorkerMode8616.SHARED,
            max(1, min(function_count or 1, shared_worker_count)),
        )

    clean_process_eligible = full_sweep and not include_library_functions and posix_available
    clean_process_selected = (
        clean_process_eligible and clean_process_override is not CleanProcessOverride8616.DISABLED
    )
    if not clean_process_selected:
        return FunctionWorkerPolicy8616(FunctionWorkerMode8616.SHARED, 1)
    return FunctionWorkerPolicy8616(
        FunctionWorkerMode8616.CLEAN_PROCESS,
        max(
            1,
            min(
                function_count or 1,
                shared_worker_count,
                CLEAN_PROCESS_WORKER_CAP_8616,
            ),
        ),
    )
