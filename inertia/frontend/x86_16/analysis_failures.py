"""Pass owned terminal failures through the installed angr resilience policy.

Layer: Frontend/runtime.
Responsibility: propagate PipelineHardError without forking angr's handling of
ordinary exceptions or enabling its general fail-fast mode.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from typing import Any, cast

from inertia.pipeline.errors import PipelineHardError

__all__ = ["guard_angr_analysis_hard_failure_passthrough"]


@contextlib.contextmanager
def guard_angr_analysis_hard_failure_passthrough() -> Iterator[None]:
    """Keep owned failures terminal while delegating other errors to angr.

    Capture the owned exception inside the original context so angr sees a
    normal exit, then raise the same exception outside that context. Ordinary
    exceptions remain entirely under the installed resilience implementation,
    including its logging, named errors and fail-fast configuration.
    """
    from angr.analyses.analysis import Analysis

    analysis_cls = cast(Any, Analysis)  # Installed third-party context manager.
    original_resilience = analysis_cls._resilience

    @contextlib.contextmanager
    def preserving_hard_failures(
        analysis: object,
        name: str | None = None,
        exception: type[BaseException] | tuple[type[BaseException], ...] = Exception,
    ) -> Iterator[None]:
        """Reraise the identical owned exception after upstream handling exits."""
        terminal: PipelineHardError | None = None
        with original_resilience(analysis, name=name, exception=exception):
            try:
                yield
            except PipelineHardError as failure:
                terminal = failure
        if terminal is not None:
            raise terminal

    analysis_cls._resilience = preserving_hard_failures
    try:
        yield
    finally:
        analysis_cls._resilience = original_resilience
