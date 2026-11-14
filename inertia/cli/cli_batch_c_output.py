# cython: language_level=3, infer_types=True
"""Layer: CLI/fallback/reporting.

Responsibility: preserve legacy CLI helper surface while delegating semantic proof to X86_16 layers.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.

Export subresponsibility: convert accepted per-function C payloads into one
canonical translation unit and report typed incomplete/conflict/error outcomes.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from inertia.cli.generated_translation_unit_assembly import (
    assemble_generated_translation_unit,
)
import dataclasses
import operator


class BatchCOutputStatus8616(StrEnum):
    """Typed whole-binary C export outcomes."""

    READY = "ready"
    INCOMPLETE = "incomplete"
    CONFLICT = "conflict"
    ERROR = "error"


@dataclasses.dataclass(frozen=True, )
class BatchCOutputResult8616:
    """Canonical or partial C plus a typed export verdict."""

    status: BatchCOutputStatus8616
    source: object
    payload_count: cython.longlong
    function_count: cython.longlong
    detail: object = None

    @property
    def failed(self) -> cython.bint:
        """Return whether a complete batch failed export assembly."""
        return self.status in {
            BatchCOutputStatus8616.CONFLICT,
            BatchCOutputStatus8616.ERROR,
        }


def build_batch_c_output_8616(
    payloads: Sequence[str],
    *,
    expected_function_count: cython.longlong,
    compiler: object = "gcc",
) -> BatchCOutputResult8616:
    """Assemble complete payloads or retain honest partial generated C."""
    normalized = tuple(payload for payload in iter(payloads) if payload.strip())
    partial_source = "\n".join(payload.rstrip() for payload in iter(normalized))
    if partial_source:
        partial_source += "\n"
    if operator.ne(len(normalized), expected_function_count):
        return BatchCOutputResult8616(
            status=BatchCOutputStatus8616.INCOMPLETE,
            source=partial_source,
            payload_count=len(normalized),
            function_count=len(normalized),
            detail=(
                f"accepted payload count {len(normalized)} does not match "
                f"expected function count {expected_function_count}"
            ),
        )
    try:
        assembled = assemble_generated_translation_unit(normalized, compiler=compiler)
    except ValueError as ex:
        return BatchCOutputResult8616(
            status=BatchCOutputStatus8616.ERROR,
            source="",
            payload_count=len(normalized),
            function_count=0,
            detail=str(ex),
        )
    if operator.ne(assembled.function_count, expected_function_count):
        return BatchCOutputResult8616(
            status=BatchCOutputStatus8616.ERROR,
            source="",
            payload_count=len(normalized),
            function_count=assembled.function_count,
            detail=(
                f"assembled function count {assembled.function_count} does not match "
                f"expected count {expected_function_count}"
            ),
        )
    if assembled.conflicts:
        conflicts = ", ".join(
            f"{conflict.kind.value}:{conflict.name}" for conflict in iter(assembled.conflicts)
        )
        return BatchCOutputResult8616(
            status=BatchCOutputStatus8616.CONFLICT,
            source="",
            payload_count=len(normalized),
            function_count=assembled.function_count,
            detail=f"conflicting generated declarations: {conflicts}",
        )
    return BatchCOutputResult8616(
        status=BatchCOutputStatus8616.READY,
        source=assembled.source,
        payload_count=len(normalized),
        function_count=assembled.function_count,
    )


__all__ = [
    "BatchCOutputResult8616",
    "BatchCOutputStatus8616",
    "build_batch_c_output_8616",
]
