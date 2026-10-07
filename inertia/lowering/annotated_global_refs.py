"""Join direct-memory facts with explicit function global annotations.

Layer: Types/Lowering.
Responsibility: bind optional global names to exact direct-memory offsets and
widths already present in decoded instruction summaries.
Consumes alias, widening, and typed facts; annotations provide names only.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, cast


class DirectOperandSummaryBoundary8616(Protocol):
    """Decoded instruction fields consumed at the lowering boundary."""

    @property
    def op0_kind(self) -> str | None:
        """Return the decoded first-operand kind."""
        ...

    @property
    def op0_value(self) -> int | str | None:
        """Return the decoded first-operand value."""
        ...

    @property
    def op0_size(self) -> int | None:
        """Return the decoded first-operand width in bytes."""
        ...

    @property
    def op1_kind(self) -> str | None:
        """Return the decoded second-operand kind."""
        ...

    @property
    def op1_value(self) -> int | str | None:
        """Return the decoded second-operand value."""
        ...

    @property
    def op1_size(self) -> int | None:
        """Return the decoded second-operand width in bytes."""
        ...


class AnnotatedFunctionBoundary8616(Protocol):
    """Third-party angr function field carrying Inertia annotations."""

    info: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class AnnotatedDirectGlobalRef8616:
    """A name-only annotation joined to binary-proven direct storage."""

    offset: int
    width: int
    name: str


def _direct_operands_8616(
    summaries: Sequence[DirectOperandSummaryBoundary8616],
) -> frozenset[tuple[int, int]]:
    """Collect exact direct-memory offsets and widths from decoded facts."""
    result: set[tuple[int, int]] = set()
    for summary in summaries:
        for kind, value, size in (
            (summary.op0_kind, summary.op0_value, summary.op0_size),
            (summary.op1_kind, summary.op1_value, summary.op1_size),
        ):
            if kind == "direct_mem" and isinstance(value, int) and isinstance(size, int) and size > 0:
                result.add((value & 0xFFFF, size))
    return frozenset(result)


def collect_annotated_direct_global_refs_8616(
    function: object | None,
    summaries: Sequence[DirectOperandSummaryBoundary8616],
) -> tuple[AnnotatedDirectGlobalRef8616, ...]:
    """Return exact direct-memory facts named by explicit annotations."""
    if function is None:
        return ()
    try:
        info = cast(AnnotatedFunctionBoundary8616, function).info
    except AttributeError:
        return ()
    annotations = info.get("x86_16_annotations")
    if not isinstance(annotations, Mapping):
        return ()
    global_vars = annotations.get("global_vars")
    if not isinstance(global_vars, Mapping):
        return ()

    direct_operands = _direct_operands_8616(summaries)
    refs: list[AnnotatedDirectGlobalRef8616] = []
    for raw_offset, raw_spec in global_vars.items():
        if not isinstance(raw_offset, int) or not isinstance(raw_spec, Mapping):
            continue
        name = raw_spec.get("name")
        if not isinstance(name, str) or not name:
            continue
        offset = raw_offset & 0xFFFF
        refs.extend(
            AnnotatedDirectGlobalRef8616(offset, width, name)
            for operand_offset, width in sorted(direct_operands)
            if operand_offset == offset
        )
    return tuple(refs)
