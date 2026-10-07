"""Layer: Tail Validation.

Responsibility: route validation delta families to likely owning layers for diagnosis.
Forbidden: treating routing as proof, recovery, or validation success.

Package ownership contract (canonical inertia/validation package):
Layer: Validation.
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

__all__ = [
    "TailValidationFamilyRoute",
    "build_tail_validation_family_routing",
]


@dataclass(frozen=True)
class TailValidationFamilyRoute:
    """Diagnostic route from a tail-validation delta family to its likely owner."""

    family: str
    count: int
    function_count: int
    stages: tuple[str, ...]
    likely_layer: str
    next_root_cause_file: str
    signal: str


_DEFAULT_ROUTE = TailValidationFamilyRoute(
    family="unclassified observable delta",
    count=0,
    function_count=0,
    stages=(),
    likely_layer="triage",
    next_root_cause_file="inertia/validation/tail_validation.py",
    signal="needs classification",
)


_FAMILY_ROUTING_TABLE: dict[str, tuple[str, str, str]] = {
    "helper call delta": (
        "helpers",
        "inertia/lowering/analysis_helpers.py",
        "interrupt/dos helper lowering and naming",
    ),
    "live-out register delta": (
        "postprocess/flags",
        "inertia.postprocess.flags_cleanup",
        "register/flag normalization",
    ),
    "stack write delta": (
        "postprocess/stack",
        "inertia.postprocess.decompiler_postprocess_simplify",
        "stack write normalization",
    ),
    "segmented/global write delta": (
        "segmented-memory",
        "inertia/lowering/segmented_memory_reasoning.py",
        "segment association/lowering",
    ),
    "global write delta": (
        "segmented-memory",
        "inertia/lowering/segmented_memory_reasoning.py",
        "global vs segmented distinction",
    ),
    "segmented write delta": (
        "segmented-memory",
        "inertia/lowering/segmented_memory_reasoning.py",
        "segmented write identity",
    ),
    "return delta": (
        "postprocess/returns",
        "inertia.postprocess.decompiler_postprocess_stage",
        "return lowering/cleanup",
    ),
    "control-flow/guard delta": (
        "structuring",
        "inertia.structuring.structuring_sequences",
        "guard normalization and structuring order",
    ),
}


def _count(value: object) -> int:
    return value if isinstance(value, int) else 0


def _stage_names(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def build_tail_validation_family_routing(
    changed_families: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Build stable owner-layer routing rows for changed validation families."""

    def _impl() -> list[dict[str, object]]:
        rows: list[TailValidationFamilyRoute] = []
        for row in changed_families:
            if not isinstance(row, Mapping):
                continue
            family = row.get("family")
            if not isinstance(family, str) or not family:
                continue
            count = _count(row.get("count", 0))
            function_count = _count(row.get("function_count", 0))
            stages = _stage_names(row.get("stages", ()))
            route = _FAMILY_ROUTING_TABLE.get(family)
            if route is None:
                layer = _DEFAULT_ROUTE.likely_layer
                next_file = _DEFAULT_ROUTE.next_root_cause_file
                signal = _DEFAULT_ROUTE.signal
            else:
                layer, next_file, signal = route
            rows.append(
                TailValidationFamilyRoute(
                    family=family,
                    count=count,
                    function_count=function_count,
                    stages=stages,
                    likely_layer=layer,
                    next_root_cause_file=next_file,
                    signal=signal,
                )
            )
        rows.sort(key=lambda item: (-item.count, item.family))
        return [
            {
                "family": item.family,
                "count": item.count,
                "function_count": item.function_count,
                "stages": item.stages,
                "likely_layer": item.likely_layer,
                "next_root_cause_file": item.next_root_cause_file,
                "signal": item.signal,
            }
            for item in rows
        ]

    return _impl()
