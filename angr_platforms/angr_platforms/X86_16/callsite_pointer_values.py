"""Typed service boundary for replaying proven pointer argument values.

Layer: Pipeline contracts.
Responsibility: carry the Types/Lowering service through an angr codegen object;
the compatibility consumer must not import or implement pointer semantics.
"""

from typing import Protocol, cast

from .pipeline.errors import PipelineHardError


class NearPointerArgumentValueLowerer8616(Protocol):
    """Lowering service for an already-classified near-pointer argument."""

    def __call__(
        self, expression: object, segment: object, *, codegen: object, c_target: str,
    ) -> tuple[object, bool]:
        """Return the C value and whether a segmented wrapper was materialized."""
        ...


class _PointerValueCarrier8616(Protocol):
    """Owned extension carried by third-party codegen objects."""

    _inertia_near_pointer_argument_value_lowerer_8616: NearPointerArgumentValueLowerer8616


def bind_near_pointer_argument_value_lowerer_8616(
    codegen: object, lowerer: NearPointerArgumentValueLowerer8616,
) -> None:
    """Bind the owning Lowering implementation before compatibility replay."""
    cast(_PointerValueCarrier8616, codegen)._inertia_near_pointer_argument_value_lowerer_8616 = lowerer


def consume_near_pointer_argument_value_8616(
    expression: object, segment: object, *, codegen: object, c_target: str,
) -> tuple[object, bool]:
    """Replay the bound service, refusing missing ownership before emission."""
    try:
        lowerer = cast(_PointerValueCarrier8616, codegen)._inertia_near_pointer_argument_value_lowerer_8616
    except AttributeError as exc:
        raise PipelineHardError(
            "near-pointer argument materialization requires a Structuring-bound Lowering service",
            layer="rewrite:callsite_compatibility",
        ) from exc
    return lowerer(expression, segment, codegen=codegen, c_target=c_target)
