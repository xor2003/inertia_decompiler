# cython: language_level=3, infer_types=True
"""Validate results crossing skipped or dynamic Python module boundaries.

Layer: Pipeline governance.
Responsibility: narrow runtime values to explicit typed pipeline results when
static analysis intentionally does not follow the authoritative owner module.
Owns runtime ordering, invariant checks, hard failures, and final emission gates.
Do not recover semantic facts or perform IR, alias, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from .errors import PipelineHardError
T = typing.TypeVar("T")

__all__ = [
    "require_optional_result_type_8616",
    "require_result_type_8616",
]

@cython.ccall
def require_result_type_8616(value: object, expected_type: type[T], *, owner: object) -> T:
    """Return ``value`` after enforcing its owner's declared runtime type."""
    if not isinstance(value, expected_type):
        raise PipelineHardError(
            f"{owner} returned {type(value).__qualname__}, expected {expected_type.__qualname__}",
            layer="pipeline:result_contracts",
        )
    return value


@cython.ccall
def require_optional_result_type_8616(
    value: object,
    expected_type: type[T],
    *,
    owner: object,
) -> T | None:
    """Return an optional result after enforcing its non-None runtime type."""
    if value is None:
        return None
    return require_result_type_8616(value, expected_type, owner=owner)
