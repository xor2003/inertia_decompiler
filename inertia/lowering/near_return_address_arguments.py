"""Remove a proven near-return control slot from the C argument interface.

Layer: Types/Lowering.
Responsibility: consume exact Alias stack identity and an authoritative function
prototype census to exclude BP+2 near-return storage from source arguments.
Unknown, overlapping, or census-incomplete interfaces are retained unchanged.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimStackVariable

from inertia.alias.alias_model_impl import _stack_slot_identity_for_variable

from .authoritative_function_prototypes import authoritative_function_prototype_8616


class NearReturnAddressArgumentVerdict8616(StrEnum):
    """Typed result of one near-return argument classification."""

    NO_CANDIDATE = "no_candidate"
    MATERIALIZED = "materialized"
    AMBIGUOUS_REFUSE = "ambiguous_refuse"
    CENSUS_UNAVAILABLE_REFUSE = "census_unavailable_refuse"


@dataclass(frozen=True, slots=True)
class NearReturnAddressArgumentStats8616:
    """Closed evidence counts for near-return argument exclusion."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class NearReturnAddressArgumentResult8616:
    """Outcome published by the near-return argument owner."""

    verdict: NearReturnAddressArgumentVerdict8616
    stats: NearReturnAddressArgumentStats8616
    changed: bool = False


class _StackIdentity8616(Protocol):
    """Alias identity fields needed to recognize the near-return word."""

    base: str
    offset: int
    width: int | None

    def end_offset(self) -> int | None:
        """Return the exclusive end offset when width is known."""
        ...


class _CFunction8616(Protocol):
    """Third-party C-function argument surface updated by this owner."""

    arg_list: Sequence[object] | None


class _Codegen8616(Protocol):
    """Third-party codegen fields carrying the typed result."""

    cfunc: _CFunction8616 | None
    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_near_return_address_argument_result_8616: (
        NearReturnAddressArgumentResult8616
    )


def _near_return_word_8616(candidate: object) -> bool:
    """Return whether one C argument is exactly the BP+2 near-return word."""
    if not isinstance(candidate, structured_c.CVariable):
        return False
    variable = candidate.variable
    if not isinstance(variable, SimStackVariable):
        return False
    identity = _stack_slot_identity_for_variable(variable)
    if identity is None:
        return False
    typed_identity = cast(_StackIdentity8616, identity)
    return (
        typed_identity.base == "bp"
        and typed_identity.offset == 2
        and typed_identity.width == 2
        and typed_identity.end_offset() == 4
    )


def prune_near_return_address_argument_8616(
    project: object,
    codegen: object,
    function: object | None,
) -> NearReturnAddressArgumentResult8616:
    """Exclude one proven BP+2 control slot when the typed census closes."""
    typed_codegen = cast(_Codegen8616, codegen)
    try:
        cfunc = typed_codegen.cfunc
    except AttributeError:
        cfunc = None
    try:
        arguments = list(cfunc.arg_list or ()) if cfunc is not None else []
    except AttributeError:
        arguments = []
    candidates = tuple(arg for arg in arguments if _near_return_word_8616(arg))
    raw_count = sum(
        1
        for arg in arguments
        if isinstance(arg, structured_c.CVariable)
        and isinstance(arg.variable, SimStackVariable)
        and arg.variable.base == "bp"
        and arg.variable.offset == 2
    )
    if not candidates:
        result = NearReturnAddressArgumentResult8616(
            NearReturnAddressArgumentVerdict8616.NO_CANDIDATE,
            NearReturnAddressArgumentStats8616(raw_fact_count=raw_count),
        )
    elif len(candidates) != 1:
        result = NearReturnAddressArgumentResult8616(
            NearReturnAddressArgumentVerdict8616.AMBIGUOUS_REFUSE,
            NearReturnAddressArgumentStats8616(
                raw_fact_count=raw_count,
                normalized_fact_count=len(candidates),
                failure_count=len(candidates),
            ),
        )
    else:
        authoritative = authoritative_function_prototype_8616(
            project,
            function,
            argument_count=len(arguments) - 1,
        )
        if authoritative is None:
            result = NearReturnAddressArgumentResult8616(
                NearReturnAddressArgumentVerdict8616.CENSUS_UNAVAILABLE_REFUSE,
                NearReturnAddressArgumentStats8616(
                    raw_fact_count=raw_count,
                    normalized_fact_count=1,
                    failure_count=1,
                ),
            )
        else:
            control_slot = candidates[0]
            assert cfunc is not None
            cfunc.arg_list = [arg for arg in arguments if arg is not control_slot]
            result = NearReturnAddressArgumentResult8616(
                NearReturnAddressArgumentVerdict8616.MATERIALIZED,
                NearReturnAddressArgumentStats8616(
                    raw_fact_count=raw_count,
                    normalized_fact_count=1,
                    classified_fact_count=1,
                    materialized_count=1,
                ),
                changed=True,
            )
            typed_codegen._inertia_codegen_decl_refresh_required_8616 = True
    typed_codegen._inertia_near_return_address_argument_result_8616 = result
    if result.stats.classified_fact_count > 0 and result.stats.materialized_count == 0:
        raise RuntimeError("near-return argument was classified but not materialized")
    return result


__all__ = [
    "NearReturnAddressArgumentResult8616",
    "NearReturnAddressArgumentStats8616",
    "NearReturnAddressArgumentVerdict8616",
    "prune_near_return_address_argument_8616",
]
