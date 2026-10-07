"""Publish binary-proven far callback argument grouping.

Layer: Types/Lowering.
Responsibility: join a direct far caller's physical PUSH facts with the
callee's decoded indirect-call ABI, preserving the physical facts while
publishing a logical argument shape for C materialization.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from inertia.lowering.analysis_helpers import CallTargetKind8616
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.callsite_summary import CallsiteArgumentClass8616, CallsiteSummary8616

from .binary_callback_targets import binary_function_pointer_parameter_evidence_8616
from .call_argument_shape import (
    CallerStackObject8616,
    exact_caller_stack_object_for_word_pair_8616,
    exact_far_callback_call_shape_evidence_8616,
)
from .function_pointer_parameter_evidence import FunctionPointerParameterFact8616


class FarCallbackCallShapeRefusalKind8616(StrEnum):
    """Explain why one candidate direct far call retained its physical shape."""

    NO_CALLEE_EVIDENCE = "no_callee_evidence"
    ABI_NOT_PROVEN = "abi_not_proven"
    NO_WIDENED_CALLER_OBJECT = "no_widened_caller_object"


@dataclass(frozen=True, slots=True)
class FarCallbackCallShapeRefusal8616:
    """One unmaterialized candidate, identified by its binary callsite."""

    callsite_addr: int
    callee_addr: int
    kind: FarCallbackCallShapeRefusalKind8616


@dataclass(frozen=True, slots=True)
class FarCallbackCallShapeResult8616:
    """Closed census and immutable callsite inventory after shape publication."""

    inventory: dict[int, CallsiteSummary8616]
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    refusals: tuple[FarCallbackCallShapeRefusal8616, ...] = ()

    @property
    def complete(self) -> bool:
        """Require every attempted candidate to publish or refuse explicitly."""
        return (
            self.raw_fact_count == self.materialized_count + self.failure_count
            and self.raw_fact_count >= self.normalized_fact_count >= self.classified_fact_count
            and self.classified_fact_count == self.materialized_count
            and self.failure_count == len(self.refusals)
        )


def publish_binary_far_callback_shapes_8616(
    project: object,
    inventory: dict[int, CallsiteSummary8616],
    *,
    caller_stack_objects: tuple[CallerStackObject8616, ...],
) -> FarCallbackCallShapeResult8616:
    """Publish only far callback shapes whose caller storage is also widened."""
    published = dict(inventory)
    raw = 0
    normalized = 0
    classified = 0
    materialized = 0
    refusals: list[FarCallbackCallShapeRefusal8616] = []
    cache: dict[
        int,
        tuple[FunctionPointerParameterFact8616, tuple[CallsiteSummary8616, ...]] | None,
    ] = {}
    for callsite_addr, caller in sorted(inventory.items()):
        callee_addr = caller.target_addr
        if (
            caller.kind is not CallTargetKind8616.DIRECT_FAR_CALL
            or caller.arg_widths != (2, 2, 2)
            or not isinstance(callee_addr, int)
        ):
            continue
        raw += 1
        if callee_addr not in cache:
            cache[callee_addr] = binary_function_pointer_parameter_evidence_8616(project, callee_addr)
        callee_evidence = cache[callee_addr]
        if callee_evidence is None:
            refusals.append(
                FarCallbackCallShapeRefusal8616(
                    callsite_addr, callee_addr, FarCallbackCallShapeRefusalKind8616.NO_CALLEE_EVIDENCE
                )
            )
            continue
        normalized += 1
        fact, indirect_calls = callee_evidence
        logical = exact_far_callback_call_shape_evidence_8616(
            caller,
            callee_addr=callee_addr,
            callee_fact=fact,
            callee_indirect_calls=indirect_calls,
        )
        if logical is None:
            refusals.append(
                FarCallbackCallShapeRefusal8616(
                    callsite_addr, callee_addr, FarCallbackCallShapeRefusalKind8616.ABI_NOT_PROVEN
                )
            )
            continue
        sources = caller.push_arg_sources
        caller_object = exact_caller_stack_object_for_word_pair_8616(
            sources[2], sources[1], caller_stack_objects
        )
        if caller_object is None:
            refusals.append(
                FarCallbackCallShapeRefusal8616(
                    callsite_addr, callee_addr, FarCallbackCallShapeRefusalKind8616.NO_WIDENED_CALLER_OBJECT
                )
            )
            continue
        classified += 1
        if caller.logical_arg_widths and caller.logical_arg_widths != logical.widths:
            raise PipelineHardError(
                "binary far callback shape conflicts with published callsite shape",
                layer="types/lowering",
                function_addr=callee_addr,
                details={"callsite": callsite_addr},
            )
        published[callsite_addr] = replace(
            caller,
            logical_arg_widths=logical.widths,
            logical_arg_classes=(CallsiteArgumentClass8616.POINTER, CallsiteArgumentClass8616.VALUE),
        )
        materialized += 1
    return FarCallbackCallShapeResult8616(
        inventory=published,
        raw_fact_count=raw,
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=len(refusals),
        refusals=tuple(refusals),
    )
