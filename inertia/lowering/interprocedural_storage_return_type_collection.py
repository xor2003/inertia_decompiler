# cython: language_level=3, infer_types=True
"""Join exact caller observations into one return-only type proof.

Layer: Types/Lowering.
Responsibility: classify every fact in a complete caller return-use census and
join scalar signedness independently of unresolved input parameter evidence.
Consumes Semantics return storage, Alias identities, exact caller boundaries,
and ConditionIR. It does not mutate function prototypes or generated C.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass

from inertia.ir.condition_ir import ConditionIR
from inertia.semantics.caller_return_use_contracts import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from inertia.semantics.callsite_summary import caller_return_use_evidence_by_addr_8616

from .condition_transfer import collect_typed_condition_artifacts_8616
from .interprocedural_storage_caller_context import caller_ssa_context_for_return_use_8616
from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageTrialSignedness8616,
    StorageTrialStats8616,
    StorageTrialValueClass8616,
)
from .interprocedural_storage_return_type_collection_contracts import (
    FunctionReturnStorageTypeFailure8616,
    FunctionReturnStorageTypeResult8616,
    FunctionReturnStorageTypeVerdict8616,
)
from .interprocedural_storage_return_type_contracts import ReturnStorageTypeResult8616
from .interprocedural_storage_return_types import classify_return_storage_type_8616
import dataclasses
import operator

__all__ = [
    "FunctionReturnStorageTypeFailure8616",
    "FunctionReturnStorageTypeResult8616",
    "FunctionReturnStorageTypeVerdict8616",
    "collect_function_return_storage_type_8616",
]


@cython.ccall
def _refused_result_8616(
    function_addr: cython.longlong,
    failure: FunctionReturnStorageTypeFailure8616,
    *,
    raw_fact_count: cython.longlong = 0,
    normalized_fact_count: cython.longlong = 0,
    classified_fact_count: cython.longlong = 0,
    materialized_count: cython.longlong = 0,
    classifications: object = (),
    neutral_fact_count: cython.longlong = 0,
    verdict: FunctionReturnStorageTypeVerdict8616 = FunctionReturnStorageTypeVerdict8616.UNKNOWN_REFUSE,
) -> FunctionReturnStorageTypeResult8616:
    """Build one typed refusal while retaining the closed-loop counters."""
    return FunctionReturnStorageTypeResult8616(
        function_addr=function_addr,
        verdict=verdict,
        signedness=None,
        value_class=None,
        classifications=classifications,
        neutral_fact_count=neutral_fact_count,
        failure=failure,
        stats=StorageTrialStats8616(
            raw_fact_count=raw_fact_count,
            normalized_fact_count=normalized_fact_count,
            classified_fact_count=classified_fact_count,
            materialized_count=materialized_count,
            failure_count=1,
        ),
    )


@dataclasses.dataclass(frozen=True, )
class _FactClassificationCensus8616:
    """Classified caller facts plus neutral and processed counters."""

    classifications: object
    neutral_fact_count: cython.longlong
    processed_fact_count: cython.longlong


@cython.ccall
def _classify_caller_facts_8616(
    project: object,
    function_addr: cython.longlong,
    evidence: CallerReturnUseEvidence8616,
    output_storages: object,
) -> _FactClassificationCensus8616 | FunctionReturnStorageTypeResult8616:
    """Classify each non-neutral caller fact or return a typed refusal."""
    fact: object
    classifications: list[ReturnStorageTypeResult8616] = []
    neutral_fact_count = 0
    processed_fact_count = 0
    for fact in evidence.facts:
        if fact.excluded_recursive_passthrough or fact.verdict is CallerReturnUseVerdict8616.UNUSED:
            neutral_fact_count += 1
            processed_fact_count += 1
            continue
        context = caller_ssa_context_for_return_use_8616(project, function_addr, fact)
        if not context.complete:
            return _refused_result_8616(
                function_addr,
                FunctionReturnStorageTypeFailure8616.CALLER_CONTEXT_UNAVAILABLE,
                raw_fact_count=evidence.raw_fact_count,
                normalized_fact_count=evidence.normalized_fact_count,
                classified_fact_count=processed_fact_count,
                materialized_count=processed_fact_count,
                classifications=tuple(classifications),
                neutral_fact_count=neutral_fact_count,
            )
        conditions: tuple[ConditionIR, ...] = ()
        if fact.kind is CallsiteReturnUseKind8616.CONDITION:
            collected, _edges = collect_typed_condition_artifacts_8616(
                context.evidence_project,
                fact.caller_addr,
                function=context.caller_function,
            )
            conditions = tuple(collected)
        classification = classify_return_storage_type_8616(
            fact,
            output_storages,
            conditions,
        )
        if not classification.complete:
            return _refused_result_8616(
                function_addr,
                FunctionReturnStorageTypeFailure8616.CALLSITE_CLASSIFICATION_REFUSED,
                raw_fact_count=evidence.raw_fact_count,
                normalized_fact_count=evidence.normalized_fact_count,
                classified_fact_count=processed_fact_count + 1,
                materialized_count=processed_fact_count,
                classifications=tuple(classifications) + (classification,),
                neutral_fact_count=neutral_fact_count,
            )
        classifications.append(classification)
        processed_fact_count += 1
    return _FactClassificationCensus8616(
        classifications=tuple(classifications),
        neutral_fact_count=neutral_fact_count,
        processed_fact_count=processed_fact_count,
    )


@cython.ccall
def collect_function_return_storage_type_8616(
    project: object,
    function_addr: cython.longlong,
    output_storages: object,
) -> FunctionReturnStorageTypeResult8616:
    """Prove one scalar return type from every fact in its caller census."""
    evidence: object
    evidence = caller_return_use_evidence_by_addr_8616(project).get(function_addr)
    if evidence is None or operator.ne(evidence.target_addr, function_addr):
        return _refused_result_8616(
            function_addr,
            FunctionReturnStorageTypeFailure8616.EVIDENCE_UNAVAILABLE,
        )
    if (
        evidence.verdict is CallerReturnUseVerdict8616.UNKNOWN
        or not evidence.fact_census_complete
    ):
        return _refused_result_8616(
            function_addr,
            FunctionReturnStorageTypeFailure8616.CENSUS_INCOMPLETE,
            raw_fact_count=evidence.raw_fact_count,
            normalized_fact_count=evidence.normalized_fact_count,
            classified_fact_count=evidence.classified_fact_count,
            materialized_count=evidence.materialized_count,
        )

    census = _classify_caller_facts_8616(project, function_addr, evidence, output_storages)
    if isinstance(census, FunctionReturnStorageTypeResult8616):
        return census
    classifications = list(census.classifications)
    neutral_fact_count = census.neutral_fact_count
    processed_fact_count = census.processed_fact_count

    if not classifications:
        return _refused_result_8616(
            function_addr,
            FunctionReturnStorageTypeFailure8616.SIGNEDNESS_UNINFORMATIVE,
            raw_fact_count=evidence.raw_fact_count,
            normalized_fact_count=evidence.normalized_fact_count,
            classified_fact_count=processed_fact_count,
            materialized_count=processed_fact_count,
            neutral_fact_count=neutral_fact_count,
        )
    value_classes = {item.value_class for item in iter(classifications)}
    if value_classes != {StorageTrialValueClass8616.VALUE}:
        return _refused_result_8616(
            function_addr,
            FunctionReturnStorageTypeFailure8616.VALUE_CLASS_CONFLICT,
            raw_fact_count=evidence.raw_fact_count,
            normalized_fact_count=evidence.normalized_fact_count,
            classified_fact_count=processed_fact_count,
            materialized_count=processed_fact_count,
            classifications=tuple(classifications),
            neutral_fact_count=neutral_fact_count,
            verdict=FunctionReturnStorageTypeVerdict8616.CONFLICT,
        )
    informative_signedness = {
        item.signedness
        for item in iter(classifications)
        if item.signedness
        in {StorageTrialSignedness8616.SIGNED, StorageTrialSignedness8616.UNSIGNED}
    }
    if len(informative_signedness) > 1:
        return _refused_result_8616(
            function_addr,
            FunctionReturnStorageTypeFailure8616.SIGNEDNESS_CONFLICT,
            raw_fact_count=evidence.raw_fact_count,
            normalized_fact_count=evidence.normalized_fact_count,
            classified_fact_count=processed_fact_count,
            materialized_count=processed_fact_count,
            classifications=tuple(classifications),
            neutral_fact_count=neutral_fact_count,
            verdict=FunctionReturnStorageTypeVerdict8616.CONFLICT,
        )
    if not informative_signedness:
        return _refused_result_8616(
            function_addr,
            FunctionReturnStorageTypeFailure8616.SIGNEDNESS_UNINFORMATIVE,
            raw_fact_count=evidence.raw_fact_count,
            normalized_fact_count=evidence.normalized_fact_count,
            classified_fact_count=processed_fact_count,
            materialized_count=processed_fact_count,
            classifications=tuple(classifications),
            neutral_fact_count=neutral_fact_count,
        )
    return FunctionReturnStorageTypeResult8616(
        function_addr=function_addr,
        verdict=FunctionReturnStorageTypeVerdict8616.PROVEN,
        signedness=(
            StorageTrialSignedness8616.SIGNED
            if StorageTrialSignedness8616.SIGNED in informative_signedness
            else StorageTrialSignedness8616.UNSIGNED
        ),
        value_class=StorageTrialValueClass8616.VALUE,
        classifications=tuple(classifications),
        neutral_fact_count=neutral_fact_count,
        failure=None,
        stats=StorageTrialStats8616(
            raw_fact_count=evidence.raw_fact_count,
            normalized_fact_count=evidence.normalized_fact_count,
            classified_fact_count=processed_fact_count,
            materialized_count=processed_fact_count,
        ),
    )
