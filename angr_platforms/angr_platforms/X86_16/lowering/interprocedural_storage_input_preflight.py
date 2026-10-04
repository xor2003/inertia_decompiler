"""Classify callsite storage inputs before constructing caller SSA.

Layer: Types/Lowering.
Responsibility: close physical argument and type-class evidence for one exact
callsite before the storage collector pays for reaching-definition SSA.
Consumes callsite, stack identity, signedness, and pointer facts. This module
does not build SSA, resolve reaching definitions, mutate codegen, or infer
missing evidence.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..callsite_summary import CallsiteSummary8616
from ..ir import IRAddress
from .callee_callsite_census import CalleeCallsiteFact8616
from .callee_pointer_evidence import CalleePointerArgumentEvidence8616
from .condition_argument_type_facts import ConditionArgumentFactsResult8616
from .interprocedural_storage_collection_contracts import (
    StorageTrialCollectionFailure8616,
    StorageTrialCollectionFailureKind8616,
)
from .interprocedural_storage_contracts import (
    StorageTrialSignedness8616,
    StorageTrialValueClass8616,
)
from .interprocedural_storage_reaching_contracts import PhysicalCallArgument8616
from .interprocedural_storage_reaching_defs import physical_call_argument_8616
from .interprocedural_storage_trial_types import classify_input_argument_8616
from .modular_argument_type_facts import ModularArgumentTypeFacts8616

__all__ = [
    "CallsiteInputPreflightResult8616",
    "CallsiteInputPreflightStats8616",
    "ClassifiedCallsiteInput8616",
    "classify_callsite_inputs_before_ssa_8616",
]


@dataclass(frozen=True, slots=True)
class ClassifiedCallsiteInput8616:
    """One logical input whose physical shape and type class are proven."""

    logical_index: int
    storage: IRAddress
    physical: PhysicalCallArgument8616
    signedness: StorageTrialSignedness8616
    value_class: StorageTrialValueClass8616


@dataclass(frozen=True, slots=True)
class CallsiteInputPreflightStats8616:
    """Closed evidence accounting before caller SSA construction."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closed(self) -> bool:
        """Return whether every logical input was selected or refused once."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        return bool(
            min(counts) >= 0
            and self.raw_fact_count == self.materialized_count + self.failure_count
            and self.classified_fact_count == self.materialized_count
            and self.classified_fact_count
            <= self.normalized_fact_count
            <= self.raw_fact_count
        )


@dataclass(frozen=True, slots=True)
class CallsiteInputPreflightResult8616:
    """Typed selections or fail-closed reasons for one exact callsite."""

    inputs: tuple[ClassifiedCallsiteInput8616, ...]
    failures: tuple[StorageTrialCollectionFailure8616, ...]
    stats: CallsiteInputPreflightStats8616

    @property
    def complete(self) -> bool:
        """Return whether every logical input is ready for caller SSA lookup."""
        return bool(
            self.stats.closed
            and self.stats.failure_count == 0
            and self.stats.materialized_count == self.stats.raw_fact_count
        )


def _failure_8616(
    kind: StorageTrialCollectionFailureKind8616,
    callee_addr: int,
    fact: CalleeCallsiteFact8616,
    logical_index: int,
) -> StorageTrialCollectionFailure8616:
    """Build one exact preflight refusal."""
    return StorageTrialCollectionFailure8616(
        kind=kind,
        callee_addr=callee_addr,
        caller_addr=fact.caller_addr,
        callsite_addr=fact.callsite_addr,
        logical_index=logical_index,
    )


def classify_callsite_inputs_before_ssa_8616(
    callee_addr: int,
    fact: CalleeCallsiteFact8616,
    summary: CallsiteSummary8616,
    argument_storage: tuple[IRAddress, ...],
    signedness_facts: ConditionArgumentFactsResult8616,
    pointer_evidence: CalleePointerArgumentEvidence8616 | None,
    modular_facts: ModularArgumentTypeFacts8616 | None = None,
) -> CallsiteInputPreflightResult8616:
    """Classify all logical inputs and refuse incomplete evidence before SSA.

    Modular facts must name this exact callee in the collection's namespace;
    a proof for the same BP slot in another function is not input evidence.
    """
    if modular_facts is not None and modular_facts.callee_addr != callee_addr:
        modular_facts = None
    inputs: list[ClassifiedCallsiteInput8616] = []
    failures: list[StorageTrialCollectionFailure8616] = []
    normalized_count = 0
    for logical_index, storage in enumerate(argument_storage):
        physical, physical_failure = physical_call_argument_8616(summary, logical_index)
        if physical_failure is not None or physical is None:
            failures.append(
                _failure_8616(
                    StorageTrialCollectionFailureKind8616.REACHING_DEFINITION_REFUSED,
                    callee_addr,
                    fact,
                    logical_index,
                )
            )
            continue
        normalized_count += 1
        classification = classify_input_argument_8616(
            summary,
            physical,
            storage,
            logical_index,
            len(argument_storage),
            signedness_facts,
            pointer_evidence,
            modular_facts,
        )
        if (
            classification.failure is not None
            or classification.signedness is None
            or classification.value_class is None
        ):
            failures.append(
                _failure_8616(
                    classification.failure
                    or StorageTrialCollectionFailureKind8616.VALUE_CLASS_UNKNOWN,
                    callee_addr,
                    fact,
                    logical_index,
                )
            )
            continue
        inputs.append(
            ClassifiedCallsiteInput8616(
                logical_index=logical_index,
                storage=storage,
                physical=physical,
                signedness=classification.signedness,
                value_class=classification.value_class,
            )
        )
    stats = CallsiteInputPreflightStats8616(
        raw_fact_count=len(argument_storage),
        normalized_fact_count=normalized_count,
        classified_fact_count=len(inputs),
        materialized_count=len(inputs),
        failure_count=len(failures),
    )
    if not stats.closed:
        raise ValueError("callsite input preflight accounting did not close")
    return CallsiteInputPreflightResult8616(
        inputs=tuple(inputs),
        failures=tuple(failures),
        stats=stats,
    )
