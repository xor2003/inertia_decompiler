"""Collect aggregate-pointee callee evidence from binary project state.

Layer: Types/Lowering.
Responsibility: prefer accepted interprocedural pointer-output objects when
joining caller targets with Widening-owned global layouts for one callee. The
older all-caller summary projection remains only for functions without an
authoritative pointer-output object contract; a typed refusal never falls back.
Consumes alias, widening, and typed facts. This module does not mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
import os

from inertia.widening.global_object_layout import GlobalObjectLayoutEvidence8616

from .callee_argument_count_evidence import collect_callee_argument_count_evidence_8616
from .callee_global_object_evidence import (
    CalleeGlobalObjectInterfaceEvidence8616,
    CalleeGlobalObjectInterfaceVerdict8616,
    CalleeGlobalObjectSourceFamilyFact8616,
    recover_callee_global_object_interface_evidence_8616,
)
from .callee_pointer_evidence import callee_pointer_argument_indices_at_address_8616
from .interprocedural_storage_transaction import (
    accepted_function_storage_contract_8616,
)
from .pointer_parameter_object_type_contracts import (
    PointerParameterObjectTypeEvidence8616,
)
from .pointer_parameter_object_types import (
    recover_pointer_parameter_object_types_8616,
)

_LOGGER = logging.getLogger(__name__)


def _project_pointer_object_types_8616(
    evidence: PointerParameterObjectTypeEvidence8616,
) -> CalleeGlobalObjectInterfaceEvidence8616:
    """Project authoritative typed facts to the existing codegen consumer."""
    if not evidence.complete or not evidence.facts:
        return CalleeGlobalObjectInterfaceEvidence8616(
            target_addr=evidence.function_addr,
            verdict=CalleeGlobalObjectInterfaceVerdict8616.UNKNOWN,
            family_base_offset=None,
            pointer_argument_indices=(),
            raw_fact_count=evidence.stats.raw_fact_count,
            normalized_fact_count=evidence.stats.normalized_fact_count,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=max(1, evidence.stats.failure_count),
            callsite_addrs=(),
            source_facts=(),
        )
    families = {fact.family_base_offset for fact in evidence.facts}
    shapes = {
        (fact.layout.element_width, fact.layout.field_offsets)
        for fact in evidence.facts
    }
    if len(families) != 1 or len(shapes) != 1:
        return CalleeGlobalObjectInterfaceEvidence8616(
            target_addr=evidence.function_addr,
            verdict=CalleeGlobalObjectInterfaceVerdict8616.CONFLICT,
            family_base_offset=None,
            pointer_argument_indices=(),
            raw_fact_count=evidence.stats.raw_fact_count,
            normalized_fact_count=evidence.stats.normalized_fact_count,
            classified_fact_count=0,
            materialized_count=0,
            failure_count=1,
            callsite_addrs=tuple(
                sorted(
                    {
                        view.source.callsite_addr
                        for fact in evidence.facts
                        for view in fact.views
                    }
                )
            ),
            source_facts=(),
        )
    family_base_offset = next(iter(families))
    source_facts = tuple(
        CalleeGlobalObjectSourceFamilyFact8616(
            target_addr=evidence.function_addr,
            callsite_addr=view.source.callsite_addr,
            argument_index=fact.logical_index,
            base_offset=view.source.effect.target_base_offset,
            canonical_base_offset=fact.layout.address.offset & 0xFFFF,
            index_identity=(
                tuple(
                    (term.source, term.coefficient)
                    for term in view.source.effect.near_offset.terms
                )
                or ("constant",)
            ),
            family_base_offset=family_base_offset,
            element_width=fact.layout.element_width,
            field_offsets=fact.layout.field_offsets,
        )
        for fact in evidence.facts
        for view in sorted(
            fact.views,
            key=lambda item: (
                item.source.callsite_addr,
                item.source.caller_addr,
            ),
        )
    )
    return CalleeGlobalObjectInterfaceEvidence8616(
        target_addr=evidence.function_addr,
        verdict=CalleeGlobalObjectInterfaceVerdict8616.COMPLETE,
        family_base_offset=family_base_offset,
        pointer_argument_indices=tuple(
            sorted(fact.logical_index for fact in evidence.facts)
        ),
        raw_fact_count=evidence.stats.raw_fact_count,
        normalized_fact_count=evidence.stats.normalized_fact_count,
        classified_fact_count=len(evidence.facts),
        materialized_count=0,
        failure_count=0,
        callsite_addrs=tuple(
            sorted({fact.callsite_addr for fact in source_facts})
        ),
        source_facts=source_facts,
    )


def collect_callee_global_object_interface_evidence_8616(
    project: object,
    target_addr: int,
    layout_evidence: GlobalObjectLayoutEvidence8616,
) -> CalleeGlobalObjectInterfaceEvidence8616:
    """Collect one complete aggregate-pointee interface census."""
    contract = accepted_function_storage_contract_8616(project, target_addr)
    if contract is not None and contract.pointer_memory_outputs:
        typed_evidence = recover_pointer_parameter_object_types_8616(
            target_addr,
            contract.pointer_memory_outputs,
            layout_evidence,
        )
        evidence = _project_pointer_object_types_8616(typed_evidence)
        if os.environ.get("INERTIA_DEBUG_CALLEE_GLOBAL_OBJECT_SOURCES") == "1":
            _LOGGER.warning(
                "callee global object collection target=%#x source=storage_contract "
                "typed=%s evidence=%s",
                target_addr,
                typed_evidence,
                evidence,
            )
        return evidence
    pointer_indices = callee_pointer_argument_indices_at_address_8616(
        project,
        target_addr,
    )
    if not pointer_indices:
        return recover_callee_global_object_interface_evidence_8616(
            target_addr,
            (),
            layout_evidence,
            (),
        )
    count_evidence = collect_callee_argument_count_evidence_8616(
        project,
        target_addr,
    )
    evidence = recover_callee_global_object_interface_evidence_8616(
        target_addr,
        count_evidence.callsite_summaries,
        layout_evidence,
        pointer_indices,
    )
    if os.environ.get("INERTIA_DEBUG_CALLEE_GLOBAL_OBJECT_SOURCES") == "1":
        _LOGGER.warning(
            "callee global object collection target=%#x pointers=%s verdict=%s "
            "summaries=%s evidence=%s",
            target_addr,
            pointer_indices,
            count_evidence.verdict,
            tuple(
                (summary.callsite_addr, summary.push_arg_sources)
                for summary in count_evidence.callsite_summaries
            ),
            evidence,
        )
    return evidence


__all__ = ["collect_callee_global_object_interface_evidence_8616"]
