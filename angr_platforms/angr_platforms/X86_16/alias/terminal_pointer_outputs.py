"""Bind terminal pointer-relative outputs to callee parameter storage.

Layer: Alias.
Responsibility: resolve each Semantics-proven pointer base register at every
STORE site and require one exact positive-BP parameter source. This module does
not inspect rendered C, infer pointee types, widen byte lanes, project caller
targets, mutate prototypes, or render code.
Owns storage identity and exact overlapping-view ownership.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from ..callsite_register_provenance import (
    recover_register_source_before_instruction_8616,
)
from ..callsite_summary import CallsitePushSourceKind8616
from ..ir import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from ..semantics.terminal_pointer_output_contracts import (
    TerminalPointerOutputEvidence8616,
)
from .register_reaching_source import (
    RegisterReachingSourceResult8616,
    RegisterReachingSourceVerdict8616,
)
from .terminal_pointer_output_contracts import (
    TerminalPointerAliasEvidence8616,
    TerminalPointerAliasFact8616,
    TerminalPointerAliasFailure8616,
    TerminalPointerAliasStats8616,
)


def _refused_8616(
    evidence: TerminalPointerOutputEvidence8616,
    failure: TerminalPointerAliasFailure8616,
    normalized_count: int = 0,
) -> TerminalPointerAliasEvidence8616:
    """Build one atomic Alias refusal without publishing a successful subset."""
    raw_count = max(1, evidence.stats.raw_fact_count, len(evidence.facts))
    return TerminalPointerAliasEvidence8616(
        evidence.function_addr,
        (),
        failure,
        TerminalPointerAliasStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            failure_count=1,
        ),
        evidence,
    )


def _parameter_storage_8616(
    source: RegisterReachingSourceResult8616,
) -> IRAddress | None:
    """Convert one proven BP-value source to its exact argument slot."""
    if source.verdict is not RegisterReachingSourceVerdict8616.PROVEN:
        return None
    identity = source.source
    if not isinstance(identity, tuple) or len(identity) != 3:
        return None
    kind, offset, width = identity
    bp_word_slot = (
        kind == CallsitePushSourceKind8616.BP_VALUE.value
        and isinstance(offset, int)
        and not isinstance(offset, bool)
        and offset >= 4
        and width == 2
    )
    if not bp_word_slot:
        return None
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


def classify_terminal_pointer_output_aliases_8616(
    function: object,
    evidence: TerminalPointerOutputEvidence8616,
) -> TerminalPointerAliasEvidence8616:
    """Bind every terminal pointer STORE to one exact callee argument slot."""
    if not evidence.complete:
        return _refused_8616(
            evidence,
            TerminalPointerAliasFailure8616.TERMINAL_EVIDENCE_REFUSED,
        )
    facts: list[TerminalPointerAliasFact8616] = []
    normalized_count = 0
    for normalized_count, output in enumerate(evidence.facts, start=1):
        register = output.base_register
        if register is None:
            return _refused_8616(
                evidence,
                TerminalPointerAliasFailure8616.BASE_REGISTER_UNAVAILABLE,
                normalized_count,
            )
        sources = tuple(
            recover_register_source_before_instruction_8616(
                function,
                instruction_addr=site.instr_addr,
                register=register,
            )
            for site in output.store_sites
        )
        if any(
            source.verdict is not RegisterReachingSourceVerdict8616.PROVEN
            for source in sources
        ):
            return _refused_8616(
                evidence,
                TerminalPointerAliasFailure8616.REACHING_SOURCE_REFUSED,
                normalized_count,
            )
        parameters = tuple(_parameter_storage_8616(source) for source in sources)
        if any(parameter is None for parameter in parameters):
            return _refused_8616(
                evidence,
                TerminalPointerAliasFailure8616.PARAMETER_SOURCE_UNSUPPORTED,
                normalized_count,
            )
        first = parameters[0]
        if first is None:
            raise RuntimeError("proven pointer source lost parameter storage")
        if any(parameter != first for parameter in parameters[1:]):
            return _refused_8616(
                evidence,
                TerminalPointerAliasFailure8616.PARAMETER_SOURCE_CONFLICT,
                normalized_count,
            )
        facts.append(TerminalPointerAliasFact8616(output, first, sources))
    count = len(facts)
    result = TerminalPointerAliasEvidence8616(
        evidence.function_addr,
        tuple(facts),
        None,
        TerminalPointerAliasStats8616(count, count, count, count),
        evidence,
    )
    if not result.complete:
        raise RuntimeError("terminal pointer Alias accounting did not close")
    return result


__all__ = ["classify_terminal_pointer_output_aliases_8616"]
