# cython: language_level=3, infer_types=True
"""Join every binary far-result caller to one exact paired-use proof.

Layer: Types/Lowering.
Responsibility: require a closed direct-caller census and one matching DX:AX
to ES:BX use for every included caller before any return-type projection.
Consumes alias, widening, and typed facts through retained proof fields only.
This is a nonpublishing gate: an access width does not prove a pointee family,
return expression, or representable C prototype.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass
from enum import StrEnum

from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir.ssa_function import SSAFunctionArtifact
from inertia.semantics.call_stack_effect_pipeline import semantic_function_ssa_artifact_at_address_8616
from inertia.semantics.caller_return_use_contracts import (
    CallerReturnUseEvidence8616,
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
from inertia.semantics.callsite_summary import collect_caller_return_use_evidence_8616
from inertia.semantics.register_value_preservation import AxValueView8616
from inertia.semantics.terminal_return_storage import (
    TerminalReturnStorage8616,
    terminal_return_storage_8616,
)

from .far_return_pointer_use import prove_far_return_pointer_use_8616
from .far_return_pointer_use_contracts import (
    FarReturnPointerUseEvidence8616,
    FarReturnPointerUseResult8616,
    FarReturnPointerUseStats8616,
)
from .interprocedural_storage_contracts import StorageIdentity8616
from .interprocedural_storage_return_defs import resolve_call_output_definitions_8616
from .interprocedural_storage_return_trial_materialization import return_output_storages_8616
import dataclasses
import operator
import builtins

__all__ = [
    "FarReturnPointerCensusFailure8616",
    "FarReturnPointerCensusResult8616",
    "FarReturnPointerCensusVerdict8616",
    "collect_far_return_pointer_census_8616",
    "join_far_return_pointer_census_8616",
]


class FarReturnPointerCensusVerdict8616(StrEnum):
    """Whether every direct caller has a matched paired-result use."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class FarReturnPointerCensusFailure8616(StrEnum):
    """Stable reasons the complete far-result use census cannot publish."""

    CENSUS_INCOMPLETE = "census_incomplete"
    RETURN_USE_NOT_VALUE = "return_use_not_value"
    PROOF_MISSING = "proof_missing"
    PROOF_DUPLICATE = "proof_duplicate"
    PROOF_EXTRA = "proof_extra"
    PROOF_UNPROVEN = "proof_unproven"
    TARGET_MISMATCH = "target_mismatch"
    WITNESS_MISMATCH = "witness_mismatch"
    CALLEE_BOUNDARY_UNPROVEN = "callee_boundary_unproven"
    CALLEE_OUTPUT_NOT_FAR_PAIR = "callee_output_not_far_pair"
    CALLER_BOUNDARY_UNPROVEN = "caller_boundary_unproven"
    CALLER_SSA_UNPROVEN = "caller_ssa_unproven"
    CALL_OUTPUT_UNPROVEN = "call_output_unproven"


@dataclasses.dataclass(frozen=True, )
class FarReturnPointerCensusResult8616:
    """Atomic all-caller proof or one typed, nonpublishing refusal."""

    census: CallerReturnUseEvidence8616
    verdict: FarReturnPointerCensusVerdict8616
    failure: FarReturnPointerCensusFailure8616 | None
    uses: object
    stats: FarReturnPointerUseStats8616

    @property
    def complete(self) -> cython.bint:
        """Recheck the census, each exact AX witness and five-stage accounting."""
        facts = tuple(sorted(self.census.facts, key=lambda fact: (fact.callsite_addr, fact.caller_addr)))
        count = len(facts)
        fact_keys = tuple((fact.caller_addr, fact.callsite_addr) for fact in iter(facts))
        return bool(
            self.verdict is FarReturnPointerCensusVerdict8616.PROVEN
            and self.failure is None
            and self.census.verdict is CallerReturnUseVerdict8616.USED
            and self.census.fact_census_complete
            and self.census.failure_count == 0
            and self.census.excluded_callsite_count == 0
            and self.census.used_callsite_count == count > 0
            and self.census.unused_callsite_count == 0
            and operator.eq(len(set(fact_keys)), count)
            and operator.eq(self.stats, FarReturnPointerUseStats8616(count, count, count, count, 0))
            and operator.eq(len(self.uses), count)
            and all(
                fact.verdict is CallerReturnUseVerdict8616.USED
                and fact.kind is CallsiteReturnUseKind8616.VALUE
                and fact.observed_value_view is AxValueView8616.AX
                and fact.classified
                and use.complete
                and operator.eq(use.callee_addr, self.census.target_addr)
                and (fact.caller_addr, fact.callsite_addr)
                == (use.caller_addr, use.callsite_addr)
                and operator.eq(fact.witness_instruction_addr, use.offset_copy.instr_addr)
                for fact, use in builtins.iter(zip(facts, self.uses, strict=True))
            )
        )


@cython.ccall
def _refuse_8616(
    census: CallerReturnUseEvidence8616,
    failure: FarReturnPointerCensusFailure8616,
    *,
    normalized: cython.bint = False,
    classified_count: cython.longlong = 0,
) -> FarReturnPointerCensusResult8616:
    """Retain the failed census as an atomic refusal with closed counters."""
    raw_count = max(1, census.raw_fact_count)
    return FarReturnPointerCensusResult8616(
        census,
        FarReturnPointerCensusVerdict8616.UNKNOWN_REFUSE,
        failure,
        (),
        FarReturnPointerUseStats8616(
            raw_count,
            raw_count if normalized else 0,
            min(classified_count, raw_count),
            0,
            raw_count,
        ),
    )


def _validate_census_8616(
    census: CallerReturnUseEvidence8616,
    facts: object,
) -> FarReturnPointerCensusFailure8616 | None:
    """Require a unique, closed inventory of classified AX value uses."""
    fact_keys = {(fact.caller_addr, fact.callsite_addr) for fact in iter(facts)}
    if not (
        census.fact_census_complete
        and facts
        and census.failure_count == 0
        and census.excluded_callsite_count == 0
        and operator.eq(census.used_callsite_count, len(facts))
        and census.unused_callsite_count == 0
        and operator.eq(len(fact_keys), len(facts))
        and census.verdict is CallerReturnUseVerdict8616.USED
    ):
        return FarReturnPointerCensusFailure8616.CENSUS_INCOMPLETE
    if any(
        fact.verdict is not CallerReturnUseVerdict8616.USED
        or fact.kind is not CallsiteReturnUseKind8616.VALUE
        or fact.observed_value_view is not AxValueView8616.AX
        or not fact.classified
        for fact in iter(facts)
    ):
        return FarReturnPointerCensusFailure8616.RETURN_USE_NOT_VALUE
    return None


@cython.ccall
def _index_proofs_8616(
    proofs: object,
) -> tuple[
    dict[tuple[cython.longlong, cython.longlong], FarReturnPointerUseResult8616],
    FarReturnPointerCensusFailure8616 | None,
]:
    """Index exact caller/callsite proofs and refuse missing or duplicate identities."""
    use: object
    proof: object
    indexed: dict[tuple[cython.longlong, cython.longlong], FarReturnPointerUseResult8616] = {}
    for proof in proofs:
        use = proof.evidence
        if use is None:
            return indexed, FarReturnPointerCensusFailure8616.PROOF_UNPROVEN
        key = (use.caller_addr, use.callsite_addr)
        if key in indexed:
            return indexed, FarReturnPointerCensusFailure8616.PROOF_DUPLICATE
        indexed[key] = proof
    return indexed, None


@cython.ccall
def _use_match_failure_8616(
    census: CallerReturnUseEvidence8616,
    fact: CallerReturnUseFact8616,
    use: FarReturnPointerUseEvidence8616,
) -> FarReturnPointerCensusFailure8616 | None:
    """Require the paired witness to name this exact callee and AX-use site."""
    if operator.ne(use.callee_addr, census.target_addr):
        return FarReturnPointerCensusFailure8616.TARGET_MISMATCH
    if operator.ne(fact.witness_instruction_addr, use.offset_copy.instr_addr):
        return FarReturnPointerCensusFailure8616.WITNESS_MISMATCH
    return None


def join_far_return_pointer_census_8616(
    census: CallerReturnUseEvidence8616,
    proofs: object,
) -> FarReturnPointerCensusResult8616:
    """Join all direct callers to paired-use witnesses without changing C."""
    census_failure: object
    mismatch: object
    proof_failure: object
    fact: object
    facts = tuple(sorted(census.facts, key=lambda fact: (fact.callsite_addr, fact.caller_addr)))
    census_failure = _validate_census_8616(census, facts)
    if census_failure is FarReturnPointerCensusFailure8616.CENSUS_INCOMPLETE:
        return _refuse_8616(census, census_failure)
    if census_failure is not None:
        return _refuse_8616(
            census, census_failure, normalized=True,
        )

    proofs_by_callsite, proof_failure = _index_proofs_8616(proofs)
    if proof_failure is not None:
        return _refuse_8616(census, proof_failure, normalized=True)
    fact_keys = {(fact.caller_addr, fact.callsite_addr) for fact in iter(facts)}
    if set(proofs_by_callsite) - fact_keys:
        return _refuse_8616(census, FarReturnPointerCensusFailure8616.PROOF_EXTRA, normalized=True)
    if fact_keys - set(proofs_by_callsite):
        return _refuse_8616(census, FarReturnPointerCensusFailure8616.PROOF_MISSING, normalized=True)

    ordered_uses: list[FarReturnPointerUseEvidence8616] = []
    for fact in facts:
        proof = proofs_by_callsite[(fact.caller_addr, fact.callsite_addr)]
        if not proof.complete or proof.evidence is None:
            return _refuse_8616(
                census, FarReturnPointerCensusFailure8616.PROOF_UNPROVEN,
                normalized=True, classified_count=len(ordered_uses),
            )
        use = proof.evidence
        mismatch = _use_match_failure_8616(census, fact, use)
        if mismatch is not None:
            return _refuse_8616(
                census, mismatch,
                normalized=True, classified_count=len(ordered_uses),
            )
        ordered_uses.append(use)
    count = len(facts)
    result = FarReturnPointerCensusResult8616(
        census,
        FarReturnPointerCensusVerdict8616.PROVEN,
        None,
        tuple(ordered_uses),
        FarReturnPointerUseStats8616(count, count, count, count, 0),
    )
    if not result.complete:
        raise RuntimeError("complete far-result caller join lost owned evidence")
    return result


@cython.ccall
def _caller_artifact_8616(
    project: object,
    caller_addr: cython.longlong,
    caller_range: object,
) -> tuple[SSAFunctionArtifact | None, FarReturnPointerCensusFailure8616 | None]:
    """Resolve one exact caller boundary and Semantics SSA, or a typed refusal."""
    boundary: object
    boundary = (
        exact_function_range_boundary_8616(project, *caller_range)
        if caller_range is not None else None
    )
    if boundary is None:
        return None, FarReturnPointerCensusFailure8616.CALLER_BOUNDARY_UNPROVEN
    resolution = semantic_function_ssa_artifact_at_address_8616(
        project, caller_addr, function=boundary,
    )
    if resolution.artifact is None:
        return None, FarReturnPointerCensusFailure8616.CALLER_SSA_UNPROVEN
    return resolution.artifact, None


@cython.ccall
def _callee_output_storages_8616(
    project: object,
    callee_range: object,
) -> tuple[tuple[StorageIdentity8616, ...], FarReturnPointerCensusFailure8616 | None]:
    """Require the callee's complete binary terminal paths to prove DX:AX."""
    boundary: object
    boundary = (
        exact_function_range_boundary_8616(project, *callee_range)
        if callee_range is not None else None
    )
    if boundary is None:
        return (), FarReturnPointerCensusFailure8616.CALLEE_BOUNDARY_UNPROVEN
    storage = terminal_return_storage_8616(project, boundary)
    if storage is not TerminalReturnStorage8616.DX_AX:
        return (), FarReturnPointerCensusFailure8616.CALLEE_OUTPUT_NOT_FAR_PAIR
    return return_output_storages_8616(storage), None


def collect_far_return_pointer_census_8616(
    project: object,
    callee_addr: cython.longlong,
    function_ranges: object,
) -> FarReturnPointerCensusResult8616:
    """Collect every caller's paired use from binary CFG/SSA without publishing C.

    The callee's terminal carrier is independently proved from its binary paths.
    Function ranges bound binary discovery; they do not supply value, pointer-type,
    or call-result evidence.
    """
    artifact: object
    callee_failure: object
    census_failure: object
    failure: object
    end: object
    fact: object
    start: object
    census = collect_caller_return_use_evidence_8616(project, callee_addr, function_ranges)
    facts = tuple(sorted(census.facts, key=lambda fact: (fact.callsite_addr, fact.caller_addr)))
    census_failure = _validate_census_8616(census, facts)
    if census_failure is not None:
        return _refuse_8616(census, census_failure)
    ranges_by_start: dict[cython.longlong, tuple[cython.longlong, cython.longlong]] = {}
    for start, end in function_ranges:
        if start in ranges_by_start:
            return _refuse_8616(
                census, FarReturnPointerCensusFailure8616.CALLER_BOUNDARY_UNPROVEN,
                normalized=True,
            )
        ranges_by_start[start] = (start, end)
    output_storages, callee_failure = _callee_output_storages_8616(
        project, ranges_by_start.get(callee_addr),
    )
    if callee_failure is not None:
        return _refuse_8616(
            census, callee_failure,
            normalized=True,
        )
    artifacts: dict[cython.longlong, SSAFunctionArtifact] = {}
    proofs: list[FarReturnPointerUseResult8616] = []
    for fact in facts:
        artifact = artifacts.get(fact.caller_addr)
        if artifact is None:
            artifact, failure = _caller_artifact_8616(
                project, fact.caller_addr, ranges_by_start.get(fact.caller_addr),
            )
            if artifact is None:
                assert failure is not None, "missing caller SSA lacks a typed refusal"
                return _refuse_8616(
                    census, failure,
                    normalized=True, classified_count=len(proofs),
                )
            artifacts[fact.caller_addr] = artifact
        definitions = resolve_call_output_definitions_8616(
            artifact, fact, callee_addr, (callee_addr,), output_storages, project=project,
        )
        if not definitions.complete:
            return _refuse_8616(
                census, FarReturnPointerCensusFailure8616.CALL_OUTPUT_UNPROVEN,
                normalized=True, classified_count=len(proofs),
            )
        proof = prove_far_return_pointer_use_8616(artifact, fact.callsite_addr, definitions)
        if not proof.complete:
            return _refuse_8616(
                census, FarReturnPointerCensusFailure8616.PROOF_UNPROVEN,
                normalized=True, classified_count=len(proofs),
            )
        proofs.append(proof)
    return join_far_return_pointer_census_8616(census, tuple(proofs))
