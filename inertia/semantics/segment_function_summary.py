"""Join function-local segment facts with typed control-transfer evidence.

Layer: function summaries.
Responsibility: own interprocedural segment requirements and effects after IR has
established local facts. Never infer aliases, types, C repairs, or memory models.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, cast

from inertia.ir.segment_contract import SegmentFactVerdict, SegmentFunctionContract
from inertia.lowering.analysis_helpers import CallTargetKind8616, CallTargetSeed, collect_neighbor_call_targets

if TYPE_CHECKING:
    from inertia.frontend.x86_16.declared_external_call_evidence import DeclaredCallEffectConsumption8616

__all__ = [
    "SegmentCalleeEffectFact8616", "SegmentControlTransferDistance8616",
    "SegmentControlTransferFact8616", "SegmentControlTransferKind8616",
    "SegmentFunctionSummary8616", "apply_x86_16_segment_function_summary",
    "build_x86_16_segment_control_transfers", "join_x86_16_segment_function_summaries",
]

_CALL_KINDS = frozenset({
    CallTargetKind8616.CFG_RESOLVED_CALL, CallTargetKind8616.DIRECT_NEAR_CALL,
    CallTargetKind8616.DIRECT_FAR_CALL, CallTargetKind8616.STORED_NEAR_CALL,
})
class _FunctionSurface8616(Protocol):
    """Dynamic angr function fields used at the frontend-summary boundary."""

    addr: int

    def get_call_sites(self) -> Iterable[int]:
        """Return machine addresses for calls represented in the CFG."""
        ...


class _FunctionManagerSurface8616(Protocol):
    """Dynamic angr function-manager lookup used by the summary attachment."""

    def function(self, *, addr: int, create: bool) -> object | None:
        """Return the function at an exact address when present."""
        ...


class _CodegenBoundary8616(Protocol):
    """Owned segment contracts carried across the dynamic angr codegen boundary."""

    _inertia_segment_function_contract: SegmentFunctionContract
    _inertia_segment_function_summary_8616: SegmentFunctionSummary8616
    _inertia_segment_state_artifact: object


class _ProjectBoundary8616(Protocol):
    """Project registry for incrementally recovered segment summaries."""

    _inertia_segment_local_contracts_8616: dict[int, SegmentFunctionContract]
    _inertia_segment_transfer_facts_8616: dict[int, tuple[SegmentControlTransferFact8616, ...]]
    _inertia_segment_function_summaries_8616: dict[int, SegmentFunctionSummary8616]


class SegmentControlTransferKind8616(StrEnum):
    """Architectural operation performed by one inter-function transfer."""

    CALL = "call"
    TAIL_JUMP = "tail_jump"


class SegmentControlTransferDistance8616(StrEnum):
    """Proven near/far distance, or an explicit refusal when unknown."""

    NEAR = "near"
    FAR = "far"
    UNKNOWN = "unknown"


_DISTANCE_BY_KIND = {
    CallTargetKind8616.DIRECT_NEAR_CALL: SegmentControlTransferDistance8616.NEAR,
    CallTargetKind8616.STORED_NEAR_CALL: SegmentControlTransferDistance8616.NEAR,
    CallTargetKind8616.DIRECT_NEAR_TAIL_JUMP: SegmentControlTransferDistance8616.NEAR,
    CallTargetKind8616.STORED_NEAR_TAIL_JUMP: SegmentControlTransferDistance8616.NEAR,
    CallTargetKind8616.DIRECT_FAR_CALL: SegmentControlTransferDistance8616.FAR,
    CallTargetKind8616.DIRECT_FAR_TAIL_JUMP: SegmentControlTransferDistance8616.FAR,
}


@dataclass(frozen=True, slots=True)
class SegmentControlTransferFact8616:
    """Typed target and architectural distance for one control transfer."""

    instruction_addr: int
    kind: SegmentControlTransferKind8616
    distance: SegmentControlTransferDistance8616
    target_addr: int | None
    return_addr: int | None
    verdict: SegmentFactVerdict

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "instruction_addr": self.instruction_addr,
            "kind": self.kind.value,
            "distance": self.distance.value,
            "target_addr": self.target_addr,
            "return_addr": self.return_addr,
            "verdict": self.verdict.value,
        }


@dataclass(frozen=True, slots=True)
class SegmentCalleeEffectFact8616:
    """Known clobber floor and completeness verdict for one callee edge."""

    instruction_addr: int
    target_addr: int | None
    clobbered_registers: tuple[str, ...]
    verdict: SegmentFactVerdict

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "instruction_addr": self.instruction_addr,
            "target_addr": self.target_addr,
            "clobbered_registers": list(self.clobbered_registers),
            "verdict": self.verdict.value,
        }


@dataclass(frozen=True, slots=True)
class SegmentFunctionSummary8616:
    """Function-local contract plus transitive, conservative callee effects."""

    function_addr: int
    local_contract: SegmentFunctionContract
    control_transfers: tuple[SegmentControlTransferFact8616, ...] = ()
    callee_effects: tuple[SegmentCalleeEffectFact8616, ...] = ()
    effective_clobbered_registers: tuple[str, ...] = ()
    unresolved_effect_sites: tuple[int, ...] = ()
    summary: dict[str, int] = field(default_factory=dict)
    local_effects_complete: bool = False
    declared_call_consumptions: tuple[DeclaredCallEffectConsumption8616, ...] = ()

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-friendly representation."""
        return {
            "function_addr": self.function_addr,
            "local_contract": self.local_contract.to_dict(),
            "control_transfers": [fact.to_dict() for fact in self.control_transfers],
            "callee_effects": [fact.to_dict() for fact in self.callee_effects],
            "effective_clobbered_registers": list(self.effective_clobbered_registers),
            "unresolved_effect_sites": list(self.unresolved_effect_sites),
            "declared_call_consumptions": [
                consumption.to_record() for consumption in self.declared_call_consumptions
            ],
            "summary": dict(self.summary),
            "local_effects_complete": self.local_effects_complete,
        }


def _callsite_addrs(function: object) -> tuple[int, ...]:
    """Read exact CFG callsites at the dynamic angr function boundary."""
    try:
        raw = cast(_FunctionSurface8616, function).get_call_sites()
    except (AttributeError, TypeError):
        return ()
    return tuple(sorted({addr for addr in raw if isinstance(addr, int)}))


def _transfer_from_seed(seed: CallTargetSeed) -> SegmentControlTransferFact8616:
    """Normalize one typed frontend seed into a segment-summary transfer."""
    kind = (
        SegmentControlTransferKind8616.CALL
        if seed.kind in _CALL_KINDS
        else SegmentControlTransferKind8616.TAIL_JUMP
    )
    distance = _DISTANCE_BY_KIND.get(seed.kind, SegmentControlTransferDistance8616.UNKNOWN)
    verdict = (
        SegmentFactVerdict.PROVEN
        if distance is not SegmentControlTransferDistance8616.UNKNOWN
        else SegmentFactVerdict.UNKNOWN_REFUSE
    )
    return SegmentControlTransferFact8616(
        instruction_addr=seed.callsite_addr,
        kind=kind,
        distance=distance,
        target_addr=seed.target_addr,
        return_addr=seed.return_addr,
        verdict=verdict,
    )


def build_x86_16_segment_control_transfers(function: object) -> tuple[SegmentControlTransferFact8616, ...]:
    """Collect resolved near/far transfers and retain unresolved CFG calls."""
    seeds = tuple(collect_neighbor_call_targets(function))
    callsites = _callsite_addrs(function)
    seed_callsites = {seed.callsite_addr for seed in seeds if seed.kind in _CALL_KINDS}
    unresolved = tuple(
        SegmentControlTransferFact8616(
            instruction_addr=addr,
            kind=SegmentControlTransferKind8616.CALL,
            distance=SegmentControlTransferDistance8616.UNKNOWN,
            target_addr=None,
            return_addr=None,
            verdict=SegmentFactVerdict.UNKNOWN_REFUSE,
        )
        for addr in callsites
        if addr not in seed_callsites
    )
    return tuple(sorted((*(_transfer_from_seed(seed) for seed in seeds), *unresolved), key=lambda fact: fact.instruction_addr))


def _local_effect_census_complete_8616(
    contract: SegmentFunctionContract,
    facts: tuple[SegmentControlTransferFact8616, ...],
) -> bool:
    """Require complete local effects and an exact nonduplicated call census."""
    proof = contract.effect_closure
    if not contract.effects_complete or proof is None:
        return False
    sites = tuple(sorted(fact.instruction_addr for fact in facts))
    return bool(
        sites == proof.callsite_addrs
        and len(set(sites)) == len(sites)
        and all(fact.kind is SegmentControlTransferKind8616.CALL for fact in facts)
    )


def _unknown_effect_functions(
    contracts: Mapping[int, SegmentFunctionContract],
    transfers: Mapping[int, tuple[SegmentControlTransferFact8616, ...]],
) -> set[int]:
    """Find functions whose transitive callee effects are incomplete."""
    unknown = {
        addr for addr, contract in contracts.items()
        if not _local_effect_census_complete_8616(contract, transfers.get(addr, ()))
    }
    unknown.update({
        function_addr
        for function_addr, facts in transfers.items()
        if any(
            fact.verdict is not SegmentFactVerdict.PROVEN
            or fact.target_addr not in contracts
            or not _effect_projects_match_8616(contracts.get(function_addr), contracts.get(cast(int, fact.target_addr)))
            for fact in facts
        )
    })
    changed = True
    while changed:
        changed = False
        for function_addr, facts in transfers.items():
            if function_addr in unknown:
                continue
            if any(fact.target_addr in unknown for fact in facts):
                unknown.add(function_addr)
                changed = True
    return unknown


def _effect_projects_match_8616(
    caller: SegmentFunctionContract | None,
    callee: SegmentFunctionContract | None,
) -> bool:
    """Forbid borrowing a target body's effects from another project."""
    if caller is None or callee is None:
        return False
    caller_proof, callee_proof = caller.effect_closure, callee.effect_closure
    return bool(
        caller_proof is not None and callee_proof is not None
        and caller_proof.coverage.boundary.project is callee_proof.coverage.boundary.project
    )


def _effective_clobbers(
    contracts: Mapping[int, SegmentFunctionContract],
    transfers: Mapping[int, tuple[SegmentControlTransferFact8616, ...]],
) -> dict[int, set[str]]:
    """Reach a deterministic fixed point for known transitive clobbers."""
    effective = {addr: set(contract.clobbered_registers) for addr, contract in contracts.items()}
    changed = True
    while changed:
        changed = False
        for function_addr, facts in transfers.items():
            current = effective.setdefault(function_addr, set())
            before = len(current)
            for fact in facts:
                if fact.target_addr in effective:
                    current.update(effective[fact.target_addr])
            changed = changed or len(current) != before
    return effective


def join_x86_16_segment_function_summaries(
    contracts: Mapping[int, SegmentFunctionContract],
    transfers: Mapping[int, tuple[SegmentControlTransferFact8616, ...]],
) -> dict[int, SegmentFunctionSummary8616]:
    """Join local contracts and callee effects without guessing missing callees."""
    effective = _effective_clobbers(contracts, transfers)
    unknown = _unknown_effect_functions(contracts, transfers)
    summaries: dict[int, SegmentFunctionSummary8616] = {}
    for function_addr in sorted(contracts):
        local = contracts[function_addr]
        function_transfers = transfers.get(function_addr, ())
        local_complete = _local_effect_census_complete_8616(local, function_transfers)
        effects = tuple(
            SegmentCalleeEffectFact8616(
                instruction_addr=fact.instruction_addr,
                target_addr=fact.target_addr,
                clobbered_registers=tuple(sorted(effective.get(cast(int, fact.target_addr), set()))),
                verdict=(
                    SegmentFactVerdict.PROVEN
                    if fact.verdict is SegmentFactVerdict.PROVEN
                    and local_complete
                    and fact.target_addr in contracts
                    and fact.target_addr not in unknown
                    and _effect_projects_match_8616(local, contracts.get(cast(int, fact.target_addr)))
                    else SegmentFactVerdict.UNKNOWN_REFUSE
                ),
            )
            for fact in function_transfers
        )
        local_raw = local.summary.get("raw_fact_count", 0)
        local_classified = local.summary.get("classified_fact_count", 0)
        local_materialized = local.summary.get("materialized_count", 0)
        local_failures = local.summary.get("failure_count", 0)
        transfer_classified = sum(fact.verdict is SegmentFactVerdict.PROVEN for fact in function_transfers)
        effect_classified = sum(fact.verdict is SegmentFactVerdict.PROVEN for fact in effects)
        summaries[function_addr] = SegmentFunctionSummary8616(
            function_addr=function_addr,
            local_contract=local,
            local_effects_complete=local_complete,
            control_transfers=function_transfers,
            callee_effects=effects,
            effective_clobbered_registers=tuple(sorted(effective.get(function_addr, set()))),
            unresolved_effect_sites=tuple(
                fact.instruction_addr for fact in effects if fact.verdict is SegmentFactVerdict.UNKNOWN_REFUSE
            ),
            summary={
                "raw_fact_count": local_raw + len(function_transfers) + len(effects) + 1,
                "normalized_fact_count": local_raw + len(function_transfers) + len(effects) + 1,
                "classified_fact_count": local_classified + transfer_classified + effect_classified + int(local_complete),
                "materialized_count": local_materialized + transfer_classified + effect_classified + int(local_complete),
                "failure_count": local_failures
                + len(function_transfers)
                - transfer_classified
                + len(effects)
                - effect_classified + int(not local_complete),
                "control_transfer_count": len(function_transfers),
                "callee_effect_count": len(effects),
            },
        )
    return summaries


def _function_for_contract(project: object, function_addr: int) -> object | None:
    """Resolve the active angr function for one exact local IR contract."""
    boundary = cast(Any, project)
    try:
        active = boundary._inertia_active_structuring_function_8616
        if cast(_FunctionSurface8616, active).addr == function_addr:
            return cast(object, active)
    except (AttributeError, TypeError):
        pass
    try:
        manager = cast(_FunctionManagerSurface8616, boundary.kb.functions)
        return manager.function(addr=function_addr, create=False)
    except (AttributeError, TypeError):
        return None


def apply_x86_16_segment_function_summary(project: object, codegen: object) -> bool:
    """Attach and register the current typed interprocedural segment summary."""
    codegen_boundary = cast(_CodegenBoundary8616, codegen)
    project_boundary = cast(_ProjectBoundary8616, project)
    try:
        local = codegen_boundary._inertia_segment_function_contract
    except AttributeError:
        return False
    if not isinstance(local, SegmentFunctionContract):
        return False
    proof = local.effect_closure
    if proof is not None and proof.coverage.boundary.project is not project:
        # A codegen-boundary contract may cross process/project boundaries;
        # its diagnostics survive, but in-process effect authorization cannot.
        local = replace(local, effect_closure=None)
    function = _function_for_contract(project, local.function_addr)
    if function is None:
        return False
    transfer_facts = build_x86_16_segment_control_transfers(function)
    try:
        contracts = dict(project_boundary._inertia_segment_local_contracts_8616)
        transfers = dict(project_boundary._inertia_segment_transfer_facts_8616)
    except AttributeError:
        contracts = {}
        transfers = {}
    contracts[local.function_addr] = local
    from .segment_call_preservation_stage import (
        SegmentCallPreservationRequest8616,
        refresh_segment_call_preservation_state_8616,
    )

    requests = tuple(
        SegmentCallPreservationRequest8616(fact.instruction_addr, fact.target_addr)
        for fact in transfer_facts
        if fact.kind is SegmentControlTransferKind8616.CALL
        and fact.distance is SegmentControlTransferDistance8616.NEAR
        and fact.verdict is SegmentFactVerdict.PROVEN
        and type(fact.target_addr) is int
    )
    local = refresh_segment_call_preservation_state_8616(project, codegen, local, contracts, requests)
    contracts[local.function_addr] = local
    transfers[local.function_addr] = transfer_facts
    summaries = join_x86_16_segment_function_summaries(contracts, transfers)
    project_boundary._inertia_segment_local_contracts_8616 = contracts
    project_boundary._inertia_segment_transfer_facts_8616 = transfers
    project_boundary._inertia_segment_function_summaries_8616 = summaries
    summary = summaries[local.function_addr]
    codegen_boundary._inertia_segment_function_summary_8616 = summary
    from inertia.ir.segment_state import republish_declared_call_consumptions_8616

    republish_declared_call_consumptions_8616(project, codegen, local.function_addr)
    return False
