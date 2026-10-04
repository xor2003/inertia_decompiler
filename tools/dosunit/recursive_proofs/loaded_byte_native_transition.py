"""Layer: dosunit initialized-memory native transition proof (staging).

Responsibility: consume closed byte-relation evidence and compare every native
output with candidate memory transformed at input and inverted at output.
Arbitrary-cutpoint SAT is retained; neither it nor local UNSAT grants a binary
verdict, image/lifter binding, caller-domain or physical/fault/environment proof.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

import z3

from tools.dosunit import straightline_ssa as S
from tools.dosunit.flat32_call_contracts import CallCompositionRefusal, _initial_state, _register_widths
from tools.dosunit.proof_contracts import Architecture, FactCounters, ProofStatus
from tools.dosunit.real16_call_contracts import initial_state, materialize_function
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
    propose_loaded_byte_relation,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import (
    LOADED_BYTE_MODEL_HASH,
    ByteRelationObligation,
    LoadedRelationProof,
)
from tools.dosunit.recursive_proofs.real16_entry_domain import (
    EntryDomainReason,
    Real16DomainProof,
    entry_domain_model_hash,
    entry_domain_requirements,
    native_effect_hash,
)
from tools.dosunit.recursive_proofs.recursive_joint_proof import strict_state_document
from tools.dosunit.register_state_relations import MachineState
from tools.dosunit.ssa_output_lemmas import OutputEqualityResult, prove_output_equalities


class LoadedTransitionReason(StrEnum):
    """Modeled transition evidence boundaries, distinct from binary outcomes."""

    DISCHARGED = "loaded_native_full_state_relation_discharged"
    INITIALIZATION = "loaded_native_initial_relation_unclosed"
    MODEL = "loaded_native_model_identity_mismatch"
    STATE = "loaded_native_state_missing_or_width_changed"
    RESOURCE = "loaded_native_term_budget_exhausted"
    CYCLE = "loaded_native_term_cycle"
    DEADLINE = "loaded_native_original_deadline_exhausted"
    LOWERING = "loaded_native_lowering_refusal"
    OUTPUTS = "loaded_native_output_manifest_incomplete"
    COUNTERMODEL = "loaded_native_arbitrary_cutpoint_countermodel"
    UNKNOWN = "loaded_native_solver_unknown"
    DOMAIN = "loaded_native_derived_domain_unclosed"


class _TransitionRefusal(Exception):
    """Internal named boundary; unanticipated defects keep their exceptions."""

    def __init__(self, reason: LoadedTransitionReason, detail: str) -> None:
        """Preserve the original diagnostic and typed missing obligation."""
        self.reason = reason
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True, slots=True)
class LoadedTransitionResult:
    """Full modeled output evidence on arbitrary related cutpoint states."""

    status: ProofStatus
    reason: LoadedTransitionReason
    initialized: LoadedRelationProof
    required_outputs: tuple[str, ...]
    counters: FactCounters
    solver: OutputEqualityResult | None = None
    detail: str = ""
    domain: Real16DomainProof | None = None

    @property
    def binary_equivalence_proved(self) -> bool:
        """Image binding, reachable domains and physical outcomes remain unclosed."""
        return False


@dataclass(slots=True)
class _TransitionRun:
    """One deadline and cumulative unique-node guard before recursive boundaries."""

    initialized: LoadedRelationProof
    limits: LoadedRelationLimits
    remaining_nodes: int
    max_depth: int
    required: tuple[str, ...] = ()
    domain: Real16DomainProof | None = None

    def guard(self, state: MachineState) -> None:
        """Bound DAG size/depth and cycles before legacy materialization/composition."""
        memo: dict[int, int] = {}
        active: set[int] = set()
        pending: list[tuple[dict[str, Any], tuple[dict[str, Any], ...] | None]] = [
            (term, None) for term in state.values()]
        while pending:
            self.limits.check_time()
            node, children = pending.pop()
            key = id(node)
            if key in memo:
                continue
            if children is not None:
                height = 1 + max((memo[id(child)] for child in children), default=0)
                if height > self.max_depth:
                    raise _TransitionRefusal(LoadedTransitionReason.RESOURCE, "native term depth exceeds materialization bound")
                memo[key] = height
                active.remove(key)
                continue
            if key in active:
                raise _TransitionRefusal(LoadedTransitionReason.CYCLE, "cyclic native effect term")
            if self.remaining_nodes <= 0:
                raise _TransitionRefusal(LoadedTransitionReason.RESOURCE, "cumulative native term budget exhausted")
            self.remaining_nodes -= 1
            if not isinstance(node, dict):
                raise _TransitionRefusal(LoadedTransitionReason.STATE, "native output or operand is not a term")
            args = node.get("args", [])
            if not isinstance(args, list) or any(not isinstance(child, dict) for child in args):
                raise _TransitionRefusal(LoadedTransitionReason.STATE, "native term operands are malformed")
            children = tuple(args)
            active.add(key)
            pending.append((node, children))
            pending.extend((child, None) for child in reversed(children))

    def report(self, status: ProofStatus, reason: LoadedTransitionReason, *,
               solver: OutputEqualityResult | None = None, detail: str = "") -> LoadedTransitionResult:
        """Retain classified outputs on every refusal or failed complete comparison."""
        count = len(self.required)
        materialized = count if solver is not None else int(count > 0)
        counters = FactCounters(count, count, count, materialized, int(status is not ProofStatus.PROVED))
        return LoadedTransitionResult(status, reason, self.initialized, self.required, counters, solver, detail, self.domain)


def _consume_initialized(run: _TransitionRun) -> Architecture:
    """Reject incomplete/stale premises and rebind every declared loaded byte."""
    proof = run.initialized
    if proof.model_hash != LOADED_BYTE_MODEL_HASH or any(f.model_hash != proof.model_hash for f in proof.facts):
        raise _TransitionRefusal(LoadedTransitionReason.MODEL, "initial algebra model identity changed")
    kinds = tuple(fact.obligation for fact in proof.facts)
    expected = set(ByteRelationObligation)
    complete = len(kinds) == len(expected) and set(kinds) == expected
    counters = FactCounters(len(expected), len(expected), len(expected), len(expected), 0)
    if (not complete or proof.status is not ProofStatus.PROVED or proof.counters != counters
            or proof.reason is not LoadedRelationReason.DISCHARGED):
        raise _TransitionRefusal(LoadedTransitionReason.INITIALIZATION, "initial relation evidence is not complete")
    if any(fact.status is not ProofStatus.PROVED for fact in proof.facts):
        raise _TransitionRefusal(LoadedTransitionReason.INITIALIZATION, "an initial relation premise is unproved")
    rebound = propose_loaded_byte_relation(proof.proposal.original, proof.proposal.candidate, limits=run.limits)
    if rebound != proof.proposal:
        raise _TransitionRefusal(LoadedTransitionReason.INITIALIZATION, "initial relation mask/snapshot binding changed")
    return proof.proposal.original.architecture


def _native_initial(architecture: Architecture) -> MachineState:
    """Derive the complete active architecture contract rather than a projection."""
    if architecture is Architecture.REAL16:
        state = initial_state()
        if state.get("control_ip", {}).get("width") != 32 or state.get("sp", {}).get("width") != 16:
            raise _TransitionRefusal(LoadedTransitionReason.MODEL, "active native real16 register table differs")
        return state
    state = _initial_state(_register_widths())
    state["ip"] = {"op": "input", "width": 32, "name": "ip"}
    return state


def _check_states(initial: MachineState, original: MachineState, candidate: MachineState) -> None:
    """Require every scalar/control/array output with its authoritative width."""
    for state in (original, candidate):
        if set(state) != set(initial):
            raise _TransitionRefusal(LoadedTransitionReason.STATE, "native full output manifest changed")
        for name, expected in initial.items():
            if not isinstance(state[name], dict):
                raise _TransitionRefusal(LoadedTransitionReason.STATE, "native output is not a term")
            if name not in {"memory", "io"} and state[name].get("width") != expected["width"]:
                raise _TransitionRefusal(LoadedTransitionReason.STATE, f"native output width changed: {name}")


def _consume_domain(run: _TransitionRun, original: MachineState, candidate: MachineState) -> None:
    """Accept only complete image/effect/model-bound native domain evidence."""
    proof = run.domain
    if proof is None:
        return
    if not proof.effects or len(proof.effects) > 4096:
        raise _TransitionRefusal(LoadedTransitionReason.DOMAIN, "derived domain effect manifest missing or oversized")
    required = entry_domain_requirements(len(proof.effects))
    ids = tuple((fact.obligation, fact.key) for fact in proof.facts)
    count = len(required)
    manifest_complete = len(ids) == count and set(ids) == set(required)
    if (proof.status is not ProofStatus.PROVED or proof.reason is not EntryDomainReason.DISCHARGED
            or not manifest_complete
            or any(fact.status is not ProofStatus.PROVED for fact in proof.facts)
            or proof.counters != FactCounters(count, count, count, count, 0)):
        raise _TransitionRefusal(LoadedTransitionReason.DOMAIN, "derived scalar invariant premises are incomplete")
    if proof.model_hash != entry_domain_model_hash():
        raise _TransitionRefusal(LoadedTransitionReason.MODEL, "derived scalar invariant model changed")
    proposal = run.initialized.proposal
    snapshots = (proposal.original.sparse_byte_sha256, proposal.candidate.sparse_byte_sha256)
    if proposal.original.architecture is not Architecture.REAL16 or proof.snapshot_hashes != snapshots:
        raise _TransitionRefusal(LoadedTransitionReason.DOMAIN, "derived invariant initialized image binding changed")
    if (native_effect_hash(original), native_effect_hash(candidate)) not in proof.effects:
        raise _TransitionRefusal(LoadedTransitionReason.DOMAIN, "native effects not in derived invariant manifest")


def _compare(run: _TransitionRun, original: MachineState, candidate: MachineState) -> OutputEqualityResult:
    """Compare all named native outputs after bijective IP-label transport only."""
    a, b = strict_state_document("loaded-native-original", original), strict_state_document("loaded-native-candidate", candidate)
    run.limits.check_time()
    inputs = S._z3_inputs(a, b, z3)
    names = sorted(a["outputs"])
    pairs, skipped = S._z3_output_pairs(names, oracle=a, candidate=b, oracle_outputs=a["outputs"],
                                      candidate_outputs=b["outputs"], inputs=inputs, z3=z3, simplify_terms=False)
    if skipped or len(pairs) != len(run.required) or {name for name, _, _ in pairs} != set(names):
        raise _TransitionRefusal(LoadedTransitionReason.OUTPUTS, "native outputs were omitted before comparison")
    run.limits.check_time()
    solver = z3.Solver()
    if run.domain is not None:
        native_inputs = {name: value[0] for name, value in inputs.items()}
        solver.add(run.domain.domain.predicate(native_inputs))
    return prove_output_equalities(pairs, solver, deadline=run.limits.deadline)


def check_loaded_native_transition(original: MachineState, candidate: MachineState,
                                    initialized: LoadedRelationProof, *, timeout_ms: int = 10000,
                                    limits: LoadedRelationLimits | None = None,
                                    max_term_nodes: int = 262144, max_term_depth: int = 128,
                                    domain: Real16DomainProof | None = None) -> LoadedTransitionResult:
    """Check complete native effects under the proved full-array initialization relation.

    Default comparisons have no caller, alias, fault or memory-value constraint.
    Optional real16 domain evidence must independently discharge loader/native
    initiation, every scalar preservation and global stack geometry; it is bound
    to these exact effects and initialized images. Local countermodels retain
    their declared cutpoint scope. The admitted
    relation's candidate input memory is R(M), and candidate output memory is
    inverted by R before comparing every register/control/flag/array output.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("native relation timeout must be a nonnegative integer")
    if type(max_term_nodes) is not int or max_term_nodes <= 0:
        raise ValueError("native term node allowance must be positive")
    if type(max_term_depth) is not int or not 0 < max_term_depth <= 128:
        raise ValueError("native term depth must fit the bounded legacy materializer")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    run = _TransitionRun(initialized, replace(selected, deadline=deadline), max_term_nodes, max_term_depth)
    run.domain = domain
    try:
        initial = _native_initial(_consume_initialized(run))
        run.required = tuple(sorted(initial))
        _check_states(initial, original, candidate)
        run.guard(original)
        run.guard(candidate)
        _consume_domain(run, original, candidate)
        related_inputs = dict(initial)
        related_inputs["memory"] = initialized.proposal.relation.apply(initial["memory"], limits=run.limits)
        run.guard(related_inputs)
        document = materialize_function("loaded-native-effect", candidate)
        transformed = S._compose_block_outputs(document, document["outputs"], related_inputs,
                                                compose_stats={"deadline": deadline})
        transformed["memory"] = initialized.proposal.relation.apply(transformed["memory"], limits=run.limits)
        run.guard(transformed)
        checked = _compare(run, original, transformed)
        run.limits.check_time()
        if run.domain is not None and run.domain.model_hash != entry_domain_model_hash():
            raise _TransitionRefusal(LoadedTransitionReason.MODEL, "derived invariant model changed during comparison")
        reasons = {ProofStatus.PROVED: LoadedTransitionReason.DISCHARGED,
                   ProofStatus.COUNTEREXAMPLE: LoadedTransitionReason.COUNTERMODEL}
        return run.report(checked.status, reasons.get(checked.status, LoadedTransitionReason.UNKNOWN),
                           solver=checked, detail=checked.detail)
    except _TransitionRefusal as refusal:
        return run.report(ProofStatus.UNKNOWN, refusal.reason, detail=refusal.detail)
    except LoadedRelationRefusal as refusal:
        refusal_reasons = {LoadedRelationReason.DEADLINE: LoadedTransitionReason.DEADLINE,
                           LoadedRelationReason.LIMIT: LoadedTransitionReason.RESOURCE}
        return run.report(ProofStatus.UNKNOWN, refusal_reasons.get(refusal.reason, LoadedTransitionReason.INITIALIZATION),
                           detail=f"{refusal.reason.value}: {refusal.detail}")
    except CallCompositionRefusal as refusal:
        return run.report(ProofStatus.UNKNOWN, LoadedTransitionReason.MODEL, detail=str(refusal))
    except S.LowerFailure as refusal:
        reason = LoadedTransitionReason.DEADLINE if refusal.reason == "compose_budget_exceeded" else LoadedTransitionReason.LOWERING
        return run.report(ProofStatus.UNKNOWN, reason, detail=f"{refusal.reason}: {refusal.message}")
