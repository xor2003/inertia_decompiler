"""Layer: dosunit native operand-segment scope proof (staging).

Responsibility: independently bind decoded logical coordinates to every native
byte address and prove the original operand fits its architectural segment.
File/domain initiation, physical permissions, faults and events remain separate.
"""
from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

import capstone
import z3

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.real16_call_contracts import initial_state, materialize_function
from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.contracts.register_state_relations import MachineState
from tools.dosunit.recursive_proofs.real16_entry_domain import Real16ScalarDomain
from tools.dosunit.recursive_proofs.real16_native_effect_binding import native_binding_model_hash
from tools.dosunit.recursive_proofs.real16_operand_access import (
    NativeOperandReport,
    OperandAccessFact,
    collect_native_operand_accesses,
)
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import _state_exprs


class OperandProofKind(StrEnum):
    """The complete independent evidence graph for original operand scope."""

    SOURCE = "fresh_decoded_operand_manifest"
    WITNESS = "operand_scope_input_domain_nonempty"
    BINDING = "logical_coordinate_equals_native_byte_address"
    SCOPE = "original_operand_within_segment_limit"
    MODEL = "operand_scope_model_unchanged"


class OperandProofReason(StrEnum):
    """A local scope result, never an executable-equivalence verdict."""

    PROVED = "native_operand_scope_discharged"
    SOURCE = "native_operand_source_manifest_refused"
    VACUOUS = "native_operand_domain_vacuous"
    BINDING = "native_operand_coordinate_countermodel"
    SCOPE = "native_operand_segment_scope_countermodel"
    UNKNOWN = "native_operand_scope_solver_unknown"
    DEADLINE = "native_operand_scope_deadline_exhausted"
    MODEL = "native_operand_scope_model_changed"
    LOWERING = "native_operand_scope_lowering_refused"


@dataclass(frozen=True, slots=True)
class OperandProofFact:
    """One mandatory obligation, retaining SAT/unknown evidence and exact cause."""

    kind: OperandProofKind
    key: str
    status: ProofStatus
    detail: str = ""
    native_result: z3.CheckSatResult | None = None
    deadline_exhausted: bool = False


@dataclass(frozen=True, slots=True)
class NativeOperandScopeProof:
    """Nonvacuous modeled byte/operand scope with all other requirements explicit."""

    status: ProofStatus
    reason: OperandProofReason
    collected: NativeOperandReport
    facts: tuple[OperandProofFact, ...]
    model_hash: str
    counters: FactCounters
    detail: str = ""

    @property
    def binary_equivalence_proved(self) -> bool:
        """Logical scope alone proves neither outcome equivalence nor real DOS allocation."""
        return False


def operand_scope_model_hash() -> str:
    """Seal coordinate collection, scalar interpretation and native lowering tools."""
    stage = Path(__file__).parent
    digest = hashlib.sha256(native_binding_model_hash().encode("ascii"))
    digest.update(capstone.__version__.encode("ascii"))
    for name in (Path(__file__).name, "real16_operand_access.py", "real16_native_memory_access.py", "real16_entry_domain.py",
                 'stack/recursive_stack_proofs.py'):
        digest.update(name.encode("ascii"))
        digest.update((stage / name).read_bytes())
    return digest.hexdigest()


def _document(fact: OperandAccessFact) -> dict[str, Any]:
    """Materialize all proposed and native terms using the same actual SSA storage."""
    if fact.access.address is None:
        raise ValueError("complete operand fact lacks its native physical address")
    requested = {"native": fact.access.address, "offset": fact.operand.offset, "selector": fact.operand.selector}
    state = S._IrsbLowerState(S._initial_reg_versions(), S.SsaExpr("mem_input", 0, name="mem"),
                             S.SsaExpr("mem_input", 0, name="io"))
    result = S._materialize_irsb_outputs(state, requested, max_assignments_per_function=4096)
    if isinstance(result, S.LowerFailure):
        raise result
    outputs, assignments = result
    return {"inputs": S._input_items(S._collect_inputs(tuple(requested.values()))),
            "outputs": outputs, "assignments": assignments}


def _query(condition: z3.BoolRef, kind: OperandProofKind, key: str, deadline: float,
           *, witness: bool = False, proved: set[z3.BoolRef] | None = None) -> OperandProofFact:
    """Reuse exact local theorems only; retain budgets and per-occurrence evidence."""
    remaining = int((deadline - time.monotonic()) * 1000)
    if remaining <= 0:
        raise TimeoutError("original operand scope query deadline exhausted")
    if not witness and proved is not None and condition in proved:
        return OperandProofFact(kind, key, ProofStatus.PROVED, native_result=z3.unsat)
    solver = z3.Solver()
    solver.set(timeout=remaining)
    solver.add(condition if witness else z3.Not(condition))
    outcome = solver.check()
    expected = z3.sat if witness else z3.unsat
    status = ProofStatus.PROVED if outcome == expected else ProofStatus.UNKNOWN
    detail = solver.reason_unknown() if outcome == z3.unknown else ""
    if not witness and outcome == z3.sat:
        status, detail = ProofStatus.COUNTEREXAMPLE, str(solver.model())
    if time.monotonic() >= deadline:
        return OperandProofFact(kind, key, ProofStatus.UNKNOWN,
             f"original operand scope query/model deadline exhausted: {detail}", outcome, True)
    # Keep ASTs alive for exact structural equality, not hash-only identity.
    # Bound retained memory and never share the set across proof invocations.
    if not witness and status is ProofStatus.PROVED and proved is not None and len(proved) < 256:
        proved.add(condition)
    return OperandProofFact(kind, key, status, detail, outcome)


def _coordinate_goals(fact: OperandAccessFact, entry: MachineState, deadline: float,
                       ) -> tuple[z3.BoolRef, z3.BoolRef]:
    """Compare native coordinates and independently retain the unsplit operand limit."""
    document = _document(fact)
    composed = S._compose_block_outputs(document, document["outputs"], entry, compose_stats={"deadline": deadline})
    inputs = S._z3_inputs(materialize_function("operand:entry", entry),
                           materialize_function("operand:coordinates", composed), z3)
    terms = _state_exprs(composed, inputs)
    offset, selector, native = (cast(z3.BitVecRef, terms[name]) for name in ("offset", "selector", "native"))
    lane = offset + z3.BitVecVal(fact.byte_lane, offset.size())
    physical = (z3.ZeroExt(16, selector) << 4) + z3.ZeroExt(32 - lane.size(), lane)
    binding = cast(z3.BoolRef, native == physical)
    scope = z3.ULE(offset, z3.BitVecVal(0x10000 - fact.operand.size, offset.size()))
    return binding, scope


def _prove(report: NativeOperandReport, entry: MachineState, domain: Real16ScalarDomain | None,
            deadline: float, facts: list[OperandProofFact], model: str) -> OperandProofReason:
    """Require source, nonvacuity, every native binding/scope clause and model stability."""
    if not report.complete:
        return OperandProofReason.SOURCE
    facts.append(OperandProofFact(OperandProofKind.SOURCE, "source", ProofStatus.PROVED))
    initial = initial_state()
    if set(entry) != set(initial):
        return OperandProofReason.SOURCE
    document = materialize_function("operand:input_domain", entry)
    inputs = S._z3_inputs(document, document, z3)
    pre = _state_exprs(entry, inputs)
    premise = z3.BoolVal(True) if domain is None else domain.predicate(pre)
    witness = _query(premise, OperandProofKind.WITNESS, "input_domain", deadline, witness=True)
    facts.append(witness)
    if witness.status is not ProofStatus.PROVED:
        if witness.deadline_exhausted:
            return OperandProofReason.DEADLINE
        return OperandProofReason.VACUOUS if witness.native_result == z3.unsat else OperandProofReason.UNKNOWN
    proved: set[z3.BoolRef] = set()
    for fact in report.facts:
        binding, scope = _coordinate_goals(fact, entry, deadline)
        key = f"{fact.access.id.statement}:{fact.access.id.occurrence}"
        for kind, goal, reason in ((OperandProofKind.BINDING, binding, OperandProofReason.BINDING),
                                  (OperandProofKind.SCOPE, scope, OperandProofReason.SCOPE)):
            child = _query(z3.Implies(premise, goal), kind, key, deadline, proved=proved)
            facts.append(child)
            if child.status is not ProofStatus.PROVED:
                if child.deadline_exhausted:
                    return OperandProofReason.DEADLINE
                return reason if child.status is ProofStatus.COUNTEREXAMPLE else OperandProofReason.UNKNOWN
    stable = model == operand_scope_model_hash()
    if time.monotonic() >= deadline:
        raise TimeoutError("original operand scope final model deadline exhausted")
    facts.append(OperandProofFact(OperandProofKind.MODEL, "model", ProofStatus.PROVED if stable else ProofStatus.UNKNOWN))
    return OperandProofReason.PROVED if stable else OperandProofReason.MODEL


def prove_native_operand_scope(data: bytes, address: int, entry: MachineState,
                               domain: Real16ScalarDomain | None, *, timeout_ms: int = 15000,
                               deadline: float | None = None,
                               ) -> NativeOperandScopeProof:
    """Prove actual-byte local operand scope under a declared nonempty input predicate.

    The caller must separately bind these immutable bytes to the executable and
    establish initiation/preservation of its supplied entry/domain. This owner
    grants no first-MiB bounds, permissions, fault/event or program-level proof.
    """
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("operand scope requires a finite nonnegative millisecond budget")
    original_deadline = time.monotonic() + timeout_ms / 1000
    if deadline is not None:
        if type(deadline) not in {float, int} or not math.isfinite(deadline):
            raise ValueError("operand scope requires a finite absolute parent deadline")
        original_deadline = min(original_deadline, deadline)
    deadline = original_deadline
    report = collect_native_operand_accesses(data, address, deadline=deadline)
    facts: list[OperandProofFact] = []
    model, detail = "", ""
    reason = OperandProofReason.SOURCE
    try:
        if time.monotonic() >= deadline:
            raise TimeoutError("original operand scope source deadline exhausted")
        model = operand_scope_model_hash()
        reason = _prove(report, entry, domain, deadline, facts, model)
    except TimeoutError as refusal:
        reason, detail = OperandProofReason.DEADLINE, str(refusal)
    except (S.LowerFailure, RecursionError) as refusal:
        reason, detail = OperandProofReason.LOWERING, str(refusal)
    required = 3 + 2 * len(report.raw.required)
    discharged = sum(fact.status is ProofStatus.PROVED for fact in facts)
    status = ProofStatus.PROVED if reason is OperandProofReason.PROVED and discharged == required else ProofStatus.UNKNOWN
    if any(fact.status is ProofStatus.COUNTEREXAMPLE for fact in facts):
        status = ProofStatus.COUNTEREXAMPLE
    cause = next((fact.detail for fact in reversed(facts) if fact.status is not ProofStatus.PROVED), "")
    return NativeOperandScopeProof(status, reason, report, tuple(facts), model,
           FactCounters(required, required, required, len(facts), required - discharged), detail or cause or report.detail)
