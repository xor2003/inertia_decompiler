"""Layer: dosunit loader/bootstrap-derived recursive domain proof (staging).

Responsibility: prove initiation, nonvacuity, all scalar preservation and full
aligned stack geometry from immutable MZ load receipts and native SSA effects.
No caller, code-disjointness or segment separation proposal is assumed proved.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, replace
from typing import cast

import z3

from tools.dosunit import straightline_ssa as S
from tools.dosunit.proof_contracts import Architecture, FactCounters, ProofStatus
from tools.dosunit.real16_call_contracts import materialize_function
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load, ImageBindingRefusal
from tools.dosunit.recursive_proofs.loaded_byte_native_transition import (
    _check_states,
    _consume_initialized,
    _native_initial,
    _TransitionRefusal,
    _TransitionRun,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import LoadedRelationProof
from tools.dosunit.recursive_proofs.real16_entry_domain import (
    EntryDomainFact,
    EntryDomainObligation,
    EntryDomainReason,
    Real16DomainProof,
    Real16ScalarDomain,
    entry_domain_model_hash,
    entry_domain_requirements,
    native_effect_hash,
)
from tools.dosunit.recursive_proofs.stack.recursive_stack_proofs import _state_exprs
from tools.dosunit.register_state_relations import MachineState


@dataclass(slots=True)
class _DomainRun:
    """One original budget, complete required keys and retained local models."""

    loads: tuple[BoundReal16Load, BoundReal16Load]
    initialized: LoadedRelationProof
    bootstrap: tuple[MachineState, MachineState]
    effects: tuple[tuple[MachineState, MachineState], ...]
    root: int
    limits: LoadedRelationLimits
    domain: Real16ScalarDomain
    model_hash: str
    required: tuple[tuple[EntryDomainObligation, str], ...]
    facts: list[EntryDomainFact] = field(default_factory=list)
    hashes: tuple[tuple[str, str], ...] = ()

    def check(self, kind: EntryDomainObligation, key: str, equation: z3.BoolRef,
              *, witness: bool = False) -> bool:
        """Check unrestricted implication or domain nonemptiness within one deadline."""
        self.limits.check_time()
        remaining = int((self.limits.deadline - time.monotonic()) * 1000)
        if remaining <= 0:
            raise LoadedRelationRefusal(LoadedRelationReason.DEADLINE, "entry domain original deadline exhausted")
        solver = z3.Solver()
        solver.set(timeout=remaining)
        solver.add(equation if witness else z3.Not(equation))
        outcome = solver.check()
        self.limits.check_time()
        expected = z3.sat if witness else z3.unsat
        status = ProofStatus.PROVED if outcome == expected else ProofStatus.UNKNOWN
        detail = solver.reason_unknown() if outcome == z3.unknown else ""
        if outcome == z3.sat and not witness:
            status, detail = ProofStatus.COUNTEREXAMPLE, str(solver.model())
        self.facts.append(EntryDomainFact(kind, key, status, detail))
        return status is ProofStatus.PROVED

    def report(self, reason: EntryDomainReason, detail: str = "") -> Real16DomainProof:
        """Missing/duplicate/unproved facts retain a non-result and exact counters."""
        ids = tuple((fact.obligation, fact.key) for fact in self.facts)
        failed = sum(fact.status is not ProofStatus.PROVED for fact in self.facts)
        failed += len(set(self.required) - set(ids)) + len(ids) - len(set(ids))
        failed += len(set(ids) - set(self.required))
        proved = failed == 0 and set(ids) == set(self.required) and reason is EntryDomainReason.DISCHARGED
        status = ProofStatus.PROVED if proved else ProofStatus.UNKNOWN
        if reason is EntryDomainReason.DISCHARGED and not proved:
            reason = EntryDomainReason.MANIFEST
        count = len(self.required)
        counters = FactCounters(count, count, count, len(self.facts), failed)
        a, b = self.loads
        snapshots = (a.binding.snapshot.sparse_byte_sha256, b.binding.snapshot.sparse_byte_sha256)
        return Real16DomainProof(status, reason, self.domain, a.binding.file_sha256, b.binding.file_sha256, snapshots,
                                 self.model_hash, self.root, self.hashes, tuple(self.facts), counters, detail)


def _registers(load: BoundReal16Load) -> dict[str, int]:
    """Read actual reconstructed MZ entry fields without permitting missing duplicates."""
    rows = load.binding.entry_registers
    result = dict(rows)
    if len(rows) != 4 or set(result) != {"cs", "ip", "ss", "sp"}:
        raise ValueError("verified MZ load lacks complete native entry registers")
    return result


def propose_entry_scalar_domain(load: BoundReal16Load) -> Real16ScalarDomain:
    """Own the selector/even-pointer proposal derived from this MZ entry.

    Construction grants no proof. Both producer and receipt consumer use this
    exact recipe so cached facts cannot transfer to a changed scalar contract.
    """
    registers = _registers(load)
    return Real16ScalarDomain(registers["ss"], registers["cs"])


def _binding(run: _DomainRun, guard: _TransitionRun) -> MachineState | None:
    """Verify loader/initialization identity and bound every exact native effect."""
    if _consume_initialized(guard) is not Architecture.REAL16:
        return None
    for load in run.loads:
        load.verify(limits=run.limits)
    a, b = run.loads
    if (run.initialized.proposal.original != a.binding.snapshot
            or run.initialized.proposal.candidate != b.binding.snapshot
            or _registers(a) != _registers(b) or not run.effects):
        return None
    if not all(any(start <= run.root < start + len(data) for start, data in load.binding.snapshot.chunks)
               for load in run.loads):
        return None
    initial = _native_initial(Architecture.REAL16)
    for pair in (run.bootstrap, *run.effects):
        _check_states(initial, *pair)
        for state in pair:
            guard.guard(state)
    run.hashes = tuple((native_effect_hash(a), native_effect_hash(b)) for a, b in run.effects)
    run.facts.append(EntryDomainFact(EntryDomainObligation.BINDING, "binding", ProofStatus.PROVED))
    return initial


def _initiate(run: _DomainRun, initial: MachineState) -> bool:
    """Derive root scalar facts and exact root control from real bootstrap effects."""
    input_document = materialize_function("entry:inputs", initial)
    for index, state in enumerate(run.bootstrap):
        entry = dict(initial)
        for name, value in _registers(run.loads[index]).items():
            if name != "ip":
                entry[name] = {"op": "const", "width": 16, "value": hex(value)}
        entry["control_ip"] = {"op": "const", "width": 32, "value": hex(run.loads[index].binding.entry)}
        document = materialize_function("entry:bootstrap", state)
        composed = S._compose_block_outputs(document, document["outputs"], entry,
                                            compose_stats={"deadline": run.limits.deadline})
        inputs = S._z3_inputs(input_document, materialize_function("entry:post", composed), z3)
        post = _state_exprs(composed, inputs)
        equation = cast(z3.BoolRef, z3.And(run.domain.predicate(post), post["control_ip"] == run.root))
        if not run.check(EntryDomainObligation.INITIATION, ("original", "candidate")[index], equation):
            return False
    return True


def _geometry(run: _DomainRun) -> EntryDomainReason | None:
    """Discharge alias/A20/straddle facts for every aligned architectural offset."""
    offset = z3.BitVec("entry_domain_arbitrary_stack_offset", 16)
    aligned = (offset & (run.domain.alignment - 1)) == 0
    first = z3.BitVecVal(run.domain.ss << 4, 32) + z3.ZeroExt(16, offset)
    conditions = [z3.Or(z3.ULT(first + byte, start), z3.UGE(first + byte, start + len(data)))
                  for load in run.loads for start, data in load.binding.snapshot.chunks for byte in range(2)]
    if not run.check(EntryDomainObligation.DISJOINT, "all_stack_bytes", z3.Implies(aligned, z3.And(*conditions))):
        return EntryDomainReason.ALIAS
    normal = z3.And(z3.ULE(offset, 0xFFFE), z3.ULT(first + 1, 0x100000))
    if not run.check(EntryDomainObligation.ADDRESS, "all_stack_words", z3.Implies(aligned, normal)):
        return EntryDomainReason.ADDRESS
    return None


def _preserve(run: _DomainRun, initial: MachineState) -> bool:
    """Prove both sides' native effects preserve the entire scalar invariant."""
    before = materialize_function("entry:inputs", initial)
    for index, pair in enumerate(run.effects):
        for side, state in zip(("original", "candidate"), pair, strict=True):
            after = materialize_function("entry:native", state)
            inputs = S._z3_inputs(before, after, z3)
            premise = run.domain.predicate(_state_exprs(initial, inputs))
            conclusion = run.domain.predicate(_state_exprs(state, inputs))
            if not run.check(EntryDomainObligation.PRESERVATION, f"{index}:{side}",
                             z3.Implies(premise, conclusion)):
                return False
    return True


def _discharge(run: _DomainRun, guard: _TransitionRun) -> Real16DomainProof:
    """Check each independently required stage without skipping failed premises."""
    initial = _binding(run, guard)
    if initial is None:
        return run.report(EntryDomainReason.IMAGE)
    witness = {name: z3.BitVec(name, 16) for name in ("ss", "cs", "sp")}
    if not run.check(EntryDomainObligation.NONVACUITY, "domain", run.domain.predicate(witness), witness=True):
        return run.report(EntryDomainReason.UNKNOWN)
    if not _initiate(run, initial):
        return run.report(EntryDomainReason.ENTRY)
    reason = _geometry(run)
    if reason is not None:
        return run.report(reason)
    if not _preserve(run, initial):
        return run.report(EntryDomainReason.PRESERVATION)
    if entry_domain_model_hash() != run.model_hash:
        return run.report(EntryDomainReason.MODEL)
    return run.report(EntryDomainReason.DISCHARGED)


def prove_real16_entry_domain(loads: tuple[BoundReal16Load, BoundReal16Load], initialized: LoadedRelationProof,
                              bootstrap: tuple[MachineState, MachineState],
                              effects: tuple[tuple[MachineState, MachineState], ...], root_address: int,
                              *, timeout_ms: int = 15000,
                              limits: LoadedRelationLimits | None = None) -> Real16DomainProof:
    """Derive the exact selector/even-stack invariant, not a recursive verdict.

    Initiation starts with reconstructed MZ entry fields; scalar preservation
    covers every supplied native pair. Physical stack geometry is universally
    checked, not inferred from SS/CS names. Complete component dispatch, caller
    frames, instruction faults and external events remain separate obligations.
    """
    if type(root_address) is not int or not 0 <= root_address < 0x100000:
        raise ValueError("root requires a normal real-mode physical coordinate")
    if type(timeout_ms) is not int or timeout_ms < 0:
        raise ValueError("entry-domain timeout requires a nonnegative integer")
    selected = limits if limits is not None else LoadedRelationLimits()
    deadline = time.monotonic() + timeout_ms / 1000
    if selected.deadline >= 0:
        deadline = min(deadline, selected.deadline)
    domain = propose_entry_scalar_domain(loads[0])
    run = _DomainRun(loads, initialized, bootstrap, effects, root_address, replace(selected, deadline=deadline),
                     domain, entry_domain_model_hash(), entry_domain_requirements(len(effects)))
    guard = _TransitionRun(initialized, run.limits, 262144, 128)
    try:
        return _discharge(run, guard)
    except LoadedRelationRefusal as refusal:
        reason = EntryDomainReason.DEADLINE if refusal.reason is LoadedRelationReason.DEADLINE else EntryDomainReason.IMAGE
        return run.report(reason, refusal.detail)
    except ImageBindingRefusal as refusal:
        return run.report(EntryDomainReason.IMAGE, refusal.detail)
    except _TransitionRefusal as refusal:
        return run.report(EntryDomainReason.MANIFEST, refusal.detail)
    except S.LowerFailure as refusal:
        reason = EntryDomainReason.DEADLINE if refusal.reason == "compose_budget_exceeded" else EntryDomainReason.UNKNOWN
        return run.report(reason, f"{refusal.reason}: {refusal.message}")
