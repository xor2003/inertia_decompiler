"""Consumer orchestration controls; successful stubs provide no semantic proof."""
from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest
import z3
from tools.dosunit.tests.recursive_proof_fixtures.image_bound_inputs import Inputs, make_inputs

import tools.dosunit.reporting.ssa_provenance as ssa_provenance
from tools.dosunit.contracts.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.recursive_proofs import real16_address_model_closure as address_owner
from tools.dosunit.recursive_proofs import real16_bound_operand_scope as bound_operand_owner
from tools.dosunit.recursive_proofs import real16_image_bound_domain_consumer as owner
from tools.dosunit.recursive_proofs import real16_normal_outcome_scope as outcome_owner
from tools.dosunit.recursive_proofs import real16_operand_scope_proof as operand_owner
from tools.dosunit.recursive_proofs import real16_physical_access_bounds as bounds_owner
from tools.dosunit.recursive_proofs.native_model_hash_snapshot import (
    captured_native_model_hash,
    native_model_hash_snapshot,
)
from tools.dosunit.recursive_proofs.real16_image_bound_domain import BoundDomainReason, ImageBoundReal16Domain


def test_operand_query_reuse_preserves_premise_and_occurrence(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exact repeated theorems reuse a solver; weakened premises still get checked."""
    calls = 0
    solver = z3.Solver

    def counted_solver() -> z3.Solver:
        nonlocal calls
        calls += 1
        return solver()

    monkeypatch.setattr(operand_owner.z3, "Solver", counted_solver)
    x = z3.BitVec("query_reuse_offset", 16)
    condition = z3.Implies(x == 8, z3.ULE(x, 10))
    proved: set[z3.BoolRef] = set()
    deadline = time.monotonic() + 10
    for key in ("lane0", "lane1"):
        fact = operand_owner._query(condition, operand_owner.OperandProofKind.SCOPE, key, deadline, proved=proved)
        assert fact.status is ProofStatus.PROVED and fact.key == key
    assert calls == 1
    bad = operand_owner._query(z3.ULE(x, 10), operand_owner.OperandProofKind.SCOPE, "bad", deadline, proved=proved)
    assert bad.status is ProofStatus.COUNTEREXAMPLE and calls == 2
    assert len(proved) == 1
    with pytest.raises(TimeoutError):
        operand_owner._query(condition, operand_owner.OperandProofKind.SCOPE, "expired", 0, proved=proved)
    # A new invocation owns a new set; witness SAT must never reuse UNSAT.
    operand_owner._query(condition, operand_owner.OperandProofKind.SCOPE, "fresh", deadline, proved=set())
    witness = operand_owner._query(condition, operand_owner.OperandProofKind.WITNESS, "witness", deadline,
                                   witness=True, proved=proved)
    assert witness.native_result == z3.sat and calls == 4


def _controlled_receipt(inputs: Inputs) -> ImageBoundReal16Domain:
    """Create an explicitly unproved controller input; validators are test stubs."""
    return ImageBoundReal16Domain(ProofStatus.UNKNOWN, BoundDomainReason.SOURCE, inputs.system,
        "controlled-model", (), None, (), FactCounters(1, 1, 1, 1, 0), proposal_hash="controlled-proposal")


def _stub_non_source_prerequisites(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reach source/model routing without claiming validity of mocked evidence."""
    def receipt_stub(receipt: ImageBoundReal16Domain) -> bool:
        return True

    def admit_stub(run: owner._BoundRun) -> int:
        return run.system.root.delta

    def proposal_stub(*args: object, **kwargs: object) -> str:
        return "controlled-proposal"

    def domain_stub(run: owner._BoundRun, root: int) -> None:
        return None

    monkeypatch.setattr(owner, "_receipt_valid", receipt_stub)
    monkeypatch.setattr(owner, "_admit", admit_stub)
    monkeypatch.setattr(owner, "joint_proposal_hash", proposal_stub)
    monkeypatch.setattr(owner, "_domain_valid", domain_stub)


def test_source_pair_shares_only_one_consumer_local_native_model(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Two invocations refresh independently; neither keeps a previous source seal."""
    inputs = make_inputs(tmp_path)
    receipt = _controlled_receipt(inputs)
    _stub_non_source_prerequisites(monkeypatch)
    native_calls = 0
    final_calls = 0
    observed: list[tuple[int, str]] = []

    def native_stub() -> str:
        nonlocal native_calls
        native_calls += 1
        return f"current-native-{native_calls}"

    def source_stub(run: owner._BoundRun, side: int, current_native_model: str | None = None) -> bool:
        model = owner.native_binding_model_hash() if current_native_model is None else current_native_model
        observed.append((side, model))
        return True

    def final_stub() -> str:
        nonlocal final_calls
        final_calls += 1
        return receipt.model_hash

    monkeypatch.setattr(owner, "native_binding_model_hash", native_stub)
    monkeypatch.setattr(owner, "_source_valid", source_stub)
    monkeypatch.setattr(owner, "image_bound_domain_model_hash", final_stub)
    for _ in range(2):
        outcome = owner.consume_image_bound_real16_domain(receipt, *inputs)
        assert outcome.status is ProofStatus.PROVED
        count = len(owner.DomainConsumptionObligation)
        assert outcome.counters == FactCounters(count, count, count, count, 0)
    assert native_calls == 2 and final_calls == 2
    assert observed == [(0, "current-native-1"), (1, "current-native-1"),
                        (0, "current-native-2"), (1, "current-native-2")]


def test_final_complete_model_refresh_rejects_change_after_original_source(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Sharing a local leaf cannot hide a later source/model mutation."""
    inputs = make_inputs(tmp_path)
    receipt = _controlled_receipt(inputs)
    _stub_non_source_prerequisites(monkeypatch)
    changed = False
    sides: list[int] = []

    def native_stub() -> str:
        return "controlled-native"

    def source_stub(run: owner._BoundRun, side: int, current_native_model: str | None = None) -> bool:
        nonlocal changed
        sides.append(side)
        if side == 0:
            changed = True
        return True

    def final_stub() -> str:
        return "mutated-complete-model" if changed else receipt.model_hash

    monkeypatch.setattr(owner, "native_binding_model_hash", native_stub)
    monkeypatch.setattr(owner, "_source_valid", source_stub)
    monkeypatch.setattr(owner, "image_bound_domain_model_hash", final_stub)
    outcome = owner.consume_image_bound_real16_domain(receipt, *inputs)
    assert sides == [0, 1]
    assert outcome.status is ProofStatus.UNKNOWN and outcome.reason is BoundDomainReason.MODEL
    assert outcome.facts[-1].obligation is owner.DomainConsumptionObligation.MODEL
    count = len(owner.DomainConsumptionObligation)
    assert outcome.counters == FactCounters(count, count, count, count, 1)


@pytest.mark.parametrize("side", [0, 1])
def test_local_model_capture_does_not_bypass_source_receipt_failure(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, side: int) -> None:
    """Either source failure stops the consumer and retains the six-row denominator."""
    inputs = make_inputs(tmp_path)
    receipt = _controlled_receipt(inputs)
    _stub_non_source_prerequisites(monkeypatch)
    observed: list[int] = []

    def native_stub() -> str:
        return "controlled-native"

    def source_stub(run: owner._BoundRun, current_side: int, current_native_model: str | None = None) -> bool:
        observed.append(current_side)
        return current_side != side

    def final_stub() -> str:
        raise AssertionError("refused source cannot proceed to final model refresh")

    monkeypatch.setattr(owner, "native_binding_model_hash", native_stub)
    monkeypatch.setattr(owner, "_source_valid", source_stub)
    monkeypatch.setattr(owner, "image_bound_domain_model_hash", final_stub)
    outcome = owner.consume_image_bound_real16_domain(receipt, *inputs)
    assert observed == list(range(side + 1))
    assert outcome.status is ProofStatus.UNKNOWN and outcome.reason is BoundDomainReason.SOURCE
    assert outcome.counters.raw_fact_count == len(owner.DomainConsumptionObligation)
    assert outcome.counters.failure_count > 0


@pytest.mark.parametrize("seal", [bounds_owner.physical_access_model_hash, address_owner.address_model_model_hash,
                                  bound_operand_owner.bound_operand_model_hash, outcome_owner.outcome_scope_model_hash])
def test_bounds_model_seal_reads_semantic_sources_once_and_refreshes(
        monkeypatch: pytest.MonkeyPatch, seal: Callable[[], str]) -> None:
    """Each seal shares its native leaf but a later seal sees changed sources."""
    scans = 0
    semantic = "a" * 64

    def current_semantic() -> str:
        nonlocal scans
        scans += 1
        return semantic

    monkeypatch.setattr(ssa_provenance, "_semantic_hash", current_semantic)
    before = seal()
    assert scans == 1
    assert captured_native_model_hash() is None
    semantic = "b" * 64
    after = seal()
    assert scans == 2 and before != after
    assert captured_native_model_hash() is None


@pytest.mark.parametrize("seal", [bounds_owner.physical_access_model_hash, address_owner.address_model_model_hash,
                                  bound_operand_owner.bound_operand_model_hash, outcome_owner.outcome_scope_model_hash])
def test_bounds_model_seal_preserves_outer_digest_capture(
        monkeypatch: pytest.MonkeyPatch, seal: Callable[[], str]) -> None:
    """Nested digest construction must not rescan an already captured leaf."""
    scans = 0

    def current_semantic() -> str:
        nonlocal scans
        scans += 1
        return "a" * 64

    monkeypatch.setattr(ssa_provenance, "_semantic_hash", current_semantic)
    with native_model_hash_snapshot():
        before = seal()
        after = seal()
        assert before == after and scans == 1
    assert captured_native_model_hash() is None


@pytest.mark.parametrize("module,seal,dependency", [
    (bounds_owner, bounds_owner.physical_access_model_hash, "code_prefix_model_hash"),
    (bound_operand_owner, bound_operand_owner.bound_operand_model_hash, "code_prefix_model_hash"),
    (outcome_owner, outcome_owner.outcome_scope_model_hash, "image_bound_domain_model_hash"),
])
def test_bounds_model_seal_exception_does_not_retain_capture(
        monkeypatch: pytest.MonkeyPatch, module: ModuleType,
        seal: Callable[[], str], dependency: str) -> None:
    """A failed digest cannot leave stale source identity for the next proof."""
    def fail_digest() -> str:
        raise OSError("controlled unreadable model dependency")

    monkeypatch.setattr(module, dependency, fail_digest)
    with pytest.raises(OSError, match="controlled unreadable"):
        seal()
    assert captured_native_model_hash() is None
