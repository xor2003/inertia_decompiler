"""Absolute loaded-byte seeds are separate from relative array transport."""
from __future__ import annotations

import time
from dataclasses import replace

import pytest
import z3

from tools.dosunit.proof_contracts import Architecture, ProofStatus
from tools.dosunit.recursive_proofs import loaded_byte_relation_proof as owner
from tools.dosunit.recursive_proofs.loaded_byte_relation import (
    LoadedRelationLimits,
    LoadedRelationReason,
    LoadedRelationRefusal,
    propose_loaded_byte_relation,
    snapshot_loaded_bytes,
)


def _memory(name: str = "seed_background") -> z3.ArrayRef:
    return z3.Array(name, z3.BitVecSort(32), z3.BitVecSort(8))


@pytest.mark.parametrize("architecture,address", [
    (Architecture.REAL16, 0x10000), (Architecture.FLAT32, 0xFFFFFFFE)])
def test_seed_anchors_actual_loaded_bytes_and_keeps_background(architecture, address) -> None:
    """Every loaded byte is literal; an arbitrary outside byte retains its value."""
    limits = LoadedRelationLimits(deadline=time.monotonic() + 10)
    snapshot = snapshot_loaded_bytes(architecture, ((address, b"\x90\xc3"),), limits=limits)
    background = _memory()
    seeded = owner.seed_loaded_array(snapshot, background, limits)
    index = z3.BitVec("outside_seed", 32)
    solver = z3.Solver()
    solver.add(z3.Or(z3.Select(seeded, address) != 0x90,
                     z3.Select(seeded, address + 1) != 0xC3,
                     z3.And(index != address, index != address + 1,
                            z3.Select(seeded, index) != z3.Select(background, index))))
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(z3.Select(background, address) != 0x90)
    assert solver.check() == z3.sat  # Relative input alone is not an absolute seed.
    assert z3.simplify(owner.seed_loaded_array(snapshot, seeded, limits) == seeded)


def test_seed_implements_the_proved_snapshot_transport() -> None:
    """Instantiate the finite seed relation on an unrestricted shared background."""
    limits = LoadedRelationLimits(deadline=time.monotonic() + 10)
    a = snapshot_loaded_bytes(Architecture.REAL16, ((0x10000, b"\x90\xc3"),), limits=limits)
    b = snapshot_loaded_bytes(Architecture.REAL16, ((0x10000, b"\x91\xc3"),), limits=limits)
    proposal = propose_loaded_byte_relation(a, b, limits=limits)
    proof = owner.prove_loaded_byte_relation(proposal, limits=limits)
    assert proof.status is ProofStatus.PROVED and not proof.binary_equivalence_proved
    background = _memory()
    original = owner.seed_loaded_array(a, background, limits)
    candidate = owner.seed_loaded_array(b, background, limits)
    transported = owner.apply_array_relation(proposal.relation, original, limits)
    solver = z3.Solver()
    solver.add(transported != candidate)
    assert solver.check() == z3.unsat


def test_seed_refuses_stale_snapshot_identity() -> None:
    """A literal snapshot replacement cannot inherit another byte manifest."""
    limits = LoadedRelationLimits(deadline=time.monotonic() + 10)
    snapshot = snapshot_loaded_bytes(Architecture.REAL16, ((0x10000, b"\x90"),), limits=limits)
    corrupted = replace(snapshot, chunks=((0x10000, b"\xcc"),))
    with pytest.raises(LoadedRelationRefusal) as refusal:
        owner.seed_loaded_array(corrupted, _memory(), limits)
    assert refusal.value.reason is LoadedRelationReason.MALFORMED


def test_seed_retains_original_deadline_and_sort_boundary() -> None:
    """No construction can replenish an expired budget or guess an array sort."""
    snapshot = snapshot_loaded_bytes(Architecture.REAL16, ((0x10000, b"\x90"),))
    with pytest.raises(LoadedRelationRefusal) as refusal:
        owner.seed_loaded_array(snapshot, _memory(), LoadedRelationLimits(deadline=time.monotonic() - 1))
    assert refusal.value.reason is LoadedRelationReason.DEADLINE
    wrong = z3.Array("wrong_seed_sort", z3.BitVecSort(16), z3.BitVecSort(8))
    with pytest.raises(LoadedRelationRefusal) as refusal:
        owner.seed_loaded_array(snapshot, wrong, LoadedRelationLimits())
    assert refusal.value.reason is LoadedRelationReason.DOMAIN
