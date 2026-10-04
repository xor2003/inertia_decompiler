"""Actual MZ bootstrap/domain controls preserve every native output.

Layer: test support.
Responsibility: construct actual MZ bootstrap and recursive state proposals for proof tests.
"""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from test_dosunit_tool import _edge_function, _mz_exe

from recursive_proof_fixtures.real16_joint_system import build_real16_joint_system
from tools.dosunit import straightline_ssa as S
from tools.dosunit.proof_contracts import ProofStatus
from tools.dosunit.real16_call_contracts import initial_state
from tools.dosunit.real16_call_evidence import group_functions
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import BoundReal16Load, bind_real16_mz
from tools.dosunit.recursive_proofs.loaded_byte_native_transition import (
    LoadedTransitionReason,
    check_loaded_native_transition,
)
from tools.dosunit.recursive_proofs.loaded_byte_relation import propose_loaded_byte_relation
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import (
    LoadedRelationProof,
    prove_loaded_byte_relation,
)
from tools.dosunit.recursive_proofs.real16_entry_domain import EntryDomainReason, entry_domain_model_hash
from tools.dosunit.recursive_proofs.real16_entry_domain_proof import prove_real16_entry_domain
from tools.dosunit.recursive_proofs.recursive_joint_contracts import JointSystem
from tools.dosunit.register_state_relations import MachineState

DEFAULT_BOOTSTRAP: bytes = bytes.fromhex("e8fd01b8004ccd21")


def _document(tmp_path: Path, code: bytes, tag: str, *, ss: int = 0x80,
              bootstrap_code: bytes = DEFAULT_BOOTSTRAP) -> dict[str, Any]:
    """Explicit loader entry bytes reach the recursive body before DOS exit."""
    image = bytearray(0x300)
    image[:len(bootstrap_code)] = bootstrap_code
    image[0x200:0x200 + len(code)] = code
    file = bytearray(_mz_exe(bytes(image)))
    file[14:16] = ss.to_bytes(2, "little")
    path = tmp_path / f"{tag}.exe"
    path.write_bytes(file)
    functions = [_edge_function("bootstrap", "bootstrap", offset=0, size=8),
                 _edge_function("recursive", "recursive", offset=0x200, size=len(code))]
    catalog = {"schema": "dosunit.functions.v1", "id": "functions:test", "module": "demo.exe",
               "program_kind": "mz_exe", "functions": functions, "diagnostics": []}
    return S.lower_straightline_ssa_document(exe_path=path, functions_catalog=catalog,
                                           output_regs=tuple(S.INTERNAL_STATE_REGS),
                                           max_blocks_per_function=32, follow_call_fallthrough=True)


def _setup(tmp_path: Path, *, ss: int = 0x80, bootstrap_code: bytes = DEFAULT_BOOTSTRAP) -> tuple[
    tuple[BoundReal16Load, BoundReal16Load], LoadedRelationProof,
    tuple[MachineState, MachineState], tuple[tuple[MachineState, MachineState], ...], JointSystem
]:
    """Construct the exact independent loader/native inputs for each proof stage."""
    codes = [bytes.fromhex("e3078d5f0149e8f7ffc3"), bytes.fromhex("e307498d5f01e8f7ffc3")]
    docs = [_document(tmp_path, code, side, ss=ss, bootstrap_code=bootstrap_code)
            for code, side in zip(codes, ("a", "b"), strict=True)]
    system = build_real16_joint_system(*docs, "recursive")
    loads = tuple(bind_real16_mz(Path(doc["exe"]).read_bytes(), load_segment=0x100) for doc in docs)
    initialized = prove_loaded_byte_relation(propose_loaded_byte_relation(*(load.binding.snapshot for load in loads)))
    groups = [group_functions(doc) for doc in docs]
    bootstrap = tuple(S._compose_block_outputs(group["bootstrap"].blocks[0],
                      group["bootstrap"].blocks[0]["outputs"], initial_state()) for group in groups)
    effects = (*tuple((step.original, step.candidate) for step in system.steps), bootstrap)
    return loads, initialized, bootstrap, effects, system


def test_actual_bootstrap_derives_domain_and_closes_native_stack_aliases(tmp_path: Path) -> None:
    """Header/CALL initiation and each native effect discharge the scalar domain."""
    loads, initialized, bootstrap, effects, system = _setup(tmp_path)
    proof = prove_real16_entry_domain(loads, initialized, bootstrap, effects, 0x1200)
    assert proof.status is ProofStatus.PROVED, proof
    assert proof.reason is EntryDomainReason.DISCHARGED
    assert proof.domain.ss == 0x180 and proof.domain.cs == 0x100
    assert proof.counters.failure_count == 0
    results = [check_loaded_native_transition(step.original, step.candidate, initialized, domain=proof)
               for step in system.steps]
    results.append(check_loaded_native_transition(*bootstrap, initialized, domain=proof))
    assert all(result.status is ProofStatus.PROVED for result in results), results
    assert all(result.domain == proof and not result.binary_equivalence_proved for result in results)
    unconstrained = check_loaded_native_transition(*bootstrap, initialized)
    assert unconstrained.status is ProofStatus.COUNTEREXAMPLE, unconstrained
    assert not unconstrained.binary_equivalence_proved

    # Scalar initiation can hold while the CALL saves an incorrect return word.
    # The full-state relation must still reject the changed caller frame.
    changed = dict(bootstrap[1])
    stack_address = {"op": "add", "width": 32, "args": [
        {"op": "shl", "width": 32, "args": [
            {"op": "zext", "width": 32, "args": [changed["ss"]]},
            {"op": "const", "width": 8, "value": "0x4"}]},
        {"op": "zext", "width": 32, "args": [changed["sp"]]}]}
    changed["memory"] = {"op": "storele", "width": 0, "args": [changed["memory"], stack_address,
                         {"op": "const", "width": 16, "value": "0x9"}]}
    changed_bootstrap = (bootstrap[0], changed)
    changed_effects = (*effects[:-1], changed_bootstrap)
    scalar_only = prove_real16_entry_domain(loads, initialized, changed_bootstrap, changed_effects, 0x1200)
    assert scalar_only.status is ProofStatus.PROVED, scalar_only
    checked = check_loaded_native_transition(*changed_bootstrap, initialized, domain=scalar_only)
    assert checked.status is ProofStatus.COUNTEREXAMPLE, checked
    assert not checked.binary_equivalence_proved


def test_loaded_stack_selector_overlapping_code_cannot_supply_disjointness(tmp_path: Path) -> None:
    """Named SS never supplies physical separation when its actual selector aliases."""
    loads, initialized, bootstrap, effects, _ = _setup(tmp_path, ss=0x20)
    proof = prove_real16_entry_domain(loads, initialized, bootstrap, effects, 0x1200)
    assert proof.status is ProofStatus.UNKNOWN
    assert proof.reason is EntryDomainReason.ALIAS, proof
    assert proof.counters.failure_count > 0


@pytest.mark.parametrize("mutation", ["selector", "alignment", "root"])
def test_unproved_bootstrap_or_scalar_preservation_cannot_authorize_domain(tmp_path: Path, mutation: str) -> None:
    """Concrete changed selectors, odd stack movement or root control stay unproved."""
    loads, initialized, bootstrap, effects, _ = _setup(tmp_path)
    changed = dict(effects[0][1])
    if mutation == "selector":
        changed["ss"] = {"op": "const", "width": 16, "value": "0x120"}
    elif mutation == "alignment":
        changed["sp"] = {"op": "add", "width": 16, "args": [initial_state()["sp"],
                         {"op": "const", "width": 16, "value": "0x1"}]}
    if mutation == "root":
        altered = dict(bootstrap[1])
        altered["control_ip"] = {"op": "const", "width": 32, "value": "0x1201"}
        bootstrap = (bootstrap[0], altered)
    else:
        effects = ((effects[0][0], changed), *effects[1:])
    proof = prove_real16_entry_domain(loads, initialized, bootstrap, effects, 0x1200)
    assert proof.status is ProofStatus.UNKNOWN, proof
    assert proof.reason in {EntryDomainReason.ENTRY, EntryDomainReason.PRESERVATION}


def test_missing_domain_fact_or_other_effect_cannot_enter_native_solver(tmp_path: Path) -> None:
    """A certificate cannot be promoted with missing premises or altered native effects."""
    loads, initialized, bootstrap, effects, _ = _setup(tmp_path)
    proof = prove_real16_entry_domain(loads, initialized, bootstrap, effects, 0x1200)
    assert proof.status is ProofStatus.PROVED, proof
    corrupted = (
        replace(proof, facts=proof.facts[:-1]),
        replace(proof, facts=proof.facts[:-1] + proof.facts[:1]),
        replace(proof, facts=(replace(proof.facts[0], status=ProofStatus.UNKNOWN), *proof.facts[1:])),
        replace(proof, snapshot_hashes=("0" * 64, proof.snapshot_hashes[1])),
        replace(proof, counters=replace(proof.counters, failure_count=1)),
    )
    for certificate in corrupted:
        checked = check_loaded_native_transition(*effects[0], initialized, domain=certificate)
        assert checked.status is ProofStatus.UNKNOWN and checked.reason is LoadedTransitionReason.DOMAIN
        assert checked.solver is None
    checked = check_loaded_native_transition(*effects[0], initialized, domain=replace(proof, model_hash="0" * 64))
    assert checked.status is ProofStatus.UNKNOWN and checked.reason is LoadedTransitionReason.MODEL
    assert checked.solver is None
    changed = dict(effects[0][1])
    changed["ax"] = {"op": "const", "width": 16, "value": "0x5"}
    checked = check_loaded_native_transition(effects[0][0], changed, initialized, domain=proof)
    assert checked.status is ProofStatus.UNKNOWN and checked.reason is LoadedTransitionReason.DOMAIN


def test_original_entry_domain_deadline_is_not_replenished(tmp_path: Path) -> None:
    """An exhausted caller budget refuses before initialization/native consumption."""
    loads, initialized, bootstrap, effects, _ = _setup(tmp_path)
    proof = prove_real16_entry_domain(loads, initialized, bootstrap, effects, 0x1200, timeout_ms=0)
    assert proof.status is ProofStatus.UNKNOWN and proof.reason is EntryDomainReason.DEADLINE


@pytest.mark.parametrize("owner", [
    "real16_entry_domain.py", "real16_entry_domain_proof.py", "loaded_byte_native_transition.py",
    "loaded_byte_image_binding.py", "recursive_stack_proofs.py", "real16_call_contracts.py",
    "real16_mz_load.py", "real16_replay_model.py", "straightline_ssa.py",
])
def test_domain_model_seal_covers_each_semantic_owner(owner: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A dependency change invalidates reuse without modifying shared source files."""
    baseline = entry_domain_model_hash()
    read_bytes = Path.read_bytes
    visited: list[Path] = []

    def changed_source(path: Path) -> bytes:
        """Emulate changed owner bytes at the source hashing boundary."""
        data = read_bytes(path)
        if path.name == owner:
            visited.append(path)
            return data + b"\n# changed semantic owner\n"
        return data

    monkeypatch.setattr(Path, "read_bytes", changed_source)
    assert entry_domain_model_hash() != baseline
    assert len(visited) == 1
