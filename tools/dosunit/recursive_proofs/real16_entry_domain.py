"""Layer: dosunit derived recursive entry-domain contracts (staging).

Responsibility: represent loader/bootstrap-derived scalar invariants without
treating proposed input constraints as proof. Certificates bind exact effects,
images and model identity; they never grant component/program equivalence.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import cast

import z3

from tools.dosunit import straightline_ssa as S
from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.proof_contracts import FactCounters, ProofStatus
from tools.dosunit.register_state_relations import MachineState


class EntryDomainReason(StrEnum):
    """The exact domain premise derived, contradicted or still unproved."""

    DISCHARGED = "real16_entry_invariant_discharged"
    IMAGE = "real16_entry_image_binding_incomplete"
    ENTRY = "real16_entry_bootstrap_or_root_relation_unproved"
    PRESERVATION = "real16_entry_scalar_invariant_not_preserved"
    ALIAS = "real16_entry_stack_aliases_initialized_image"
    ADDRESS = "real16_entry_physical_or_operand_scope_unclosed"
    MANIFEST = "real16_entry_effect_manifest_incomplete"
    MODEL = "real16_entry_model_identity_changed"
    DEADLINE = "real16_entry_original_deadline_exhausted"
    COUNTERMODEL = "real16_entry_obligation_countermodel"
    UNKNOWN = "real16_entry_solver_unknown"


class EntryDomainObligation(StrEnum):
    """Every consumed fact is separate from an invariant proposal."""

    BINDING = "loader_and_effect_binding"
    NONVACUITY = "native_scalar_domain_nonempty"
    INITIATION = "native_bootstrap_initiation"
    PRESERVATION = "every_native_cutpoint_preserves_scalar_domain"
    DISJOINT = "full_stack_space_disjoint_from_loaded_initial_bytes"
    ADDRESS = "all_aligned_stack_words_within_normal_real_mode"


@dataclass(frozen=True, slots=True)
class Real16ScalarDomain:
    """One proposed selector/alignment invariant, never proof by construction."""

    ss: int
    cs: int
    alignment: int = 2

    def __post_init__(self) -> None:
        """Require concrete native selectors and a supported near-frame alignment."""
        if any(type(value) is not int or not 0 <= value <= 0xFFFF for value in (self.ss, self.cs)):
            raise ValueError("native selector domain requires unsigned16 constants")
        if type(self.alignment) is not int or self.alignment not in {2, 4}:
            raise ValueError("native stack alignment requires two or four bytes")

    def predicate(self, state: Mapping[str, z3.ExprRef]) -> z3.BoolRef:
        """Express only the typed proposal over actual native scalar fields."""
        selected = [state[name] for name in ("ss", "cs", "sp")]
        if any(not isinstance(value, z3.BitVecRef) or value.size() != 16 for value in selected):
            raise ValueError("domain predicate requires complete native16 selector/pointer fields")
        ss, cs, sp = (cast(z3.BitVecRef, value) for value in selected)
        return cast(z3.BoolRef, z3.And(ss == self.ss, cs == self.cs, (sp & (self.alignment - 1)) == 0))


@dataclass(frozen=True, slots=True)
class EntryDomainFact:
    """One retained native/geometry result including raw models and refusals."""

    obligation: EntryDomainObligation
    key: str
    status: ProofStatus
    detail: str = ""


@dataclass(frozen=True, slots=True)
class Real16DomainProof:
    """Proof of the explicit scalar domain for exact loader/native inputs."""

    status: ProofStatus
    reason: EntryDomainReason
    domain: Real16ScalarDomain
    original_file_hash: str
    candidate_file_hash: str
    snapshot_hashes: tuple[str, str]
    model_hash: str
    root_address: int
    effects: tuple[tuple[str, str], ...]
    facts: tuple[EntryDomainFact, ...]
    counters: FactCounters
    detail: str = ""

    @property
    def binary_equivalence_proved(self) -> bool:
        """Full-state/frame/control/fault/environment closure is separate."""
        return False


def native_effect_hash(state: MachineState) -> str:
    """Bind an already bounded native effect through the canonical JSON owner."""
    return hashlib.sha256(canonical_json_bytes(state)).hexdigest()


def entry_domain_requirements(count: int) -> tuple[tuple[EntryDomainObligation, str], ...]:
    """Own the exact required ledger, independent of attempted successful checks."""
    if type(count) is not int or not 0 < count <= 4096:
        raise ValueError("entry domain requires one through4096 bounded effect pairs")
    fixed = ((EntryDomainObligation.BINDING, "binding"), (EntryDomainObligation.NONVACUITY, "domain"),
             (EntryDomainObligation.INITIATION, "original"), (EntryDomainObligation.INITIATION, "candidate"),
             (EntryDomainObligation.DISJOINT, "all_stack_bytes"), (EntryDomainObligation.ADDRESS, "all_stack_words"))
    return fixed + tuple((EntryDomainObligation.PRESERVATION, f"{index}:{side}")
                         for index in range(count) for side in ("original", "candidate"))


def entry_domain_model_hash() -> str:
    """Bind the owners that produce and consume the native scalar theorem.

    Composition alone does not own register materialization, loader entry
    fields or the native predicate consumer. Changing any of those owners
    invalidates a certificate, even if the scalar contract itself is unchanged.
    This source seal does not prove that supplied effects came from an image.
    """
    stage = Path(__file__).parent
    dosunit = Path(S.__file__).parent
    paths = (Path(__file__), stage / "real16_entry_domain_proof.py",
             stage / "loaded_byte_native_transition.py", stage / "loaded_byte_image_binding.py",
             stage / 'stack' / "recursive_stack_proofs.py",
             dosunit / "real16_call_contracts.py", dosunit / "real16_mz_load.py",
             dosunit / "real16_replay_model.py", Path(S.__file__))
    description = ["real16-loader-bootstrap-scalar-domain-v2", z3.get_version_string(),
                   *(hashlib.sha256(path.read_bytes()).hexdigest() for path in paths)]
    return hashlib.sha256(canonical_json_bytes(description)).hexdigest()
