"""Register-slice widening candidates and join proofs.

Layer: Widening.
Responsibility: owns register-slice widening candidates and join proofs.
Owns register-slice widening candidates and join proofs.
Consumes alias-proven storage identity for register domains before joining
byte and word views.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.
Dynamic boundary: this module reads third-party angr and codegen attributes
when translating register variables and generated code into owned widening
candidates.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, TypeGuard

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from ..alias.domains import (
    FULL16,
    HIGH8,
    LOW8,
    DomainKey,
    View,
    register_domain_for_name,
    register_offset_for_name,
    register_pair_name,
    register_view_for_name,
)
from ..alias.state import AliasState


class _RegisterWideningProofLike(Protocol):
    """Structural alias proof required before register slices can widen."""

    ok: bool
    register_pair: str | None
    left_version: int | None
    right_version: int | None


def _is_register_widening_proof_like(value: object) -> TypeGuard[_RegisterWideningProofLike]:
    """Validate dynamic boundary proof fields from the widening-model plugin contract."""
    ok = getattr(value, "ok", None)
    register_pair = getattr(value, "register_pair", None)
    left_version = getattr(value, "left_version", None)
    right_version = getattr(value, "right_version", None)
    return (
        isinstance(ok, bool)
        and (register_pair is None or isinstance(register_pair, str))
        and (left_version is None or isinstance(left_version, int))
        and (right_version is None or isinstance(right_version, int))
    )


@dataclass(frozen=True)
class RegisterWideningCandidate:
    """Alias-proven register slice that may participate in a widening join."""

    domain: DomainKey
    view: View
    expr: object

    def is_joinable_with(self, other: RegisterWideningCandidate) -> bool:
        """Return whether this slice is adjacent-compatible with another slice."""
        return self.domain == other.domain and self.view.can_join(other.view)

    @classmethod
    def from_expr(cls, expr: object) -> RegisterWideningCandidate:
        """Build a candidate across the dynamic boundary from third-party angr C expressions."""
        if not isinstance(expr, structured_c.CVariable):
            raise ValueError("expected a register CVariable")
        variable = getattr(expr, "variable", None)
        if not isinstance(variable, SimRegisterVariable):
            raise ValueError("expected a register variable")
        domain, view = _register_domain_and_view(variable)
        if domain is None or view is None:
            raise ValueError("unsupported register slice")
        return cls(domain, view, expr)


def _register_pair_name_for_variable(variable: SimRegisterVariable) -> str | None:
    """Read register identity across the dynamic boundary from third-party angr variables."""
    pair_name = register_pair_name(getattr(variable, "name", None))
    if pair_name is not None:
        return pair_name
    reg = getattr(variable, "reg", None)
    size = getattr(variable, "size", 0) or 0
    if isinstance(reg, int) and size in {1, 2}:
        pair_names = ("ax", "cx", "dx", "bx")
        pair_index = reg // 2
        if 0 <= pair_index < len(pair_names):
            return pair_names[pair_index]
    return None


def _register_domain_and_view(variable: SimRegisterVariable) -> tuple[DomainKey | None, View | None]:
    """Return alias domain/view across the dynamic boundary from third-party angr variables."""

    def _impl() -> tuple[DomainKey | None, View | None]:
        """Read register view fields across the dynamic boundary from third-party angr variables."""
        pair_name = _register_pair_name_for_variable(variable)
        if pair_name is None:
            return None, None
        domain = register_domain_for_name(pair_name)
        if domain is None:
            return None, None
        view = register_view_for_name(getattr(variable, "name", None))
        size = getattr(variable, "size", 0) or 0
        if view is not None and view.bit_width == size * 8:
            return domain, view
        reg = getattr(variable, "reg", None)
        if isinstance(reg, int) and size == 1:
            view = HIGH8 if reg % 2 else LOW8
        elif isinstance(reg, int) and size == 2:
            view = FULL16
        else:
            view = register_view_for_name(getattr(variable, "name", None))
        return domain, view

    return _impl()


def _positive_matching_versions_8616(candidate_proof: _RegisterWideningProofLike) -> bool:
    """Check both slices carry equal positive version evidence."""
    return (
        candidate_proof.left_version is not None
        and candidate_proof.right_version is not None
        and candidate_proof.left_version > 0
        and candidate_proof.right_version > 0
        and candidate_proof.left_version == candidate_proof.right_version
    )


def _can_join_slices_8616(
    low_expr: object,
    high_expr: object,
    alias_state: AliasState | None,
    proof: object | None,
) -> bool:
    """Run the join-evidence ladder over proof, candidates, and domain."""
    if alias_state is None:
        return False
    candidate_proof = proof
    if candidate_proof is None:
        from .. import widening_model as _widening_model

        candidate_proof = _widening_model.prove_adjacent_storage_slices(
            low_expr, high_expr, alias_state=alias_state
        )
    if not _is_register_widening_proof_like(candidate_proof):
        return False
    if not candidate_proof.ok:
        return False
    if candidate_proof.register_pair is None:
        return False
    if not _positive_matching_versions_8616(candidate_proof):
        return False
    try:
        low_candidate = RegisterWideningCandidate.from_expr(low_expr)
        high_candidate = RegisterWideningCandidate.from_expr(high_expr)
    except ValueError:
        return False
    expected_domain = register_domain_for_name(candidate_proof.register_pair)
    if expected_domain is None:
        return False
    if low_candidate.domain != expected_domain or high_candidate.domain != expected_domain:
        return False
    return low_candidate.is_joinable_with(high_candidate)


def can_join_adjacent_register_slices(
    low_expr: object, high_expr: object, *, alias_state: AliasState | None = None, proof: object | None = None
) -> bool:
    """Return whether alias/version evidence proves two register slices join."""
    return _can_join_slices_8616(low_expr, high_expr, alias_state, proof)


def join_adjacent_register_slices(
    low_expr: object,
    high_expr: object,
    codegen: object,
    *,
    alias_state: AliasState | None = None,
    proof: object | None = None,
) -> structured_c.CVariable | None:
    """Materialize a widened register C variable at the dynamic codegen boundary."""
    candidate_proof = proof
    if candidate_proof is None and alias_state is not None:
        from .. import widening_model as _widening_model

        candidate_proof = _widening_model.prove_adjacent_storage_slices(low_expr, high_expr, alias_state=alias_state)
    if not _is_register_widening_proof_like(candidate_proof):
        return None
    if not can_join_adjacent_register_slices(low_expr, high_expr, alias_state=alias_state, proof=candidate_proof):
        return None

    pair_name = candidate_proof.register_pair
    if pair_name is None:
        return None

    reg_offset = register_offset_for_name(pair_name)
    project = getattr(codegen, "project", None)
    if project is not None:
        registers = getattr(project.arch, "registers", {})
        reg_info = registers.get(pair_name)
        if reg_info is not None and isinstance(reg_info, tuple):
            reg_offset = reg_info[0]
    if reg_offset is None:
        return None

    return structured_c.CVariable(
        SimRegisterVariable(reg_offset, 2, name=pair_name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


__all__ = [
    "RegisterWideningCandidate",
    "can_join_adjacent_register_slices",
    "join_adjacent_register_slices",
]
