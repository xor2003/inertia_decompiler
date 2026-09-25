"""Normalize proven register carriers across decrement dispatch chains.

Layer: Alias.
Responsibility: Owns storage identity by binding a condition register to concrete
storage when paired typed facts or self-test bindings prove it at the same branch, then
carry that identity through unique typed CFG successors of ``DEC reg`` branches.
This module never decodes assembly or inspects source, symbols, or rendered C.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from ..ir.condition_ir import ConditionIR, ConditionOp, condition_sort_key_8616
from ..ir.core import IRValue, MemSpace
from .condition_register_bindings import (
    condition_self_test_register_binding_8616,
    condition_self_test_storage_bindings_8616,
)

type _BranchIdentity8616 = tuple[
    object,
    int,
    tuple[str, ...],
    int | None,
    int | None,
    int | None,
    int | None,
    int | None,
    int | None,
]


@dataclass(frozen=True, slots=True)
class ConditionRegisterCarrierStats8616:
    """Closed evidence counters for register-carrier normalization."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class ConditionRegisterCarrierResult8616:
    """Return normalized conditions and their evidence accounting."""

    conditions: tuple[ConditionIR, ...]
    stats: ConditionRegisterCarrierStats8616


@dataclass(frozen=True, slots=True)
class _CarrierSeed8616:
    """Proven concrete identity for one register at a selected branch successor."""

    next_block: int
    register_name: str
    value: IRValue
    width_bits: int


def _branch_identity_8616(condition: ConditionIR) -> _BranchIdentity8616:
    """Return one operand-independent branch identity."""
    return (
        condition.op,
        condition.width_bits,
        condition.source,
        condition.src_insn,
        condition.block_addr,
        condition.producer_insn,
        condition.taken_target,
        condition.fallthrough_target,
        condition.operand_bind_insn,
    )


def _unique_values_8616(values: list[IRValue]) -> tuple[IRValue, ...]:
    """Deduplicate owned IR values while preserving deterministic order."""
    unique: list[IRValue] = []
    for value in values:
        if value not in unique:
            unique.append(value)
    return tuple(unique)


def _register_lhs_values_8616(group: list[ConditionIR]) -> tuple[IRValue, ...]:
    """Return the unique named-register lhs values of one branch group."""
    return _unique_values_8616(
        [
            condition.lhs
            for condition in group
            if isinstance(condition.lhs, IRValue)
            and condition.lhs.space is MemSpace.REG
            and isinstance(condition.lhs.name, str)
        ]
    )


def _storage_lhs_values_8616(group: list[ConditionIR]) -> tuple[IRValue, ...]:
    """Return the unique segmented-memory lhs values of one branch group."""
    return _unique_values_8616(
        [
            condition.lhs
            for condition in group
            if isinstance(condition.lhs, IRValue)
            and condition.lhs.space in {MemSpace.SS, MemSpace.DS, MemSpace.ES}
        ]
    )


def _memory_lhs_width_8616(operand: object, width_bits: int) -> bool:
    """Return whether one bound operand is a width-exact segmented memory lhs."""
    return (
        isinstance(operand, IRValue)
        and operand.space in {MemSpace.SS, MemSpace.DS, MemSpace.ES}
        and operand.size == max(1, width_bits // 8)
    )


def _binding_proofs_8616(group: list[ConditionIR]) -> list[tuple[str, IRValue]]:
    """Collect proven register→storage bindings from self-test facts."""
    proofs: list[tuple[str, IRValue]] = []
    for condition in group:
        binding = condition_self_test_register_binding_8616(condition)
        if binding is not None:
            register_name, operand = binding
            if _memory_lhs_width_8616(operand, condition.width_bits):
                proofs.append((register_name, operand))
        for bound_register, bound_operand in condition_self_test_storage_bindings_8616(
            condition
        ):
            if _memory_lhs_width_8616(bound_operand, condition.width_bits):
                proofs.append((bound_register, bound_operand))
    return proofs


def _group_unique_proof_8616(
    group: list[ConditionIR],
    register_values: tuple[IRValue, ...],
    storage_values: tuple[IRValue, ...],
) -> tuple[tuple[str, IRValue] | None, bool]:
    """Return the unique proven register→storage pair, or a counted refusal."""
    proofs: list[tuple[str, IRValue]] = []
    if register_values and storage_values:
        register = register_values[0]
        register_name = register.name
        if not isinstance(register_name, str) or register.size != storage_values[0].size:
            return None, True
        proofs.append((register_name.lower(), storage_values[0]))
    proofs.extend(_binding_proofs_8616(group))
    unique_proofs = tuple(dict.fromkeys(proofs))
    if not unique_proofs:
        return None, False
    if len(unique_proofs) != 1:
        return None, True
    register_name, storage = unique_proofs[0]
    if storage_values and storage_values[0] != storage:
        return None, True
    return (register_name, storage), False


def _group_carrier_seed_8616(
    group: list[ConditionIR],
    proof: tuple[str, IRValue],
    by_block: dict[int, list[tuple[int, ConditionIR]]],
) -> _CarrierSeed8616 | None:
    """Return the seed when the DEC successor and rhs consensus are proven."""
    register_name, storage = proof
    representative = group[0]
    next_block, ambiguous = _next_dec_block_8616(
        representative, by_block, register_name=register_name,
        width_bits=representative.width_bits,
    )
    if ambiguous:
        return None
    if next_block is None:
        next_block = representative.fallthrough_target
    if not isinstance(next_block, int):
        return None
    if any(condition.rhs != representative.rhs for condition in group):
        return None
    return _CarrierSeed8616(
        next_block=next_block,
        register_name=register_name,
        value=storage,
        width_bits=representative.width_bits,
    )


def _group_seed_8616(
    group: list[ConditionIR],
    by_block: dict[int, list[tuple[int, ConditionIR]]],
) -> tuple[_CarrierSeed8616 | None, bool]:
    """Return the proven seed for one branch group, or a counted refusal."""
    register_values = _register_lhs_values_8616(group)
    storage_values = _storage_lhs_values_8616(group)
    if len(register_values) > 1 or len(storage_values) > 1:
        return None, True
    proof, proof_failed = _group_unique_proof_8616(
        group,
        register_values,
        storage_values,
    )
    if proof_failed:
        return None, True
    if proof is None:
        return None, False
    seed = _group_carrier_seed_8616(group, proof, by_block)
    if seed is None:
        return None, True
    return seed, False


def _dedupe_seeds_8616(candidates: list[_CarrierSeed8616]) -> tuple[list[_CarrierSeed8616], int]:
    """Return unique seeds keyed by (next_block, register_name) plus refusals."""
    by_key: dict[tuple[int, str], list[_CarrierSeed8616]] = {}
    for seed in candidates:
        by_key.setdefault((seed.next_block, seed.register_name), []).append(seed)
    seeds: list[_CarrierSeed8616] = []
    failures = 0
    for grouped_seeds in by_key.values():
        unique: list[_CarrierSeed8616] = []
        for seed in grouped_seeds:
            if seed not in unique:
                unique.append(seed)
        if len(unique) == 1:
            seeds.append(unique[0])
        else:
            failures += 1
    seeds.sort(key=lambda seed: (seed.next_block, seed.register_name))
    return seeds, failures


def _carrier_seeds_8616(
    conditions: tuple[ConditionIR, ...],
    by_block: dict[int, list[tuple[int, ConditionIR]]],
) -> tuple[tuple[_CarrierSeed8616, ...], int]:
    """Collect unambiguous register-to-storage proofs and unique DEC edges."""
    grouped: dict[_BranchIdentity8616, list[ConditionIR]] = {}
    for condition in conditions:
        grouped.setdefault(_branch_identity_8616(condition), []).append(condition)

    candidates: list[_CarrierSeed8616] = []
    failures = 0
    for group in grouped.values():
        seed, failed = _group_seed_8616(group, by_block)
        if failed:
            failures += 1
            continue
        if seed is not None:
            candidates.append(seed)
    seeds, dedup_failures = _dedupe_seeds_8616(candidates)
    return tuple(seeds), failures + dedup_failures


def _dec_semantics_8616(condition: ConditionIR) -> tuple[str, int] | None:
    """Return a validated ``DEC reg`` producer description."""
    semantics = condition.producer_semantics
    if (
        not isinstance(semantics, tuple)
        or len(semantics) != 3
        or semantics[0] != "dec_reg16"
    ):
        return None
    if not isinstance(semantics[1], str) or not isinstance(semantics[2], int) or semantics[2] <= 0:
        return None
    return semantics[1].lower(), semantics[2]


def _next_dec_block_8616(
    condition: ConditionIR,
    by_block: dict[int, list[tuple[int, ConditionIR]]],
    *,
    register_name: str,
    width_bits: int,
) -> tuple[int | None, bool]:
    """Return the unique successor with a compatible typed ``DEC`` fact.

    Compiler dispatch chains may continue on either edge: ``JE`` commonly
    continues on fallthrough, while ``JNE`` commonly continues on the taken
    edge.  Follow only an exact successor carrying the same register/width
    evidence and refuse when both edges could continue the chain.
    """
    candidates: list[int] = []
    for target in (condition.fallthrough_target, condition.taken_target):
        if not isinstance(target, int) or target in candidates:
            continue
        if any(
            candidate.width_bits == width_bits
            and (semantics := _dec_semantics_8616(candidate)) is not None
            and semantics[0] == register_name
            for _index, candidate in by_block.get(target, ())
        ):
            candidates.append(target)
    if len(candidates) > 1:
        return None, True
    return (candidates[0] if candidates else None), False


def normalize_condition_register_carriers_8616(
    conditions: list[ConditionIR] | tuple[ConditionIR, ...],
) -> ConditionRegisterCarrierResult8616:
    """Bind pre-input comparisons or JCC-bound result tests to proven storage."""
    comparison_ops: dict[ConditionOp, ConditionOp] = {"zero": "eq", "nonzero": "ne"}
    ordered = tuple(sorted(conditions, key=condition_sort_key_8616))
    by_block: dict[int, list[tuple[int, ConditionIR]]] = {}
    for index, condition in enumerate(ordered):
        if isinstance(condition.block_addr, int):
            by_block.setdefault(condition.block_addr, []).append((index, condition))
    seeds, failures = _carrier_seeds_8616(ordered, by_block)

    replacements: dict[int, ConditionIR] = {}
    classified = 0
    materialized = 0
    for seed in seeds:
        block_addr = seed.next_block
        delta = 0
        visited: set[int] = set()
        while block_addr not in visited:
            visited.add(block_addr)
            dec_candidates = [
                (index, condition, semantics)
                for index, condition in by_block.get(block_addr, ())
                if (semantics := _dec_semantics_8616(condition)) is not None
            ]
            identities = {
                _branch_identity_8616(condition)
                for _index, condition, _semantics in dec_candidates
            }
            if len(identities) != 1:
                # No DEC ends the chain; competing branch identities refuse it.
                failures += bool(dec_candidates)
                break
            representative = dec_candidates[0][1]
            semantics = dec_candidates[0][2]
            register_name, dec_count = semantics
            rhs = representative.rhs
            post_update_test = (
                representative.is_zero_test and rhs is None
                and representative.operand_bind_insn == representative.src_insn
                and representative.src_insn is not None
            )
            boundary_matches = post_update_test or (
                isinstance(rhs, IRValue) and rhs.space is MemSpace.CONST and rhs.const == dec_count
            )
            register_matches = (
                isinstance(representative.lhs, IRValue)
                and representative.lhs.space is MemSpace.REG
                and representative.lhs.name == register_name
            )
            if (
                register_name != seed.register_name
                or representative.width_bits != seed.width_bits
                or not register_matches
                or not boundary_matches
            ):
                failures += 1
                break
            classified += 1
            delta += dec_count
            normalized_rhs = replace(rhs, const=delta) if isinstance(rhs, IRValue) else IRValue(
                MemSpace.CONST, const=delta, size=representative.width_bits // 8,
            )
            for index, condition, candidate_semantics in dec_candidates:
                replacement = replace(
                    condition,
                    lhs=seed.value,
                    rhs=normalized_rhs,
                    op=comparison_ops.get(condition.op, condition.op),
                    operand_bind_insn=None if post_update_test else condition.operand_bind_insn,
                )
                existing = replacements.get(index)
                conflicting_replacement = existing is not None and existing != replacement
                if candidate_semantics != semantics or conflicting_replacement:
                    failures += 1
                    continue
                replacements[index] = replacement
            materialized += 1
            next_block, ambiguous = _next_dec_block_8616(
                representative,
                by_block,
                register_name=seed.register_name,
                width_bits=seed.width_bits,
            )
            if ambiguous or next_block is None:
                failures += ambiguous
                break
            block_addr = next_block

    normalized = tuple(
        replacements.get(index, condition)
        for index, condition in enumerate(ordered)
    )
    return ConditionRegisterCarrierResult8616(
        conditions=normalized,
        stats=ConditionRegisterCarrierStats8616(
            raw_fact_count=len(ordered),
            normalized_fact_count=len(seeds),
            classified_fact_count=classified,
            materialized_count=materialized,
            failure_count=failures,
        ),
    )
