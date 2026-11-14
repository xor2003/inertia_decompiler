# cython: language_level=3, infer_types=True
"""Materialize signed scalar global declarations from typed conditions.

Layer: Types/Lowering.
Responsibility: join canonical wide scalar storage with signed high-word
ConditionIR evidence and materialize the corresponding C declaration type.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: name/address allowlists, rendered-C parsing, AST semantic rewrites,
or signed promotion without an exact canonical scalar and high-word join.
"""

from __future__ import annotations
import typing
import cython

import logging
import os
from dataclasses import dataclass, field
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CBinaryOp, CConstant, CIndexedVariable, CVariable
from angr.sim_variable import SimMemoryVariable

from inertia.ir.condition_ir import ConditionIR
from inertia.ir.core import IRValue, MemSpace
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.codegen_metadata import GlobalDeclarationArrayLength8616
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.direct_global_ordering import DirectGlobalOrdering8616

from .global_declarations import (
    GlobalDeclarationCType8616,
    initialize_global_declaration_specs_8616,
    replace_global_declaration_spec_from_stronger_typed_evidence_8616,
)
from .project_global_signedness import (
    ProjectGlobalSignednessEvidence8616,
    collect_project_global_signedness_evidence_8616,
)
import dataclasses
import operator
import builtins

log: logging.Logger = logging.getLogger(__name__)

__all__ = [
    "SignedGlobalDeclarationFact8616",
    "SignedGlobalDeclarationStats8616",
    "materialize_signed_global_declarations_8616",
]


class _CodegenSurface8616(Protocol):
    """Owned codegen metadata consumed and produced by this lowering pass."""

    cfunc: object
    _inertia_global_declaration_specs_8616: object
    _inertia_signed_global_declaration_facts_8616: object
    _inertia_signed_global_declaration_stats_8616: SignedGlobalDeclarationStats8616
    _inertia_typed_conditions: object


@cython.dataclasses.dataclass()
class SignedGlobalDeclarationStats8616:
    """Closed evidence census for signed wide-global declaration lowering."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0


@dataclasses.dataclass(frozen=True, )
class SignedGlobalDeclarationFact8616:
    """One canonical scalar whose high word has signed comparison semantics."""

    base_offset: cython.longlong
    name: object
    width: cython.longlong = 4


@dataclasses.dataclass(frozen=True, )
class _WideScalarCandidate8616:
    """One exact canonical four-byte scalar visible in the current C AST."""

    base_offset: cython.longlong
    name: object


def _typed_conditions_8616(codegen: _CodegenSurface8616) -> tuple[ConditionIR, ...]:
    """Return transferred typed conditions from the owned codegen contract."""
    try:
        raw_conditions = codegen._inertia_typed_conditions
    except AttributeError:
        return ()
    if not isinstance(raw_conditions, (list, tuple)):
        return ()
    return tuple(condition for condition in iter(raw_conditions) if isinstance(condition, ConditionIR))


@cython.ccall
def _condition_key_8616(condition: ConditionIR) -> object:
    """Return exact instruction/block provenance for one ordering condition."""
    if (
        not (condition.is_signed or condition.is_unsigned)
        or not isinstance(condition.src_insn, int)
        or not isinstance(condition.block_addr, int)
    ):
        return None
    return condition.src_insn, condition.block_addr


@cython.ccall
def _ast_condition_key_8616(node: CBinaryOp) -> object:
    """Return typed provenance from one materialized C comparison."""
    block_addr: object
    ins_addr: object
    ins_addr = node.tags.get("ins_addr")
    block_addr = node.tags.get("vex_block_addr")
    if not isinstance(ins_addr, int) or not isinstance(block_addr, int):
        return None
    return ins_addr, block_addr


def _global_declaration_specs_8616(
    codegen: _CodegenSurface8616,
) -> tuple[tuple[str, str, GlobalDeclarationArrayLength8616], ...]:
    """Return normalized declaration specs from the owned metadata contract."""
    try:
        raw_specs = codegen._inertia_global_declaration_specs_8616
    except AttributeError:
        return ()
    return tuple(
        (ctype, name, array_len)
        for ctype, name, array_len in iter(raw_specs)
        if isinstance(ctype, str) and isinstance(name, str)
    )


def _canonical_scalar_names_8616(codegen: _CodegenSurface8616) -> frozenset[str]:
    """Return four-byte scalar names already proven by widening."""
    return frozenset(
        name
        for ctype, name, array_len in builtins.iter(_global_declaration_specs_8616(codegen))
        if ctype in {"long", "unsigned long", "int32_t", "uint32_t"} and array_len is None
    )


@cython.ccall
def _wide_scalar_candidate_8616(
    node: object,
    scalar_names: object,
) -> _WideScalarCandidate8616 | None:
    """Return a canonical scalar from an exact high-word projection."""
    base: object | None = None
    if (
        isinstance(node, CBinaryOp)
        and node.op == "Shr"
        and isinstance(node.rhs, CConstant)
        and node.rhs.value == 16
    ):
        base = node.lhs
    elif (
        isinstance(node, CIndexedVariable)
        and isinstance(node.index, CConstant)
        and node.index.value == 1
    ):
        base = node.variable
    return _wide_scalar_variable_candidate_8616(base, scalar_names)


@cython.ccall
def _wide_scalar_variable_candidate_8616(
    node: object,
    scalar_names: object,
) -> _WideScalarCandidate8616 | None:
    """Return an exact canonical four-byte scalar variable."""
    if not isinstance(node, CVariable) or not isinstance(node.variable, SimMemoryVariable):
        return None
    variable = node.variable
    name = node.name
    if (
        not isinstance(variable.addr, int)
        or int(variable.size or 0) != 4
        or not isinstance(name, str)
        or name not in scalar_names
    ):
        return None
    return _WideScalarCandidate8616(variable.addr & 0xFFFF, name)


def _condition_high_word_candidate_8616(
    condition: ConditionIR,
    candidates: object,
) -> _WideScalarCandidate8616 | None:
    """Join one typed DS high-word comparison to one canonical wide scalar."""
    other: object
    value: object
    if not isinstance(condition.lhs, IRValue) or not isinstance(condition.rhs, IRValue):
        return None
    operands = ((condition.lhs, condition.rhs), (condition.rhs, condition.lhs))
    matched: set[_WideScalarCandidate8616] = set()
    for value, other in operands:
        if (
            value.space is not MemSpace.DS
            or not isinstance(value.offset, int)
            or int(value.size or 0) != 2
            or other.space is not MemSpace.CONST
        ):
            continue
        matched.update(
            candidate
            for candidate in iter(candidates)
            if operator.eq(((candidate.base_offset + 2) & 0xFFFF), (value.offset & 0xFFFF))
        )
    if len(matched) != 1:
        return None
    return next(iter(matched))


def _comparison_high_word_candidate_8616(
    node: object,
    scalar_names: object,
) -> _WideScalarCandidate8616 | None:
    """Return the sole canonical high-word projection in one comparison."""
    if not isinstance(node, CBinaryOp) or not str(node.op).startswith("Cmp"):
        return None
    candidates = tuple(
        candidate
        for candidate in iter((
            _wide_scalar_candidate_8616(node.lhs, scalar_names),
            _wide_scalar_candidate_8616(node.rhs, scalar_names),
        ))
        if candidate is not None
    )
    other_is_constant = isinstance(node.rhs, CConstant) or isinstance(node.lhs, CConstant)
    if len(candidates) != 1 or not other_is_constant:
        return None
    return candidates[0]


@cython.dataclasses.dataclass()
class _SignedCandidateCensus8616:
    """Join signedness evidence into signed/unsigned candidate buckets."""

    scalar_names: object
    signed_keys: object
    unsigned_keys: object
    signed_candidates: object = field(default_factory=set)
    unsigned_candidates: object = field(default_factory=set)
    normalized_joins: object = field(
        default_factory=set
    )

    @cython.ccall
    def bucket_project_bases(
        self,
        scalar_candidates: object,
        project_evidence: ProjectGlobalSignednessEvidence8616,
    ) -> None:
        """Bucket candidates by proven project-level ordering contracts."""
        candidate: object
        signed_bases = {
            contract.base_offset
            for contract in iter(project_evidence.contracts)
            if contract.ordering is DirectGlobalOrdering8616.SIGNED
        }
        unsigned_bases = {
            contract.base_offset
            for contract in iter(project_evidence.contracts)
            if contract.ordering is DirectGlobalOrdering8616.UNSIGNED
        }
        conflicting_bases = set(project_evidence.conflicting_base_offsets)
        for candidate in scalar_candidates:
            if candidate.base_offset in signed_bases:
                self.signed_candidates.add(candidate)
            if candidate.base_offset in unsigned_bases:
                self.unsigned_candidates.add(candidate)
            if candidate.base_offset in conflicting_bases:
                self.signed_candidates.add(candidate)
                self.unsigned_candidates.add(candidate)

    @cython.ccall
    def join_ast(self, node: object) -> None:
        """Join one AST comparison node into the candidate buckets."""
        candidate: object
        if not isinstance(node, CBinaryOp):
            return
        key = _ast_condition_key_8616(node)
        if key not in self.signed_keys and key not in self.unsigned_keys:
            return
        candidate = _comparison_high_word_candidate_8616(node, self.scalar_names)
        if candidate is None:
            return
        self.normalized_joins.add((key, candidate))
        if key in self.signed_keys:
            self.signed_candidates.add(candidate)
        if key in self.unsigned_keys:
            self.unsigned_candidates.add(candidate)

    @cython.ccall
    def join_condition(
        self,
        condition: ConditionIR,
        scalar_candidates: object,
    ) -> None:
        """Join one typed condition into the candidate buckets."""
        candidate: object
        key: object
        key = _condition_key_8616(condition)
        if key is None:
            return
        candidate = _condition_high_word_candidate_8616(condition, scalar_candidates)
        if candidate is None:
            return
        self.normalized_joins.add((key, candidate))
        if condition.is_signed:
            self.signed_candidates.add(candidate)
        if condition.is_unsigned:
            self.unsigned_candidates.add(candidate)


@cython.ccall
def _condition_key_sets_8616(
    conditions: object,
) -> tuple[set[tuple[cython.longlong, cython.longlong]], set[tuple[cython.longlong, cython.longlong]]]:
    """Bucket proven condition keys by signedness."""
    key: object
    condition: object
    signed_keys: set[tuple[cython.longlong, cython.longlong]] = set()
    unsigned_keys: set[tuple[cython.longlong, cython.longlong]] = set()
    for condition in conditions:
        key = _condition_key_8616(condition)
        if key is None:
            continue
        target = signed_keys if condition.is_signed else unsigned_keys
        target.add(key)
    return signed_keys, unsigned_keys


def _project_candidate_fact_count_8616(
    scalar_candidates: object,
    project_evidence: ProjectGlobalSignednessEvidence8616,
) -> cython.longlong:
    """Count scalar candidates backed by any project-level ordering evidence."""
    signed_bases = {
        contract.base_offset
        for contract in iter(project_evidence.contracts)
        if contract.ordering is DirectGlobalOrdering8616.SIGNED
    }
    unsigned_bases = {
        contract.base_offset
        for contract in iter(project_evidence.contracts)
        if contract.ordering is DirectGlobalOrdering8616.UNSIGNED
    }
    conflicting_bases = set(project_evidence.conflicting_base_offsets)
    return sum(
        candidate.base_offset in signed_bases | unsigned_bases | conflicting_bases
        for candidate in iter(scalar_candidates)
    )


def _materialize_signed_facts_8616(
    codegen: object,
    surface: _CodegenSurface8616,
    census: _SignedCandidateCensus8616,
    previous_facts: object,
    stats: SignedGlobalDeclarationStats8616,
) -> tuple[SignedGlobalDeclarationFact8616, ...]:
    """Materialize proven signed-only candidates into declaration specs."""
    candidate: object
    materialized_facts: list[SignedGlobalDeclarationFact8616] = []
    for candidate in sorted(
        census.signed_candidates, key=lambda item: (item.base_offset, item.name)
    ):
        if candidate in census.unsigned_candidates:
            stats.failure_count += 1
            continue
        stats.classified_fact_count += 1
        fact = SignedGlobalDeclarationFact8616(candidate.base_offset, candidate.name)
        if fact not in previous_facts or ("long", candidate.name, None) not in _global_declaration_specs_8616(surface):
            replace_global_declaration_spec_from_stronger_typed_evidence_8616(
                codegen,
                ctype=GlobalDeclarationCType8616.SIGNED_LONG,
                name=candidate.name,
                array_len=None,
            )
        if ("long", candidate.name, None) not in _global_declaration_specs_8616(surface):
            stats.failure_count += 1
            continue
        materialized_facts.append(fact)
        stats.materialized_count += 1
    return tuple(dict.fromkeys(materialized_facts))


def materialize_signed_global_declarations_8616(project: object, codegen: object) -> cython.bint:
    """Materialize signed wide globals from exact high-word condition evidence.

    A signed ordering comparison of the high word gives the sign semantics of
    an already-proven four-byte scalar. An unsigned comparison of that same
    high word is a conflict and causes conservative refusal. The body AST is
    intentionally unchanged so validation continues to compare semantics, not
    declaration representation.
    """
    condition: object
    node: object
    surface = cast(_CodegenSurface8616, codegen)
    initialize_global_declaration_specs_8616(codegen)
    project_evidence = collect_project_global_signedness_evidence_8616(project)
    conditions = _typed_conditions_8616(surface)
    stats = SignedGlobalDeclarationStats8616(raw_fact_count=len(conditions))
    signed_keys, unsigned_keys = _condition_key_sets_8616(conditions)

    try:
        previous_facts = surface._inertia_signed_global_declaration_facts_8616
    except AttributeError:
        previous_facts = ()
    before_specs = _global_declaration_specs_8616(surface)
    scalar_names = _canonical_scalar_names_8616(surface)
    if os.environ.get("INERTIA_DEBUG_SIGNED_GLOBAL_DECLARATIONS") == "1":
        log.warning(
            "signed-global inputs conditions=%d signed=%d unsigned=%d declaration_specs=%r",
            len(conditions),
            len(signed_keys),
            len(unsigned_keys),
            before_specs,
        )
    try:
        cfunc = surface.cfunc
    except AttributeError:
        cfunc = None
    c_nodes = tuple(_iter_c_nodes_deep_8616(cfunc))
    scalar_candidates = frozenset(
        candidate
        for node in iter(c_nodes)
        if (candidate := _wide_scalar_variable_candidate_8616(node, scalar_names)) is not None
    )
    census = _SignedCandidateCensus8616(scalar_names, signed_keys, unsigned_keys)
    census.bucket_project_bases(scalar_candidates, project_evidence)
    for node in c_nodes:
        census.join_ast(node)
    for condition in conditions:
        census.join_condition(condition, scalar_candidates)

    project_candidate_fact_count = _project_candidate_fact_count_8616(
        scalar_candidates, project_evidence
    )
    stats.raw_fact_count += project_candidate_fact_count
    stats.normalized_fact_count = len(census.normalized_joins) + project_candidate_fact_count

    if os.environ.get("INERTIA_DEBUG_SIGNED_GLOBAL_DECLARATIONS") == "1":
        log.warning(
            "signed-global candidates signed=%r unsigned=%r stats=%r",
            census.signed_candidates,
            census.unsigned_candidates,
            stats,
        )

    facts = _materialize_signed_facts_8616(codegen, surface, census, previous_facts, stats)
    surface._inertia_signed_global_declaration_facts_8616 = facts
    surface._inertia_signed_global_declaration_stats_8616 = stats
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified signed global declarations were not materialized")
    return facts != previous_facts or operator.ne(_global_declaration_specs_8616(surface), before_specs)
