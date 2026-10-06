"""Check a structured C operand against the retained near-return IR proof.

Layer: Types/Lowering.
Responsibility: mutation-free preflight that proves one structured C
expression is numerically congruent, as a 16-bit bit pattern, to the retained
modular affine ``AX = base + 2 * index`` evidence of an already complete
``NearScaledReturnCandidateResult8616``. Every C variable leaf must resolve to
the exact canonical stack-coordinate projection object (or a registered
variable alias) for one proven SS:BP word storage; numeric offsets, names,
and rendered text never carry identity. The result establishes operand
congruence only: no pointer representation, segment binding, pointer
arithmetic, prototype, or publication claim. It never mutates the C AST,
codegen, candidate, or project.
Consumes retained IR proof fields and typed codegen projections only.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeInt
from angr.sim_variable import SimStackVariable

from ..ir import IRAddress
from ..ir.scalar_affine_contracts import ScalarAffineExpression8616
from ..ir.stack_argument_scaled_return import _same_stack_storage_8616
from .near_scaled_return_candidate import (
    NearScaledReturnCandidateFailure8616,
    NearScaledReturnCandidateResult8616,
)
from .stack_variable_coordinates import (
    StackVariableCoordinateProjection8616,
    StackVariableCoordinateRegistry8616,
    stack_variable_coordinate_registry_8616,
)

__all__ = [
    "NearReturnBoundOperand8616",
    "NearReturnOperandCongruenceFailure8616",
    "NearReturnOperandCongruenceResult8616",
    "NearReturnOperandCongruenceStats8616",
    "NearReturnOperandCongruenceVerdict8616",
    "NearReturnOperandRole8616",
    "bind_near_return_offset_c_ast_8616",
]


_MODULAR_WORD_MODULUS_8616 = 1 << 16
_OPERAND_NODE_BUDGET_8616 = 128


class _CFunctionBoundary8616(Protocol):
    """Owned field used from the dynamic angr C-function boundary."""

    addr: object


class _CodegenBoundary8616(Protocol):
    """Owned field used from the dynamic angr codegen boundary."""

    cfunc: _CFunctionBoundary8616 | None


class _UnsignedTypeBoundary8616(Protocol):
    """Third-party angr integer fields read at a cast boundary."""

    signed: object
    size: object


class NearReturnOperandCongruenceVerdict8616(StrEnum):
    """Whether one structured C operand matched the proven affine form."""

    CONGRUENT = "congruent"
    UNKNOWN_REFUSE = "unknown_refuse"


class NearReturnOperandCongruenceFailure8616(StrEnum):
    """Stable reasons an operand congruence check cannot publish."""

    CANDIDATE_INCOMPLETE = "candidate_incomplete"
    CODEGEN_SURFACE_UNPROVEN = "codegen_surface_unproven"
    FUNCTION_MISMATCH = "function_mismatch"
    OPERAND_UNBOUND = "operand_unbound"
    OPERAND_STORAGE_MISMATCH = "operand_storage_mismatch"
    EXPRESSION_UNSUPPORTED = "expression_unsupported"
    AFFINE_MISMATCH = "affine_mismatch"


class NearReturnOperandRole8616(StrEnum):
    """Which proven storage role one operand leaf binds."""

    OFFSET_BASE = "offset_base"
    OFFSET_INDEX = "offset_index"


@dataclass(frozen=True, slots=True)
class NearReturnOperandCongruenceStats8616:
    """Closed five-stage evidence loop for one requested congruence check."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class NearReturnBoundOperand8616:
    """One proven storage role bound to its canonical codegen C variable."""

    role: NearReturnOperandRole8616
    storage: IRAddress
    coefficient: int
    projection: StackVariableCoordinateProjection8616
    cvar: structured_c.CVariable

    def matches(
        self, role: NearReturnOperandRole8616, storage: IRAddress, coefficient: int
    ) -> bool:
        """Recheck the exact retained role, storage and canonical C projection."""
        role_matches = self.role is role and self.coefficient == coefficient
        storage_matches = (
            self.storage == storage
            and self.projection.bp_offset == storage.offset
            and self.projection.size == storage.size
        )
        projection_matches = (
            isinstance(self.cvar, structured_c.CVariable)
            and self.cvar is self.projection.cvar
        )
        return role_matches and storage_matches and projection_matches


@dataclass(frozen=True, slots=True)
class NearReturnOperandCongruenceResult8616:
    """One congruent operand binding or a typed atomic refusal.

    ``candidate`` and ``expression`` always retain the exact checked evidence;
    ``bound_operands`` stays empty unless every proven role bound by identity.
    ``registry`` retains the canonical identity owner so ``complete`` can
    re-evaluate the mutable AST and its live projection bindings before use.
    This contract never authorizes a C return expression or pointer type.
    """

    verdict: NearReturnOperandCongruenceVerdict8616
    failure: NearReturnOperandCongruenceFailure8616 | None
    stats: NearReturnOperandCongruenceStats8616
    callee_addr: int = -1
    candidate: NearScaledReturnCandidateResult8616 | None = None
    expression: object | None = None
    bound_operands: tuple[NearReturnBoundOperand8616, ...] = ()
    upstream_failure: NearScaledReturnCandidateFailure8616 | None = None
    registry: StackVariableCoordinateRegistry8616 | None = None

    @property
    def complete(self) -> bool:
        """Recheck current arithmetic and canonical bindings for both roles."""
        if (
            self.verdict is not NearReturnOperandCongruenceVerdict8616.CONGRUENT
            or self.failure is not None
            or self.upstream_failure is not None
        ):
            return False
        candidate = self.candidate
        if candidate is None or not candidate.complete or candidate.callee_addr != self.callee_addr:
            return False
        if self.expression is None or self.stats != NearReturnOperandCongruenceStats8616(1, 1, 1, 1, 0):
            return False
        base, index, expression = candidate.base_storage, candidate.index_storage, candidate.offset_expression
        if base is None or index is None or expression is None:
            return False
        expected = _expected_operand_coefficients_8616(expression, base, index)
        if expected is None or len(self.bound_operands) != 2:
            return False
        operands = {operand.role: operand for operand in self.bound_operands}
        if set(operands) != set(NearReturnOperandRole8616):
            return False
        bindings_match = all(
            operands[role].matches(role, storage, expected[role])
            for role, storage in (
                (NearReturnOperandRole8616.OFFSET_BASE, base),
                (NearReturnOperandRole8616.OFFSET_INDEX, index),
            )
        )
        if not bindings_match or self.registry is None:
            return False
        evaluator = _OperandCongruenceEvaluator8616(self.registry, base, index)
        form = evaluator.evaluate(self.expression)
        if isinstance(form, NearReturnOperandCongruenceFailure8616):
            return False
        modulus = _MODULAR_WORD_MODULUS_8616
        return (
            form.base == expected[NearReturnOperandRole8616.OFFSET_BASE] % modulus
            and form.index == expected[NearReturnOperandRole8616.OFFSET_INDEX] % modulus
            and form.constant == expression.constant % modulus
            and all(evaluator.projections.get(role) is operand.projection for role, operand in operands.items())
        )


@dataclass(frozen=True, slots=True)
class _OperandAffineForm8616:
    """One mod-2^16 affine accumulator over the two proven operand roles."""

    base: int = 0
    index: int = 0
    constant: int = 0

    @property
    def constant_only(self) -> bool:
        """Return whether this form carries no proven operand term."""
        return self.base == 0 and self.index == 0

    def add(self, other: _OperandAffineForm8616) -> _OperandAffineForm8616:
        """Return the modular sum of two operand affine forms."""
        modulus = _MODULAR_WORD_MODULUS_8616
        return _OperandAffineForm8616(
            (self.base + other.base) % modulus,
            (self.index + other.index) % modulus,
            (self.constant + other.constant) % modulus,
        )

    def subtract(self, other: _OperandAffineForm8616) -> _OperandAffineForm8616:
        """Return the modular difference of two operand affine forms."""
        modulus = _MODULAR_WORD_MODULUS_8616
        return _OperandAffineForm8616(
            (self.base - other.base) % modulus,
            (self.index - other.index) % modulus,
            (self.constant - other.constant) % modulus,
        )

    def scale(self, factor: int) -> _OperandAffineForm8616:
        """Return this form scaled by one integer constant modulo 2^16."""
        modulus = _MODULAR_WORD_MODULUS_8616
        reduced = factor % modulus
        return _OperandAffineForm8616(
            self.base * reduced % modulus,
            self.index * reduced % modulus,
            self.constant * reduced % modulus,
        )


def _refuse_8616(
    failure: NearReturnOperandCongruenceFailure8616,
    *,
    normalized: bool = False,
    classified: bool = False,
    candidate: NearScaledReturnCandidateResult8616 | None = None,
    expression: object | None = None,
    upstream: NearScaledReturnCandidateFailure8616 | None = None,
) -> NearReturnOperandCongruenceResult8616:
    """Keep one failed congruence check as an atomic typed refusal."""
    return NearReturnOperandCongruenceResult8616(
        verdict=NearReturnOperandCongruenceVerdict8616.UNKNOWN_REFUSE,
        failure=failure,
        stats=NearReturnOperandCongruenceStats8616(
            1, int(normalized), int(classified), 0, 1
        ),
        callee_addr=candidate.callee_addr if candidate is not None else -1,
        candidate=candidate,
        expression=expression,
        upstream_failure=upstream,
    )


def _codegen_function_addr_8616(codegen: object) -> int | None:
    """Read the exact linear function identity at the codegen boundary."""
    boundary = cast(_CodegenBoundary8616, codegen)
    try:
        cfunc = boundary.cfunc
        addr = cfunc.addr if cfunc is not None else None
    except AttributeError:
        return None
    return addr if type(addr) is int and addr >= 0 else None


def _full_word_unsigned_cast_8616(dst_type: object) -> bool:
    """Accept only an unsigned integer view preserving the 16-bit word.

    A narrower destination truncates the proven word and a signed or
    non-integer view changes the claimed bit pattern, so both refuse.
    """
    if not isinstance(dst_type, SimTypeInt):
        return False
    boundary = cast(_UnsignedTypeBoundary8616, dst_type)
    try:
        signed = boundary.signed
        size = boundary.size
    except (AttributeError, TypeError, ValueError):
        return False
    return signed is False and type(size) is int and size >= 16


class _OperandCongruenceEvaluator8616:
    """Reduce the bounded numeric fragment to a proven-role affine form.

    The evaluator is read-only: it inspects structured C nodes and resolves
    operand leaves through the canonical stack-coordinate registry by object
    identity. Every refusal keeps the fragment unbound instead of guessing.
    """

    def __init__(
        self,
        registry: StackVariableCoordinateRegistry8616,
        base_storage: IRAddress,
        index_storage: IRAddress,
    ) -> None:
        """Retain the canonical registry and the two proven SS:BP storages."""
        self._registry = registry
        self._storages = (
            (NearReturnOperandRole8616.OFFSET_BASE, base_storage),
            (NearReturnOperandRole8616.OFFSET_INDEX, index_storage),
        )
        self._projections: dict[
            NearReturnOperandRole8616, StackVariableCoordinateProjection8616
        ] = {}
        self._budget = _OPERAND_NODE_BUDGET_8616

    @property
    def projections(
        self,
    ) -> dict[NearReturnOperandRole8616, StackVariableCoordinateProjection8616]:
        """Return the projections bound while evaluating, keyed by role."""
        return self._projections

    def evaluate(
        self, node: object
    ) -> _OperandAffineForm8616 | NearReturnOperandCongruenceFailure8616:
        """Return the affine form of one bounded numeric C fragment."""
        if self._budget <= 0:
            return NearReturnOperandCongruenceFailure8616.EXPRESSION_UNSUPPORTED
        self._budget -= 1
        if isinstance(node, structured_c.CConstant):
            return self._constant(node)
        if isinstance(node, structured_c.CVariable):
            return self._variable(node)
        if isinstance(node, structured_c.CBinaryOp):
            return self._binary(node)
        if isinstance(node, structured_c.CTypeCast):
            return self._cast(node)
        return NearReturnOperandCongruenceFailure8616.EXPRESSION_UNSUPPORTED

    def _constant(
        self, node: structured_c.CConstant
    ) -> _OperandAffineForm8616 | NearReturnOperandCongruenceFailure8616:
        """Fold one integer literal into the accumulator's constant."""
        value = node.value
        if type(value) is not int:
            return NearReturnOperandCongruenceFailure8616.EXPRESSION_UNSUPPORTED
        return _OperandAffineForm8616(constant=value)

    def _variable(
        self, node: structured_c.CVariable
    ) -> _OperandAffineForm8616 | NearReturnOperandCongruenceFailure8616:
        """Bind one leaf to a proven role through exact object identity only."""
        variables = (
            (node.variable, node.unified_variable)
            if node.unified_variable is not None else (node.variable,)
        )
        projections = tuple(
            self._registry.for_variable(variable) if isinstance(variable, SimStackVariable) else None
            for variable in variables
        )
        projection = projections[0]
        if projection is None or any(item is None for item in projections):
            return NearReturnOperandCongruenceFailure8616.OPERAND_UNBOUND
        if any(item is not projection for item in projections):
            return NearReturnOperandCongruenceFailure8616.OPERAND_STORAGE_MISMATCH
        if not isinstance(projection.cvar, structured_c.CVariable):
            return NearReturnOperandCongruenceFailure8616.OPERAND_UNBOUND
        role = self._role_for_projection(projection)
        if role is None:
            return NearReturnOperandCongruenceFailure8616.OPERAND_STORAGE_MISMATCH
        self._projections.setdefault(role, projection)
        return _OperandAffineForm8616(
            base=int(role is NearReturnOperandRole8616.OFFSET_BASE),
            index=int(role is NearReturnOperandRole8616.OFFSET_INDEX),
        )

    def _role_for_projection(
        self, projection: StackVariableCoordinateProjection8616
    ) -> NearReturnOperandRole8616 | None:
        """Require the canonical projection to cover a proven word exactly."""
        for role, storage in self._storages:
            if (
                projection.bp_offset == storage.offset
                and projection.size == storage.size
                and self._registry.for_bp_range(storage.offset, storage.size) is projection
            ):
                return role
        return None

    def _binary(
        self, node: structured_c.CBinaryOp
    ) -> _OperandAffineForm8616 | NearReturnOperandCongruenceFailure8616:
        """Combine operand forms through the allowed numeric operators."""
        lhs = self.evaluate(node.lhs)
        if not isinstance(lhs, _OperandAffineForm8616):
            return lhs
        rhs = self.evaluate(node.rhs)
        if not isinstance(rhs, _OperandAffineForm8616):
            return rhs
        if node.op == "Add":
            return lhs.add(rhs)
        if node.op == "Sub":
            return lhs.subtract(rhs)
        if node.op == "Mul":
            return self._multiply(lhs, rhs)
        if node.op == "Shl":
            # Shift counts are not modular operand words. In particular,
            # reducing 65536 + 1 to 1 would accept an undefined C shift.
            count = node.rhs.value if isinstance(node.rhs, structured_c.CConstant) else None
            if type(count) is not int or not 0 <= count < 16:
                return NearReturnOperandCongruenceFailure8616.EXPRESSION_UNSUPPORTED
            return lhs.scale(1 << count)
        return NearReturnOperandCongruenceFailure8616.EXPRESSION_UNSUPPORTED

    def _multiply(
        self, lhs: _OperandAffineForm8616, rhs: _OperandAffineForm8616
    ) -> _OperandAffineForm8616 | NearReturnOperandCongruenceFailure8616:
        """Scale one side only when the other is a pure integer constant."""
        if lhs.constant_only:
            return rhs.scale(lhs.constant)
        if rhs.constant_only:
            return lhs.scale(rhs.constant)
        return NearReturnOperandCongruenceFailure8616.EXPRESSION_UNSUPPORTED

    def _cast(
        self, node: structured_c.CTypeCast
    ) -> _OperandAffineForm8616 | NearReturnOperandCongruenceFailure8616:
        """Cross one safe full-word unsigned cast; narrower views refuse."""
        if not _full_word_unsigned_cast_8616(node.dst_type):
            return NearReturnOperandCongruenceFailure8616.EXPRESSION_UNSUPPORTED
        return self.evaluate(node.expr)


def _expected_operand_coefficients_8616(
    expression: ScalarAffineExpression8616,
    base_storage: IRAddress,
    index_storage: IRAddress,
) -> dict[NearReturnOperandRole8616, int] | None:
    """Derive proven per-role coefficients from the retained IR proof."""
    coefficients = dict.fromkeys(NearReturnOperandRole8616, 0)
    storages = (
        (NearReturnOperandRole8616.OFFSET_BASE, base_storage),
        (NearReturnOperandRole8616.OFFSET_INDEX, index_storage),
    )
    for term in expression.terms:
        source = term.source
        if not isinstance(source, IRAddress):
            return None
        matched = False
        for role, storage in storages:
            if _same_stack_storage_8616(source, storage):
                coefficients[role] += term.coefficient
                matched = True
                break
        if not matched:
            return None
    return coefficients


def bind_near_return_offset_c_ast_8616(
    codegen: object,
    candidate: NearScaledReturnCandidateResult8616,
    expression: object,
) -> NearReturnOperandCongruenceResult8616:
    """Bind a structured C operand to the retained scaled-return proof.

    The result is a nonpublishing candidate: numeric 16-bit bit-pattern
    congruence between the C fragment and the proven modular affine offset,
    with operand identity bound through canonical stack projections. It never
    mutates the AST, codegen, prototype, callsite, or project state, and it
    does not decide pointer representation, segment binding, or signedness.
    """
    if not candidate.complete:
        return _refuse_8616(
            NearReturnOperandCongruenceFailure8616.CANDIDATE_INCOMPLETE,
            candidate=candidate,
            expression=expression,
            upstream=candidate.failure,
        )
    function_addr = _codegen_function_addr_8616(codegen)
    if function_addr is None:
        return _refuse_8616(
            NearReturnOperandCongruenceFailure8616.CODEGEN_SURFACE_UNPROVEN,
            candidate=candidate,
            expression=expression,
        )
    if function_addr != candidate.callee_addr:
        return _refuse_8616(
            NearReturnOperandCongruenceFailure8616.FUNCTION_MISMATCH,
            candidate=candidate,
            expression=expression,
        )
    offset_expression = candidate.offset_expression
    base_storage = candidate.base_storage
    index_storage = candidate.index_storage
    if (
        offset_expression is None
        or base_storage is None
        or index_storage is None
    ):
        return _refuse_8616(
            NearReturnOperandCongruenceFailure8616.CANDIDATE_INCOMPLETE,
            normalized=True,
            candidate=candidate,
            expression=expression,
        )
    expected = _expected_operand_coefficients_8616(
        offset_expression, base_storage, index_storage
    )
    if expected is None:
        return _refuse_8616(
            NearReturnOperandCongruenceFailure8616.CANDIDATE_INCOMPLETE,
            normalized=True,
            candidate=candidate,
            expression=expression,
        )
    registry = stack_variable_coordinate_registry_8616(codegen)
    evaluator = _OperandCongruenceEvaluator8616(
        registry,
        base_storage,
        index_storage,
    )
    form = evaluator.evaluate(expression)
    if isinstance(form, NearReturnOperandCongruenceFailure8616):
        return _refuse_8616(
            form, normalized=True, candidate=candidate, expression=expression
        )
    modulus = _MODULAR_WORD_MODULUS_8616
    congruent = (
        form.base == expected[NearReturnOperandRole8616.OFFSET_BASE] % modulus
        and form.index == expected[NearReturnOperandRole8616.OFFSET_INDEX] % modulus
        and form.constant % modulus == offset_expression.constant % modulus
    )
    if not congruent:
        return _refuse_8616(
            NearReturnOperandCongruenceFailure8616.AFFINE_MISMATCH,
            normalized=True,
            classified=True,
            candidate=candidate,
            expression=expression,
        )
    projections = evaluator.projections
    base_projection = projections.get(NearReturnOperandRole8616.OFFSET_BASE)
    index_projection = projections.get(NearReturnOperandRole8616.OFFSET_INDEX)
    if (
        base_projection is None
        or index_projection is None
        or not isinstance(base_projection.cvar, structured_c.CVariable)
        or not isinstance(index_projection.cvar, structured_c.CVariable)
    ):
        return _refuse_8616(
            NearReturnOperandCongruenceFailure8616.OPERAND_UNBOUND,
            normalized=True,
            classified=True,
            candidate=candidate,
            expression=expression,
        )
    result = NearReturnOperandCongruenceResult8616(
        verdict=NearReturnOperandCongruenceVerdict8616.CONGRUENT,
        failure=None,
        stats=NearReturnOperandCongruenceStats8616(1, 1, 1, 1, 0),
        callee_addr=candidate.callee_addr,
        candidate=candidate,
        expression=expression,
        registry=registry,
        bound_operands=(
            NearReturnBoundOperand8616(
                NearReturnOperandRole8616.OFFSET_BASE,
                base_storage,
                expected[NearReturnOperandRole8616.OFFSET_BASE],
                base_projection,
                base_projection.cvar,
            ),
            NearReturnBoundOperand8616(
                NearReturnOperandRole8616.OFFSET_INDEX,
                index_storage,
                expected[NearReturnOperandRole8616.OFFSET_INDEX],
                index_projection,
                index_projection.cvar,
            ),
        ),
    )
    if not result.complete:
        raise RuntimeError("near-return operand congruence lost owned evidence")
    return result
