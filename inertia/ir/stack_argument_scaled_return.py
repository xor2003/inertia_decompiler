"""Prove one exact modular scaled return from two stable stack inputs.

Layer: IR.
Responsibility: join closed stack-input uses with exact affine SSA paths to
prove AX = base + scale * index modulo 16 bits and, separately, exact DX
segment carry for a far result. This is address arithmetic evidence, not
pointer classification, source signedness, or C materialization.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616

from .core import IRAddress, IRValue, MemSpace
from .indexed_address_contracts import IndexedAddressDefinitionSite8616
from .logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryAccessKey8616,
    IRMemoryAccessKind8616,
)
from .scalar_affine_contracts import (
    ScalarAffineExpression8616,
    ScalarAffineFailure8616,
    ScalarAffineTerm8616,
)
from .scalar_affine_trace import trace_scalar_affine_expression_8616
from .ssa_function import SSAFunctionArtifact
from .stack_argument_modular_use import prove_stack_argument_modular_return_use_8616
from .stack_argument_modular_use_contracts import (
    ModularArgumentUseFailure8616,
    ModularArgumentUseVerdict8616,
    ModularReturnRegister8616,
)


class ScaledReturnVerdict8616(Enum):
    """Whether exact two-word modular return arithmetic was proven."""

    PROVEN = "proven"
    UNKNOWN_REFUSE = "unknown_refuse"


class ScaledReturnFailure8616(Enum):
    """Typed reason an AX return cannot be a proven scaled sum."""

    INPUT_IDENTITY_CONFLICT = "input_identity_conflict"
    BASE_USE_UNPROVEN = "base_use_unproven"
    INDEX_USE_UNPROVEN = "index_use_unproven"
    RETURN_SITE_CONFLICT = "return_site_conflict"
    LOGICAL_ACCESS_UNPROVEN = "logical_access_unproven"
    AX_ROOT_UNPROVEN = "ax_root_unproven"
    AFFINE_TRACE_UNPROVEN = "affine_trace_unproven"
    AFFINE_SHAPE_MISMATCH = "affine_shape_mismatch"
    LEAF_SITE_MISMATCH = "leaf_site_mismatch"


class FarScaledReturnFailure8616(Enum):
    """Typed reason the far AX:DX result cannot be proved atomically."""

    INPUT_SHAPE_MISMATCH = "input_shape_mismatch"
    OFFSET_UNPROVEN = "offset_unproven"
    SEGMENT_USE_UNPROVEN = "segment_use_unproven"
    RETURN_SITE_CONFLICT = "return_site_conflict"
    SEGMENT_ACCESS_UNPROVEN = "segment_access_unproven"
    DX_ROOT_UNPROVEN = "dx_root_unproven"
    SEGMENT_TRACE_UNPROVEN = "segment_trace_unproven"
    SEGMENT_SHAPE_MISMATCH = "segment_shape_mismatch"
    SEGMENT_LEAF_MISMATCH = "segment_leaf_mismatch"


@dataclass(frozen=True, slots=True)
class ScaledReturnStats8616:
    """Account for one requested IR fact through all five evidence stages."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class ScaledReturnResult8616:
    """One proven modular offset value plus its exact affine expression.

    ``offset_expression`` retains the ``ScalarAffineExpression8616`` proven by
    the upstream trace, never a rebuilt copy; refusals keep it ``None``.
    """

    verdict: ScaledReturnVerdict8616
    failure: ScaledReturnFailure8616 | None
    stats: ScaledReturnStats8616
    base_access_key: IRLogicalMemoryAccessKey8616 | None = None
    index_access_key: IRLogicalMemoryAccessKey8616 | None = None
    return_instruction_addr: int | None = None
    definition_path: tuple[IndexedAddressDefinitionSite8616, ...] = ()
    offset_expression: ScalarAffineExpression8616 | None = None
    upstream_failure: ModularArgumentUseFailure8616 | ScalarAffineFailure8616 | None = None

    def _closed_offset_expression(self) -> bool:
        """Return whether the retained expression still matches this proof."""
        expression = self.offset_expression
        if expression is None or not expression.complete:
            return False
        terms = expression.terms
        exact_ax_root = (
            expression.root.space is MemSpace.REG
            and expression.root.name == "ax"
            and expression.root.size == 2
            and isinstance(expression.root.version, int)
        )
        fixed_word_expression = expression.width == 2 and expression.constant == 0
        exact_terms = (
            len(terms) == 2
            and all(isinstance(term.source, IRAddress) for term in terms)
            and terms[0].source != terms[1].source
            and sorted(term.coefficient for term in terms) == [1, 2]
        )
        return bool(
            exact_ax_root
            and fixed_word_expression
            and expression.definition_path == self.definition_path
            and exact_terms
        )

    def matches_storage_inputs(self, base: IRAddress, index: IRAddress) -> bool:
        """Bind the retained coefficient roles to these exact stable stack words."""
        expression = self.offset_expression
        return bool(
            self.complete
            and expression is not None
            and _scaled_terms_match_8616(expression.terms, base, index)
        )

    @property
    def complete(self) -> bool:
        """Require one closed fact with both source and return identities."""
        return bool(
            self.verdict is ScaledReturnVerdict8616.PROVEN
            and self.failure is None
            and self.base_access_key is not None
            and self.index_access_key is not None
            and self.base_access_key != self.index_access_key
            and self.return_instruction_addr is not None
            and self.definition_path
            and self._closed_offset_expression()
            and self.stats == ScaledReturnStats8616(1, 1, 1, 1, 0)
        )


@dataclass(frozen=True, slots=True)
class FarScaledReturnResult8616:
    """Exact AX offset and DX segment paths, or one nonpublishing refusal."""

    verdict: ScaledReturnVerdict8616
    failure: FarScaledReturnFailure8616 | None
    stats: ScaledReturnStats8616
    offset: ScaledReturnResult8616 | None = None
    segment_access_key: IRLogicalMemoryAccessKey8616 | None = None
    return_instruction_addr: int | None = None
    segment_definition_path: tuple[IndexedAddressDefinitionSite8616, ...] = ()
    upstream_failure: (
        ScaledReturnFailure8616 | ModularArgumentUseFailure8616 | ScalarAffineFailure8616 | None
    ) = None

    @property
    def complete(self) -> bool:
        """Require both return words and one exact shared terminal return."""
        return bool(
            self.verdict is ScaledReturnVerdict8616.PROVEN
            and self.failure is None
            and self.offset is not None
            and self.offset.complete
            and self.segment_access_key is not None
            and self.return_instruction_addr == self.offset.return_instruction_addr
            and self.segment_definition_path
            and self.stats == ScaledReturnStats8616(1, 1, 1, 1, 0)
        )


def _refuse_8616(
    failure: ScaledReturnFailure8616,
    *,
    normalized: bool = False,
    upstream: ModularArgumentUseFailure8616 | ScalarAffineFailure8616 | None = None,
) -> ScaledReturnResult8616:
    """Keep one failed fact without partial type or expression publication."""
    return ScaledReturnResult8616(
        ScaledReturnVerdict8616.UNKNOWN_REFUSE,
        failure,
        ScaledReturnStats8616(1, int(normalized), 0, 0, 1),
        upstream_failure=upstream,
    )


def _refuse_far_8616(
    failure: FarScaledReturnFailure8616,
    *,
    normalized: bool = False,
    upstream: ScaledReturnFailure8616 | ModularArgumentUseFailure8616 | ScalarAffineFailure8616 | None = None,
) -> FarScaledReturnResult8616:
    """Retain a failed far-return obligation without partial publication."""
    return FarScaledReturnResult8616(
        ScaledReturnVerdict8616.UNKNOWN_REFUSE,
        failure,
        ScaledReturnStats8616(1, int(normalized), 0, 0, 1),
        upstream_failure=upstream,
    )


def _approved_access_8616(
    artifact: SSAFunctionArtifact,
    key: IRLogicalMemoryAccessKey8616,
    storage: IRAddress,
) -> IRLogicalMemoryAccess8616 | None:
    """Bind an upstream proof key to one complete exact word-read operand."""
    logical = artifact.logical_memory
    if logical is None or not logical.closed or logical.refusals:
        return None
    matches = tuple(access for access in logical.accesses if access.key == key)
    if len(matches) != 1:
        return None
    access = matches[0]
    if (
        not access.complete
        or access.kind is not IRMemoryAccessKind8616.READ
        or not _same_stack_storage_8616(access.address, storage)
        or key.function_addr != artifact.function_addr
    ):
        return None
    return access


def _same_stack_storage_8616(left: IRAddress, right: IRAddress) -> bool:
    """Compare proven stable BP storage, ignoring versioned address carriers."""
    return bool(
        left.space is right.space is MemSpace.SS
        and left.base == right.base == ("bp",)
        and left.offset == right.offset
        and left.size == right.size == 2
        and left.status is right.status
        and left.segment_origin is right.segment_origin
    )


def _last_return_word_root_8616(
    artifact: SSAFunctionArtifact,
    block_addr: int,
    return_register: ModularReturnRegister8616,
) -> tuple[IRValue, int] | None:
    """Find the final full-word register definition in the proven source block."""
    block = next((item for item in artifact.blocks if item.addr == block_addr), None)
    if block is None:
        return None
    writes = tuple(
        (instruction.dst, index)
        for index, instruction in enumerate(block.instrs)
        if instruction.dst is not None
        and instruction.dst.space is MemSpace.REG
        and instruction.dst.name == return_register.value
    )
    if not writes or writes[-1][0].size != 2:
        return None
    return writes[-1]


def _scaled_terms_match_8616(
    terms: tuple[ScalarAffineTerm8616, ...],
    base: IRAddress,
    index: IRAddress,
) -> bool:
    """Require exactly two distinct source words and no hidden term."""
    return bool(
        len(terms) == 2
        and sum(
            isinstance(term.source, IRAddress)
            and _same_stack_storage_8616(term.source, base)
            and term.coefficient == 1
            for term in terms
        ) == 1
        and sum(
            isinstance(term.source, IRAddress)
            and _same_stack_storage_8616(term.source, index)
            and term.coefficient == 2
            for term in terms
        ) == 1
    )


def _leaf_sites_match_8616(
    path: tuple[IndexedAddressDefinitionSite8616, ...],
    accesses: tuple[IRLogicalMemoryAccess8616, ...],
) -> bool:
    """Bind every affine LOAD leaf to approved exact logical byte reads."""
    expected = {
        (slice_.block_addr, slice_.instr_index, slice_.insn_addr)
        for access in accesses for slice_ in access.execution_slices
    }
    actual = {
        (site.block_addr, site.instr_index, site.instr_addr)
        for site in path if site.op == "LOAD"
    }
    expected_count = len(accesses) * 2
    return bool(expected_count > 0 and len(expected) == expected_count and len(actual) == expected_count and actual == expected)


def _approved_input_pair_8616(
    boundary: ExactFunctionRangeBoundary8616,
    artifact: SSAFunctionArtifact,
    base_storage: IRAddress,
    index_storage: IRAddress,
) -> tuple[IRLogicalMemoryAccess8616, IRLogicalMemoryAccess8616, int] | ScaledReturnResult8616:
    """Close both modular uses, their exact memory reads, and one return site."""
    if _same_stack_storage_8616(base_storage, index_storage):
        return _refuse_8616(ScaledReturnFailure8616.INPUT_IDENTITY_CONFLICT)
    base_use = prove_stack_argument_modular_return_use_8616(boundary, artifact, base_storage)
    if base_use.verdict is not ModularArgumentUseVerdict8616.PROVEN:
        return _refuse_8616(
            ScaledReturnFailure8616.BASE_USE_UNPROVEN,
            upstream=base_use.failure,
        )
    index_use = prove_stack_argument_modular_return_use_8616(boundary, artifact, index_storage)
    if index_use.verdict is not ModularArgumentUseVerdict8616.PROVEN:
        return _refuse_8616(
            ScaledReturnFailure8616.INDEX_USE_UNPROVEN,
            normalized=True,
            upstream=index_use.failure,
        )
    base_key = base_use.input_access_key
    index_key = index_use.input_access_key
    if base_key is None or index_key is None:
        return _refuse_8616(ScaledReturnFailure8616.RETURN_SITE_CONFLICT, normalized=True)
    same_return = (
        base_use.return_instruction_addr is not None
        and base_use.return_instruction_addr == index_use.return_instruction_addr
    )
    distinct_same_block_inputs = base_key != index_key and base_key.block_addr == index_key.block_addr
    if not same_return or not distinct_same_block_inputs:
        return _refuse_8616(ScaledReturnFailure8616.RETURN_SITE_CONFLICT, normalized=True)
    base_access = _approved_access_8616(artifact, base_key, base_storage)
    index_access = _approved_access_8616(artifact, index_key, index_storage)
    if base_access is None or index_access is None:
        return _refuse_8616(ScaledReturnFailure8616.LOGICAL_ACCESS_UNPROVEN, normalized=True)
    assert base_use.return_instruction_addr is not None
    return base_access, index_access, base_use.return_instruction_addr


def prove_stack_argument_scaled_return_8616(
    boundary: ExactFunctionRangeBoundary8616,
    artifact: SSAFunctionArtifact,
    base_storage: IRAddress,
    index_storage: IRAddress,
) -> ScaledReturnResult8616:
    """Prove AX equals base plus twice index modulo 16 bits, not pointer C."""
    pair = _approved_input_pair_8616(boundary, artifact, base_storage, index_storage)
    if isinstance(pair, ScaledReturnResult8616):
        return pair
    base_access, index_access, return_addr = pair
    base_key = base_access.key
    index_key = index_access.key
    root = _last_return_word_root_8616(
        artifact, base_key.block_addr, ModularReturnRegister8616.AX,
    )
    if root is None:
        return _refuse_8616(ScaledReturnFailure8616.AX_ROOT_UNPROVEN, normalized=True)
    value, instr_index = root
    trace = trace_scalar_affine_expression_8616(
        artifact, value, block_addr=base_key.block_addr, before_index=instr_index + 1,
    )
    expression = trace.expression
    if not trace.complete or expression is None:
        return _refuse_8616(
            ScaledReturnFailure8616.AFFINE_TRACE_UNPROVEN,
            normalized=True,
            upstream=trace.failure,
        )
    if (
        expression.root != value or expression.width != 2 or expression.constant != 0
        or not _scaled_terms_match_8616(expression.terms, base_storage, index_storage)
    ):
        return _refuse_8616(ScaledReturnFailure8616.AFFINE_SHAPE_MISMATCH, normalized=True)
    if not _leaf_sites_match_8616(expression.definition_path, (base_access, index_access)):
        return _refuse_8616(ScaledReturnFailure8616.LEAF_SITE_MISMATCH, normalized=True)
    return ScaledReturnResult8616(
        ScaledReturnVerdict8616.PROVEN,
        None,
        ScaledReturnStats8616(1, 1, 1, 1, 0),
        base_key,
        index_key,
        return_addr,
        expression.definition_path,
        offset_expression=expression,
    )


def _prove_far_segment_identity_8616(
    artifact: SSAFunctionArtifact,
    key: IRLogicalMemoryAccessKey8616,
    access: IRLogicalMemoryAccess8616,
    storage: IRAddress,
) -> tuple[IndexedAddressDefinitionSite8616, ...] | FarScaledReturnResult8616:
    """Bind the final DX word to exactly one unchanged input segment read."""
    root = _last_return_word_root_8616(
        artifact, key.block_addr, ModularReturnRegister8616.DX,
    )
    if root is None:
        return _refuse_far_8616(
            FarScaledReturnFailure8616.DX_ROOT_UNPROVEN, normalized=True,
        )
    value, instr_index = root
    trace = trace_scalar_affine_expression_8616(
        artifact, value,
        block_addr=key.block_addr,
        before_index=instr_index + 1,
    )
    expression = trace.expression
    if not trace.complete or expression is None:
        return _refuse_far_8616(
            FarScaledReturnFailure8616.SEGMENT_TRACE_UNPROVEN,
            normalized=True,
            upstream=trace.failure,
        )
    if (
        expression.root != value
        or expression.width != 2
        or expression.constant != 0
        or len(expression.terms) != 1
    ):
        return _refuse_far_8616(
            FarScaledReturnFailure8616.SEGMENT_SHAPE_MISMATCH, normalized=True,
        )
    term = expression.terms[0]
    if (
        not isinstance(term.source, IRAddress)
        or not _same_stack_storage_8616(term.source, storage)
        or term.coefficient != 1
    ):
        return _refuse_far_8616(
            FarScaledReturnFailure8616.SEGMENT_SHAPE_MISMATCH, normalized=True,
        )
    if not _leaf_sites_match_8616(expression.definition_path, (access,)):
        return _refuse_far_8616(
            FarScaledReturnFailure8616.SEGMENT_LEAF_MISMATCH, normalized=True,
        )
    segment_path: tuple[IndexedAddressDefinitionSite8616, ...] = expression.definition_path
    return segment_path


def prove_stack_argument_far_scaled_return_8616(
    boundary: ExactFunctionRangeBoundary8616,
    artifact: SSAFunctionArtifact,
    base_storage: IRAddress,
    segment_storage: IRAddress,
    index_storage: IRAddress,
) -> FarScaledReturnResult8616:
    """Prove far DX:AX equals input segment and modular scaled input offset.

    The result is IR evidence only. It does not authorize a C pointer type or
    return expression until a later layer binds the guest segment and offset.
    """
    if (
        not _same_stack_storage_8616(
            segment_storage,
            IRAddress(
                space=base_storage.space,
                base=base_storage.base,
                offset=base_storage.offset + 2,
                size=base_storage.size,
                status=base_storage.status,
                segment_origin=base_storage.segment_origin,
            ),
        )
        or _same_stack_storage_8616(segment_storage, index_storage)
    ):
        return _refuse_far_8616(FarScaledReturnFailure8616.INPUT_SHAPE_MISMATCH)
    offset = prove_stack_argument_scaled_return_8616(
        boundary, artifact, base_storage, index_storage,
    )
    if not offset.complete:
        return _refuse_far_8616(
            FarScaledReturnFailure8616.OFFSET_UNPROVEN,
            upstream=offset.failure,
        )
    segment_use = prove_stack_argument_modular_return_use_8616(
        boundary, artifact, segment_storage,
        return_register=ModularReturnRegister8616.DX,
    )
    if segment_use.verdict is not ModularArgumentUseVerdict8616.PROVEN:
        return _refuse_far_8616(
            FarScaledReturnFailure8616.SEGMENT_USE_UNPROVEN,
            normalized=True,
            upstream=segment_use.failure,
        )
    segment_key = segment_use.input_access_key
    if (
        segment_key is None
        or segment_use.return_instruction_addr != offset.return_instruction_addr
        or segment_key == offset.base_access_key
        or segment_key == offset.index_access_key
    ):
        return _refuse_far_8616(
            FarScaledReturnFailure8616.RETURN_SITE_CONFLICT, normalized=True,
        )
    access = _approved_access_8616(artifact, segment_key, segment_storage)
    if access is None:
        return _refuse_far_8616(
            FarScaledReturnFailure8616.SEGMENT_ACCESS_UNPROVEN, normalized=True,
        )
    segment_path = _prove_far_segment_identity_8616(
        artifact, segment_key, access, segment_storage,
    )
    if isinstance(segment_path, FarScaledReturnResult8616):
        return segment_path
    return FarScaledReturnResult8616(
        ScaledReturnVerdict8616.PROVEN,
        None,
        ScaledReturnStats8616(1, 1, 1, 1, 0),
        offset,
        segment_key,
        offset.return_instruction_addr,
        segment_path,
    )


__all__ = [
    "FarScaledReturnFailure8616", "FarScaledReturnResult8616",
    "ScaledReturnFailure8616", "ScaledReturnResult8616", "ScaledReturnStats8616",
    "ScaledReturnVerdict8616", "prove_stack_argument_far_scaled_return_8616",
    "prove_stack_argument_scaled_return_8616",
]
