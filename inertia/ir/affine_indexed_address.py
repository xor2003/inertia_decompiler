"""Retain complete modular affine sums for indexed segmented addresses.

Layer: IR.
Responsibility: consume exact machine-access normalization and scalar affine
provenance for every address component. No term is guessed to be a pointer or
induction variable. This does not prove memory-load stability, ranges, Alias
identity, physical disjointness, types, or binary coverage.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from .core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from .indexed_address_access_normalization import (
    NormalizedIndexedAddressAccess8616,
    normalize_indexed_address_accesses_8616,
)
from .indexed_address_contracts import IndexedAddressStats8616
from .scalar_affine_contracts import ScalarAffineExpression8616, ScalarAffineFailure8616, ScalarAffineTerm8616
from .scalar_affine_trace import trace_scalar_affine_expression_8616
from .ssa_function import SSAFunctionArtifact


class AffineIndexedAddressFailure8616(StrEnum):
    """Why the exact segmented address sum remains unproved."""

    SOURCE_MISMATCH = "source_mismatch"
    ADDRESS_UNPROVEN = "address_unproven"
    COMPONENT_UNPROVEN = "component_unproven"


@dataclass(frozen=True, slots=True)
class _Projection8616:
    """Atomic source projection or explicit scalar component refusal."""

    components: tuple[ScalarAffineExpression8616, ...]
    failure: AffineIndexedAddressFailure8616 | None
    component_failure: ScalarAffineFailure8616 | None = None


def _same_access_8616(
    left: NormalizedIndexedAddressAccess8616, right: NormalizedIndexedAddressAccess8616,
) -> bool:
    """Include capture identities omitted by ordinary value equality."""
    return bool(left == right and left.address.to_dict() == right.address.to_dict())


def _address_proven_8616(access: NormalizedIndexedAddressAccess8616) -> bool:
    """Require exact 16-bit components and coherent segmented access width."""
    address = access.address
    if access.failure is not None or not access.complete:
        return False
    coherent = (address.status is AddressStatus.STABLE
                and address.segment_origin is SegmentOrigin.PROVEN
                and address.size == access.access_size and type(address.offset) is int
                and len(address.base_values) == len(address.base))
    if not coherent:
        return False
    return all(value.space is MemSpace.REG and value.name == name and value.size == 2
               and value.offset == 0 and value.index is None and not value.index_shift
               for name, value in zip(address.base, address.base_values, strict=True))


def _project_8616(
    artifact: SSAFunctionArtifact, access: NormalizedIndexedAddressAccess8616,
) -> _Projection8616:
    """Trace all current components atomically, never publishing a partial sum."""
    normalization = normalize_indexed_address_accesses_8616(artifact)
    matches = tuple(item for item in normalization.accesses if _same_access_8616(item, access))
    blocks = tuple(block for block in artifact.blocks if block.addr == access.block_addr)
    if not normalization.closed or len(matches) != 1 or len(blocks) != 1 or blocks[0].refusals:
        return _Projection8616((), AffineIndexedAddressFailure8616.SOURCE_MISMATCH)
    if not _address_proven_8616(access):
        return _Projection8616((), AffineIndexedAddressFailure8616.ADDRESS_UNPROVEN)
    components: list[ScalarAffineExpression8616] = []
    for value in access.address.base_values:
        traced = trace_scalar_affine_expression_8616(
            artifact, value, block_addr=access.block_addr, before_index=min(access.member_instr_indices),
        )
        if not traced.complete or traced.expression is None:
            return _Projection8616((), AffineIndexedAddressFailure8616.COMPONENT_UNPROVEN, traced.failure)
        components.append(traced.expression)
    return _Projection8616(tuple(components), None)


def _expression_evidence_8616(expression: ScalarAffineExpression8616) -> tuple[object, ...]:
    """Compare complete structured provenance rather than rendered text."""
    sources: list[object] = []
    for term in expression.terms:
        source = term.source
        if isinstance(source, IRAddress):
            source_evidence: object = source.to_dict()
        else:
            source_evidence = (source.function_addr, source.register_name, source.size)
        sources.append((term.value.to_dict(), source_evidence, term.coefficient))
    return (expression.root.to_dict(), expression.width, expression.constant,
            tuple(sources), expression.definition_path)


@dataclass(frozen=True, slots=True)
class AffineIndexedAddressReceipt8616:
    """Replayable address sum retaining all components and exact source access."""

    artifact: SSAFunctionArtifact
    access: NormalizedIndexedAddressAccess8616
    components: tuple[ScalarAffineExpression8616, ...]
    failure: AffineIndexedAddressFailure8616 | None
    component_failure: ScalarAffineFailure8616 | None
    stats: IndexedAddressStats8616

    @property
    def complete(self) -> bool:
        """Require current source, exact component provenance and closed counts."""
        counts = (self.stats.raw_fact_count, self.stats.normalized_fact_count,
                  self.stats.classified_fact_count, self.stats.materialized_count,
                  self.stats.failure_count, self.stats.coalesced_fact_count)
        expected = (self.access.raw_fact_count, 1, 1, 1, 0, self.access.raw_fact_count - 1)
        if (self.failure is not None or self.component_failure is not None
                or not all(type(count) is int for count in counts) or counts != expected):
            return False
        current = _project_8616(self.artifact, self.access)
        if current.failure is not None or not all(component.complete for component in self.components):
            return False
        return (tuple(_expression_evidence_8616(component) for component in current.components)
                == tuple(_expression_evidence_8616(component) for component in self.components))

    @property
    def constant(self) -> int | None:
        """Return the modular displacement, not a physical linear address."""
        if not self.complete:
            return None
        return int((self.access.address.offset + sum(component.constant for component in self.components)) & 0xFFFF)

    @property
    def terms(self) -> tuple[ScalarAffineTerm8616, ...]:
        """Retain distinct load values; do not merge by stack-address spelling."""
        if not self.complete:
            return ()
        return tuple(term for component in self.components for term in component.terms)


def prove_affine_indexed_address_8616(
    artifact: SSAFunctionArtifact, access: NormalizedIndexedAddressAccess8616,
) -> AffineIndexedAddressReceipt8616:
    """Retain every component or a typed atomic refusal for one access group."""
    projected = _project_8616(artifact, access)
    accepted = int(projected.failure is None)
    raw = max(1, access.raw_fact_count)
    return AffineIndexedAddressReceipt8616(
        artifact, access, projected.components, projected.failure, projected.component_failure,
        IndexedAddressStats8616(raw, 1, 1, accepted, 1 - accepted, raw - 1),
    )
