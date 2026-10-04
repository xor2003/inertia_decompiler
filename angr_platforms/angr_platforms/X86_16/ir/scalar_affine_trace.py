"""Trace exact modular affine scalar expressions through function SSA.

Layer: IR.
Responsibility: normalize constants, MOVs, ADD/SUB, constant shifts, direct
stack loads, and closed byte-composed logical word loads into one typed affine
expression with exact definition provenance. Explicit opt-in admits word-sized
entry SP/BP roots in the entry block without predecessors. Under that same opt-in,
bare BP reads may cross supplied CFG paths only to one exact reaching definition,
with explicit BP-preserving CALL effects. Other missing definitions, unsupported
operations and unproved cross-block flow refuse atomically.
This module does not choose pointer segments, infer aliases or types, mutate
code generation, or consume callsite summaries.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .core import IRValue, MemSpace
from .frame_register_reaching_definition import (
    frame_register_family_8616,
    is_bare_word_bp_read_8616,
    resolve_bp_reaching_definition_8616,
)
from .indexed_address_contracts import (
    IndexedAddressDefinitionSite8616,
    IndexedAddressFailureKind8616,
)
from .logical_memory_value_trace import trace_logical_word_load_8616
from .scalar_affine_contracts import (
    ScalarAffineExpression8616,
    ScalarAffineFailure8616,
    ScalarAffineTerm8616,
    ScalarAffineTrace8616,
    ScalarAffineTraceStats8616,
)
from .scalar_affine_sources import entry_register_affine_term_8616, stack_affine_source_8616
from .scalar_definitions import (
    ScalarDefinition8616,
    ScalarDefinitionIndex8616,
    ScalarDefinitionKey8616,
    build_scalar_definition_index_8616,
    reaching_scalar_definitions_8616,
    scalar_definition_key_8616,
)
from .scalar_value_projection import (
    ScalarProjectionKind8616,
    scalar_produced_decoration_8616,
    scalar_read_projection_8616,
)
from .ssa_function import SSAFunctionArtifact

type _AffineVisitKey8616 = tuple[int, ScalarDefinitionKey8616]


@dataclass(frozen=True, slots=True)
class _AffineNode8616:
    """Internal normalized expression before the root contract is attached."""

    constant: int
    terms: tuple[ScalarAffineTerm8616, ...]
    path: tuple[IndexedAddressDefinitionSite8616, ...]


@dataclass(frozen=True, slots=True)
class _NodeTrace8616:
    """Internal successful node or one typed refusal."""

    node: _AffineNode8616 | None
    failure: ScalarAffineFailure8616 | None


def _refusal_8616(failure: ScalarAffineFailure8616) -> ScalarAffineTrace8616:
    """Build one atomic trace refusal with closed failure accounting."""
    return ScalarAffineTrace8616(
        None,
        failure,
        ScalarAffineTraceStats8616(1, 1, 1, 0, 1),
    )


def _site_8616(
    definition: ScalarDefinition8616,
) -> IndexedAddressDefinitionSite8616 | None:
    """Project one scalar definition to an exact path site."""
    instruction = definition.instruction
    if instruction.addr is None:
        return None
    return IndexedAddressDefinitionSite8616(
        definition.block_addr,
        definition.instr_index,
        instruction.addr,
        instruction.op,
    )


def _definition_8616(
    definitions: ScalarDefinitionIndex8616,
    value: IRValue,
    *,
    block_addr: int,
    before_index: int,
) -> tuple[ScalarDefinition8616 | None, ScalarAffineFailure8616 | None]:
    """Return one exact same-block reaching definition or a typed refusal."""
    candidates = reaching_scalar_definitions_8616(
        definitions,
        value,
        block_addr=block_addr,
        before_index=before_index,
    )
    if not candidates:
        return None, ScalarAffineFailure8616.DEFINITION_MISSING
    if len(candidates) != 1:
        return None, ScalarAffineFailure8616.DEFINITION_CONFLICT
    return candidates[0], None


def _logical_failure_8616(
    failure: IndexedAddressFailureKind8616 | None,
) -> ScalarAffineFailure8616:
    """Map logical-load tracing failures to the scalar affine contract."""
    if failure is IndexedAddressFailureKind8616.INDEX_DEFINITION_MISSING:
        return ScalarAffineFailure8616.DEFINITION_MISSING
    if failure is IndexedAddressFailureKind8616.INDEX_DEFINITION_CONFLICT:
        return ScalarAffineFailure8616.DEFINITION_CONFLICT
    if failure is IndexedAddressFailureKind8616.INDEX_EXPRESSION_UNSUPPORTED:
        return ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED
    return ScalarAffineFailure8616.SOURCE_UNPROVEN


def _scale_node_8616(
    node: _AffineNode8616,
    factor: int,
    mask: int,
) -> _AffineNode8616:
    """Apply one modular constant scale without losing term provenance."""
    terms = tuple(
        ScalarAffineTerm8616(term.value, term.source, coefficient)
        for term in node.terms
        if (coefficient := term.coefficient * factor & mask) != 0
    )
    return _AffineNode8616(node.constant * factor & mask, terms, node.path)


def _combine_nodes_8616(
    left: _AffineNode8616,
    right: _AffineNode8616,
    *,
    sign: int,
    mask: int,
) -> _AffineNode8616:
    """Combine two affine nodes under modular addition or subtraction."""
    scaled_right = _scale_node_8616(right, sign, mask)
    return _AffineNode8616(
        (left.constant + scaled_right.constant) & mask,
        (*left.terms, *scaled_right.terms),
        (*left.path, *scaled_right.path),
    )


@dataclass(frozen=True, slots=True)
class _AffineTraceContext8616:
    """Shared recursion state for exact scalar affine normalization."""

    artifact: SSAFunctionArtifact
    definitions: ScalarDefinitionIndex8616
    block_addr: int
    width: int
    mask: int
    allow_entry_registers: bool


def _trace_argument_8616(
    ctx: _AffineTraceContext8616,
    argument: IRValue,
    definition: ScalarDefinition8616,
    seen: frozenset[_AffineVisitKey8616],
) -> _NodeTrace8616:
    """Recurse into one exact scalar argument at the definition boundary."""
    return _trace_value_8616(
        ctx.artifact,
        ctx.definitions,
        argument,
        block_addr=ctx.block_addr,
        before_index=definition.instr_index,
        width=ctx.width,
        mask=ctx.mask,
        seen=seen,
        allow_entry_registers=ctx.allow_entry_registers,
    )


def _proven_affine_definition_8616(
    artifact: SSAFunctionArtifact,
    definitions: ScalarDefinitionIndex8616,
    value: IRValue,
    *,
    block_addr: int,
    before_index: int,
    allow_entry_registers: bool,
) -> tuple[ScalarDefinition8616, IndexedAddressDefinitionSite8616] | _NodeTrace8616:
    """Resolve the unique reaching definition or the entry-register leaf."""
    definition, failure = _definition_8616(
        definitions,
        value,
        block_addr=block_addr,
        before_index=before_index,
    )
    if failure is not None or definition is None:
        if (allow_entry_registers and failure is ScalarAffineFailure8616.DEFINITION_MISSING
                and artifact.predecessor_map.get(block_addr) == ()):
            term = entry_register_affine_term_8616(value, function_addr=artifact.function_addr, block_addr=block_addr)
            sites = _entry_leaf_preservation_sites_8616(artifact, value, block_addr, before_index)
            if term is not None and sites is not None:
                return _NodeTrace8616(_AffineNode8616(0, (term,), sites), None)
        return _NodeTrace8616(None, failure or ScalarAffineFailure8616.DEFINITION_MISSING)
    site = _site_8616(definition)
    if site is None:
        return _NodeTrace8616(None, ScalarAffineFailure8616.SOURCE_UNPROVEN)
    return definition, site


def _entry_leaf_preservation_sites_8616(
    artifact: SSAFunctionArtifact, value: IRValue, block_addr: int, before_index: int,
) -> tuple[IndexedAddressDefinitionSite8616, ...] | None:
    """Retain exact CALL sites or refuse unproved entry-register transport."""
    block = next((item for item in artifact.blocks if item.addr == block_addr), None)
    if block is None or block.refusals or not 0 <= before_index <= len(block.instrs):
        return None
    sites: list[IndexedAddressDefinitionSite8616] = []
    for index, instruction in enumerate(block.instrs[:before_index]):
        destination = instruction.dst
        if destination is not None and destination.space is MemSpace.REG and destination.name in frame_register_family_8616(value.name or ""):
            return None
        if instruction.op != "CALL":
            continue
        effect = instruction.call_stack_effect
        if instruction.addr is None or effect is None or not effect.complete:
            return None
        if value.name == "sp" and effect.net_stack_delta != 0:
            return None
        if value.name == "bp" and not effect.bp_preserved:
            return None
        sites.append(IndexedAddressDefinitionSite8616(block.addr, index, instruction.addr, instruction.op))
    return tuple(sites)


def _leaf_term_trace_8616(
    ctx: _AffineTraceContext8616,
    definition: ScalarDefinition8616,
    site: IndexedAddressDefinitionSite8616,
) -> _NodeTrace8616 | None:
    """Return the leaf term for direct stack loads or closed word reads."""
    instruction = definition.instruction
    source = stack_affine_source_8616(instruction, ctx.width)
    if source is not None and instruction.dst is not None:
        term = ScalarAffineTerm8616(instruction.dst, source, 1)
        return _NodeTrace8616(_AffineNode8616(0, (term,), (site,)), None)
    if instruction.op != "Iop_Or16" or ctx.width != 2:
        return None
    logical = trace_logical_word_load_8616(
        instruction,
        ctx.definitions,
        ctx.artifact.logical_memory,
        function_addr=ctx.artifact.function_addr,
        block_addr=ctx.block_addr,
        before_index=definition.instr_index,
    )
    if not logical.complete or logical.source is None or instruction.dst is None:
        return _NodeTrace8616(None, _logical_failure_8616(logical.failure))
    term = ScalarAffineTerm8616(instruction.dst, logical.source, 1)
    return _NodeTrace8616(
        _AffineNode8616(0, (term,), (site, *logical.definition_path)),
        None,
    )


def _mov_copy_trace_8616(
    ctx: _AffineTraceContext8616,
    definition: ScalarDefinition8616,
    site: IndexedAddressDefinitionSite8616,
    next_seen: frozenset[_AffineVisitKey8616],
) -> _NodeTrace8616:
    """Trace through one exact MOV copy, retaining the copy site."""
    argument = definition.instruction.args[0]
    if not isinstance(argument, IRValue):
        return _NodeTrace8616(None, ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED)
    traced = _trace_argument_8616(ctx, argument, definition, next_seen)
    if traced.node is None:
        return traced
    return _NodeTrace8616(
        _AffineNode8616(
            traced.node.constant,
            traced.node.terms,
            (site, *traced.node.path),
        ),
        None,
    )


def _addsub_trace_8616(
    ctx: _AffineTraceContext8616,
    definition: ScalarDefinition8616,
    site: IndexedAddressDefinitionSite8616,
    next_seen: frozenset[_AffineVisitKey8616],
) -> _NodeTrace8616:
    """Combine both operand traces under modular addition or subtraction."""
    instruction = definition.instruction
    if len(instruction.args) != 2:
        return _NodeTrace8616(None, ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED)
    left, right = instruction.args
    if not isinstance(left, IRValue) or not isinstance(right, IRValue):
        return _NodeTrace8616(None, ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED)
    left_trace = _trace_argument_8616(ctx, left, definition, next_seen)
    if left_trace.node is None:
        return left_trace
    right_trace = _trace_argument_8616(ctx, right, definition, next_seen)
    if right_trace.node is None:
        return right_trace
    combined = _combine_nodes_8616(
        left_trace.node,
        right_trace.node,
        sign=1 if instruction.op.startswith("Iop_Add") else -1,
        mask=ctx.mask,
    )
    return _NodeTrace8616(
        _AffineNode8616(combined.constant, combined.terms, (site, *combined.path)),
        None,
    )


def _shl_trace_8616(
    ctx: _AffineTraceContext8616,
    definition: ScalarDefinition8616,
    site: IndexedAddressDefinitionSite8616,
    next_seen: frozenset[_AffineVisitKey8616],
) -> _NodeTrace8616:
    """Trace through one constant left shift as a modular scale."""
    argument, amount = definition.instruction.args
    if (
        not isinstance(argument, IRValue)
        or not isinstance(amount, IRValue)
        or not isinstance(amount.const, int)
        or not 0 <= amount.const < ctx.width * 8
    ):
        return _NodeTrace8616(None, ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED)
    traced = _trace_argument_8616(ctx, argument, definition, next_seen)
    if traced.node is None:
        return traced
    scaled = _scale_node_8616(traced.node, 1 << amount.const, ctx.mask)
    return _NodeTrace8616(
        _AffineNode8616(scaled.constant, scaled.terms, (site, *scaled.path)),
        None,
    )


def _bp_transport_trace_8616(
    artifact: SSAFunctionArtifact, definitions: ScalarDefinitionIndex8616, value: IRValue,
    *, block_addr: int, before_index: int, width: int, mask: int,
    seen: frozenset[_AffineVisitKey8616],
) -> _NodeTrace8616 | tuple[IndexedAddressDefinitionSite8616, ...]:
    """Consume exact BP transport, never infer preservation from absent writes."""
    proof = resolve_bp_reaching_definition_8616(
        artifact, value, block_addr=block_addr, before_index=before_index,
    )
    if not proof.complete:
        return _NodeTrace8616(None, proof.failure or ScalarAffineFailure8616.SOURCE_UNPROVEN)
    definition = proof.definition
    if definition is None or definition.block_addr == block_addr:
        return tuple(proof.preservation_sites)
    source = definition.instruction.dst
    assert source is not None
    traced = _trace_value_8616(
        artifact, definitions, source, block_addr=definition.block_addr,
        before_index=definition.instr_index + 1, width=width, mask=mask,
        allow_entry_registers=True, seen=seen | {(block_addr, scalar_definition_key_8616(value))},
    )
    if traced.node is None:
        return traced
    return _NodeTrace8616(_AffineNode8616(
        traced.node.constant, traced.node.terms,
        (*proof.preservation_sites, *traced.node.path),
    ), None)


def _definition_trace_8616(
    ctx: _AffineTraceContext8616, definition: ScalarDefinition8616,
    site: IndexedAddressDefinitionSite8616, next_seen: frozenset[_AffineVisitKey8616],
) -> _NodeTrace8616:
    """Normalize one resolved producer under the existing affine operations."""
    if definition.instruction.size != ctx.width:
        return _NodeTrace8616(None, ScalarAffineFailure8616.WIDTH_CONFLICT)
    leaf = _leaf_term_trace_8616(ctx, definition, site)
    if leaf is not None:
        return leaf
    instruction = definition.instruction
    expected_suffix = str(ctx.width * 8)
    if instruction.op == "MOV" and len(instruction.args) == 1:
        return _mov_copy_trace_8616(ctx, definition, site, next_seen)
    if instruction.op in {f"Iop_Add{expected_suffix}", f"Iop_Sub{expected_suffix}"}:
        return _addsub_trace_8616(ctx, definition, site, next_seen)
    if instruction.op == f"Iop_Shl{expected_suffix}" and len(instruction.args) == 2:
        return _shl_trace_8616(ctx, definition, site, next_seen)
    return _NodeTrace8616(None, ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED)


def _trace_value_8616(
    artifact: SSAFunctionArtifact,
    definitions: ScalarDefinitionIndex8616,
    value: IRValue,
    *,
    block_addr: int,
    before_index: int,
    width: int,
    mask: int,
    allow_entry_registers: bool = False,
    seen: frozenset[_AffineVisitKey8616] = frozenset(),
) -> _NodeTrace8616:
    """Normalize exact scalar values, crossing only proven BP transports."""
    if value.size != width:
        return _NodeTrace8616(None, ScalarAffineFailure8616.WIDTH_CONFLICT)
    if isinstance(value.const, int):
        if value.expr:
            return _NodeTrace8616(None, ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED)
        return _NodeTrace8616(_AffineNode8616(value.const & mask, (), ()), None)
    key = (block_addr, scalar_definition_key_8616(value))
    if key in seen:
        return _NodeTrace8616(None, ScalarAffineFailure8616.DEFINITION_CONFLICT)
    preservation_sites: tuple[IndexedAddressDefinitionSite8616, ...] = ()
    if allow_entry_registers and is_bare_word_bp_read_8616(value):
        transported = _bp_transport_trace_8616(
            artifact, definitions, value, block_addr=block_addr, before_index=before_index,
            width=width, mask=mask, seen=seen,
        )
        if isinstance(transported, _NodeTrace8616):
            return transported
        preservation_sites = transported
    resolved = _proven_affine_definition_8616(
        artifact,
        definitions,
        value,
        block_addr=block_addr,
        before_index=before_index,
        allow_entry_registers=allow_entry_registers,
    )
    if isinstance(resolved, _NodeTrace8616):
        return resolved
    definition, site = resolved
    # Capture identity proves lineage, not that a decorated read is a copy.
    # Only the exact producer's earned label may pass through unchanged;
    # conversions need their own affine proof and currently refuse.
    projection = scalar_read_projection_8616(
        read_expr=value.expr,
        read_bits=value.size * 8,
        produced=scalar_produced_decoration_8616(definition.instruction),
        produced_bits=definition.instruction.size * 8,
    )
    if projection is None or projection.kind is ScalarProjectionKind8616.CONVERSION:
        return _NodeTrace8616(None, ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED)
    ctx = _AffineTraceContext8616(
        artifact, definitions, block_addr, width, mask, allow_entry_registers
    )
    traced = _definition_trace_8616(ctx, definition, site, seen | {key})
    if traced.node is None or not preservation_sites:
        return traced
    return _NodeTrace8616(_AffineNode8616(
        traced.node.constant, traced.node.terms,
        (*preservation_sites, *traced.node.path),
    ), None)


def trace_scalar_affine_expression_8616(
    artifact: SSAFunctionArtifact,
    root: IRValue,
    *,
    block_addr: int,
    before_index: int,
    allow_entry_registers: bool = False,
) -> ScalarAffineTrace8616:
    """Trace modular terms; entry-register origins and BP transport are opt-in."""
    width = root.size
    if width not in {1, 2, 4} or before_index < 0:
        return _refusal_8616(ScalarAffineFailure8616.ROOT_UNPROVEN)
    mask = (1 << (width * 8)) - 1
    traced = _trace_value_8616(
        artifact,
        build_scalar_definition_index_8616(artifact),
        root,
        block_addr=block_addr,
        before_index=before_index,
        width=width,
        mask=mask,
        allow_entry_registers=allow_entry_registers,
    )
    if traced.node is None or traced.failure is not None:
        return _refusal_8616(traced.failure or ScalarAffineFailure8616.SOURCE_UNPROVEN)
    expression = ScalarAffineExpression8616(
        root,
        width,
        traced.node.constant,
        traced.node.terms,
        traced.node.path,
    )
    if not expression.complete:
        return _refusal_8616(ScalarAffineFailure8616.SOURCE_UNPROVEN)
    return ScalarAffineTrace8616(
        expression,
        None,
        ScalarAffineTraceStats8616(1, 1, 1, 1, 0),
    )


__all__ = ["trace_scalar_affine_expression_8616"]
