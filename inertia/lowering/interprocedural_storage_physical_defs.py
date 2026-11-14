# cython: language_level=3, infer_types=True
"""Prove logical call sources from byte-executed outgoing stack stores.

Layer: Types/Lowering.
Responsibility: trace exact SSA values through physical byte stores and bind
them to one structured logical call-argument source. This module consumes IR
and callsite evidence; it does not infer signatures, classify C types, or
mutate code generation.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import replace

from inertia.ir.core import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from inertia.ir.scalar_value_projection import (
    ScalarProjectionKind8616,
    scalar_active_unary_projection_8616,
    scalar_produced_decoration_8616,
    scalar_read_projection_8616,
)
from inertia.semantics.callsite_summary import CallsitePushSourceKind8616

from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
)
from .interprocedural_storage_reaching_contracts import (
    CallArgumentDefinitionFailure8616,
    LogicalPushValue8616,
    PhysicalCallArgumentPiece8616,
    PhysicalPushStoreSlice8616,
    SSAInstructionSite8616,
)
import operator
import builtins

__all__ = [
    "logical_push_value_8616",
    "reaching_definition_width_8616",
    "resolve_physical_store_definitions_8616",
]


@cython.ccall
def reaching_definition_width_8616(
    definition: StorageReachingDefinition8616,
) -> cython.longlong:
    """Return one exact source-piece width from the owned definition contract."""
    source_storage: object
    source_storage = definition.source_storage
    if source_storage is not None:
        source_width = source_storage.width
        return source_width if isinstance(source_width, int) else 0
    value_width = definition.value.size
    return value_width if isinstance(value_width, int) else 0


def _prior_value_definition_8616(
    site: SSAInstructionSite8616,
    value: IRValue,
) -> IRInstr | None:
    """Return one prior instruction defining an exact SSA value or VEX tmp."""
    candidates = tuple(
        instr
        for instr in iter(site.block.instrs[: site.instr_index])
        if instr.dst is not None
        and (
            (
                isinstance(value.source_tmp, int)
                and operator.eq(instr.dst.source_tmp, value.source_tmp)
            )
            or (
                value.source_tmp is None
                and instr.dst.space is value.space
                and operator.eq(instr.dst.name, value.name)
                and operator.eq(instr.dst.version, value.version)
                and operator.eq(instr.dst.size, value.size)
            )
        )
    )
    return candidates[0] if len(candidates) == 1 else None


@cython.ccall
def _logical_source_slice_8616(
    site: SSAInstructionSite8616,
    value: IRValue,
    logical_width: cython.longlong,
    seen: object = frozenset(),
    *,
    follow_register_definitions: cython.bint = False,
) -> object:
    """Trace one physical store value to its logical source and byte offset."""
    definition: object
    projection: object
    traced: object
    unary: object
    key = (value.space, value.name, value.version, value.source_tmp, value.size)
    if key in seen:
        return None
    unary = value.active_unary
    if unary is not None:
        projection = scalar_active_unary_projection_8616(value)
        if (projection is None or projection.signed
                or projection.target_bits >= projection.source_bits
                or projection.target_bits != 8):
            return None
        return _logical_source_slice_8616(
            site, unary.operand, logical_width, seen | {key},
            follow_register_definitions=follow_register_definitions,
        )
    if value.const is not None or (
        value.space is MemSpace.REG
        and value.size >= logical_width
        and not follow_register_definitions
    ):
        return value, 0
    definition = _prior_value_definition_8616(site, value)
    if definition is None:
        return (
            (value, 0)
            if value.space is MemSpace.REG and value.size >= logical_width
            else None
        )
    if definition.op == "MOV" and len(definition.args) == 1:
        source = definition.args[0]
        return (
            _logical_source_slice_8616(
                site,
                source,
                logical_width,
                seen | {key},
                follow_register_definitions=follow_register_definitions,
            )
            if isinstance(source, IRValue)
            else None
        )
    if definition.op.startswith("Iop_Shr") and len(definition.args) == 2:
        source, shift = definition.args
        if (
            isinstance(source, IRValue)
            and isinstance(shift, IRValue)
            and isinstance(shift.const, int)
            and shift.const % 8 == 0
        ):
            traced = _logical_source_slice_8616(
                site,
                source,
                logical_width,
                seen | {key},
                follow_register_definitions=follow_register_definitions,
            )
            return None if traced is None else (traced[0], traced[1] + shift.const // 8)
    return None


@cython.ccall
def _bp_affine_8616(
    site: SSAInstructionSite8616,
    value: IRValue,
    seen: object = frozenset(),
) -> object:
    """Resolve one structured SSA value to ``BP * coefficient + offset``."""
    definition: object
    left_affine: object
    right_affine: object
    if value.space is MemSpace.REG and value.name == "bp":
        return 1, value.offset
    if isinstance(value.const, int):
        return 0, value.const
    key = (value.space, value.name, value.version, value.source_tmp, value.size)
    if key in seen:
        return None
    definition = _prior_value_definition_8616(site, value)
    if definition is None:
        return None
    if definition.op == "MOV" and len(definition.args) == 1:
        source = definition.args[0]
        return (
            _bp_affine_8616(site, source, seen | {key})
            if isinstance(source, IRValue)
            else None
        )
    if definition.op in {"Iop_Add16", "Iop_Sub16"} and len(definition.args) == 2:
        left, right = definition.args
        if not isinstance(left, IRValue) or not isinstance(right, IRValue):
            return None
        left_affine = _bp_affine_8616(site, left, seen | {key})
        right_affine = _bp_affine_8616(site, right, seen | {key})
        if left_affine is None or right_affine is None:
            return None
        sign = 1 if definition.op == "Iop_Add16" else -1
        return (
            left_affine[0] + sign * right_affine[0],
            left_affine[1] + sign * right_affine[1],
        )
    return None


@cython.ccall
def _captured_root_producer_8616(
    site: SSAInstructionSite8616, value: IRValue,
) -> IRInstr | None:
    """Authenticate an unchanged capture against its exact prior producer."""
    definition: object
    projection: object
    definition = _prior_value_definition_8616(site, value)
    if definition is None or definition.dst is None or value.active_unary is not None:
        return None
    if operator.ne(value.size, definition.dst.size) or operator.ne(definition.size, value.size):
        return None
    projection = scalar_read_projection_8616(
        read_expr=value.expr, read_bits=value.size * 8,
        produced=scalar_produced_decoration_8616(definition),
        produced_bits=definition.size * 8,
    )
    if projection is None or projection.kind is ScalarProjectionKind8616.CONVERSION:
        return None
    return definition


@cython.ccall
def _same_logical_root_8616(
    left: IRValue, right: IRValue, width: cython.longlong,
    left_site: SSAInstructionSite8616, right_site: SSAInstructionSite8616,
) -> cython.bint:
    """Bind captures to the same actual producer; compare bare roots exactly."""
    producer: object
    if left.active_unary is not None or right.active_unary is not None:
        return False
    if left.const is not None or right.const is not None:
        mask = (1 << (width * 8)) - 1
        return bool(
            isinstance(left.const, int) and isinstance(right.const, int)
            and operator.eq(left.const & mask, right.const & mask)
        )
    if left.source_tmp is not None or right.source_tmp is not None:
        if left.source_tmp is None or operator.ne(left.source_tmp, right.source_tmp):
            return False
        producer = _captured_root_producer_8616(left_site, left)
        return bool(
            producer is not None
            and producer is _captured_root_producer_8616(right_site, right)
            and operator.eq(replace(left, version=right.version), right)
            and operator.eq(left.memory_access_insn, right.memory_access_insn)
        )
    return bool(left == right and operator.eq(left.memory_access_insn, right.memory_access_insn))


def logical_push_value_8616(
    sites: object,
    piece: PhysicalCallArgumentPiece8616,
    *,
    follow_register_definitions: cython.bint = False,
) -> tuple[LogicalPushValue8616 | None, CallArgumentDefinitionFailure8616 | None]:
    """Reconstruct one logical pushed value from exact physical stores."""
    root: object
    traced: object
    address: object
    site: object
    value: object
    candidates = tuple(
        (site, site.instr.args[0], site.instr.args[1])
        for site in iter(sites)
        if site.instr.op == "STORE"
        and operator.eq(site.instr.addr, piece.push_addr)
        and len(site.instr.args) == 2
        and isinstance(site.instr.args[0], IRAddress)
        and site.instr.args[0].space is MemSpace.SS
        and site.instr.args[0].base == ("sp",)
        and site.instr.args[0].status is AddressStatus.STABLE
        and site.instr.args[0].segment_origin is SegmentOrigin.PROVEN
        and isinstance(site.instr.args[1], IRValue)
        and operator.eq(site.instr.args[0].size, site.instr.args[1].size)
    )
    if not candidates:
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    ordered = tuple(sorted(candidates, key=lambda item: item[1].offset))
    first_address = ordered[0][1]
    cursor = first_address.offset
    source_offset = 0
    slices: list[PhysicalPushStoreSlice8616] = []
    roots: list[IRValue] = []
    for site, address, value in ordered:
        if operator.ne(address.offset, cursor) or operator.ne(address.base_values, first_address.base_values):
            return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_CONFLICT
        traced = _logical_source_slice_8616(
            site,
            value,
            piece.width,
            follow_register_definitions=follow_register_definitions,
        )
        if traced is None or operator.ne(traced[1], source_offset):
            return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
        slices.append(PhysicalPushStoreSlice8616(site, address, value, source_offset))
        roots.append(traced[0])
        cursor += address.size
        source_offset += address.size
    if operator.ne(source_offset, piece.width):
        return None, CallArgumentDefinitionFailure8616.SOURCE_WIDTH_CONFLICT
    if any(
        not _same_logical_root_8616(roots[0], root, piece.width, slices[0].site, item.site)
        for root, item in builtins.iter(zip(roots[1:], slices[1:], strict=True))
    ):
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_CONFLICT
    root = next((item for item in iter(roots) if operator.eq(item.size, piece.width)), roots[0])
    result = LogicalPushValue8616(root, piece.width, tuple(slices))
    if not result.complete:
        return None, CallArgumentDefinitionFailure8616.SOURCE_WIDTH_CONFLICT
    return result, None


def resolve_physical_store_definitions_8616(
    sites: object,
    piece: PhysicalCallArgumentPiece8616,
) -> tuple[
    tuple[StorageReachingDefinition8616, ...] | None,
    CallArgumentDefinitionFailure8616 | None,
]:
    """Bind one logical pushed value to its exact outgoing stack-store pieces."""
    affine: object
    logical: object
    logical_failure: object
    source = piece.source
    kind = source[0] if source else None
    logical, logical_failure = logical_push_value_8616(
        sites,
        piece,
        follow_register_definitions=kind
        in {
            CallsitePushSourceKind8616.IMMEDIATE,
            CallsitePushSourceKind8616.IMMEDIATE.value,
        },
    )
    if logical_failure is not None or logical is None:
        return (
            None,
            logical_failure
            or CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND,
        )
    root = logical.root
    source_storages: object
    if kind in {
        CallsitePushSourceKind8616.IMMEDIATE,
        CallsitePushSourceKind8616.IMMEDIATE.value,
    }:
        if len(source) != 2 or not isinstance(source[1], int):
            return None, CallArgumentDefinitionFailure8616.SOURCE_SHAPE_CONFLICT
        mask = (1 << (piece.width * 8)) - 1
        if root.const is None or operator.ne(root.const & mask, source[1] & mask):
            return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
        source_storages = (None,) * len(logical.slices)
    elif kind in {
        CallsitePushSourceKind8616.BP_ADDRESS,
        CallsitePushSourceKind8616.BP_ADDRESS.value,
    }:
        if len(source) != 2 or not isinstance(source[1], int):
            return None, CallArgumentDefinitionFailure8616.SOURCE_SHAPE_CONFLICT
        affine = _bp_affine_8616(logical.slices[0].site, root)
        if (
            affine is None
            or affine[0] != 1
            or operator.ne(affine[1] & 0xFFFF, source[1] & 0xFFFF)
        ):
            return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
        source_storages = tuple(
            StorageIdentity8616(
                kind=StorageIdentityKind8616.STACK,
                width=address.size,
                address=IRAddress(
                    space=MemSpace.SS,
                    base=("bp",),
                    offset=source[1] + offset,
                    size=address.size,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.PROVEN,
                ),
            )
            for item in iter(logical.slices)
            for address, offset in iter(((item.address, item.source_offset),))
        )
    elif kind in {
        CallsitePushSourceKind8616.EXPR,
        CallsitePushSourceKind8616.EXPR.value,
    }:
        source_storages = (None,) * len(logical.slices)
    else:
        return None, CallArgumentDefinitionFailure8616.UNSUPPORTED_SOURCE_KIND
    definitions = tuple(
        StorageReachingDefinition8616(
            value=value,
            block_addr=site.block.addr,
            instr_index=site.instr_index,
            instr_addr=piece.push_addr,
            source_storage=source_storage,
            logical_push=logical,
        )
        for item, source_storage in builtins.iter(zip(
            logical.slices,
            source_storages,
            strict=True,
        ))
        for site, value in iter(((item.site, item.value),))
    )
    if any(not definition.is_complete for definition in iter(definitions)):
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    return definitions, None
