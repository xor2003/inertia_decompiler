"""Match structured call-argument sources to exact IR/SSA definitions.

Layer: Types/Lowering.
Responsibility: prove immediate, register, stack-load, address, and stable
segmented-memory source definitions for one physical call argument.
Consumes alias, widening, and typed facts. This module does not select logical
arguments, classify C types, or mutate codegen.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from ..callsite_summary import CallsitePushSourceKind8616
from ..ir import AddressStatus, IRAddress, IRInstr, IRValue, MemSpace, SegmentOrigin
from .interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageReachingDefinition8616,
)
from .interprocedural_storage_reaching_contracts import (
    CallArgumentDefinitionFailure8616,
    PhysicalCallArgumentPiece8616,
    SSAInstructionSite8616,
)

__all__ = ["resolve_argument_source_definitions_8616"]


def _storage_for_address_8616(address: IRAddress) -> StorageIdentity8616:
    """Project one stable segmented address to its architectural category."""
    kind = StorageIdentityKind8616.STACK if address.space is MemSpace.SS else StorageIdentityKind8616.MEMORY
    return StorageIdentity8616(kind=kind, width=address.size, address=address)


def _load_definitions_8616(
    sites: tuple[SSAInstructionSite8616, ...],
    fact: PhysicalCallArgumentPiece8616,
    *,
    space: MemSpace | None,
    base: tuple[str, ...],
    offset: int,
) -> tuple[tuple[StorageReachingDefinition8616, ...] | None, CallArgumentDefinitionFailure8616 | None]:
    """Prove byte-accurate LOAD coverage for one pushed memory value."""
    end = offset + fact.width
    candidates: list[tuple[SSAInstructionSite8616, IRAddress, IRValue]] = []
    for site in sites:
        instr = site.instr
        if instr.op != "LOAD" or instr.addr != fact.push_addr or instr.dst is None or not instr.args:
            continue
        address = instr.args[0]
        if not _load_address_covers_8616(address, base, space, offset, end):
            continue
        candidates.append((site, address, instr.dst))
    selected: list[tuple[SSAInstructionSite8616, IRAddress, IRValue]] = []
    cursor = offset
    while cursor < end:
        choices = tuple(candidate for candidate in candidates if candidate[1].offset == cursor)
        if not choices:
            return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
        if len(choices) != 1:
            return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_CONFLICT
        selected.append(choices[0])
        cursor += choices[0][1].size
    if len(selected) != len(candidates):
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_CONFLICT
    definitions = tuple(
        StorageReachingDefinition8616(
            value=value,
            block_addr=site.block.addr,
            instr_index=site.instr_index,
            instr_addr=fact.push_addr,
            source_storage=_storage_for_address_8616(address),
        )
        for site, address, value in selected
    )
    if not definitions or any(not definition.is_complete for definition in definitions):
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    return definitions, None


def _store_data_sites_8616(
    sites: tuple[SSAInstructionSite8616, ...],
    fact: PhysicalCallArgumentPiece8616,
) -> tuple[tuple[SSAInstructionSite8616, IRValue], ...]:
    """Return outgoing SS:SP stores emitted by one physical push."""
    stores: list[tuple[SSAInstructionSite8616, IRValue]] = []
    for site in sites:
        instr = site.instr
        if instr.op != "STORE" or instr.addr != fact.push_addr or len(instr.args) != 2:
            continue
        address, value = instr.args
        if _is_ss_sp_address_8616(address) and _store_value_matches_8616(value, fact.width):
            stores.append((site, value))
    return tuple(stores)


def _is_ss_sp_address_8616(address: object) -> bool:
    """Check the STORE target is the SS:SP push slot."""
    return (
        isinstance(address, IRAddress)
        and address.space is MemSpace.SS
        and address.base == ("sp",)
    )


def _store_value_matches_8616(value: object, width: int) -> bool:
    """Check the stored IRValue's size agrees with the pushed piece width."""
    return isinstance(value, IRValue) and (value.size <= 0 or value.size == width)


def _load_address_covers_8616(
    address: object,
    base: tuple[str, ...],
    space: MemSpace | None,
    offset: int,
    end: int,
) -> bool:
    """Check a LOAD address lands fully inside the pushed memory window."""
    return (
        isinstance(address, IRAddress)
        and _address_origin_matches_8616(address, base, space)
        and _address_range_covers_8616(address, offset, end)
    )


def _address_origin_matches_8616(
    address: IRAddress, base: tuple[str, ...], space: MemSpace | None
) -> bool:
    """Check the LOAD address shares the expected base and segment space."""
    return address.base == base and (space is None or address.space is space)


def _address_range_covers_8616(address: IRAddress, offset: int, end: int) -> bool:
    """Check the LOAD range is bounded by the pushed window."""
    return bool(
        address.offset >= offset
        and address.offset + address.size <= end
        and address.size > 0
    )


def _has_prior_binding_8616(site: SSAInstructionSite8616, value: IRValue) -> bool:
    """Return whether this block defines the exact value before its push."""
    return any(
        binding.instr_index < site.instr_index
        and binding.target.space is value.space
        and binding.target.name == value.name
        and binding.target.version == value.version
        for binding in site.block.bindings
    )


def _same_ssa_value_8616(lhs: IRValue, rhs: IRValue) -> bool:
    """Return whether two values name the same constant or SSA definition."""
    lhs_size = lhs.size
    rhs_size = rhs.size
    if not isinstance(lhs_size, int) or not isinstance(rhs_size, int):
        return False
    if lhs.const is not None or rhs.const is not None:
        lhs_const = lhs.const
        rhs_const = rhs.const
        return (
            isinstance(lhs_const, int)
            and isinstance(rhs_const, int)
            and lhs_const == rhs_const
            and lhs_size == rhs_size
        )
    return lhs.space is rhs.space and lhs.name == rhs.name and lhs.version == rhs.version and lhs_size == rhs_size


def _prior_definition_8616(
    site: SSAInstructionSite8616,
    value: IRValue,
) -> IRInstr | None:
    """Return the unique local instruction defining one exact SSA value."""
    candidates = tuple(
        instr
        for instr in site.block.instrs[: site.instr_index]
        if instr.dst is not None and _same_ssa_value_8616(instr.dst, value)
    )
    return candidates[0] if len(candidates) == 1 else None


def _has_bp_address_origin_8616(
    site: SSAInstructionSite8616,
    value: IRValue,
    *,
    offset: int,
    width: int,
    seen: frozenset[tuple[MemSpace, str | None, int | None]] = frozenset(),
) -> bool:
    """Trace one local SSA value to the exact structured ``BP+offset`` origin."""
    key = (value.space, value.name, value.version)
    if key in seen:
        return False
    definition = _prior_definition_8616(site, value)
    if definition is None or definition.op != "MOV" or len(definition.args) != 1:
        return False
    source = definition.args[0]
    if not isinstance(source, IRValue):
        return False
    if source.space is MemSpace.REG and source.name == "bp":
        source_offset = source.offset
        source_size = source.size
        return (
            isinstance(source_offset, int)
            and isinstance(source_size, int)
            and source_offset == (offset & 0xFFFF)
            and source_size == width
        )
    if source.const is not None or not isinstance(source.version, int):
        return False
    return _has_bp_address_origin_8616(
        site,
        source,
        offset=offset,
        width=width,
        seen=seen | {key},
    )


def _store_definition_8616(
    sites: tuple[SSAInstructionSite8616, ...],
    fact: PhysicalCallArgumentPiece8616,
    *,
    expected_const: int | None = None,
    source_storage: StorageIdentity8616 | None = None,
    source_register: str | None = None,
) -> tuple[tuple[StorageReachingDefinition8616, ...] | None, CallArgumentDefinitionFailure8616 | None]:
    """Prove one immediate, address, or locally defined register push."""
    candidates = _store_data_sites_8616(sites, fact)
    if expected_const is not None:
        candidates = tuple(candidate for candidate in candidates if candidate[1].const == expected_const)
    if source_register is not None:
        candidates = tuple(
            candidate
            for candidate in candidates
            if candidate[1].space is MemSpace.REG and candidate[1].name == source_register
        )
    if not candidates:
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    if len(candidates) != 1:
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_CONFLICT
    site, value = candidates[0]
    if value.const is None and not _has_prior_binding_8616(site, value):
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    definition = StorageReachingDefinition8616(
        value=value,
        block_addr=site.block.addr,
        instr_index=site.instr_index,
        instr_addr=fact.push_addr,
        source_storage=source_storage,
    )
    if not definition.is_complete:
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    return (definition,), None


def _bp_address_definition_8616(
    sites: tuple[SSAInstructionSite8616, ...],
    fact: PhysicalCallArgumentPiece8616,
    *,
    offset: int,
) -> tuple[
    tuple[StorageReachingDefinition8616, ...] | None,
    CallArgumentDefinitionFailure8616 | None,
]:
    """Prove that the pushed value is the exact local ``SS:BP+offset`` address."""
    candidates = _store_data_sites_8616(sites, fact)
    if not candidates:
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    if len(candidates) != 1:
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_CONFLICT
    site, value = candidates[0]
    if not _has_bp_address_origin_8616(
        site,
        value,
        offset=offset,
        width=fact.width,
    ):
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    address = IRAddress(
        space=MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=fact.width,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )
    definition = StorageReachingDefinition8616(
        value=value,
        block_addr=site.block.addr,
        instr_index=site.instr_index,
        instr_addr=fact.push_addr,
        source_storage=StorageIdentity8616(
            kind=StorageIdentityKind8616.STACK,
            width=fact.width,
            address=address,
        ),
    )
    if not definition.is_complete:
        return None, CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    return (definition,), None


def _source_kind_8616(
    source: tuple[object, ...],
) -> CallsitePushSourceKind8616 | str | None:
    """Decode the structured source category, including legacy register facts."""
    if not source:
        return None
    value = source[0]
    if isinstance(value, CallsitePushSourceKind8616):
        return value
    if value == "reg":
        return "reg"
    if not isinstance(value, str):
        return None
    try:
        return CallsitePushSourceKind8616(value)
    except ValueError:
        return None


def resolve_argument_source_definitions_8616(
    sites: tuple[SSAInstructionSite8616, ...],
    fact: PhysicalCallArgumentPiece8616,
) -> tuple[tuple[StorageReachingDefinition8616, ...] | None, CallArgumentDefinitionFailure8616 | None]:
    """Resolve one structured physical source to exact IR/SSA definitions."""
    source = fact.source
    kind = _source_kind_8616(source)
    if kind is CallsitePushSourceKind8616.IMMEDIATE:
        return _resolve_immediate_source_8616(sites, fact, source)
    if kind is CallsitePushSourceKind8616.BP_VALUE:
        return _resolve_bp_value_source_8616(sites, fact, source)
    if kind is CallsitePushSourceKind8616.GLOBAL_VALUE:
        return _resolve_global_value_source_8616(sites, fact, source)
    if kind is CallsitePushSourceKind8616.BP_ADDRESS:
        return _resolve_bp_address_source_8616(sites, fact, source)
    if kind == "reg":
        return _resolve_register_source_8616(sites, fact, source)
    if kind is CallsitePushSourceKind8616.RETURN_REGISTER:
        return None, CallArgumentDefinitionFailure8616.UNMODELED_CALL_OUTPUT
    return None, CallArgumentDefinitionFailure8616.UNSUPPORTED_SOURCE_KIND


def _resolve_immediate_source_8616(
    sites: tuple[SSAInstructionSite8616, ...],
    fact: PhysicalCallArgumentPiece8616,
    source: tuple[object, ...],
) -> tuple[tuple[StorageReachingDefinition8616, ...] | None, CallArgumentDefinitionFailure8616 | None]:
    """Resolve a pushed immediate to its exact STORE definition."""
    if len(source) != 2 or not isinstance(source[1], int):
        return None, CallArgumentDefinitionFailure8616.SOURCE_SHAPE_CONFLICT
    return _store_definition_8616(sites, fact, expected_const=source[1])


def _resolve_bp_value_source_8616(
    sites: tuple[SSAInstructionSite8616, ...],
    fact: PhysicalCallArgumentPiece8616,
    source: tuple[object, ...],
) -> tuple[tuple[StorageReachingDefinition8616, ...] | None, CallArgumentDefinitionFailure8616 | None]:
    """Resolve a pushed SS:BP load to its exact LOAD definitions."""
    if len(source) not in {2, 3} or not isinstance(source[1], int):
        return None, CallArgumentDefinitionFailure8616.SOURCE_SHAPE_CONFLICT
    if len(source) == 3 and source[2] != fact.width:
        return None, CallArgumentDefinitionFailure8616.SOURCE_WIDTH_CONFLICT
    return _load_definitions_8616(
        sites,
        fact,
        space=MemSpace.SS,
        base=("bp",),
        offset=source[1],
    )


def _resolve_global_value_source_8616(
    sites: tuple[SSAInstructionSite8616, ...],
    fact: PhysicalCallArgumentPiece8616,
    source: tuple[object, ...],
) -> tuple[tuple[StorageReachingDefinition8616, ...] | None, CallArgumentDefinitionFailure8616 | None]:
    """Resolve a pushed global load to its exact LOAD definitions."""
    if len(source) != 3 or not isinstance(source[1], int) or source[2] != fact.width:
        return None, CallArgumentDefinitionFailure8616.SOURCE_WIDTH_CONFLICT
    return _load_definitions_8616(sites, fact, space=None, base=(), offset=source[1])


def _resolve_bp_address_source_8616(
    sites: tuple[SSAInstructionSite8616, ...],
    fact: PhysicalCallArgumentPiece8616,
    source: tuple[object, ...],
) -> tuple[tuple[StorageReachingDefinition8616, ...] | None, CallArgumentDefinitionFailure8616 | None]:
    """Resolve a pushed BP-address value to its exact definition."""
    if len(source) != 2 or not isinstance(source[1], int):
        return None, CallArgumentDefinitionFailure8616.SOURCE_SHAPE_CONFLICT
    return _bp_address_definition_8616(
        sites,
        fact,
        offset=source[1],
    )


def _resolve_register_source_8616(
    sites: tuple[SSAInstructionSite8616, ...],
    fact: PhysicalCallArgumentPiece8616,
    source: tuple[object, ...],
) -> tuple[tuple[StorageReachingDefinition8616, ...] | None, CallArgumentDefinitionFailure8616 | None]:
    """Resolve a pushed register value to its exact STORE definition."""
    if len(source) != 2 or not isinstance(source[1], str):
        return None, CallArgumentDefinitionFailure8616.SOURCE_SHAPE_CONFLICT
    return _store_definition_8616(
        sites,
        fact,
        source_storage=StorageIdentity8616(
            kind=StorageIdentityKind8616.REGISTER,
            width=fact.width,
            register=source[1],
        ),
        source_register=source[1],
    )
