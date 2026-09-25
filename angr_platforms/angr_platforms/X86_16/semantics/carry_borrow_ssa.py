"""Exact SSA helpers for carry/borrow semantic classification.

Layer: Semantics.
Responsibility: normalize exact IR operations, temporary definitions, operands,
and dependency traversal used by carry/borrow classification. This module does
not classify aliases, widen values, lower types, or inspect rendered text.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Iterable

from ..ir import IRAddress, IRInstr, IRValue, MemSpace
from ..ir.logical_memory_contracts import (
    IRLogicalMemoryAccess8616,
    IRLogicalMemoryArtifact8616,
    IRMemoryAccessKind8616,
    logical_memory_execution_address_matches_8616,
)
from .carry_borrow_contracts import (
    CarryBorrowConversion8616,
    CarryBorrowDefinitionSite8616,
    CarryBorrowIROp8616,
    CarryBorrowKind8616,
    CarryBorrowMemoryLoadUse8616,
    CarryBorrowMemoryWordUse8616,
    CarryBorrowOperandUse8616,
)

type CarryBorrowDefinitions8616 = dict[int, CarryBorrowDefinitionSite8616]


def ir_op_8616(instruction: IRInstr) -> CarryBorrowIROp8616 | None:
    """Normalize one exact IR operation into the admitted operation enum."""
    try:
        return CarryBorrowIROp8616(instruction.op)
    except ValueError:
        return None


def arithmetic_kind_8616(instruction: IRInstr) -> CarryBorrowKind8616 | None:
    """Return the carry/borrow kind of one admitted arithmetic operation."""
    op = ir_op_8616(instruction)
    if op is CarryBorrowIROp8616.ADD16:
        return CarryBorrowKind8616.ADD_WITH_CARRY
    if op is CarryBorrowIROp8616.SUB16:
        return CarryBorrowKind8616.SUB_WITH_BORROW
    return None


def site_value_args_8616(site: CarryBorrowDefinitionSite8616) -> tuple[IRValue, ...]:
    """Return typed value arguments only when every argument is a value."""
    if not all(isinstance(arg, IRValue) for arg in site.instruction.args):
        return ()
    return tuple(arg for arg in site.instruction.args if isinstance(arg, IRValue))


def definition_for_8616(
    value: IRValue,
    definitions: CarryBorrowDefinitions8616,
) -> CarryBorrowDefinitionSite8616 | None:
    """Resolve one exact temporary use without parsing its display name."""
    if value.source_tmp is None:
        return None
    return definitions.get(value.source_tmp)


def single_source_8616(site: CarryBorrowDefinitionSite8616) -> IRValue | None:
    """Return the only source of one exact typed MOV definition."""
    args = site_value_args_8616(site)
    if ir_op_8616(site.instruction) is not CarryBorrowIROp8616.MOV or len(args) != 1:
        return None
    return args[0]


def conversion_source_8616(
    site: CarryBorrowDefinitionSite8616,
    conversion: CarryBorrowConversion8616,
) -> IRValue | None:
    """Return the source of one exact unary conversion projection."""
    source = single_source_8616(site)
    if source is None or source.expr != (conversion.value,):
        return None
    return source


def is_constant_8616(value: IRValue, expected: int) -> bool:
    """Return whether a value is the expected exact IR constant."""
    return value.space is MemSpace.CONST and value.const == expected


def _value_identity_8616(value: IRValue) -> tuple[object, ...]:
    return (
        value.space,
        value.name,
        value.offset,
        value.const,
        value.size,
        value.version,
        value.expr,
        value.source_tmp,
    )


def same_operands_8616(lhs: Iterable[IRValue], rhs: Iterable[IRValue]) -> bool:
    """Compare arithmetic operands including exact temporary provenance."""
    return tuple(_value_identity_8616(value) for value in lhs) == tuple(
        _value_identity_8616(value) for value in rhs
    )


def operand_use_8616(
    value: IRValue,
    definitions: CarryBorrowDefinitions8616,
    logical_memory: IRLogicalMemoryArtifact8616 | None = None,
) -> CarryBorrowOperandUse8616 | None:
    """Retain an operand together with its exact temporary definition."""
    if value.space is MemSpace.CONST:
        return CarryBorrowOperandUse8616(value, None)
    definition = definition_for_8616(value, definitions)
    if definition is None:
        return None
    return CarryBorrowOperandUse8616(
        value,
        definition,
        _memory_word_use_8616(definition, definitions, logical_memory),
    )


def _load_byte_8616(
    value: IRValue,
    definitions: CarryBorrowDefinitions8616,
) -> tuple[CarryBorrowDefinitionSite8616, IRAddress] | None:
    conversion = definition_for_8616(value, definitions)
    if conversion is None:
        return None
    source = conversion_source_8616(
        conversion,
        CarryBorrowConversion8616.WIDEN_BYTE_TO_WORD,
    )
    load = None if source is None else definition_for_8616(source, definitions)
    address = _sized_load_address_8616(load, 1)
    if address is None:
        return None
    assert load is not None
    return load, address


def _sized_load_address_8616(
    site: CarryBorrowDefinitionSite8616 | None,
    width: int,
) -> IRAddress | None:
    """Return the exact `width`-byte address of a proven LOAD site."""
    if site is None or ir_op_8616(site.instruction) is not CarryBorrowIROp8616.LOAD:
        return None
    instruction = site.instruction
    dst = instruction.dst
    if dst is None or dst.size != width or len(instruction.args) != 1:
        return None
    arg = instruction.args[0]
    if not isinstance(arg, IRAddress) or arg.size != width:
        return None
    return arg


def _shifted_high_byte_8616(
    value: IRValue,
    definitions: CarryBorrowDefinitions8616,
) -> tuple[CarryBorrowDefinitionSite8616, IRAddress] | None:
    shift = definition_for_8616(value, definitions)
    if shift is None or ir_op_8616(shift.instruction) is not CarryBorrowIROp8616.SHL16:
        return None
    args = site_value_args_8616(shift)
    if len(args) != 2 or not is_constant_8616(args[1], 8):
        return None
    return _load_byte_8616(args[0], definitions)


def _authoritative_word_access_8616(
    execution_loads: tuple[CarryBorrowMemoryLoadUse8616, ...],
    logical_memory: IRLogicalMemoryArtifact8616 | None,
) -> IRLogicalMemoryAccess8616 | None:
    """Return the unique complete logical word owning these exact load sites."""
    if logical_memory is None or not logical_memory.closed or len(execution_loads) != 2:
        return None
    matches = tuple(
        access
        for access in logical_memory.accesses
        if access.complete
        and access.kind is IRMemoryAccessKind8616.READ
        and access.key.function_addr == logical_memory.function_addr
        and access.address.size == 2
        and len(access.execution_slices) == len(execution_loads)
        and all(
            logical_memory_execution_address_matches_8616(
                load.address,
                access.address,
                source_byte_offset,
                access.address_bits,
            )
            and load.address.size == 1
            and execution.source_byte_offset == source_byte_offset
            and execution.block_addr == load.site.block_addr
            and execution.instr_index == load.site.instr_index
            and execution.insn_addr == load.site.instruction.addr
            and execution.address.size == load.address.size
            and logical_memory_execution_address_matches_8616(
                load.address,
                execution.address,
                0,
                access.address_bits,
            )
            for source_byte_offset, (load, execution) in enumerate(
                zip(execution_loads, access.execution_slices, strict=True)
            )
        )
    )
    return matches[0] if len(matches) == 1 else None


def _memory_word_use_8616(
    definition: CarryBorrowDefinitionSite8616,
    definitions: CarryBorrowDefinitions8616,
    logical_memory: IRLogicalMemoryArtifact8616 | None,
) -> CarryBorrowMemoryWordUse8616 | None:
    """Retain direct words or exact byte sites with optional logical ownership."""
    logical_address = _sized_load_address_8616(definition, 2)
    if logical_address is not None:
        execution_load = CarryBorrowMemoryLoadUse8616(definition, logical_address)
        return CarryBorrowMemoryWordUse8616(
            execution_loads=(execution_load,),
            logical_address=logical_address,
            address_bits=16,
        )
    if ir_op_8616(definition.instruction) is not CarryBorrowIROp8616.OR16:
        return None
    args = site_value_args_8616(definition)
    if len(args) != 2:
        return None
    choices = tuple(
        (low, high)
        for low_index, low_value in enumerate(args)
        if (low := _load_byte_8616(low_value, definitions)) is not None
        for high_index, high_value in enumerate(args)
        if high_index != low_index
        and (high := _shifted_high_byte_8616(high_value, definitions)) is not None
    )
    if len(choices) != 1:
        return None
    (low_load, low_address), (high_load, high_address) = choices[0]
    execution_loads = (
        CarryBorrowMemoryLoadUse8616(low_load, low_address),
        CarryBorrowMemoryLoadUse8616(high_load, high_address),
    )
    logical_access = _authoritative_word_access_8616(
        execution_loads,
        logical_memory,
    )
    if logical_access is None:
        return None
    return CarryBorrowMemoryWordUse8616(
        execution_loads=execution_loads,
        logical_address=logical_access.address,
        address_bits=logical_access.address_bits,
    )


def dependency_arithmetic_sites_8616(
    value: IRValue,
    definitions: CarryBorrowDefinitions8616,
    kind: CarryBorrowKind8616,
) -> tuple[CarryBorrowDefinitionSite8616, ...]:
    """Collect exact matching arithmetic definitions in one SSA dependency DAG."""
    pending = [value]
    seen: set[int] = set()
    matches: list[CarryBorrowDefinitionSite8616] = []
    while pending:
        current = pending.pop()
        if current.source_tmp is None or current.source_tmp in seen:
            continue
        seen.add(current.source_tmp)
        site = definitions.get(current.source_tmp)
        if site is None:
            continue
        if arithmetic_kind_8616(site.instruction) is kind:
            matches.append(site)
        pending.extend(site_value_args_8616(site))
    return tuple(matches)


__all__ = [
    "CarryBorrowDefinitions8616",
    "arithmetic_kind_8616",
    "conversion_source_8616",
    "definition_for_8616",
    "dependency_arithmetic_sites_8616",
    "ir_op_8616",
    "is_constant_8616",
    "operand_use_8616",
    "same_operands_8616",
    "single_source_8616",
    "site_value_args_8616",
]
